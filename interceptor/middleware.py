import hashlib
import json
import logging
import sys
import os
import ssl
import socket
import stat
import tempfile
import time
import uuid
import httpx
from urllib.parse import urlparse
from prometheus_client import Counter, start_http_server, REGISTRY

# Add the ledger directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'ledger'))

# Import pre-flight validation schemas
from schemas import TOOL_VALIDATORS

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

# Runtime modes:
#   Production (inside Docker): SPIRE socket present → mTLS enforced via Envoy
#   Development (local venv):   Set SPIRE_DISABLED=true and point OPA_URL at
#                               http://localhost:8181/v1/data/ail/main/deny
#                               Policy is still evaluated; transport identity is not.
_SPIRE_DISABLED = os.getenv("SPIRE_DISABLED", "false").lower() == "true"
# Query the explicit /allow endpoint, not /deny.
# If the policy fails to compile, OPA returns {"result": null} for this path,
# which the middleware treats as DENIED (fail-closed). Checking allow == True
# is strictly safer than checking absence of denials.
_OPA_URL = os.getenv("OPA_URL", "https://localhost:8443/v1/data/ail/main/allow")

# Bundle key under OPA's `bundles:` config (opa-config.yaml), not tenant-
# specific. Single-sourced via AIL_BUNDLE_NAME so opa-config.yaml (which
# reads the same env var via ${AIL_BUNDLE_NAME} substitution) and this
# module can never independently drift apart - see
# docs/reports/phase-0-redteam.md, C4, and docs/reports/phase-0-1.md, P01-3.
_BUNDLE_NAME = os.getenv("AIL_BUNDLE_NAME", "ail-policies")

# Used only for the startup readiness check below - is OPA's bundle plugin
# done loading *some* bundle under this name yet. Per-call revision
# attribution no longer reads this at all (Phase 1.2, D9): the `evaluation`
# rule finds whichever loaded bundle's manifest claims the `ail` root, not
# whatever name a caller (or this env var) supplies.
_OPA_REVISION_URL = _OPA_URL.replace(
    "/v1/data/ail/main/allow", f"/v1/data/system/bundles/{_BUNDLE_NAME}/manifest/revision"
)

# Single combined query (Phase 1, P1-1): verdict, deny reasons, and bundle
# revision in one round trip. See policy/core/main.rego's `evaluation` rule.
# The revision is attributed by OPA itself, from whichever loaded bundle's
# manifest claims the `ail` root (Phase 1.2, D9) - the request carries no
# bundle name at all, so a caller cannot influence which bundle's revision
# gets recorded.
_OPA_EVAL_URL = _OPA_URL.replace("/v1/data/ail/main/allow", "/v1/data/ail/main/evaluation")

# Closed set of outcome types (D1). Never inferred from message text anywhere
# downstream - this is the only vocabulary that exists.
OUTCOME_POLICY_ALLOW = "policy_allow"
OUTCOME_POLICY_DENY = "policy_deny"
OUTCOME_SCHEMA_DENY = "schema_deny"
OUTCOME_FAULT = "fault"

FAULT_OPA_UNREACHABLE = "opa_unreachable"
FAULT_REVISION_UNAVAILABLE = "revision_unavailable"
FAULT_VERIFIER_UNREACHABLE = "verifier_unreachable"
FAULT_SPIFFE_UNAVAILABLE = "spiffe_unavailable"
# Phase 1.1: OPA answered but the /evaluation body was missing or
# mistyped allow/reasons/revision (P11-3) - a fault, never an implicit allow.
FAULT_MALFORMED_POLICY_RESPONSE = "malformed_policy_response"
# Phase 1.1: the content-store write (D7) failed before the ledger write was
# attempted - the call denies and no ledger entry is written at all (there is
# no entry to carry a wrong content_state).
FAULT_CONTENT_STORE_UNREACHABLE = "content_store_unreachable"

# Closed set of content states (D7, Phase 1.1). Written into the ledger entry
# itself - never "erased", which is inferred at read time (control_plane/
# main.py::get_audit) from content_state plus whether a CallContent row still
# exists, the same pattern D2/D8 uses for verification.
CONTENT_PRESENT = "present"
CONTENT_UNAVAILABLE = "unavailable"


def _outcome(outcome_type, fault_class=None, policy_revision=None, reasons=None):
    """Build the one shape query_opa_policy ever returns - the single point
    outcome_type/fault_class/policy_revision are set. Nothing downstream
    re-derives these from message text."""
    return {
        "outcome_type": outcome_type,
        "fault_class": fault_class,
        "policy_revision": policy_revision,
        "reasons": reasons or [],
    }

# Fields whose values must never appear in container logs.
# Add any future PII or credential keys here - the helper recurses into nested dicts.
# 'tags' is included whole, not recursed into: its keys are caller-supplied and
# unconstrained by schema (Dict[str, str]), so there is no fixed set of "safe"
# sub-keys to allow through - any of them could carry free text or PII. This
# only affects what reaches stdout; the ledger still stores the raw payload
# (see docs/reports/phase-0.md, P0-8 - redacting the ledger itself is Phase 1).
_SENSITIVE_KEYS = frozenset({"query", "approval_ticket", "commit_hash", "tags"})


def _redact_args(args) -> dict:
    """
    Return a shallow copy of args with sensitive field values replaced by [REDACTED].
    Recurses one level into nested dicts not themselves listed in _SENSITIVE_KEYS.
    Non-sensitive metadata with fixed, known key names (region, instance_type,
    environment, etc.) is preserved in the clear for ops visibility.

    A non-dict top-level value (P11-2: an LLM can emit a list/string/null/int
    for `arguments`) is not an error here - this is only ever used for a log
    line, and classification of the malformed shape itself happens once, in
    query_opa_policy. This must not raise ahead of that classification.
    """
    if not isinstance(args, dict):
        return {"_shape": type(args).__name__}
    redacted = {}
    for k, v in args.items():
        if k in _SENSITIVE_KEYS:
            redacted[k] = "[REDACTED]"
        elif isinstance(v, dict):
            redacted[k] = _redact_args(v)
        else:
            redacted[k] = v
    return redacted

# Expected SPIFFE ID of the OPA gateway (Envoy mTLS terminator).
# Any peer presenting a different URI SAN — even if CA-signed — is rejected.
_EXPECTED_OPA_SPIFFE_ID = os.getenv(
    "OPA_SPIFFE_ID", "spiffe://ail.internal/workload/envoy"
)


def _validate_peer_spiffe_san(ssl_ctx: ssl.SSLContext) -> bool:
    """
    Establish a raw TLS connection to the OPA/Envoy endpoint and verify that
    the peer's certificate URI SAN matches _EXPECTED_OPA_SPIFFE_ID.

    check_hostname is disabled globally because SPIFFE certs carry URI SANs,
    not DNS SANs. This function reinstates identity verification at the
    application layer by extracting and comparing the URI SAN directly.

    Returns False on any error (fail-closed).
    """
    if _SPIRE_DISABLED:
        return True  # SAN validation only applies when mTLS is active.

    parsed = urlparse(_OPA_URL)
    host = parsed.hostname or "envoy"
    port = parsed.port or 443

    try:
        from cryptography import x509 as _cx509

        raw = socket.create_connection((host, port), timeout=5)
        tls_sock = ssl_ctx.wrap_socket(raw, server_side=False, server_hostname=host)
        try:
            der = tls_sock.getpeercert(binary_form=True)
        finally:
            tls_sock.close()

        if not der:
            logging.error("Peer SPIFFE SAN validation: no peer certificate returned.")
            return False

        cert = _cx509.load_der_x509_certificate(der)
        try:
            san_ext = cert.extensions.get_extension_for_class(
                _cx509.SubjectAlternativeName
            )
            uri_sans = san_ext.value.get_values_for_type(
                _cx509.UniformResourceIdentifier
            )
        except Exception:
            uri_sans = []

        if _EXPECTED_OPA_SPIFFE_ID in uri_sans:
            logging.debug("Peer SPIFFE SAN validated: %s", _EXPECTED_OPA_SPIFFE_ID)
            return True

        logging.error(
            "Peer SPIFFE SAN mismatch — expected '%s', peer presented: %s. "
            "Fail-closed: OPA request blocked.",
            _EXPECTED_OPA_SPIFFE_ID,
            uri_sans,
        )
        return False

    except Exception as exc:
        logging.error("Peer SPIFFE SAN validation error: %s", exc)
        return False

# Prometheus metrics — guard against double-registration when the module is
# re-imported in the same process (e.g. pytest collecting multiple test files).
try:
    _POLICY_DECISIONS = Counter(
        "ail_policy_decisions_total",
        "Total AIL policy decisions by status, outcome_type, fault_class, and tool",
        ["status", "outcome_type", "fault_class", "tool_name"],
    )
except ValueError:
    _POLICY_DECISIONS = REGISTRY._names_to_collectors["ail_policy_decisions_total"]

try:
    start_http_server(8000)
    logging.info("Prometheus metrics server started on 0.0.0.0:8000")
except OSError:
    pass  # port already bound (e.g. module reloaded)


def _fetch_opa_bundle_revision(ssl_context) -> str | None:
    """
    Read back the revision of the bundle the OPA instance we just queried has
    actually loaded, over the same channel used for the policy query itself.

    OPA exposes this at data.system.bundles.<name>.manifest.revision as soon
    as the Bundle API has activated a bundle - no separate service, so the
    value returned here cannot name a bundle other than the one that produced
    the decision this call is paired with.

    Returns None on any error or on an undefined result (bundle not yet
    loaded, wrong bundle name). Callers must treat None as the digest being
    unobtainable, not as an empty digest.
    """
    try:
        with httpx.Client(verify=ssl_context) as client:
            response = client.get(_OPA_REVISION_URL, timeout=5)
        if response.status_code != 200:
            return None
        revision = response.json().get("result")
        return revision if isinstance(revision, str) and revision else None
    except Exception as e:
        logging.error(f"OPA bundle revision query failed: {e}")
        return None


def _get_spiffe_ssl_context() -> ssl.SSLContext | None:
    """
    Create an SSL context with SPIFFE SVID fetched entirely in-memory.
    
    Returns:
        ssl.SSLContext | None: SSL context with SPIFFE certificates, or None if unavailable
    """
    # Declare socket_path at the very top to ensure it's always bound
    socket_path = os.getenv('SPIFFE_ENDPOINT_SOCKET', 'unix:///tmp/spire-sockets/workload_api.sock')
    
    try:
        from spiffe import WorkloadApiClient, TrustDomain
        from cryptography.hazmat.primitives import serialization

        # One-shot fetch — no background watcher thread that can block indefinitely
        client = WorkloadApiClient(socket_path=socket_path)
        x509_context = client.fetch_x509_context()
        svid = x509_context.default_svid
        bundle = x509_context.x509_bundle_set.get_bundle_for_trust_domain(TrustDomain("ail.internal"))
        
        # Serialize certificates to PEM bytes (in-memory only)
        cert_pem = b"".join(
            cert.public_bytes(serialization.Encoding.PEM) for cert in svid.cert_chain
        )
        key_pem = svid.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        ca_pem = b"".join(
            cert.public_bytes(serialization.Encoding.PEM) for cert in bundle.x509_authorities
        )
        
        # Generate SSL context directly from in-memory certificates
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.check_hostname = False  # SPIFFE certs use URI SANs, not DNS SANs
        ssl_ctx.verify_mode = ssl.CERT_REQUIRED
        
        # Load cert/key without writing private key material to the filesystem.
        if hasattr(os, 'memfd_create'):
            # Linux production path: anonymous RAM-only FDs — SOC2 compliant.
            cert_fd = os.memfd_create("spiffe_cert", flags=0)
            key_fd  = os.memfd_create("spiffe_key",  flags=0)
            try:
                os.write(cert_fd, cert_pem)
                os.write(key_fd,  key_pem)
                cert_path = f"/proc/self/fd/{cert_fd}"
                key_path  = f"/proc/self/fd/{key_fd}"
                ssl_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
                ssl_ctx.load_verify_locations(cadata=ca_pem.decode())
            finally:
                os.close(cert_fd)
                os.close(key_fd)
        else:
            # macOS/Windows dev fallback: disk-backed temp files.
            # WARNING: private key material touches the filesystem.
            # This path must never run in production.
            logging.warning(
                "os.memfd_create unavailable on this OS — using disk-backed temp files "
                "for SPIFFE certificate loading. This is a LOCAL DEV fallback only and "
                "must not run in production (SOC2 violation)."
            )
            cert_file = tempfile.NamedTemporaryFile(delete=False)
            key_file  = tempfile.NamedTemporaryFile(delete=False)
            try:
                cert_file.write(cert_pem)
                cert_file.flush()
                # Restrict to owner read/write immediately after write —
                # prevents other processes from reading key material off disk.
                os.chmod(cert_file.name, stat.S_IRUSR | stat.S_IWUSR)
                key_file.write(key_pem)
                key_file.flush()
                os.chmod(key_file.name, stat.S_IRUSR | stat.S_IWUSR)
                ssl_ctx.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)
                ssl_ctx.load_verify_locations(cadata=ca_pem.decode())
            finally:
                cert_file.close()
                key_file.close()
                # Overwrite key material with random bytes before unlinking to
                # close the disk-recovery window (prevents forensic file carving).
                with open(cert_file.name, "wb") as f:
                    f.write(os.urandom(len(cert_pem)))
                with open(key_file.name, "wb") as f:
                    f.write(os.urandom(len(key_pem)))
                os.unlink(cert_file.name)
                os.unlink(key_file.name)
        
        logging.info(f"SPIFFE SVID loaded in-memory: {svid.spiffe_id}")
        return ssl_ctx
            
    except Exception as e:
        logging.error(f"Failed to fetch SPIFFE SVID from {socket_path}: {e}")
        return None


def get_spiffe_ssl_context() -> ssl.SSLContext | None:
    """
    Get SPIFFE SSL context for mTLS authentication.
    
    Returns:
        ssl.SSLContext | None: SSL context with SPIFFE certificates, or None if unavailable
    """
    return _get_spiffe_ssl_context()


def verify_bundle_at_startup(timeout_seconds: float = 30, poll_interval: float = 2) -> None:
    """
    Verify the configured OPA bundle name resolves to a loaded bundle before
    the agent accepts work, and exit the process if it does not.

    A bundle-name mismatch between opa-config.yaml's `bundles:` key and this
    module's AIL_BUNDLE_NAME (both meant to be the same value via env
    substitution - see _BUNDLE_NAME above) otherwise surfaces only as every
    subsequent tool call being DENIED, indistinguishable at the time from a
    real policy denial (docs/reports/phase-0-redteam.md, C4). Checking once
    at boot, with the same actionable message either config location would
    need to diagnose it, turns that into a startup failure instead.

    Polls for up to timeout_seconds because OPA's bundle plugin loads
    asynchronously after the container reports healthy (opa-config.yaml's
    polling.min_delay_seconds/max_delay_seconds) - a single immediate check
    would false-positive during ordinary startup timing, not just on a real
    mismatch.
    """
    if _SPIRE_DISABLED:
        ssl_context = True
    else:
        ssl_context = _get_spiffe_ssl_context()
        if not ssl_context or not _validate_peer_spiffe_san(ssl_context):
            logging.error(
                "STARTUP FAILURE: could not establish a verified mTLS channel to "
                "OPA/Envoy - cannot confirm the policy bundle is loaded. Check the "
                "SPIRE agent and Envoy sidecar are healthy before retrying."
            )
            sys.exit(1)

    deadline = time.monotonic() + timeout_seconds
    revision = None
    while time.monotonic() < deadline:
        revision = _fetch_opa_bundle_revision(ssl_context)
        if revision:
            break
        time.sleep(poll_interval)

    if not revision:
        logging.error(
            "STARTUP FAILURE: bundle '%s' has no revision on OPA after %ss "
            "(queried %s). This means opa-config.yaml's `bundles:` key and "
            "AIL_BUNDLE_NAME (currently '%s', read by interceptor/middleware.py) "
            "do not name the same bundle, or OPA has not loaded any bundle under "
            "this name. Check: (1) opa-config.yaml's `bundles:` map key resolves "
            "to '%s' after ${AIL_BUNDLE_NAME} substitution - confirm AIL_BUNDLE_NAME "
            "is set identically for the opa and this agent's containers; "
            "(2) OPA's own logs for bundle download/activation errors.",
            _BUNDLE_NAME, timeout_seconds, _OPA_REVISION_URL, _BUNDLE_NAME, _BUNDLE_NAME,
        )
        sys.exit(1)

    logging.info("Startup check: OPA bundle '%s' loaded, revision=%s", _BUNDLE_NAME, revision)


def query_opa_policy(tool_name, tool_args):
    """
    Query OPA policy for tool call authorization using mTLS authentication.

    Single round trip (Phase 1, P1-1): verdict, deny reasons, and the bundle
    revision that produced them all come from one query to
    data.ail.main.evaluation. This is the single point outcome_type,
    fault_class, policy_revision, and reasons are set - callers never
    reconstruct any of these from message text.

    Args:
        tool_name (str): Name of the tool being called
        tool_args (dict): Arguments passed to the tool

    Returns:
        dict: see _outcome() - outcome_type, fault_class, policy_revision, reasons
    """
    # P11-2 (Phase 1.1): validate the input shape before anything else
    # touches it. json.loads happily parses a list/string/null/number for
    # `arguments` - none of those are a dict, and everything downstream
    # (schema validators' **tool_args, _redact_args' old .items()) assumed
    # one. This is the single point that classifies a malformed shape, same
    # as every other outcome_type in this function.
    if not isinstance(tool_args, dict):
        msg = f"tool_args must be a JSON object; got {type(tool_args).__name__}."
        logging.warning(f"Pre-flight validation blocked malformed tool_args shape for {tool_name}: {type(tool_args).__name__}")
        return _outcome(OUTCOME_SCHEMA_DENY, reasons=[msg])

    # Epic 2: Pre-Flight Input Validation
    # Catch LLM hallucinations before they are sent to OPA over the network.
    # Fail-closed: tools not present in TOOL_VALIDATORS are blocked here.
    # 0 OPA requests for this outcome - schema rejection never reaches evaluation.
    validator = TOOL_VALIDATORS.get(tool_name)
    if validator is None:
        msg = f"No registered schema for tool '{tool_name}'."
        logging.warning(f"Pre-flight validation blocked unregistered tool: {tool_name}")
        return _outcome(OUTCOME_SCHEMA_DENY, reasons=[msg])
    is_valid, error_message = validator(tool_args)
    if not is_valid:
        logging.warning(f"Pre-flight validation failed for {tool_name}: {error_message}")
        return _outcome(OUTCOME_SCHEMA_DENY, reasons=[error_message])

    if _SPIRE_DISABLED:
        if not (_OPA_URL.startswith("http://localhost") or _OPA_URL.startswith("http://127.0.0.1") or _OPA_URL.startswith("http://opa")):
            logging.error(
                "SPIRE_DISABLED=true requires a plain http:// OPA_URL pointing to localhost or opa. "
                "Set OPA_URL=http://localhost:8181/v1/data/ail/main/deny or OPA_URL=http://opa:8181/v1/data/ail/main/deny"
            )
            return _outcome(OUTCOME_FAULT, fault_class=FAULT_OPA_UNREACHABLE)
        logging.warning("SPIRE_DISABLED=true: querying OPA over plain HTTP (dev mode only, no transport identity)")
        ssl_context = True  # unused for http://, but explicit
    else:
        ssl_context = _get_spiffe_ssl_context()
        if not ssl_context:
            return _outcome(OUTCOME_FAULT, fault_class=FAULT_SPIFFE_UNAVAILABLE)

        # Verify the OPA endpoint's SPIFFE URI SAN before transmitting policy
        # data. Prevents any CA-signed workload from impersonating the policy
        # engine — only spiffe://ail.internal/workload/envoy is accepted.
        if not _validate_peer_spiffe_san(ssl_context):
            return _outcome(OUTCOME_FAULT, fault_class=FAULT_SPIFFE_UNAVAILABLE)

    # Single query: verdict + reasons + revision together.
    try:
        with httpx.Client(verify=ssl_context) as client:
            response = client.post(
                _OPA_EVAL_URL,
                json={"input": {
                    "tool_name": tool_name,
                    "tool_args": tool_args,
                }},
                timeout=5,
            )
    except httpx.ConnectError as e:
        logging.error(f"OPA connection error: {e}")
        return _outcome(OUTCOME_FAULT, fault_class=FAULT_OPA_UNREACHABLE)
    except httpx.RequestError as e:
        logging.error(f"OPA request error: {e}")
        return _outcome(OUTCOME_FAULT, fault_class=FAULT_OPA_UNREACHABLE)
    except Exception as e:
        logging.error(f"OPA query failed: {e}")
        return _outcome(OUTCOME_FAULT, fault_class=FAULT_OPA_UNREACHABLE)

    logging.debug(f"OPA /evaluation status={response.status_code} body={response.text[:200]}")

    if response.status_code != 200:
        logging.error(f"OPA /evaluation returned HTTP {response.status_code}. Fail-closed policy enforced.")
        return _outcome(OUTCOME_FAULT, fault_class=FAULT_OPA_UNREACHABLE)

    result = response.json().get("result")
    if result is None:
        # evaluation is only undefined if the revision lookup was - allow and
        # reasons both always have a value by construction (see main.rego).
        logging.error(
            "OPA answered /evaluation but the result was undefined - the bundle revision "
            "could not be read back in the same cycle. Refusing to record an unattributable decision."
        )
        return _outcome(OUTCOME_FAULT, fault_class=FAULT_REVISION_UNAVAILABLE)

    # P11-3 (Phase 1.1): a 200 with a defined result is not enough - the body
    # must actually carry all three fields evaluation always sets by
    # construction. A version skew, a future Rego change, or a mocked
    # response upstream that drops one of them must not be read as an
    # implicit allow with a null revision (ADR-0005's own table requires
    # policy_allow to always carry a set revision).
    allow = result.get("allow")
    reasons = result.get("reasons")
    revision = result.get("revision")
    if not isinstance(allow, bool) or not isinstance(reasons, list) or not isinstance(revision, str) or not revision:
        logging.error(
            "OPA /evaluation response missing or malformed field(s) - "
            "allow=%r reasons=%r revision=%r. Refusing to record an outcome "
            "from an incomplete response.",
            allow, reasons, revision,
        )
        return _outcome(OUTCOME_FAULT, fault_class=FAULT_MALFORMED_POLICY_RESPONSE)

    if allow is True:
        return _outcome(OUTCOME_POLICY_ALLOW, policy_revision=revision)
    return _outcome(OUTCOME_POLICY_DENY, policy_revision=revision, reasons=list(reasons))


def _canonical_hash(tool_args) -> str:
    """SHA-256 over the canonically serialized tool arguments (D5). Sorted
    keys and a fixed separator so the same logical payload always hashes
    the same way regardless of dict construction order. tool_args need not
    be a dict (P11-2, Phase 1.1) - json.dumps(sort_keys=True) is well-defined
    for any JSON-serializable value; sort_keys only affects dict ordering."""
    canonical = json.dumps(tool_args, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


_DENIED_PREFIX = "DENIED: "


def _strip_denied_prefix(reason: str) -> str:
    """Some Rego packs already prefix their own message with "DENIED: "
    (finops.rego, some of gdpr.rego/soc2.rego); others don't (soc2.rego's
    and finops.rego's deploy_to_production rules). Normalize so the single
    canonical prefix added below is never doubled."""
    return reason[len(_DENIED_PREFIX):] if reason.startswith(_DENIED_PREFIX) else reason


def _render_message(outcome_type, fault_class, reasons):
    """Presentational text only - classification already happened in
    query_opa_policy. This never feeds back into outcome_type/fault_class."""
    if outcome_type == OUTCOME_POLICY_ALLOW:
        return "Action approved by policy"
    if outcome_type == OUTCOME_POLICY_DENY:
        normalized = [_strip_denied_prefix(r) for r in reasons]
        return _DENIED_PREFIX + ("; ".join(normalized) if normalized else "Action did not pass policy evaluation.")
    if outcome_type == OUTCOME_SCHEMA_DENY:
        return _DENIED_PREFIX + "Schema Validation Failed. " + "; ".join(reasons)
    # OUTCOME_FAULT
    return f"{_DENIED_PREFIX}Compliance engine fault ({fault_class}). Fail-closed policy enforced."


def intercept_tool_call(tool_name, tool_args, agent_id="base_agent"):
    """
    Intercept and validate tool calls using OPA policy.

    Args:
        tool_name (str): Name of the tool being called
        tool_args (dict): Arguments passed to the tool
        agent_id (str): Identifier for the agent making the call

    Returns:
        dict: 'status', 'message', 'outcome_type', 'fault_class',
        'policy_revision', and, only when a ledger record actually exists,
        'ledger_tx_id'.
    """
    logging.info(f"Agent Request -> AIL Intercept: {tool_name} | args={json.dumps(_redact_args(tool_args))}")

    outcome = query_opa_policy(tool_name, tool_args)
    outcome_type = outcome["outcome_type"]
    fault_class = outcome["fault_class"]
    policy_revision = outcome["policy_revision"]
    reasons = outcome["reasons"]

    input_sha256 = _canonical_hash(tool_args)
    # Minted here, independent of ImmuDB's own tx numbering (D7, Phase 1.1) -
    # joins the ledger entry to its content-store row without exposing the
    # ledger's transaction id as the join key.
    call_id = uuid.uuid4().hex

    # D7 (Phase 1.1): content is written first. A dict-shaped payload is
    # attempted; the P11-2 shape guard above already turned anything else
    # into schema_deny, so there is nothing storable to attempt for it.
    if isinstance(tool_args, dict):
        try:
            from content_store import store_content
            store_content(call_id, tool_args)
            content_state = CONTENT_PRESENT
        except Exception as e:
            # Unlike the old best-effort write, a content-store failure now
            # denies as a fault: the ledger entry that would have recorded
            # this decision is never written, so there is no entry left
            # around to carry a content_state that contradicts what actually
            # happened (the incoherence the old best-effort write produced).
            logging.error(f"Content store write failed for call_id={call_id}: {e}")
            outcome_type = OUTCOME_FAULT
            fault_class = FAULT_CONTENT_STORE_UNREACHABLE
            policy_revision = None
            reasons = []
            content_state = None
    else:
        content_state = CONTENT_UNAVAILABLE

    # Fail-closed: log to ImmuDB ledger or the call denies. A fault here is
    # itself undocumentable (D1's boundary): the recording path is what just
    # failed, so no record exists and outcome_type is overwritten to fault -
    # this is one of two outcomes that never produce a ledger_tx_id (the
    # other being the content-store fault above, which skips this block
    # entirely via content_state is None).
    ledger_tx_id = None
    if content_state is not None:
        try:
            from immudb_ledger import get_ledger
            ledger = get_ledger()

            ledger_tx_id = ledger.log_tool_call(
                agent_id=agent_id,
                tool_name=tool_name,
                call_id=call_id,
                input_sha256=input_sha256,
                outcome_type=outcome_type,
                fault_class=fault_class,
                policy_revision=policy_revision,
                reasons=reasons,
                content_state=content_state,
            )
            logging.info(f"Ledger tx_id: {ledger_tx_id}")
        except Exception as e:
            logging.error(f"ImmuDB ledger unavailable: {e}")
            outcome_type = OUTCOME_FAULT
            fault_class = FAULT_VERIFIER_UNREACHABLE
            policy_revision = None
            reasons = []

    # P11-6 (Phase 1.1): allowlist against the closed TOOL_VALIDATORS
    # registry before using tool_name as a Prometheus label value - a
    # hallucinated tool name must not grow the metric's cardinality.
    metric_tool_name = tool_name if tool_name in TOOL_VALIDATORS else "_unregistered"

    # One increment per call, using the final recorded outcome - not the
    # OPA-only verdict - so a call OPA approved but never got written never
    # shows up in metrics as "approved" (see D1/D3).
    status = "APPROVED" if outcome_type == OUTCOME_POLICY_ALLOW else "DENIED"
    _POLICY_DECISIONS.labels(
        status=status,
        outcome_type=outcome_type,
        fault_class=fault_class or "",
        tool_name=metric_tool_name,
    ).inc()

    message = _render_message(outcome_type, fault_class, reasons)
    logging.info(f"Policy Engine Decision: {status}: {message}")

    response = {
        "status": status,
        "message": message,
        "outcome_type": outcome_type,
        "fault_class": fault_class,
        "policy_revision": policy_revision,
    }

    if ledger_tx_id is not None:
        response["ledger_tx_id"] = ledger_tx_id

    return response
