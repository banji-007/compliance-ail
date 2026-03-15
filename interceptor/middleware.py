import json
import logging
import sys
import os
import ssl
import socket
import stat
import tempfile
import time
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
# Control plane connection — override for Docker vs local dev.
# Docker: http://ail-control-plane:8002  |  Local dev: http://localhost:8002
_CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL", "http://localhost:8002")
_AIL_TENANT_ID = os.getenv("AIL_TENANT_ID", "tenant_default")

_SPIRE_DISABLED = os.getenv("SPIRE_DISABLED", "false").lower() == "true"
# Query the explicit /allow endpoint, not /deny.
# If the policy fails to compile, OPA returns {"result": null} for this path,
# which the middleware treats as DENIED (fail-closed). Checking allow == True
# is strictly safer than checking absence of denials.
_OPA_URL = os.getenv("OPA_URL", "https://localhost:8443/v1/data/ail/main/allow")

_DENIED_UNAVAILABLE = {"allowed": False, "reason": "Compliance engine unavailable. Fail-closed policy enforced."}

# Fields whose values must never appear in container logs.
# Add any future PII or credential keys here — the helper recurses into nested dicts.
_SENSITIVE_KEYS = frozenset({"query", "approval_ticket", "commit_hash"})


def _redact_args(args: dict) -> dict:
    """
    Return a shallow copy of args with sensitive field values replaced by [REDACTED].
    Recurses one level into nested dicts (e.g. the 'tags' dict in provision_cloud_server).
    Non-sensitive metadata (region, instance_type, environment, tags, etc.) is preserved
    in the clear for ops visibility.
    """
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
        "Total AIL policy decisions by status, tool, and policy",
        ["status", "tool_name", "policy"],
    )
except ValueError:
    _POLICY_DECISIONS = REGISTRY._names_to_collectors["ail_policy_decisions_total"]

try:
    start_http_server(8000, addr="127.0.0.1")
    logging.info("Prometheus metrics server started on 127.0.0.1:8000")
except OSError:
    pass  # port already bound (e.g. module reloaded)


def _compute_policy_hash() -> str:
    """
    Fetch the active bundle ETag from the AIL Control Plane.

    The ETag is a SHA-256 digest of all active Rego files + tenant data.json,
    computed by control_plane/bundle.py — exactly the policy surface OPA is
    currently evaluating. Recording it in ImmuDB makes policy drift immediately
    visible: any change to an enabled pack or tenant config produces a new ETag.

    Uses HTTP HEAD to /bundles/{tenant_id}: FastAPI/Starlette strips the
    response body for HEAD requests on GET routes, so the bundle bytes are
    never transferred over the wire.

    Falls back to 'bundle-hash-unavailable' on any error, logs a WARNING so
    the degradation is visible in monitoring, and still allows ledger writes.
    """
    bundle_url = f"{_CONTROL_PLANE_URL}/bundles/{_AIL_TENANT_ID}"
    try:
        with httpx.Client(timeout=2) as client:
            response = client.head(bundle_url)
        etag = response.headers.get("etag")
        if etag:
            logging.debug(f"Bundle ETag from control plane ({_AIL_TENANT_ID}): {etag[:16]}…")
            return etag
        logging.warning(
            f"Control plane at {bundle_url} responded but returned no ETag header. "
            "Policy version recorded as 'bundle-hash-unavailable'."
        )
        return "bundle-hash-unavailable"
    except Exception as e:
        logging.warning(
            f"Control plane unreachable at {bundle_url} — policy version will be "
            f"recorded as 'bundle-hash-unavailable' in the ledger. Error: {e}"
        )
        return "bundle-hash-unavailable"


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


def query_opa_policy(tool_name, tool_args):
    """
    Query OPA policy for tool call authorization using mTLS authentication.
    Implements two-query fallback: primary /allow check, then /deny for details.

    Args:
        tool_name (str): Name of the tool being called
        tool_args (dict): Arguments passed to the tool

    Returns:
        dict: OPA policy decision with denial reasons if applicable
    """
    # Epic 2: Pre-Flight Input Validation
    # Catch LLM hallucinations before they are sent to OPA over the network.
    # Fail-closed: tools not present in TOOL_VALIDATORS are blocked here.
    validator = TOOL_VALIDATORS.get(tool_name)
    if validator is None:
        error_details = f"DENIED: Schema Validation Failed. No registered schema for tool '{tool_name}'."
        logging.warning(f"Pre-flight validation blocked unregistered tool: {tool_name}")
        return {
            "allowed": False,
            "reason": error_details,
            "deny": [error_details],
        }
    is_valid, error_message = validator(tool_args)
    if not is_valid:
        error_details = f"DENIED: Schema Validation Failed. {error_message}"
        logging.warning(f"Pre-flight validation failed for {tool_name}: {error_details}")
        return {
            "allowed": False,
            "reason": error_details,
            "deny": [error_details],
        }
    
    if _SPIRE_DISABLED:
        if not (_OPA_URL.startswith("http://localhost") or _OPA_URL.startswith("http://127.0.0.1") or _OPA_URL.startswith("http://opa")):
            logging.error(
                "SPIRE_DISABLED=true requires a plain http:// OPA_URL pointing to localhost or opa. "
                "Set OPA_URL=http://localhost:8181/v1/data/ail/main/deny or OPA_URL=http://opa:8181/v1/data/ail/main/deny"
            )
            return _DENIED_UNAVAILABLE
        logging.warning("SPIRE_DISABLED=true: querying OPA over plain HTTP (dev mode only, no transport identity)")
        ssl_context = True  # unused for http://, but explicit
    else:
        ssl_context = _get_spiffe_ssl_context()
        if not ssl_context:
            return {
                "allowed": False,
                "reason": "DENIED: Workload Identity missing or invalid. Execution blocked by AIL.",
                "deny": ["Workload Identity missing or invalid. Execution blocked by AIL."]
            }

        # Verify the OPA endpoint's SPIFFE URI SAN before transmitting policy
        # data. Prevents any CA-signed workload from impersonating the policy
        # engine — only spiffe://ail.internal/workload/envoy is accepted.
        if not _validate_peer_spiffe_san(ssl_context):
            return {
                "allowed": False,
                "reason": "DENIED: OPA endpoint SPIFFE identity could not be verified. Execution blocked by AIL.",
                "deny": ["OPA endpoint SPIFFE identity could not be verified. Execution blocked by AIL."]
            }

    # Primary query to /allow endpoint
    try:
        with httpx.Client(verify=ssl_context) as client:
            response = client.post(
                _OPA_URL,
                json={"input": {"tool_name": tool_name, "tool_args": tool_args}},
                timeout=5,
            )

        logging.debug(f"OPA /allow status={response.status_code} body={response.text[:200]}")

        if response.status_code == 200:
            result = response.json().get("result")
            # result must be explicitly True. Any other value — False, null,
            # or missing (policy not loaded / compile error) — is DENIED.
            if result is None:
                logging.error(
                    "OPA returned null for /allow — policy not loaded or failed to compile. "
                    "Fail-closed policy enforced."
                )
                return _DENIED_UNAVAILABLE
            if result is True:
                return {"allowed": True, "reason": "Action approved by policy", "deny": []}
            else:
                # allow is False, execute second query to /deny for specific reasons
                deny_url = _OPA_URL.replace("/allow", "/deny")
                try:
                    with httpx.Client(verify=ssl_context) as client:
                        deny_response = client.post(
                            deny_url,
                            json={"input": {"tool_name": tool_name, "tool_args": tool_args}},
                            timeout=5,
                        )
                    
                    logging.debug(f"OPA /deny status={deny_response.status_code} body={deny_response.text[:200]}")
                    
                    if deny_response.status_code == 200:
                        deny_result = deny_response.json().get("result", [])
                        # Ensure deny_result is a list of strings
                        if isinstance(deny_result, list) and deny_result:
                            combined_reason = "; ".join(deny_result)
                            return {
                                "allowed": False,
                                "reason": f"DENIED: {combined_reason}",
                                "deny": deny_result
                            }
                        else:
                            return {
                                "allowed": False,
                                "reason": "DENIED: Action did not pass policy evaluation.",
                                "deny": ["Action did not pass policy evaluation."]
                            }
                    else:
                        return {
                            "allowed": False,
                            "reason": "DENIED: Action did not pass policy evaluation.",
                            "deny": ["Action did not pass policy evaluation."]
                        }
                except Exception as e:
                    logging.error(f"OPA /deny query failed: {e}")
                    return {
                        "allowed": False,
                        "reason": "DENIED: Action did not pass policy evaluation.",
                        "deny": ["Action did not pass policy evaluation."]
                    }
        else:
            return _DENIED_UNAVAILABLE

    except httpx.ConnectError as e:
        logging.error(f"OPA connection error: {e}")
        return _DENIED_UNAVAILABLE
    except httpx.RequestError as e:
        logging.error(f"OPA request error: {e}")
        return _DENIED_UNAVAILABLE
    except Exception as e:
        logging.error(f"OPA query failed: {e}")
        return _DENIED_UNAVAILABLE


def intercept_tool_call(tool_name, tool_args, agent_id="base_agent"):
    """
    Intercept and validate tool calls using OPA policy.

    Args:
        tool_name (str): Name of the tool being called
        tool_args (dict): Arguments passed to the tool
        agent_id (str): Identifier for the agent making the call

    Returns:
        dict: Response with 'status', 'message', and 'record_hash' keys
    """
    logging.info(f"Agent Request -> AIL Intercept: {tool_name} | args={json.dumps(_redact_args(tool_args))}")

    opa_decision = query_opa_policy(tool_name, tool_args)

    if opa_decision.get("allowed", False):
        response = {
            "status": "APPROVED",
            "message": opa_decision.get("reason", "Action approved by policy")
        }
        decision_for_ledger = "APPROVED"
        # For approved requests, use "approved" as policy label
        policy_label = "approved"
    else:
        deny_messages = opa_decision.get("deny", [])
        combined_reason = (
            "; ".join(deny_messages) if deny_messages
            else opa_decision.get("reason", "Action denied by policy")
        )
        response = {"status": "DENIED", "message": combined_reason}
        decision_for_ledger = f"DENIED: {combined_reason}"
        
        # Extract policy name from denial reason for Prometheus labeling
        # Get the first denial message and extract first word (e.g., "SOC2", "FinOps")
        if deny_messages and deny_messages[0]:
            first_denial = deny_messages[0]
            # Extract first word, removing any "DENIED:" prefix
            policy_label = first_denial.replace("DENIED:", "").strip().split()[0].lower()
        else:
            # Fallback: extract from combined reason
            policy_label = combined_reason.replace("DENIED:", "").strip().split()[0].lower()

    logging.info(f"Policy Engine Decision: {response['status']}: {response['message']}")
    _POLICY_DECISIONS.labels(status=response["status"], tool_name=tool_name, policy=policy_label).inc()

    # Fail-closed: log to ImmuDB ledger or block execution if unavailable
    record_hash = "unavailable"  # Initialize to prevent uninitialized variable usage
    try:
        from immudb_ledger import get_ledger
        ledger = get_ledger()

        policy_version = _compute_policy_hash()
        ledger.log_tool_call(
            agent_id=agent_id,
            tool_name=tool_name,
            payload=tool_args,
            decision=f"{decision_for_ledger} (policy: {policy_version})",
        )
        record_hash = ledger.get_previous_hash()
        logging.info(f"Ledger Hash: {record_hash[:16]}")
    except Exception as e:
        logging.error(f"ImmuDB ledger unavailable: {e}")
        return {
            "status": "DENIED",
            "message": "Audit ledger unavailable. Execution blocked.",
            "record_hash": record_hash
        }

    response["record_hash"] = record_hash
    return response
