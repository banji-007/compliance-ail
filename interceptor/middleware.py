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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

# Runtime modes:
#   Production (inside Docker): SPIRE socket present -> mTLS enforced via Envoy
#   Development (local venv):   Set SPIRE_DISABLED=true and point
#                               DECISION_SERVICE_URL at a plain http:// URL.
#                               Policy is still evaluated (inside the
#                               decision service); transport identity is not.
_SPIRE_DISABLED = os.getenv("SPIRE_DISABLED", "false").lower() == "true"

# D12 (Phase 2): the agent no longer queries OPA or writes to the ledger in
# its own process. It sends one request here and returns the verdict
# unchanged. In production this is Envoy's mTLS-terminated listener,
# retargeted from OPA to the decision service (envoy/envoy.yaml) - the same
# Stage-1 identity check that used to gate the agent's direct path to OPA
# now gates its path to the decision service instead. In SPIRE_DISABLED dev
# mode it is a plain HTTP call straight to the service.
_DECISION_SERVICE_URL = os.getenv("DECISION_SERVICE_URL", "https://envoy:8443/decide")
_DECISION_SERVICE_HEALTH_URL = _DECISION_SERVICE_URL.rsplit("/", 1)[0] + "/health"

# Expected SPIFFE ID of the mTLS terminator the agent talks to (Envoy).
# Any peer presenting a different URI SAN, even if CA-signed, is rejected.
_EXPECTED_ENVOY_SPIFFE_ID = os.getenv(
    "OPA_SPIFFE_ID", "spiffe://ail.internal/workload/envoy"
)

# Fields whose values must never appear in container logs.
_SENSITIVE_KEYS = frozenset({"query", "approval_ticket", "commit_hash", "tags"})


def _redact_args(args) -> dict:
    """
    Return a shallow copy of args with sensitive field values replaced by [REDACTED].
    Recurses one level into nested dicts not themselves listed in _SENSITIVE_KEYS.
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


def _validate_peer_spiffe_san(ssl_ctx: ssl.SSLContext) -> bool:
    """
    Establish a raw TLS connection to the decision-service endpoint (Envoy)
    and verify that the peer's certificate URI SAN matches
    _EXPECTED_ENVOY_SPIFFE_ID.

    check_hostname is disabled globally because SPIFFE certs carry URI SANs,
    not DNS SANs. This function reinstates identity verification at the
    application layer by extracting and comparing the URI SAN directly.

    Returns False on any error (fail-closed).
    """
    if _SPIRE_DISABLED:
        return True  # SAN validation only applies when mTLS is active.

    parsed = urlparse(_DECISION_SERVICE_URL)
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

        if _EXPECTED_ENVOY_SPIFFE_ID in uri_sans:
            logging.debug("Peer SPIFFE SAN validated: %s", _EXPECTED_ENVOY_SPIFFE_ID)
            return True

        logging.error(
            "Peer SPIFFE SAN mismatch — expected '%s', peer presented: %s. "
            "Fail-closed: decision-service request blocked.",
            _EXPECTED_ENVOY_SPIFFE_ID,
            uri_sans,
        )
        return False

    except Exception as exc:
        logging.error("Peer SPIFFE SAN validation error: %s", exc)
        return False


def _get_spiffe_ssl_context() -> ssl.SSLContext | None:
    """
    Create an SSL context with SPIFFE SVID fetched entirely in-memory.

    Returns:
        ssl.SSLContext | None: SSL context with SPIFFE certificates, or None if unavailable
    """
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
                os.chmod(cert_file.name, stat.S_IRUSR | stat.S_IWUSR)
                key_file.write(key_pem)
                key_file.flush()
                os.chmod(key_file.name, stat.S_IRUSR | stat.S_IWUSR)
                ssl_ctx.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)
                ssl_ctx.load_verify_locations(cadata=ca_pem.decode())
            finally:
                cert_file.close()
                key_file.close()
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
    """
    return _get_spiffe_ssl_context()


def _spire_absent_exit(context_url: str) -> None:
    """
    P2-5 (Phase 2): the SPIRE-absent exit as its own dedicated guard,
    independent of any decision-service readiness check. Named after SPIRE
    specifically in its own message so it can never be mistaken for a
    policy-engine or decision-service problem.

    Before this phase, this behavior existed only as a side effect of one
    function (the old verify_bundle_at_startup) - reordering that function's
    internals silently removed this documented security property with no
    other signal. It is now a standalone function with its own call site and
    its own test (tests/test_spire_absent_guard.py), so removing this guard
    specifically is what the P2-5 mutation targets, independent of anything
    else verify_bundle_at_startup checks.
    """
    if _SPIRE_DISABLED:
        return
    ssl_context = _get_spiffe_ssl_context()
    if not ssl_context or not _validate_peer_spiffe_san(ssl_context):
        logging.error(
            "STARTUP FAILURE: SPIRE workload identity unavailable, or the "
            "peer at %s did not present the expected SPIFFE ID - cannot "
            "establish a verified mTLS channel. Check the SPIRE agent and "
            "Envoy sidecar are healthy before retrying.",
            context_url,
        )
        sys.exit(1)


def verify_bundle_at_startup(timeout_seconds: float = 30, poll_interval: float = 2) -> None:
    """
    Startup readiness check for the agent process. Two independent things,
    checked in order:

    (1) The SPIRE-absent exit (_spire_absent_exit, P2-5's own guard) -
    unconditional, checked first, regardless of what follows.

    (2) That the decision service is actually reachable through the same
    mTLS channel every real call will use, polling because Envoy and the
    decision service may not have finished starting yet.

    The old bundle-revision check (is OPA's configured bundle name actually
    loaded) moved into decision_service's own startup in Phase 2 (D12) -
    that is now the decision service's concern; the agent has no route to
    OPA to check it directly any more, and no reason to.
    """
    _spire_absent_exit(_DECISION_SERVICE_URL)

    ssl_context = True if _SPIRE_DISABLED else _get_spiffe_ssl_context()

    deadline = time.monotonic() + timeout_seconds
    reachable = False
    last_error = None
    while time.monotonic() < deadline:
        try:
            with httpx.Client(verify=ssl_context) as client:
                resp = client.get(_DECISION_SERVICE_HEALTH_URL, timeout=5)
            if resp.status_code == 200:
                reachable = True
                break
        except Exception as exc:
            last_error = exc
        time.sleep(poll_interval)

    if not reachable:
        logging.error(
            "STARTUP FAILURE: decision service not reachable at %s after %ss "
            "(last error: %s). Check the decision-service and envoy "
            "containers are healthy before retrying.",
            _DECISION_SERVICE_HEALTH_URL, timeout_seconds, last_error,
        )
        sys.exit(1)

    logging.info("Startup check: decision service reachable at %s", _DECISION_SERVICE_URL)


def _client_fault(fault_class: str, message: str) -> dict:
    """
    Shape a fault the agent's own client leg produced - the decision service
    was never reached, so there is nothing for it to have written a ledger
    entry about. Same closed-set discipline as every other fault (ADR-0005):
    no free-text 'decision' string, no ledger_tx_id key at all.
    """
    return {
        "status": "DENIED",
        "message": f"DENIED: {message}",
        "outcome_type": "fault",
        "fault_class": fault_class,
        "policy_revision": None,
    }


def intercept_tool_call(tool_name, tool_args, agent_id="base_agent"):
    """
    Intercept a tool call and return the decision service's verdict.

    D12 (Phase 2): this function is now a thin client. It used to run
    schema validation, the OPA query, the ledger write, and the content
    store write directly in this process; all of that now lives in
    decision_service/main.py, reachable only over the network this agent
    has no other path into (see docker-compose.yml's edge/backend split).
    This function builds the request, sends it, and returns the response
    unchanged - decision_service's /decide route is contracted to return
    exactly the shape this function used to construct itself: status,
    message, outcome_type, fault_class, policy_revision, and, only when a
    ledger record actually exists, ledger_tx_id (plus, for the one D14 tool,
    an optional result key holding what the decision service executed on
    the agent's behalf).

    D12's own stated limit, unchanged by this function: it still cannot
    stop the agent from calling the real underlying action directly instead
    of calling this first, for any tool whose authority the agent itself
    independently holds (the three "observed" tools - see
    docs/adr/0008-decision-service-boundary.md). Only D14's per-tool
    authority exclusivity closes that, and only for the one tool that has
    it.

    Args:
        tool_name (str): Name of the tool being called
        tool_args (dict): Arguments passed to the tool
        agent_id (str): Identifier for the agent making the call

    Returns:
        dict: see decision_service/main.py::decide
    """
    logging.info(f"Agent Request -> AIL Intercept: {tool_name} | args={json.dumps(_redact_args(tool_args))}")

    if _SPIRE_DISABLED:
        ssl_context = True
    else:
        ssl_context = _get_spiffe_ssl_context()
        if not ssl_context:
            return _client_fault("spiffe_unavailable", "Compliance engine fault (spiffe_unavailable). Fail-closed policy enforced.")
        if not _validate_peer_spiffe_san(ssl_context):
            return _client_fault("spiffe_unavailable", "Compliance engine fault (spiffe_unavailable). Fail-closed policy enforced.")

    try:
        with httpx.Client(verify=ssl_context) as client:
            response = client.post(
                _DECISION_SERVICE_URL,
                json={"tool_name": tool_name, "tool_args": tool_args, "agent_id": agent_id},
                timeout=20,
            )
    except httpx.RequestError as e:
        logging.error(f"Decision service request error: {e}")
        return _client_fault("decision_service_unreachable", "Compliance engine fault (decision_service_unreachable). Fail-closed policy enforced.")

    if response.status_code != 200:
        logging.error(f"Decision service returned HTTP {response.status_code}. Fail-closed policy enforced.")
        return _client_fault("decision_service_unreachable", "Compliance engine fault (decision_service_unreachable). Fail-closed policy enforced.")

    try:
        decision = response.json()
    except Exception as e:
        logging.error(f"Decision service returned an unparsable response: {e}")
        return _client_fault("decision_service_unreachable", "Compliance engine fault (decision_service_unreachable). Fail-closed policy enforced.")

    logging.info(f"Policy Engine Decision: {decision.get('status')}: {decision.get('message')}")
    return decision
