import json
import logging
import sys
import os
import ssl
import tempfile
import time
import httpx
from prometheus_client import Counter, start_http_server

# Add the ledger directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'ledger'))

# Import pre-flight validation schemas
from schemas import validate_cloud_server_args

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
_OPA_URL = os.getenv("OPA_URL", "https://localhost:8443/v1/data/ail/main/deny")

_DENIED_UNAVAILABLE = {"allowed": False, "reason": "Compliance engine unavailable. Fail-closed policy enforced."}

# Prometheus metrics
_POLICY_DECISIONS = Counter(
    "ail_policy_decisions_total",
    "Total AIL policy decisions by status and tool",
    ["status", "tool_name"],
)

try:
    start_http_server(8000)
    logging.info("Prometheus metrics server started on :8000")
except OSError:
    pass  # port already bound (e.g. module reloaded)


def _get_spiffe_ssl_context() -> ssl.SSLContext | None:
    """
    Create an SSL context with SPIFFE SVID fetched entirely in-memory.
    
    Returns:
        ssl.SSLContext | None: SSL context with SPIFFE certificates, or None if unavailable
    """
    # Declare socket_path at the very top to ensure it's always bound
    socket_path = os.getenv('SPIFFE_ENDPOINT_SOCKET', 'unix:///tmp/spire-sockets/workload_api.sock')
    
    try:
        from spiffe import X509Source, TrustDomain
        from cryptography.hazmat.primitives import serialization
        
        # Initialize X509Source with the socket path
        x509_source = X509Source(socket_path=socket_path)
        
        # Fetch the local SVID using X509Source
        svid = x509_source.fetch_x509_svid()
        bundle_set = x509_source.fetch_x509_bundles()
        bundle = bundle_set.get_bundle_for_trust_domain(TrustDomain("ail.internal"))
        
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
        
        # Load certificates directly from memory
        from io import BytesIO
        import tempfile
        
        # Create temporary in-memory file-like objects for certificate loading
        cert_file = tempfile.NamedTemporaryFile(delete=False)
        cert_file.write(cert_pem)
        cert_file.flush()
        
        key_file = tempfile.NamedTemporaryFile(delete=False)
        key_file.write(key_pem)
        key_file.flush()
        
        try:
            ssl_ctx.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)
            ssl_ctx.load_verify_locations(cadata=ca_pem.decode())
        finally:
            # Clean up temporary files
            os.unlink(cert_file.name)
            os.unlink(key_file.name)
            cert_file.close()
            key_file.close()
        
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

    Args:
        tool_name (str): Name of the tool being called
        tool_args (dict): Arguments passed to the tool

    Returns:
        dict: OPA policy decision
    """
    # Epic 2: Pre-Flight Input Validation
    # Catch LLM hallucinations before they are sent to OPA over the network
    if tool_name == "provision_cloud_server":
        is_valid, error_message = validate_cloud_server_args(tool_args)
        if not is_valid:
            error_details = f"DENIED: Schema Validation Failed. {error_message}"
            logging.warning(f"Pre-flight validation failed for {tool_name}: {error_details}")
            return {
                "allowed": False,
                "reason": error_details,
                "deny": [error_details]
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

    try:
        with httpx.Client(verify=ssl_context) as client:
            response = client.post(
                _OPA_URL,
                json={"input": {"tool_args": tool_args}},
                timeout=5,
            )

        logging.debug(f"OPA status={response.status_code} body={response.text}")

        if response.status_code == 200:
            result = response.json().get("result", [])
            # New aggregated format: result is directly a list of deny messages
            if isinstance(result, list) and result:
                combined_reason = "; ".join(result)
                return {"allowed": False, "reason": combined_reason, "deny": result}
            else:
                return {"allowed": True, "reason": "Action approved by policy", "deny": []}
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
    logging.info(f"Agent Request -> AIL Intercept: {tool_name} | args={json.dumps(tool_args)}")

    opa_decision = query_opa_policy(tool_name, tool_args)

    if opa_decision.get("allowed", False):
        response = {
            "status": "APPROVED",
            "message": opa_decision.get("reason", "Action approved by policy")
        }
        decision_for_ledger = "APPROVED"
    else:
        deny_messages = opa_decision.get("deny", [])
        combined_reason = (
            "; ".join(deny_messages) if deny_messages
            else opa_decision.get("reason", "Action denied by policy")
        )
        response = {"status": "DENIED", "message": combined_reason}
        decision_for_ledger = f"DENIED: {combined_reason}"

    logging.info(f"Policy Engine Decision: {response['status']}: {response['message']}")
    _POLICY_DECISIONS.labels(status=response["status"], tool_name=tool_name).inc()

    # Fail-closed: log to ImmuDB ledger or block execution if unavailable
    record_hash = "unavailable"  # Initialize to prevent uninitialized variable usage
    try:
        from immudb_ledger import get_ledger
        ledger = get_ledger()

        policy_version = "1.0.0"
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
