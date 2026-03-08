import json
import logging
import sys
import os
import time
import requests
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

# Add the ledger directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'ledger'))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

# Configure retry strategy for OPA requests
retry_strategy = Retry(
    total=3,
    backoff_factor=0.5,
    status_forcelist=[500, 502, 503, 504]
)

# Create session with retry adapter
session = requests.Session()
session.mount('http://', HTTPAdapter(max_retries=retry_strategy))

_DENIED_UNAVAILABLE = {"allowed": False, "reason": "Compliance engine unavailable. Fail-closed policy enforced."}

def query_opa_policy(tool_name, tool_args):
    """
    Query OPA policy for tool call authorization.

    Args:
        tool_name (str): Name of the tool being called
        tool_args (dict): Arguments passed to the tool

    Returns:
        dict: OPA policy decision
    """
    try:
        response = session.post(
            os.getenv('OPA_URL', 'http://localhost:8181/v1/data/ail/policy'),
            json={"input": {"tool_args": tool_args}},
            timeout=5
        )

        logging.debug(f"OPA status={response.status_code} body={response.text}")

        if response.status_code == 200:
            result = response.json().get("result", {})
            # Evaluate deny array directly
            deny_messages = result.get("deny", [])
            if deny_messages:
                # Return deny items as DENIED string
                combined_reason = "; ".join(deny_messages)
                return {
                    "allowed": False,
                    "reason": combined_reason,
                    "deny": deny_messages
                }
            else:
                # Empty deny array means APPROVED
                return {
                    "allowed": True,
                    "reason": "Action approved by policy",
                    "deny": []
                }
        else:
            # Fail-closed: non-200 treated as policy engine unavailable
            return _DENIED_UNAVAILABLE

    except requests.exceptions.ConnectionError as e:
        logging.error(f"OPA connection error (not running?): {e}")
        return _DENIED_UNAVAILABLE
    except requests.exceptions.RequestException as e:
        logging.error(f"OPA request error: {e}")
        return _DENIED_UNAVAILABLE
    except Exception as e:
        logging.error(f"OPA retry failed after 3 attempts: {e}")
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
        # Handle deny messages list from new policy format
        deny_messages = opa_decision.get("deny", [])
        if deny_messages:
            # Join multiple deny messages with semicolons
            combined_reason = "; ".join(deny_messages)
        else:
            combined_reason = opa_decision.get("reason", "Action denied by policy")
            
        response = {
            "status": "DENIED",
            "message": combined_reason
        }
        decision_for_ledger = f"DENIED: {combined_reason}"

    logging.info(f"Policy Engine Decision: {response['status']}: {response['message']}")

    # Fail-closed: Log to ImmuDB ledger or block execution if unavailable
    try:
        from immudb_ledger import get_ledger
        ledger = get_ledger()
        
        # Extract policy version for audit trail
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
        # Fail-closed: Block execution if audit ledger is unavailable
        return {
            "status": "DENIED",
            "message": "Audit ledger unavailable. Execution blocked.",
            "record_hash": "unavailable"
        }

    response["record_hash"] = record_hash
    return response
