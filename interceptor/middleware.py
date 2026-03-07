import json
import sys
import os
import requests

# Add the ledger directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'ledger'))
from sqlite_ledger import get_ledger

_DENIED_UNAVAILABLE = {"allowed": False, "reason": "Policy Engine Unavailable"}

def query_opa_policy(tool_name, tool_args):
    """
    Query OPA policy for tool call authorization.

    Args:
        tool_name (str): Name of the tool being called
        tool_args (dict): Arguments passed to the tool

    Returns:
        dict: OPA policy decision
    """
    opa_input = {"action": tool_name, **tool_args}

    try:
        response = requests.post(
            "http://localhost:8181/v1/data/compliance/cloud/decision",
            json=opa_input,
            timeout=5
        )

        if response.status_code == 200:
            result = response.json()
            return result.get("result", {})
        else:
            # Fail-closed: non-200 treated as policy engine unavailable
            return _DENIED_UNAVAILABLE

    except requests.exceptions.RequestException:
        # Fail-closed: connection failure treated as policy engine unavailable
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
    print(f"[Agent Request] -> [AIL Intercept] {tool_name} | args={json.dumps(tool_args)}")

    opa_decision = query_opa_policy(tool_name, tool_args)

    if opa_decision.get("allowed", False):
        response = {
            "status": "APPROVED",
            "message": opa_decision.get("reason", "Action approved by policy")
        }
    else:
        response = {
            "status": "DENIED",
            "message": opa_decision.get("reason", "Action denied by policy")
        }

    print(f"[Agent Request] -> [AIL Intercept] -> [Policy Engine Decision] {response['status']}: {response['message']}")

    ledger = get_ledger()
    ledger.log_tool_call(
        agent_id=agent_id,
        tool_name=tool_name,
        payload=tool_args,
        decision=response["status"]
    )
    record_hash = ledger.get_previous_hash()

    print(f"[Agent Request] -> [AIL Intercept] -> [Policy Engine Decision] -> [Ledger Hash] {record_hash[:16]}...")

    response["record_hash"] = record_hash
    return response
