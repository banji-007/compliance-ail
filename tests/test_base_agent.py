"""
tests/test_base_agent.py - P1-8, second of two gate tests.

Red-team R2 (docs/reports/phase-0-1-redteam.md) showed agent/base_agent.py's
tool-handling path (handle_tool_calls) has no automated coverage at all: a
plausible refactor typo (function_args["region"] -> function_args["region_name"])
in its APPROVED execution branch crashed the reconstructed old test, but left
`pytest tests/` fully green, because nothing pytest-collected calls it.

This test calls BaseAgent.handle_tool_calls directly with a stub tool-call
object, matching the shape the OpenAI SDK's ChatCompletionMessageToolCall
would have (.id, .function.name, .function.arguments), so no OpenAI network
call or API key is needed - handle_tool_calls itself never touches
self.client. Everything downstream of that (the real interceptor, the real
OPA/ledger round trip) is live code, matching P01-4's own reproduction
approach.

Requires the docker-compose.test.yml stack (OPA + control plane + ImmuDB +
verifier). SPIRE_DISABLED=true bypasses mTLS, matching Makefile:45-53.
"""

import json
import os
import sys
from types import SimpleNamespace

import httpx
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "interceptor"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))

os.environ.setdefault("SPIRE_DISABLED", "true")
os.environ.setdefault("OPA_URL", "http://localhost:8181/v1/data/ail/main/allow")
# BaseAgent.__init__ constructs an OpenAI client eagerly; handle_tool_calls
# never uses it, so a dummy key avoids a construction-time OpenAIError
# without ever making a real network call.
os.environ.setdefault("OPENAI_API_KEY", "test-key-not-used")


def _opa_reachable() -> bool:
    try:
        httpx.get("http://localhost:8181/health", timeout=2)
        return True
    except Exception:
        return False


def _immudb_reachable() -> bool:
    immudb_url = os.getenv("IMMUDB_URL", "http://localhost:8080")
    try:
        httpx.get(immudb_url, timeout=2)
        return True
    except Exception:
        return False


requires_stack = pytest.mark.skipif(
    not (_opa_reachable() and _immudb_reachable()),
    reason="OPA and/or ImmuDB not reachable",
)


def _stub_tool_call(name: str, arguments: dict, call_id: str = "call_1"):
    """Mimics openai.types.chat.ChatCompletionMessageToolCall's shape - the
    only attributes handle_tool_calls actually reads."""
    return SimpleNamespace(
        id=call_id,
        function=SimpleNamespace(name=name, arguments=json.dumps(arguments)),
    )


@requires_stack
def test_approved_tool_call_executes_and_reports_ledger_tx():
    from base_agent import BaseAgent

    agent = BaseAgent(agent_id="base_agent_contract_test")
    tool_call = _stub_tool_call(
        "provision_cloud_server",
        {
            "instance_type": "t3.micro",
            "region": "us-east-1",
            "cost_per_hour": 5.0,
            "tags": {
                "environment": "dev",
                "data_classification": "internal",
                "cost_center": "engineering",
                "project": "webapp",
            },
        },
    )

    results = agent.handle_tool_calls([tool_call])

    assert len(results) == 1
    content = results[0]["content"]
    assert "provisioning initiated" in content, f"Expected a successful provision, got: {content!r}"
    assert "[Interceptor:" in content, f"Expected the interceptor's message appended, got: {content!r}"


@requires_stack
def test_denied_tool_call_reports_block_not_execution():
    from base_agent import BaseAgent

    agent = BaseAgent(agent_id="base_agent_contract_test")
    tool_call = _stub_tool_call(
        "provision_cloud_server",
        {
            "instance_type": "p4d.24xlarge",
            "region": "us-east-1",
            "cost_per_hour": 50.0,
            "tags": {
                "environment": "dev",
                "data_classification": "internal",
                "cost_center": "engineering",
                "project": "webapp",  # not ml-training -> FinOps denial
            },
        },
    )

    results = agent.handle_tool_calls([tool_call])

    assert len(results) == 1
    content = results[0]["content"]
    assert content.startswith("Action blocked by interceptor:"), (
        f"Expected a policy block, got: {content!r}"
    )
    assert "provisioning initiated" not in content
