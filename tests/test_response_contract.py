"""
tests/test_response_contract.py - P1-8, first of two gate tests.

Red-team R1 (docs/reports/phase-0-1-redteam.md) showed that a producer-side
rename of a key in intercept_tool_call's return value (mutation 3:
response["record_hash"] instead of response["ledger_tx_id"]) is caught only
by one incidental assertion in an unrelated test, not by any test written
for that purpose. Deleting that test made the mutation invisible to the
other 29.

This test closes that gap by construction rather than by a maintained list:

  1. Dynamic ground truth - drive the decision through each outcome_type
     (policy_allow, policy_deny, schema_deny, fault) against the real test
     stack, and take the union of keys actually present in the returned
     dicts. If a producer renames a key, that key simply is not in this set.
  2. Static scan - walk every file in the tree that calls
     intercept_tool_call and assigns its result to a variable, and collect
     every string-literal key that variable is ever read with (.get("k"),
     x["k"], or "k" in x).

The contract: every key ever read (2) must be a subset of the keys the
function can actually produce (1). A rename in the producer shrinks (1)
without touching (2), so the assertion fails - this is what makes the test
load-bearing rather than incidental.

Migrated in Phase 2 (P2-1) from interceptor/middleware.py to
decision_service/main.py: D12 moved schema validation, the OPA query, the
content-store write, and the ledger write into decision_service - the
response dict interceptor/middleware.py::intercept_tool_call returns is now
just decision_service's /decide response, passed through unchanged (see
decision_service/main.py::decide's own docstring). Part (1)'s dynamic ground
truth therefore now comes from decision_main.decide() directly, the actual
producer of the shape - the client leg (middleware.intercept_tool_call) only
ever narrows that shape further (its own client-side faults,
spiffe_unavailable/decision_service_unreachable, are a strict subset of the
keys decide() already produces: status, message, outcome_type, fault_class,
policy_revision - never ledger_tx_id or result), so it adds nothing this
dynamic scan would miss. Part (2)'s static scan is unchanged: consumers
still call middleware.intercept_tool_call by that name, so the AST scan
still looks for exactly that call.
"""

import ast
import asyncio
import os
import sys
from pathlib import Path

import httpx
import pytest


import importlib.util as _importlib_util

# decision_service/main.py's own `from schemas import ...` needs this
# directory on sys.path - loading main.py itself via spec_from_file_location
# below (to dodge the module-name collision, see _load_decision_service_main)
# does not add its own directory to sys.path automatically the way a normal
# package-relative import would.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "decision_service"))


def _load_decision_service_main():
    """decision_service/main.py and control_plane/main.py are both named
    main.py - a bare `import main` in one test file clobbers whichever
    module sys.modules["main"] already held for every other test file in
    the same pytest session (Python caches by module name, not by which
    sys.path entry was active when the import statement ran - confirmed
    live: test_verification.py's control-plane tests got decision_service's
    module back instead, AttributeError on a function that only exists in
    control_plane/main.py). Loading this one under its own explicit module
    name sidesteps the collision instead of depending on import order."""
    spec = _importlib_util.spec_from_file_location(
        "decision_service_main",
        os.path.join(os.path.dirname(__file__), "..", "decision_service", "main.py"),
    )
    module = _importlib_util.module_from_spec(spec)
    sys.modules["decision_service_main"] = module
    spec.loader.exec_module(module)
    return module


os.environ.setdefault("SPIRE_DISABLED", "true")
os.environ.setdefault("OPA_URL", "http://localhost:8181/v1/data/ail/main/evaluation")
os.environ.setdefault("DECISION_SERVICE_URL", "http://localhost:8010/decide")

decision_main = _load_decision_service_main()

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "interceptor"))
import middleware  # noqa: E402 - real HTTP client, needed for the read_vault_secret call below

REPO_ROOT = Path(__file__).resolve().parents[1]

_APPROVED_ARGS = {
    "instance_type": "t3.micro",
    "region": "us-east-1",
    "cost_per_hour": 5.0,
    "tags": {"environment": "dev", "data_classification": "internal", "cost_center": "engineering", "project": "webapp"},
}

_DENIED_ARGS = {
    "instance_type": "p4d.24xlarge",
    "region": "us-east-1",
    "cost_per_hour": 50.0,
    "tags": {"environment": "dev", "data_classification": "internal", "cost_center": "engineering", "project": "webapp"},
}


def _decide(tool_name, tool_args, agent_id="contract_test") -> dict:
    """Call decision_service/main.py's /decide route function directly -
    the actual producer of the response shape intercept_tool_call now just
    passes through unchanged. See tests/test_outcome_types.py's identical
    helper."""
    req = decision_main.DecideRequest(tool_name=tool_name, tool_args=tool_args, agent_id=agent_id)
    return asyncio.run(decision_main.decide(req))


requires_stack = pytest.mark.needs_stack("opa", "immudb", "verifier", "control_plane", "decision_service")


# ---------------------------------------------------------------------------
# 1. Dynamic ground truth
# ---------------------------------------------------------------------------

def _live_response_keys(monkeypatch) -> set[str]:
    responses = [
        _decide("provision_cloud_server", _APPROVED_ARGS),
        _decide("provision_cloud_server", _DENIED_ARGS),
        _decide("hallucinated_tool", {"anything": "goes"}),
        # D14: the one tool that produces a "result" key - approved so it's
        # actually present in this call's response, not just theoretically
        # possible. framework_integration/langgraph_demo.py reads this key;
        # without a call that actually produces it, this contract test
        # would flag a real, used key as "never produced". Uses the real
        # HTTP client (middleware), not the in-process _decide() helper:
        # vault_server.py resolves its token from a fixed default path
        # (/run/secrets/vault_api_token) that only exists inside
        # decision-service's own container - the MCP SDK's stdio spawn does
        # not inherit this test process's environment, so an in-process
        # call on the host cannot reach the vault at all.
        middleware.intercept_tool_call("read_vault_secret", {"secret_name": "db_master_password"}, "contract_test"),
    ]

    with monkeypatch.context() as m:
        # Phase 1.2 (D9): bundle_name no longer travels in the request, so a
        # bogus bundle name can no longer force a fault outcome - force the
        # same undefined-/evaluation-result response shape by pointing at a
        # rule path OPA has never heard of instead.
        m.setattr(
            decision_main, "_OPA_URL",
            "http://localhost:8181/v1/data/ail/main/nonexistent_entrypoint",
        )
        responses.append(_decide("provision_cloud_server", _APPROVED_ARGS))

    keys: set[str] = set()
    for r in responses:
        keys |= set(r.keys())
    return keys


# ---------------------------------------------------------------------------
# 2. Static scan
# ---------------------------------------------------------------------------

_CONSUMER_GLOBS = [
    "agent/base_agent.py",
    "framework_integration/langgraph_demo.py",
]


def _consumer_files() -> list[Path]:
    files = [REPO_ROOT / rel for rel in _CONSUMER_GLOBS]
    files += sorted((REPO_ROOT / "tests").glob("*.py"))
    files += sorted((REPO_ROOT / "scripts").glob("*.py"))
    this_file = Path(__file__).resolve()
    return [f for f in files if f.exists() and f.resolve() != this_file]


def _tracked_names(tree: ast.AST) -> set[str]:
    """Variable names assigned directly from an intercept_tool_call(...) call."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            func = node.value.func
            is_call = (isinstance(func, ast.Name) and func.id == "intercept_tool_call") or (
                isinstance(func, ast.Attribute) and func.attr == "intercept_tool_call"
            )
            if is_call:
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        names.add(tgt.id)
    return names


def _read_keys(tree: ast.AST, names: set[str]) -> set[str]:
    """Every string-literal key `names` is ever read with: .get("k"), x["k"], "k" in x."""
    keys: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in names
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            keys.add(node.args[0].value)

        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id in names:
            sl = node.slice
            if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
                keys.add(sl.value)

        if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], (ast.In, ast.NotIn)):
            left = node.left
            (rhs,) = node.comparators
            if (
                isinstance(left, ast.Constant)
                and isinstance(left.value, str)
                and isinstance(rhs, ast.Name)
                and rhs.id in names
            ):
                keys.add(left.value)
    return keys


def _static_read_keys() -> dict[str, set[str]]:
    """Map of file -> keys that file reads off an intercept_tool_call result."""
    per_file: dict[str, set[str]] = {}
    for path in _consumer_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        names = _tracked_names(tree)
        if not names:
            continue
        found = _read_keys(tree, names)
        if found:
            per_file[str(path.relative_to(REPO_ROOT))] = found
    return per_file


# ---------------------------------------------------------------------------
# The contract
# ---------------------------------------------------------------------------

@requires_stack
def test_every_read_key_is_a_key_the_function_can_set(monkeypatch):
    live_keys = _live_response_keys(monkeypatch)
    assert live_keys, "No keys observed live - intercept_tool_call returned nothing to check against"

    per_file = _static_read_keys()
    assert per_file, "No consumer read intercept_tool_call's result - contract test found nothing to check"

    violations = {
        file: sorted(read_keys - live_keys)
        for file, read_keys in per_file.items()
        if read_keys - live_keys
    }
    assert not violations, (
        f"Keys read that intercept_tool_call never actually produced (live keys were "
        f"{sorted(live_keys)}): {violations}. Either the producer renamed/dropped a key, "
        f"or a consumer reads a key that never existed."
    )
