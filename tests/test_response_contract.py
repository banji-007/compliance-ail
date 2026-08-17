"""
tests/test_response_contract.py - P1-8, first of two gate tests.

Red-team R1 (docs/reports/phase-0-1-redteam.md) showed that a producer-side
rename of a key in intercept_tool_call's return value (mutation 3:
response["record_hash"] instead of response["ledger_tx_id"]) is caught only
by one incidental assertion in an unrelated test, not by any test written
for that purpose. Deleting that test made the mutation invisible to the
other 29.

This test closes that gap by construction rather than by a maintained list:

  1. Dynamic ground truth - drive intercept_tool_call live through each
     outcome_type (policy_allow, policy_deny, schema_deny, fault) against
     the real test stack, and take the union of keys actually present in
     the returned dicts. If a producer renames a key, that key simply is
     not in this set.
  2. Static scan - walk every file in the tree that calls
     intercept_tool_call and assigns its result to a variable, and collect
     every string-literal key that variable is ever read with (.get("k"),
     x["k"], or "k" in x).

The contract: every key ever read (2) must be a subset of the keys the
function can actually produce (1). A rename in the producer shrinks (1)
without touching (2), so the assertion fails - this is what makes the test
load-bearing rather than incidental.
"""

import ast
import os
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "interceptor"))

os.environ.setdefault("SPIRE_DISABLED", "true")
os.environ.setdefault("OPA_URL", "http://localhost:8181/v1/data/ail/main/allow")

import middleware  # noqa: E402

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


# ---------------------------------------------------------------------------
# 1. Dynamic ground truth
# ---------------------------------------------------------------------------

def _live_response_keys(monkeypatch) -> set[str]:
    responses = [
        middleware.intercept_tool_call("provision_cloud_server", _APPROVED_ARGS, "contract_test"),
        middleware.intercept_tool_call("provision_cloud_server", _DENIED_ARGS, "contract_test"),
        middleware.intercept_tool_call("hallucinated_tool", {"anything": "goes"}, "contract_test"),
    ]

    with monkeypatch.context() as m:
        m.setattr(middleware, "_BUNDLE_NAME", "nonexistent-bundle-for-contract-test")
        responses.append(
            middleware.intercept_tool_call("provision_cloud_server", _APPROVED_ARGS, "contract_test")
        )

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
