"""
tests/test_outcome_types.py - Phase 1, D1/P1-2 automated coverage.

Exercises every outcome_type and every fault_class the interceptor can
produce, asserting the taxonomy directly (never inferred from message
text). Live infrastructure faults (OPA genuinely down, verifier genuinely
down, SPIRE genuinely absent) are reproduced manually for the report;
these tests get equivalent coverage in CI by substituting the same failure
at the point middleware.py itself would observe it.

Requires the docker-compose.test.yml stack. SPIRE_DISABLED=true bypasses
mTLS, matching Makefile:45-53.
"""

import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "interceptor"))

os.environ.setdefault("SPIRE_DISABLED", "true")
os.environ.setdefault("OPA_URL", "http://localhost:8181/v1/data/ail/main/allow")

import middleware  # noqa: E402

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
# Non-fault outcomes
# ---------------------------------------------------------------------------

@requires_stack
def test_policy_allow():
    r = middleware.intercept_tool_call("provision_cloud_server", _APPROVED_ARGS, "outcome_test")
    assert r["outcome_type"] == "policy_allow"
    assert r["fault_class"] is None
    assert r["policy_revision"]
    assert "ledger_tx_id" in r
    # reasons are recorded on the ledger entry (asserted via /audit elsewhere),
    # not echoed back in the caller-facing response - only message/outcome_type/
    # fault_class/policy_revision/ledger_tx_id are (see test_response_contract.py).


@requires_stack
def test_policy_deny():
    r = middleware.intercept_tool_call("provision_cloud_server", _DENIED_ARGS, "outcome_test")
    assert r["outcome_type"] == "policy_deny"
    assert r["fault_class"] is None
    assert r["policy_revision"]
    assert r["message"].startswith("DENIED:")
    assert "ledger_tx_id" in r


@requires_stack
def test_schema_deny_unregistered_tool():
    r = middleware.intercept_tool_call("hallucinated_tool", {"anything": "goes"}, "outcome_test")
    assert r["outcome_type"] == "schema_deny"
    assert r["fault_class"] is None
    assert r["policy_revision"] is None
    assert "ledger_tx_id" in r


@requires_stack
def test_schema_deny_invalid_payload():
    bad_args = {**_APPROVED_ARGS, "cost_per_hour": -5.0}
    r = middleware.intercept_tool_call("provision_cloud_server", bad_args, "outcome_test")
    assert r["outcome_type"] == "schema_deny"
    assert r["policy_revision"] is None


# ---------------------------------------------------------------------------
# Fault outcomes - each fault_class produced at the exact point
# query_opa_policy / intercept_tool_call would observe it
# ---------------------------------------------------------------------------

@requires_stack
def test_fault_opa_unreachable(monkeypatch):
    monkeypatch.setattr(middleware, "_OPA_EVAL_URL", "http://localhost:1/v1/data/ail/main/evaluation")
    r = middleware.intercept_tool_call("provision_cloud_server", _APPROVED_ARGS, "outcome_test")
    assert r["status"] == "DENIED"
    assert r["outcome_type"] == "fault"
    assert r["fault_class"] == "opa_unreachable"
    assert r["policy_revision"] is None
    assert "ledger_tx_id" in r  # the fault itself is still recorded (D1)


@requires_stack
def test_fault_revision_unavailable(monkeypatch):
    monkeypatch.setattr(middleware, "_BUNDLE_NAME", "nonexistent-bundle-for-outcome-test")
    r = middleware.intercept_tool_call("provision_cloud_server", _APPROVED_ARGS, "outcome_test")
    assert r["status"] == "DENIED"
    assert r["outcome_type"] == "fault"
    assert r["fault_class"] == "revision_unavailable"
    assert r["policy_revision"] is None
    assert "ledger_tx_id" in r


@requires_stack
def test_fault_spiffe_unavailable(monkeypatch):
    monkeypatch.setattr(middleware, "_SPIRE_DISABLED", False)
    monkeypatch.setattr(middleware, "_get_spiffe_ssl_context", lambda: None)
    r = middleware.intercept_tool_call("provision_cloud_server", _APPROVED_ARGS, "outcome_test")
    assert r["status"] == "DENIED"
    assert r["outcome_type"] == "fault"
    assert r["fault_class"] == "spiffe_unavailable"
    assert r["policy_revision"] is None
    assert "ledger_tx_id" in r


@requires_stack
def test_fault_verifier_unreachable_writes_no_record(monkeypatch):
    """The one documented boundary (D1): a fault in the recording path
    itself cannot be recorded - no ledger_tx_id, no ledger entry."""

    class _BrokenLedger:
        def log_tool_call(self, **kwargs):
            raise RuntimeError("verifier unreachable (simulated)")

    # intercept_tool_call does `from immudb_ledger import get_ledger` fresh on
    # every call, so patching the attribute on the module (not middleware's
    # namespace) is what actually takes effect.
    import immudb_ledger
    monkeypatch.setattr(immudb_ledger, "get_ledger", lambda: _BrokenLedger())

    r = middleware.intercept_tool_call("provision_cloud_server", _APPROVED_ARGS, "outcome_test")
    assert r["status"] == "DENIED"
    assert r["outcome_type"] == "fault"
    assert r["fault_class"] == "verifier_unreachable"
    assert r["policy_revision"] is None
    assert "ledger_tx_id" not in r
