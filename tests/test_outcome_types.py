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
import re
import sys
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

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
# P11-2 (Phase 1.1): non-dict tool_args must still produce a record, not an
# uncaught crash before classification. Red-team S3 attack 1: an LLM emitting
# a list/string/null/number for `arguments` is valid JSON that isn't a dict.
# ---------------------------------------------------------------------------

@requires_stack
@pytest.mark.parametrize("bad_args", [[], None, "not-a-dict", 42], ids=["list", "null", "str", "int"])
def test_malformed_tool_args_shape_still_produces_a_record(bad_args):
    r = middleware.intercept_tool_call("provision_cloud_server", bad_args, "outcome_test")
    assert r["outcome_type"] == "schema_deny", f"Expected schema_deny for shape {type(bad_args).__name__}, got: {r}"
    assert r["fault_class"] is None
    assert r["policy_revision"] is None
    assert "ledger_tx_id" in r, f"Expected a ledger record for shape {type(bad_args).__name__}, got: {r}"


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
    # Phase 1.2 (D9): the request no longer carries a caller-supplied bundle
    # name, so a bogus bundle name can no longer force this fault - the
    # revision now comes from whichever loaded bundle's manifest claims the
    # `ail` root (see tests/test_bundle_revision_attribution.py for that
    # mechanism directly). Simulated here the same way any other undefined
    # /evaluation result would occur: pointing at a rule path OPA has never
    # heard of, which returns HTTP 200 with no "result" key - the exact
    # response shape query_opa_policy treats as revision_unavailable.
    monkeypatch.setattr(
        middleware, "_OPA_EVAL_URL",
        middleware._OPA_URL.replace("/v1/data/ail/main/allow", "/v1/data/ail/main/nonexistent_entrypoint"),
    )
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


# ---------------------------------------------------------------------------
# P11-6 / P11-8 (Phase 1.1): metric labels are bounded. tool_name is
# allowlisted against TOOL_VALIDATORS before use as a Prometheus label -
# a hallucinated tool name must not grow the metric's cardinality.
# ---------------------------------------------------------------------------

def _series_count() -> int:
    """Count of distinct label-combinations currently registered for
    ail_policy_decisions_total, via the public .collect() API (not the
    prometheus_client-internal _metrics dict)."""
    for metric in middleware._POLICY_DECISIONS.collect():
        return sum(1 for s in metric.samples if s.name.endswith("_total"))
    return 0


@requires_stack
def test_hallucinated_tool_names_do_not_grow_metric_cardinality():
    before = _series_count()
    for i in range(50):
        middleware.intercept_tool_call(f"hallucinated_tool_variant_{i}", {"anything": "goes"}, "cardinality_test")
    after = _series_count()
    # All 50 calls share one outcome_type/fault_class/status combination
    # (schema_deny), so they must collapse into exactly one new series
    # (tool_name="_unregistered"), not 50.
    assert after - before <= 1, (
        f"Expected at most 1 new series for 50 distinct hallucinated tool names, "
        f"got {after - before} (before={before}, after={after})"
    )


@requires_stack
def test_metric_label_set_matches_closed_collection():
    middleware.intercept_tool_call("some_other_hallucinated_name", {"anything": "goes"}, "cardinality_test")
    middleware.intercept_tool_call("provision_cloud_server", _APPROVED_ARGS, "cardinality_test")

    allowed_tool_names = set(middleware.TOOL_VALIDATORS) | {"_unregistered"}
    allowed_outcome_types = {
        middleware.OUTCOME_POLICY_ALLOW, middleware.OUTCOME_POLICY_DENY,
        middleware.OUTCOME_SCHEMA_DENY, middleware.OUTCOME_FAULT,
    }
    allowed_fault_classes = {
        "", middleware.FAULT_OPA_UNREACHABLE, middleware.FAULT_REVISION_UNAVAILABLE,
        middleware.FAULT_VERIFIER_UNREACHABLE, middleware.FAULT_SPIFFE_UNAVAILABLE,
        middleware.FAULT_MALFORMED_POLICY_RESPONSE, middleware.FAULT_CONTENT_STORE_UNREACHABLE,
    }
    allowed_statuses = {"APPROVED", "DENIED"}

    for metric in middleware._POLICY_DECISIONS.collect():
        for sample in metric.samples:
            if not sample.name.endswith("_total"):
                continue
            assert sample.labels["tool_name"] in allowed_tool_names, sample.labels
            assert sample.labels["outcome_type"] in allowed_outcome_types, sample.labels
            assert sample.labels["fault_class"] in allowed_fault_classes, sample.labels
            assert sample.labels["status"] in allowed_statuses, sample.labels


# ---------------------------------------------------------------------------
# R5 (Phase 1.3 completion pass, red-team V1 finding 3): dashboard/lib/
# types.ts's FaultClass union must match the fault classes /audit can
# actually send, not the full six-member closed set middleware.py defines.
# docs/adr/0005-outcome-taxonomy.md's Documented Boundary section states
# verifier_unreachable and content_store_unreachable never produce a ledger
# record - each is discovered in a path that itself precedes, or is, the
# ledger write, so a fault of that class can never carry a ledger_tx_id for
# /audit to later surface. test_fault_verifier_unreachable_writes_no_record
# (above) and test_content_states.py::test_content_store_down_denies_as_
# fault_and_writes_no_record cover that structural claim directly, live.
# This test covers the other half: the dashboard's own type must include
# every fault class that DOES reach /audit, and nothing else.
# ---------------------------------------------------------------------------

_NEVER_REACHES_LEDGER = {
    middleware.FAULT_VERIFIER_UNREACHABLE,
    middleware.FAULT_CONTENT_STORE_UNREACHABLE,
}

_ALL_FAULT_CLASSES = {
    middleware.FAULT_OPA_UNREACHABLE,
    middleware.FAULT_REVISION_UNAVAILABLE,
    middleware.FAULT_VERIFIER_UNREACHABLE,
    middleware.FAULT_SPIFFE_UNAVAILABLE,
    middleware.FAULT_MALFORMED_POLICY_RESPONSE,
    middleware.FAULT_CONTENT_STORE_UNREACHABLE,
}

_REACHES_AUDIT = _ALL_FAULT_CLASSES - _NEVER_REACHES_LEDGER


def _dashboard_fault_class_union() -> set[str]:
    types_ts = (REPO_ROOT / "dashboard" / "lib" / "types.ts").read_text(encoding="utf-8")
    match = re.search(r"export type FaultClass =\s*((?:\s*\|\s*(?:\"[^\"]+\"|null)\s*)+);", types_ts)
    assert match, "Could not find `export type FaultClass = ...;` in dashboard/lib/types.ts"
    members = re.findall(r'"([^"]+)"', match.group(1))
    return set(members)


def test_dashboard_fault_class_type_matches_reachable_set():
    """
    Mutation: add FAULT_VERIFIER_UNREACHABLE (or any never-reaches-ledger
    class) back to dashboard/lib/types.ts's FaultClass union, or remove
    FAULT_MALFORMED_POLICY_RESPONSE from it. This test must fail against
    either mutation.
    """
    dashboard_set = _dashboard_fault_class_union()
    assert dashboard_set == _REACHES_AUDIT, (
        f"dashboard/lib/types.ts FaultClass {sorted(dashboard_set)} does not match the "
        f"fault classes /audit can actually send {sorted(_REACHES_AUDIT)} - "
        f"missing: {sorted(_REACHES_AUDIT - dashboard_set)}, "
        f"unreachable-but-present: {sorted(dashboard_set - _REACHES_AUDIT)}"
    )
