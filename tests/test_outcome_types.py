"""
tests/test_outcome_types.py - Phase 1, D1/P1-2 automated coverage, migrated
in Phase 2 (P2-1) from interceptor/middleware.py to decision_service/main.py
- schema validation, the OPA query, and the ledger write all moved there
(D12); this file's assertions are unchanged in substance, only their target.

Exercises every outcome_type and every fault_class the decision service can
produce, asserting the taxonomy directly (never inferred from message
text), plus one client-leg fault (spiffe_unavailable) that now belongs to
interceptor/middleware.py instead, since that is the leg that still holds
an mTLS identity (the agent-to-Envoy-to-decision-service hop).

Requires the docker-compose.test.yml stack. SPIRE_DISABLED=true bypasses
mTLS for the agent-leg test, matching Makefile:45-53.
"""

import asyncio
import os
import re
import sys
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "interceptor"))

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

decision_main = _load_decision_service_main()
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


def _decide(tool_name, tool_args, agent_id="outcome_test") -> dict:
    """Call decision_service/main.py's /decide route function directly, the
    same way the module-level test suite always has - in-process, with OPA/
    ImmuDB/verifier/control-plane reached live over the network from the
    test process itself. FastAPI route functions remain plain callables."""
    req = decision_main.DecideRequest(tool_name=tool_name, tool_args=tool_args, agent_id=agent_id)
    return asyncio.run(decision_main.decide(req))


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
    r = _decide("provision_cloud_server", _APPROVED_ARGS)
    assert r["outcome_type"] == "policy_allow"
    assert r["fault_class"] is None
    assert r["policy_revision"]
    assert "ledger_tx_id" in r


@requires_stack
def test_policy_deny():
    r = _decide("provision_cloud_server", _DENIED_ARGS)
    assert r["outcome_type"] == "policy_deny"
    assert r["fault_class"] is None
    assert r["policy_revision"]
    assert r["message"].startswith("DENIED:")
    assert "ledger_tx_id" in r


@requires_stack
def test_schema_deny_unregistered_tool():
    r = _decide("hallucinated_tool", {"anything": "goes"})
    assert r["outcome_type"] == "schema_deny"
    assert r["fault_class"] is None
    assert r["policy_revision"] is None
    assert "ledger_tx_id" in r


@requires_stack
def test_schema_deny_invalid_payload():
    bad_args = {**_APPROVED_ARGS, "cost_per_hour": -5.0}
    r = _decide("provision_cloud_server", bad_args)
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
    r = _decide("provision_cloud_server", bad_args)
    assert r["outcome_type"] == "schema_deny", f"Expected schema_deny for shape {type(bad_args).__name__}, got: {r}"
    assert r["fault_class"] is None
    assert r["policy_revision"] is None
    assert "ledger_tx_id" in r, f"Expected a ledger record for shape {type(bad_args).__name__}, got: {r}"


# ---------------------------------------------------------------------------
# Fault outcomes - each fault_class produced at the exact point
# decision_service/main.py::query_opa_policy / decide would observe it
# ---------------------------------------------------------------------------

@requires_stack
def test_fault_opa_unreachable(monkeypatch):
    monkeypatch.setattr(decision_main, "_OPA_URL", "http://localhost:1/v1/data/ail/main/evaluation")
    r = _decide("provision_cloud_server", _APPROVED_ARGS)
    assert r["status"] == "DENIED"
    assert r["outcome_type"] == "fault"
    assert r["fault_class"] == "opa_unreachable"
    assert r["policy_revision"] is None
    assert "ledger_tx_id" in r  # the fault itself is still recorded (D1)


@requires_stack
def test_fault_revision_unavailable(monkeypatch):
    # Phase 1.2 (D9): the request carries no caller-supplied bundle name, so
    # a bogus bundle name can no longer force this fault - the revision
    # comes from whichever loaded bundle's manifest claims the `ail` root
    # (see tests/test_bundle_revision_attribution.py). Simulated here the
    # same way any other undefined /evaluation result would occur: pointing
    # at a rule path OPA has never heard of, which returns HTTP 200 with no
    # "result" key - the exact shape query_opa_policy treats as
    # revision_unavailable.
    monkeypatch.setattr(
        decision_main, "_OPA_URL",
        "http://localhost:8181/v1/data/ail/main/nonexistent_entrypoint",
    )
    r = _decide("provision_cloud_server", _APPROVED_ARGS)
    assert r["status"] == "DENIED"
    assert r["outcome_type"] == "fault"
    assert r["fault_class"] == "revision_unavailable"
    assert r["policy_revision"] is None
    assert "ledger_tx_id" in r


@requires_stack
def test_fault_verifier_unreachable_writes_no_record(monkeypatch):
    """The one documented boundary (D1): a fault in the recording path
    itself cannot be recorded - no ledger_tx_id, no ledger entry."""

    class _BrokenLedger:
        def log_tool_call(self, **kwargs):
            raise RuntimeError("verifier unreachable (simulated)")

    # decide() does `from immudb_ledger import get_ledger` fresh on every
    # call, so patching the attribute on the module (not decision_main's
    # namespace) is what actually takes effect.
    import immudb_ledger
    monkeypatch.setattr(immudb_ledger, "get_ledger", lambda: _BrokenLedger())

    r = _decide("provision_cloud_server", _APPROVED_ARGS)
    assert r["status"] == "DENIED"
    assert r["outcome_type"] == "fault"
    assert r["fault_class"] == "verifier_unreachable"
    assert r["policy_revision"] is None
    assert "ledger_tx_id" not in r


def test_fault_spiffe_unavailable(monkeypatch):
    """
    D12 (Phase 2): spiffe_unavailable now belongs to the agent's client leg
    (interceptor/middleware.py::intercept_tool_call), not the decision
    service - the agent is the one presenting an mTLS identity to Envoy now,
    not decision-service reaching OPA. This fault is produced entirely
    before any network call, so it needs no live stack.
    """
    monkeypatch.setattr(middleware, "_SPIRE_DISABLED", False)
    monkeypatch.setattr(middleware, "_get_spiffe_ssl_context", lambda: None)
    r = middleware.intercept_tool_call("provision_cloud_server", _APPROVED_ARGS, "outcome_test")
    assert r["status"] == "DENIED"
    assert r["outcome_type"] == "fault"
    assert r["fault_class"] == "spiffe_unavailable"
    assert r["policy_revision"] is None
    assert "ledger_tx_id" not in r  # never reached the decision service at all


def test_fault_decision_service_unreachable(monkeypatch):
    """
    D12 (Phase 2): the agent's other new client-leg fault - it presented a
    valid identity but the decision service (or Envoy in front of it) could
    not be reached at all. No live stack needed: the target URL is simply
    unroutable.
    """
    monkeypatch.setattr(middleware, "_SPIRE_DISABLED", True)
    monkeypatch.setattr(middleware, "_DECISION_SERVICE_URL", "http://localhost:1/decide")
    r = middleware.intercept_tool_call("provision_cloud_server", _APPROVED_ARGS, "outcome_test")
    assert r["status"] == "DENIED"
    assert r["outcome_type"] == "fault"
    assert r["fault_class"] == "decision_service_unreachable"
    assert r["policy_revision"] is None
    assert "ledger_tx_id" not in r


# ---------------------------------------------------------------------------
# P11-6 / P11-8 (Phase 1.1): metric labels are bounded. tool_name is
# allowlisted against the tool registry before use as a Prometheus label -
# a hallucinated tool name must not grow the metric's cardinality.
# ---------------------------------------------------------------------------

def _series_count() -> int:
    """Count of distinct label-combinations currently registered for
    ail_policy_decisions_total, via the public .collect() API (not the
    prometheus_client-internal _metrics dict)."""
    for metric in decision_main._POLICY_DECISIONS.collect():
        return sum(1 for s in metric.samples if s.name.endswith("_total"))
    return 0


@requires_stack
def test_hallucinated_tool_names_do_not_grow_metric_cardinality():
    before = _series_count()
    for i in range(50):
        _decide(f"hallucinated_tool_variant_{i}", {"anything": "goes"}, "cardinality_test")
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
    _decide("some_other_hallucinated_name", {"anything": "goes"}, "cardinality_test")
    _decide("provision_cloud_server", _APPROVED_ARGS, "cardinality_test")

    allowed_tool_names = set(decision_main.TOOL_REGISTRY) | {"_unregistered"}
    allowed_outcome_types = {
        decision_main.OUTCOME_POLICY_ALLOW, decision_main.OUTCOME_POLICY_DENY,
        decision_main.OUTCOME_SCHEMA_DENY, decision_main.OUTCOME_FAULT,
    }
    allowed_fault_classes = {
        "", decision_main.FAULT_OPA_UNREACHABLE, decision_main.FAULT_REVISION_UNAVAILABLE,
        decision_main.FAULT_VERIFIER_UNREACHABLE, decision_main.FAULT_MALFORMED_POLICY_RESPONSE,
        decision_main.FAULT_CONTENT_STORE_UNREACHABLE, decision_main.FAULT_TOOL_EXECUTION_FAILED,
        decision_main.FAULT_INTENT_WRITE_FAILED,
    }
    allowed_statuses = {"APPROVED", "DENIED"}

    for metric in decision_main._POLICY_DECISIONS.collect():
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
# actually send. docs/adr/0005-outcome-taxonomy.md's Documented Boundary
# section states verifier_unreachable and content_store_unreachable never
# produce a ledger record - each is discovered in a path that itself
# precedes, or is, the ledger write. Phase 2 adds tool_execution_failed
# (D14) to the reachable set: the ledger write already succeeded by the
# point the mediated tool call itself can fail. The Phase 2 completion pass
# adds intent_write_failed (D16), for the same reason: the intent write is a
# separate, earlier ledger write than the completion record documenting its
# own failure.
# ---------------------------------------------------------------------------

_NEVER_REACHES_LEDGER = {
    decision_main.FAULT_VERIFIER_UNREACHABLE,
    decision_main.FAULT_CONTENT_STORE_UNREACHABLE,
}

_ALL_FAULT_CLASSES = {
    decision_main.FAULT_OPA_UNREACHABLE,
    decision_main.FAULT_REVISION_UNAVAILABLE,
    decision_main.FAULT_VERIFIER_UNREACHABLE,
    decision_main.FAULT_MALFORMED_POLICY_RESPONSE,
    decision_main.FAULT_CONTENT_STORE_UNREACHABLE,
    decision_main.FAULT_TOOL_EXECUTION_FAILED,
    decision_main.FAULT_INTENT_WRITE_FAILED,
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
    FAULT_TOOL_EXECUTION_FAILED from it. This test must fail against
    either mutation. Note: spiffe_unavailable and decision_service_unreachable
    are deliberately absent from both sides - they are the agent's own
    client-leg faults (interceptor/middleware.py) and never reach the
    ledger at all (see test_fault_spiffe_unavailable and
    test_fault_decision_service_unreachable above), so they were never part
    of this set even before Phase 2.
    """
    dashboard_set = _dashboard_fault_class_union()
    assert dashboard_set == _REACHES_AUDIT, (
        f"dashboard/lib/types.ts FaultClass {sorted(dashboard_set)} does not match the "
        f"fault classes /audit can actually send {sorted(_REACHES_AUDIT)} - "
        f"missing: {sorted(_REACHES_AUDIT - dashboard_set)}, "
        f"unreachable-but-present: {sorted(dashboard_set - _REACHES_AUDIT)}"
    )
