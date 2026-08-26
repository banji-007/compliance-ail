"""
tests/test_policy_digest.py - the recorded policy digest must be the policy
that actually ran (Phase 0, P0-1).

_compute_policy_hash was deleted: it HEADed the control plane for whatever
tenant the interceptor's own env believed it was, which has no relationship
to the bundle the queried OPA instance had actually loaded. The replacement
reads the revision back from the same OPA instance, in the same call, over
data.system.bundles.<name>.manifest.revision. If that read fails, the whole
call denies and nothing is written to the ledger - there is no placeholder.

Requires the docker-compose.test.yml stack (OPA + control plane + ImmuDB +
verifier). SPIRE_DISABLED=true bypasses mTLS, matching Makefile:45-53.

Migrated in Phase 2 (P2-1): schema validation, the OPA query, and the
ledger write all moved from interceptor/middleware.py to
decision_service/main.py (D12). Both tests below exercise exactly that
internal pipeline (not the agent's mTLS client leg), so they now call
decision_main.decide() in-process via the same `_decide()` pattern
tests/test_outcome_types.py established, rather than
middleware.intercept_tool_call (now just an HTTP client to
decision_service).
"""

import asyncio
import os
import sys

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

decision_main = _load_decision_service_main()

OPA_BASE = os.environ["OPA_URL"].replace("/v1/data/ail/main/evaluation", "")
CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL", "http://localhost:8002")
READ_API_KEY = os.getenv("CONTROL_PLANE_READ_KEY", "test-read-key")

_APPROVED_ARGS = {
    "instance_type": "t3.micro",
    "region": "us-east-1",
    "cost_per_hour": 5.0,
    "tags": {
        "environment": "dev",
        "data_classification": "internal",
        "cost_center": "engineering",
        "project": "webapp",
    },
}


def _decide(tool_name, tool_args, agent_id="test_digest_agent") -> dict:
    req = decision_main.DecideRequest(tool_name=tool_name, tool_args=tool_args, agent_id=agent_id)
    return asyncio.run(decision_main.decide(req))


requires_stack = pytest.mark.needs_stack("opa", "immudb", "verifier", "control_plane", "decision_service")


_BUNDLE_NAME = os.getenv("AIL_BUNDLE_NAME", "ail-policies")


def _opa_live_revision() -> str:
    """The ground truth: what OPA itself currently has loaded."""
    resp = httpx.get(f"{OPA_BASE}/v1/data/system/bundles/{_BUNDLE_NAME}/manifest/revision", timeout=5)
    resp.raise_for_status()
    revision = resp.json().get("result")
    assert revision, f"OPA has no bundle revision loaded: {resp.json()}"
    return revision


def _audit_entries() -> list[dict]:
    resp = httpx.get(f"{CONTROL_PLANE_URL}/audit", headers={"X-API-Key": READ_API_KEY}, timeout=30)
    resp.raise_for_status()
    return resp.json()["entries"]


@requires_stack
def test_recorded_digest_matches_opa_not_interceptor_belief(monkeypatch):
    """
    This is the V2 scenario: the interceptor's own environment claims a
    tenant OPA is not actually serving. Reproduced live by setting
    AIL_TENANT_ID to a tenant the test stack's OPA never loaded (the test
    stack always seeds only tenant_default). Under the old
    _compute_policy_hash, this environment variable is exactly what
    selected which bundle's ETag got HEADed and stamped into the ledger,
    independent of what OPA was actually evaluating against. Under the
    fix, decision_service no longer reads AIL_TENANT_ID at all for this
    purpose - the assertion below is that changing it has no effect on
    the recorded digest, because the digest now comes from OPA itself.
    """
    monkeypatch.setenv("AIL_TENANT_ID", "tenant_finance")

    live_revision = _opa_live_revision()

    response = _decide(
        "provision_cloud_server", _APPROVED_ARGS, "test_digest_agent"
    )
    assert response["status"] == "APPROVED", f"Expected APPROVED, got: {response}"
    assert "ledger_tx_id" in response, f"Expected a ledger write, got: {response}"

    entries = _audit_entries()
    matching = [e for e in entries if e.get("tx_id") == response["ledger_tx_id"]]
    assert matching, f"tx_id {response['ledger_tx_id']} not found in /audit"

    recorded_digest = matching[0]["policy_revision"]
    assert recorded_digest, f"No policy_revision recorded on entry: {matching[0]!r}"

    assert recorded_digest == live_revision, (
        f"Recorded digest {recorded_digest} does not match OPA's live revision "
        f"{live_revision} - the ledger is attributing this decision to the wrong policy."
    )


@requires_stack
def test_digest_unavailable_denies_and_writes_a_fault_record(monkeypatch):
    """
    Simulates the bundle-revision read failing in the same cycle as an
    otherwise-successful OPA decision. Under D1 (Phase 1) this denies AND
    writes a fault record with a null revision - this reverses the old
    assertion ("no ledger entry"), the one pre-authorized change in Phase 1.

    Phase 1.2 (D9): the request no longer carries a caller-supplied bundle
    name - policy/core/main.rego's `evaluation` rule now derives the
    revision from whichever loaded bundle's manifest claims the `ail` root
    (see tests/test_bundle_revision_attribution.py for that mechanism
    exercised directly, live). Undefined revision is simulated here the
    same way any other undefined /evaluation result would occur: pointing
    the query at a rule path OPA has never heard of.
    """
    monkeypatch.setattr(
        decision_main, "_OPA_URL",
        OPA_BASE + "/v1/data/ail/main/nonexistent_entrypoint",
    )

    response = _decide(
        "provision_cloud_server", _APPROVED_ARGS, "test_digest_agent"
    )

    assert response["status"] == "DENIED", f"Expected DENIED, got: {response}"
    assert response["outcome_type"] == "fault", f"Expected a fault outcome, got: {response}"
    assert response["fault_class"] == "revision_unavailable", f"Expected revision_unavailable, got: {response}"
    assert response["policy_revision"] is None, f"Expected a null revision, got: {response}"
    assert "ledger_tx_id" in response, f"Expected a fault record to still be written, got: {response}"

    entries = _audit_entries()
    matching = [e for e in entries if e.get("tx_id") == response["ledger_tx_id"]]
    assert matching, f"tx_id {response['ledger_tx_id']} not found in /audit"
    entry = matching[0]
    assert entry["outcome_type"] == "fault"
    assert entry["fault_class"] == "revision_unavailable"
    assert entry["policy_revision"] is None
