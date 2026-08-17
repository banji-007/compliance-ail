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
"""

import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "interceptor"))

os.environ.setdefault("SPIRE_DISABLED", "true")
os.environ.setdefault("OPA_URL", "http://localhost:8181/v1/data/ail/main/allow")

import middleware  # noqa: E402

OPA_BASE = os.environ["OPA_URL"].replace("/v1/data/ail/main/allow", "")
CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL", "http://localhost:8002")
API_KEY = os.getenv("CONTROL_PLANE_API_KEY", "test-api-key")

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


def _opa_reachable() -> bool:
    try:
        httpx.get(f"{OPA_BASE}/health", timeout=2)
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


_BUNDLE_NAME = os.getenv("AIL_BUNDLE_NAME", "ail-policies")


def _opa_live_revision() -> str:
    """The ground truth: what OPA itself currently has loaded."""
    resp = httpx.get(f"{OPA_BASE}/v1/data/system/bundles/{_BUNDLE_NAME}/manifest/revision", timeout=5)
    resp.raise_for_status()
    revision = resp.json().get("result")
    assert revision, f"OPA has no bundle revision loaded: {resp.json()}"
    return revision


def _audit_entries() -> list[dict]:
    resp = httpx.get(f"{CONTROL_PLANE_URL}/audit", headers={"X-API-Key": API_KEY}, timeout=30)
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
    fix, the interceptor no longer reads AIL_TENANT_ID at all for this
    purpose - the assertion below is that changing it has no effect on
    the recorded digest, because the digest now comes from OPA itself.
    """
    monkeypatch.setenv("AIL_TENANT_ID", "tenant_finance")

    live_revision = _opa_live_revision()

    response = middleware.intercept_tool_call(
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
    otherwise-successful OPA decision, by pointing the interceptor's
    combined evaluation query at a bundle name OPA never loaded (OPA's
    revision lookup returns undefined, exactly as it would for any other
    reason the read fails, so `evaluation` itself is undefined - see
    policy/core/main.rego). Under D1 (Phase 1) this denies AND writes a
    fault record with a null revision - this reverses the old assertion
    ("no ledger entry"), the one pre-authorized change in Phase 1.
    """
    # The bundle name travels in the request body (input.bundle_name), read
    # from this module global at call time - point it at a bundle OPA never
    # loaded so policy/core/main.rego's revision lookup is undefined.
    monkeypatch.setattr(middleware, "_BUNDLE_NAME", "nonexistent-bundle")

    response = middleware.intercept_tool_call(
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
