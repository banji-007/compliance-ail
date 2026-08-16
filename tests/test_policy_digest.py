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
import re
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


def _opa_live_revision() -> str:
    """The ground truth: what OPA itself currently has loaded."""
    resp = httpx.get(f"{OPA_BASE}/v1/data/system/bundles/ail-policies/manifest/revision", timeout=5)
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

    decision = matching[0]["decision"]
    m = re.search(r"\(policy: ([0-9a-f]+)\)", decision)
    assert m, f"No policy revision recorded in decision string: {decision!r}"
    recorded_digest = m.group(1)

    assert recorded_digest == live_revision, (
        f"Recorded digest {recorded_digest} does not match OPA's live revision "
        f"{live_revision} - the ledger is attributing this decision to the wrong policy."
    )


@requires_stack
def test_digest_unavailable_denies_and_writes_no_ledger_entry(monkeypatch):
    """
    Simulates the bundle-revision read failing in the same cycle as an
    otherwise-successful OPA decision, by pointing the revision lookup at a
    bundle name OPA never loaded (OPA returns {} - undefined - for that
    path, exactly as it would for any other reason the read fails). The
    call must deny and must not write to the ledger - no placeholder digest,
    no unattributable entry.
    """
    monkeypatch.setattr(
        middleware,
        "_OPA_REVISION_URL",
        f"{OPA_BASE}/v1/data/system/bundles/nonexistent-bundle/manifest/revision",
    )

    before = {e["tx_id"] for e in _audit_entries()}

    response = middleware.intercept_tool_call(
        "provision_cloud_server", _APPROVED_ARGS, "test_digest_agent"
    )

    assert response["status"] == "DENIED", f"Expected DENIED, got: {response}"
    assert "ledger_tx_id" not in response, f"Expected no ledger write, got: {response}"

    after = {e["tx_id"] for e in _audit_entries()}
    assert after == before, (
        f"Ledger gained entries {after - before} despite the digest being unobtainable"
    )
