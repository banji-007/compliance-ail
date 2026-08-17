"""
tests/test_content_states.py - P11-4, Phase 1.1 (D7).

Content is written first, keyed by call_id (minted at intercept, independent
of ImmuDB's own tx numbering). The ledger entry then records content_state
(present/unavailable); /audit derives payload_state (present/erased/
unavailable) at read time - the same read-time-inference pattern D2/D8 use
for verification. A content-store failure denies the call as a fault and
writes no ledger entry at all, closing the incoherence red-team S4/S5 found
(an approved call executing while its content silently never lands).

Requires the docker-compose.test.yml stack. SPIRE_DISABLED=true bypasses
mTLS, matching Makefile:45-53.
"""

import os
import sys
import uuid

import httpx
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "interceptor"))

os.environ.setdefault("SPIRE_DISABLED", "true")
os.environ.setdefault("OPA_URL", "http://localhost:8181/v1/data/ail/main/allow")

import middleware  # noqa: E402
import content_store  # noqa: E402 - importable once middleware's sys.path.append runs above

CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL", "http://localhost:8002")
READ_API_KEY = os.getenv("CONTROL_PLANE_READ_KEY", "test-read-key")
WRITE_API_KEY = os.getenv("CONTROL_PLANE_WRITE_KEY", "test-write-key")

_APPROVED_ARGS = {
    "instance_type": "t3.micro",
    "region": "us-east-1",
    "cost_per_hour": 5.0,
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


def _audit_entries(limit: int = 200) -> list[dict]:
    resp = httpx.get(
        f"{CONTROL_PLANE_URL}/audit",
        params={"limit": limit},
        headers={"X-API-Key": READ_API_KEY},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["entries"]


def _audit_entry_for_tx(tx_id: int) -> dict:
    matching = [e for e in _audit_entries() if e["tx_id"] == tx_id]
    assert matching, f"tx_id {tx_id} not found in /audit"
    return matching[0]


# ---------------------------------------------------------------------------
# present -> erased (the V9-marker-style round trip, D7's read-time
# inference of "erased" from content_state="present" + a missing row)
# ---------------------------------------------------------------------------

@requires_stack
def test_present_then_erased_via_delete_content():
    marker = f"V11-MARKER-PHASE1-1-{uuid.uuid4().hex}"
    args = {
        "target_table": "pii_records",
        "query": f"SELECT * FROM pii_records WHERE marker='{marker}'",
        "processing_purpose": "customer_support",
        "masking_enabled": True,
    }
    r = middleware.intercept_tool_call("query_database", args, "content_state_test")
    assert "ledger_tx_id" in r, f"Expected a recorded call, got: {r}"
    tx_id = r["ledger_tx_id"]

    entry = _audit_entry_for_tx(tx_id)
    assert entry["payload_state"] == "present", entry
    assert entry["payload"] is not None and marker in entry["payload"]["query"], entry
    call_id = entry["call_id"]
    assert call_id, f"Expected a call_id on the entry, got: {entry}"

    del_resp = httpx.delete(
        f"{CONTROL_PLANE_URL}/content/{call_id}",
        headers={"X-API-Key": WRITE_API_KEY},
        timeout=10,
    )
    assert del_resp.status_code == 204, del_resp.text

    entry_after = _audit_entry_for_tx(tx_id)
    assert entry_after["payload_state"] == "erased", entry_after
    assert entry_after["payload"] is None
    # Hash and verification are unaffected by erasure - only the erasable
    # content is gone, not the proof of what was decided.
    assert entry_after["input_sha256"] == entry["input_sha256"]
    assert entry_after["outcome_type"] == entry["outcome_type"]
    assert entry_after["verification"]["state"] == entry["verification"]["state"]


# ---------------------------------------------------------------------------
# unavailable (P11-2's non-dict-args case: nothing dict-shaped to store)
# ---------------------------------------------------------------------------

@requires_stack
def test_unavailable_for_non_dict_args():
    r = middleware.intercept_tool_call("provision_cloud_server", "not-a-dict", "content_state_test")
    assert "ledger_tx_id" in r, f"Expected a recorded call, got: {r}"
    entry = _audit_entry_for_tx(r["ledger_tx_id"])
    assert entry["payload_state"] == "unavailable", entry
    assert entry["payload"] is None


# ---------------------------------------------------------------------------
# content-store fault: fail-closed, no ledger entry at all (S4/S5's fix)
# ---------------------------------------------------------------------------

@requires_stack
def test_content_store_down_denies_as_fault_and_writes_no_record(monkeypatch):
    def _broken_store(call_id, payload):
        raise RuntimeError("content store down (simulated)")

    monkeypatch.setattr(content_store, "store_content", _broken_store)

    probe_agent_id = f"content_fault_probe_{uuid.uuid4().hex}"
    r = middleware.intercept_tool_call("provision_cloud_server", _APPROVED_ARGS, probe_agent_id)

    assert r["status"] == "DENIED", f"Expected DENIED, got: {r}"
    assert r["outcome_type"] == "fault", f"Expected fault, got: {r}"
    assert r["fault_class"] == "content_store_unreachable", f"Expected content_store_unreachable, got: {r}"
    assert r["policy_revision"] is None
    assert "ledger_tx_id" not in r, f"Expected no ledger record when content write fails, got: {r}"

    # There is no ledger entry to contradict (D7) - confirm this probe's
    # marker agent_id never made it into /audit at all.
    matching = [e for e in _audit_entries() if e.get("agent_id") == probe_agent_id]
    assert not matching, f"Expected no /audit entry for a content-store fault, found: {matching}"
