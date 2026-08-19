"""
tests/test_record_profile.py - P13-8, Phase 1.3.

Every record now carries a conformance profile, from a closed set:
"observed" | "mediated" | "attested" (see docs/adr/0005-outcome-taxonomy.md).
This codebase can only ever produce "observed" - the agent independently
holds every tool's authority, so a bypass of this gateway is possible and
would leave no record at all (see the ADR's own profile table). Checked
against the raw ImmuDB value directly, the same way test_raw_ledger_fields.py
checks other fields the /audit projection could silently drop or fabricate,
and against a live /audit response for the same reason.

Requires the docker-compose.test.yml stack. SPIRE_DISABLED=true bypasses
mTLS, matching Makefile:45-53.
"""

import base64
import json
import os
import sys
import uuid

import httpx
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "interceptor"))

os.environ.setdefault("SPIRE_DISABLED", "true")
os.environ.setdefault("OPA_URL", "http://localhost:8181/v1/data/ail/main/allow")

import middleware  # noqa: E402

CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL", "http://localhost:8002")
READ_API_KEY = os.getenv("CONTROL_PLANE_READ_KEY", "test-read-key")
IMMUDB_URL = os.getenv("IMMUDB_URL", "http://localhost:8080")
IMMUDB_USER = os.getenv("IMMUDB_USER", "immudb")
IMMUDB_PASSWORD = os.getenv("IMMUDB_PASSWORD", "immudb")

_CLOSED_PROFILE_SET = {"observed", "mediated", "attested"}


def _opa_reachable() -> bool:
    try:
        httpx.get("http://localhost:8181/health", timeout=2)
        return True
    except Exception:
        return False


def _immudb_reachable() -> bool:
    try:
        httpx.get(IMMUDB_URL, timeout=2)
        return True
    except Exception:
        return False


requires_stack = pytest.mark.skipif(
    not (_opa_reachable() and _immudb_reachable()),
    reason="OPA and/or ImmuDB not reachable",
)


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _raw_scan(prefix: str, limit: int = 500) -> list[dict]:
    with httpx.Client(timeout=30) as client:
        login = client.post(
            f"{IMMUDB_URL}/api/v2/login",
            json={"user": b64(IMMUDB_USER), "password": b64(IMMUDB_PASSWORD), "database": b64("defaultdb")},
        )
        login.raise_for_status()
        token = login.json()["token"]
        scan = client.post(
            f"{IMMUDB_URL}/api/v2/db/scan",
            json={"prefix": b64(prefix), "desc": True, "limit": limit},
            headers={"Authorization": f"Bearer {token}"},
        )
        scan.raise_for_status()
        return scan.json().get("entries", [])


def _find_raw_decision_by_agent_id(agent_id: str) -> dict:
    for raw in _raw_scan("tool_call:"):
        value = json.loads(base64.b64decode(raw["value"]).decode())
        if value.get("agent_id") == agent_id:
            return value
    raise AssertionError(f"No raw ledger entry found for agent_id={agent_id}")


def _find_raw_tombstone_by_call_id(call_id: str) -> dict:
    for raw in _raw_scan("content_erasure:"):
        value = json.loads(base64.b64decode(raw["value"]).decode())
        if value.get("call_id") == call_id:
            return value
    raise AssertionError(f"No raw tombstone found for call_id={call_id}")


@requires_stack
def test_raw_decision_record_carries_observed_profile():
    """
    Mutation: drop "profile" (or the RECORD_PROFILE constant it comes from)
    from ledger/immudb_ledger.py::log_tool_call's log_entry. This test must
    fail with a KeyError/None, not silently pass.
    """
    probe_agent_id = f"profile_probe_{uuid.uuid4().hex}"
    r = middleware.intercept_tool_call(
        "provision_cloud_server",
        {
            "instance_type": "t3.micro", "region": "us-east-1", "cost_per_hour": 5.0,
            "tags": {"environment": "dev", "data_classification": "internal", "cost_center": "engineering", "project": "webapp"},
        },
        probe_agent_id,
    )
    assert "ledger_tx_id" in r, f"Expected a recorded call, got: {r}"

    entry = _find_raw_decision_by_agent_id(probe_agent_id)
    assert entry.get("profile") in _CLOSED_PROFILE_SET, f"profile missing or not in the closed set: {entry}"
    assert entry["profile"] == "observed", f"Expected 'observed' - this codebase cannot produce anything else: {entry}"


@requires_stack
def test_raw_tombstone_record_carries_observed_profile():
    """The erasure tombstone is a record too (D11) - it must carry the same
    closed-set profile field, not just decision records."""
    marker = f"PROFILE-TOMBSTONE-MARKER-{uuid.uuid4().hex}"
    args = {
        "target_table": "pii_records",
        "query": f"SELECT * FROM pii_records WHERE marker='{marker}'",
        "processing_purpose": "customer_support",
        "masking_enabled": True,
    }
    r = middleware.intercept_tool_call("query_database", args, f"profile_probe_{uuid.uuid4().hex}")
    assert "ledger_tx_id" in r, f"Expected a recorded call, got: {r}"

    entries = httpx.get(
        f"{CONTROL_PLANE_URL}/audit",
        params={"limit": 200},
        headers={"X-API-Key": READ_API_KEY},
        timeout=30,
    ).json()["entries"]
    matching = [e for e in entries if e["tx_id"] == r["ledger_tx_id"]]
    assert matching, f"tx_id {r['ledger_tx_id']} not found in /audit"
    call_id = matching[0]["call_id"]

    write_key = os.getenv("CONTROL_PLANE_WRITE_KEY", "test-write-key")
    del_resp = httpx.delete(
        f"{CONTROL_PLANE_URL}/content/{call_id}",
        headers={"X-API-Key": write_key},
        timeout=10,
    )
    assert del_resp.status_code == 204, del_resp.text

    tombstone = _find_raw_tombstone_by_call_id(call_id)
    assert tombstone.get("profile") in _CLOSED_PROFILE_SET, f"profile missing or not in the closed set: {tombstone}"
    assert tombstone["profile"] == "observed", f"Expected 'observed': {tombstone}"


@requires_stack
def test_audit_forged_profile_less_record_renders_as_unknown_not_observed():
    """
    R3 (Phase 1.3 completion pass, red-team V5): a record written directly
    to the verifier with no "profile" key at all must render distinctly as
    "unknown" in /audit, never as "observed" - the default that would make
    a structurally profile-less record indistinguishable from a genuine
    one. Reproduces the red-team's own live forgery.

    Mutation: change control_plane/main.py::get_audit's
    `log_entry.get("profile", "unknown")` back to
    `log_entry.get("profile", RECORD_PROFILE)`. This test must fail against
    that mutation - the forged entry would render "observed" again.
    """
    agent_id = f"profile_less_probe_{uuid.uuid4().hex}"
    call_id = f"profile-less-{uuid.uuid4().hex}"
    key = f"tool_call:{agent_id}:{uuid.uuid4().hex}:provision_cloud_server"
    entry = {
        "record_type": "decision",
        "agent_id": agent_id,
        "timestamp": "2026-08-19T00:00:00",
        "tool_name": "provision_cloud_server",
        "call_id": call_id,
        "input_sha256": "deadbeef",
        "outcome_type": "policy_allow",
        "fault_class": None,
        "policy_revision": "test-revision",
        "reasons": [],
        "content_state": "unavailable",
        # deliberately no "profile" key
    }
    write_resp = httpx.post(
        f"{os.getenv('VERIFIER_URL', 'http://localhost:8003')}/write",
        json={"key": b64(key), "value": b64(json.dumps(entry))},
        timeout=15,
    )
    write_resp.raise_for_status()
    assert write_resp.json().get("verified"), write_resp.json()

    entries = httpx.get(
        f"{CONTROL_PLANE_URL}/audit",
        params={"limit": 500},
        headers={"X-API-Key": READ_API_KEY},
        timeout=30,
    ).json()["entries"]
    matching = [e for e in entries if e["agent_id"] == agent_id]
    assert matching, f"forged entry for {agent_id} not found in /audit"
    assert matching[0]["profile"] == "unknown", (
        f"Expected 'unknown' for a structurally profile-less record, "
        f"got {matching[0]['profile']!r} - this masks a forged or "
        f"pre-P13-8 record as a genuine 'observed' one: {matching[0]}"
    )


@requires_stack
def test_audit_response_carries_profile_from_closed_set():
    """The /audit projection must surface profile, not drop it the way it
    would if a producer forgot to read the field back out of log_entry."""
    probe_agent_id = f"profile_probe_{uuid.uuid4().hex}"
    r = middleware.intercept_tool_call(
        "provision_cloud_server",
        {
            "instance_type": "t3.micro", "region": "us-east-1", "cost_per_hour": 5.0,
            "tags": {"environment": "dev", "data_classification": "internal", "cost_center": "engineering", "project": "webapp"},
        },
        probe_agent_id,
    )
    assert "ledger_tx_id" in r, f"Expected a recorded call, got: {r}"

    entries = httpx.get(
        f"{CONTROL_PLANE_URL}/audit",
        params={"limit": 200},
        headers={"X-API-Key": READ_API_KEY},
        timeout=30,
    ).json()["entries"]
    matching = [e for e in entries if e["tx_id"] == r["ledger_tx_id"]]
    assert matching, f"tx_id {r['ledger_tx_id']} not found in /audit"
    assert matching[0]["profile"] in _CLOSED_PROFILE_SET, matching[0]
