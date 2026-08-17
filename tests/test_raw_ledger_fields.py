"""
tests/test_raw_ledger_fields.py - P11-8, Phase 1.1.

Two of the five properties Phase 1 proved only by hand (red-team S1
mutations #2 and #4): the raw ImmuDB value for a ledger entry must never
contain a verification field, and must never contain the raw argument
content - only input_sha256 represents the input. /audit's own handler only
reads the keys it expects (log_entry.get("outcome_type") etc.) and silently
ignores anything else present, so an extra field is invisible everywhere
/audit could be observed - these must be checked against the raw stored
value directly.

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

IMMUDB_URL = os.getenv("IMMUDB_URL", "http://localhost:8080")
IMMUDB_USER = os.getenv("IMMUDB_USER", "immudb")
IMMUDB_PASSWORD = os.getenv("IMMUDB_PASSWORD", "immudb")


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


def _raw_scan(limit: int = 500) -> list[dict]:
    """Raw ImmuDB REST scan for tool_call: keys - bypasses the control
    plane's /audit projection entirely."""
    with httpx.Client(timeout=30) as client:
        login = client.post(
            f"{IMMUDB_URL}/api/v2/login",
            json={"user": b64(IMMUDB_USER), "password": b64(IMMUDB_PASSWORD), "database": b64("defaultdb")},
        )
        login.raise_for_status()
        token = login.json()["token"]
        scan = client.post(
            f"{IMMUDB_URL}/api/v2/db/scan",
            json={"prefix": b64("tool_call:"), "desc": True, "limit": limit},
            headers={"Authorization": f"Bearer {token}"},
        )
        scan.raise_for_status()
        return scan.json().get("entries", [])


def _find_raw_entry_by_agent_id(agent_id: str) -> dict:
    for raw in _raw_scan():
        value = json.loads(base64.b64decode(raw["value"]).decode())
        if value.get("agent_id") == agent_id:
            return value
    raise AssertionError(f"No raw ledger entry found for agent_id={agent_id}")


@requires_stack
def test_raw_ledger_entry_has_no_verification_field():
    """Mutation (S1 #2): ledger/immudb_ledger.py::log_tool_call gaining
    log_entry["verified"] = True - a ledger entry self-certifying its own
    verification status, which D2 forbids."""
    probe_agent_id = f"raw_field_probe_{uuid.uuid4().hex}"
    r = middleware.intercept_tool_call(
        "provision_cloud_server",
        {
            "instance_type": "t3.micro", "region": "us-east-1", "cost_per_hour": 5.0,
            "tags": {"environment": "dev", "data_classification": "internal", "cost_center": "engineering", "project": "webapp"},
        },
        probe_agent_id,
    )
    assert "ledger_tx_id" in r, f"Expected a recorded call, got: {r}"

    entry = _find_raw_entry_by_agent_id(probe_agent_id)
    assert "verification" not in entry, f"Raw ledger entry must not contain a verification field: {entry}"
    assert "verified" not in entry, f"Raw ledger entry must not self-certify verification: {entry}"


@requires_stack
def test_raw_ledger_entry_has_no_raw_argument_content():
    """Mutation (S1 #4): raw tool_args written into the ledger entry
    alongside input_sha256, defeating D5 erasability at the source. Uses a
    unique marker string that would only appear in the raw value if the
    arguments themselves were written there."""
    marker = f"RAW-FIELD-PROBE-{uuid.uuid4().hex}"
    probe_agent_id = f"raw_field_probe_{uuid.uuid4().hex}"
    args = {
        "target_table": "pii_records",
        "query": f"SELECT * FROM pii_records WHERE marker='{marker}'",
        "processing_purpose": "customer_support",
        "masking_enabled": True,
    }
    r = middleware.intercept_tool_call("query_database", args, probe_agent_id)
    assert "ledger_tx_id" in r, f"Expected a recorded call, got: {r}"

    entry = _find_raw_entry_by_agent_id(probe_agent_id)
    raw_serialized = json.dumps(entry)
    assert marker not in raw_serialized, f"Raw ledger entry must not contain argument content: {entry}"
    assert "tool_args" not in entry, f"Raw ledger entry must not contain a tool_args field: {entry}"
    assert entry.get("input_sha256"), f"Expected input_sha256 to represent the input: {entry}"
