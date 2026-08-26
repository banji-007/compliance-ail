"""
tests/test_intent_completion_visibility.py - D16 (Phase 2 completion pass).

Execution and its own durable recording cannot be made atomic across two
separate systems (decision-service's own process, and ImmuDB via the
verifier). Rather than let that gap stay silent, D16 makes it visible:
decision_service/main.py writes a write-ahead intent record
(ledger/immudb_ledger.py::log_tool_intent) immediately before a mediated
tool's own execution, and refuses to execute at all if that write fails.
An intent record with no matching completion ("decision") record for the
same call_id means the tool executed but its outcome was never durably
recorded - control_plane/main.py::get_audit surfaces this at read time as
execution_state "unknown", the same read-time-inference discipline
content_state/payload_state already use (docs/adr/0005-outcome-taxonomy.md).

Two halves:
  - The write-side gate (no live stack needed): if the intent write fails,
    _execute_vault_tool must never be called at all.
  - The read-side surfacing (requires the docker-compose.test.yml stack):
    a real mediated call produces execution_state "completed"; an intent
    forged directly against the verifier with no completion record (the
    same live-forgery style test_record_profile.py's own profile-less-
    record test uses) surfaces as execution_state "unknown".
"""

import asyncio
import base64
import json
import os
import sys
import uuid

import httpx
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "interceptor"))

import importlib.util as _importlib_util

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "decision_service"))


def _load_decision_service_main():
    spec = _importlib_util.spec_from_file_location(
        "decision_service_main",
        os.path.join(os.path.dirname(__file__), "..", "decision_service", "main.py"),
    )
    module = _importlib_util.module_from_spec(spec)
    sys.modules["decision_service_main"] = module
    spec.loader.exec_module(module)
    return module


os.environ.setdefault("SPIRE_DISABLED", "true")
os.environ.setdefault("DECISION_SERVICE_URL", "http://localhost:8010/decide")

decision_main = _load_decision_service_main()
import middleware  # noqa: E402


def _decide(tool_name, tool_args, agent_id="intent_test") -> dict:
    req = decision_main.DecideRequest(tool_name=tool_name, tool_args=tool_args, agent_id=agent_id)
    return asyncio.run(decision_main.decide(req))


CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL", "http://localhost:8002")
READ_API_KEY = os.getenv("CONTROL_PLANE_READ_KEY", "test-read-key")
IMMUDB_URL = os.getenv("IMMUDB_URL", "http://localhost:8080")
VERIFIER_URL = os.getenv("VERIFIER_URL", "http://localhost:8003")
IMMUDB_USER = os.getenv("IMMUDB_USER", "immudb")
IMMUDB_PASSWORD = os.getenv("IMMUDB_PASSWORD", "immudb")
# D21 (Phase 3a completion): this file's own direct forged-intent write
# below needs the verifier's write-scoped credential now - see
# docs/adr/0011-verifier-authentication.md.
VERIFIER_WRITE_KEY = os.getenv("VERIFIER_WRITE_KEY", "test-verifier-write-key")


requires_stack = pytest.mark.needs_stack("opa", "immudb", "verifier", "control_plane", "decision_service")


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


# ---------------------------------------------------------------------------
# Write-side gate: no live stack needed. query_opa_policy, content_store, and
# the ledger are all monkeypatched so this test exercises exactly one thing -
# decide()'s own control flow around the intent write.
# ---------------------------------------------------------------------------

class _FailingIntentLedger:
    def __init__(self):
        self.log_tool_call_calls = []

    def log_tool_intent(self, **kwargs):
        raise RuntimeError("verifier unreachable (simulated)")

    def log_tool_call(self, **kwargs):
        self.log_tool_call_calls.append(kwargs)
        return 999


def test_failed_intent_write_refuses_execution(monkeypatch):
    """
    D16's own rule, as a test: if the intent write fails, nothing executes.
    _execute_vault_tool must never be called, and the response must be a
    fault with fault_class intent_write_failed - never tool_execution_failed
    (which would mean execution was attempted) and never a result payload.

    Mutation (D16's named mutation): write the intent record but ignore
    whether it raised - call _execute_vault_tool unconditionally regardless
    of intent-write success. This test must fail against that mutation (the
    execute mock would then have been called).
    """
    execute_called = {"n": 0}

    async def _fake_execute(tool_args):
        execute_called["n"] += 1
        return "should never run"

    fake_ledger = _FailingIntentLedger()

    monkeypatch.setattr(
        decision_main, "query_opa_policy",
        lambda tool_name, tool_args: decision_main._outcome(
            decision_main.OUTCOME_POLICY_ALLOW, policy_revision="test-revision",
        ),
    )

    import content_store
    monkeypatch.setattr(content_store, "store_content", lambda call_id, payload: None)

    import immudb_ledger
    monkeypatch.setattr(immudb_ledger, "get_ledger", lambda: fake_ledger)

    monkeypatch.setattr(decision_main, "_execute_vault_tool", _fake_execute)

    r = _decide("read_vault_secret", {"secret_name": "db_master_password"}, "intent_gate_test")

    assert execute_called["n"] == 0, "the vault tool was executed despite the intent write failing"
    assert r["outcome_type"] == "fault", r
    assert r["fault_class"] == "intent_write_failed", r
    assert r["policy_revision"] is None, r
    assert "result" not in r, r
    assert len(fake_ledger.log_tool_call_calls) == 1, "the completion record must still be written, documenting the fault"
    assert fake_ledger.log_tool_call_calls[0]["fault_class"] == "intent_write_failed"


# ---------------------------------------------------------------------------
# Read-side surfacing: requires the docker-compose.test.yml stack.
# ---------------------------------------------------------------------------

@requires_stack
def test_real_mediated_call_surfaces_execution_state_completed():
    """
    The ordinary case: a real read_vault_secret call writes both an intent
    record and a completion record for the same call_id, and /audit must
    render this as execution_state "completed", not "unknown" and not "n/a".
    """
    probe_agent_id = f"execstate_completed_{uuid.uuid4().hex}"
    r = middleware.intercept_tool_call(
        "read_vault_secret", {"secret_name": "db_master_password"}, probe_agent_id,
    )
    assert "ledger_tx_id" in r, f"Expected a recorded, approved call, got: {r}"

    entries = httpx.get(
        f"{CONTROL_PLANE_URL}/audit",
        params={"limit": 200},
        headers={"X-API-Key": READ_API_KEY},
        timeout=90,
    ).json()["entries"]
    matching = [e for e in entries if e["tx_id"] == r["ledger_tx_id"]]
    assert matching, f"tx_id {r['ledger_tx_id']} not found in /audit"
    assert matching[0]["execution_state"] == "completed", matching[0]


@requires_stack
def test_observed_tool_call_surfaces_execution_state_na():
    """The three Python-function tools never enter the intent/completion
    protocol at all - their records must render execution_state "n/a"."""
    probe_agent_id = f"execstate_na_{uuid.uuid4().hex}"
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
        timeout=90,
    ).json()["entries"]
    matching = [e for e in entries if e["tx_id"] == r["ledger_tx_id"]]
    assert matching, f"tx_id {r['ledger_tx_id']} not found in /audit"
    assert matching[0]["execution_state"] == "n/a", matching[0]


@requires_stack
def test_orphaned_intent_with_no_completion_surfaces_as_unknown():
    """
    D16's exit criterion, reproduced live: forge a tool_call_intent: record
    directly against the verifier (the same live-forgery style
    test_record_profile.py::test_audit_forged_profile_less_record_renders_as_unknown_not_observed
    already uses for a different field) with no matching tool_call:
    completion record for the same call_id. /audit must surface it with
    execution_state "unknown" - not silently absent, and not rendered
    identically to a completed call.

    Mutation: change get_audit's orphan-detection loop to skip appending
    unmatched intents entirely (silently drop them). This test must fail
    against that mutation - the forged call_id would never appear in
    /audit at all.
    """
    agent_id = f"orphan_intent_probe_{uuid.uuid4().hex}"
    call_id = f"orphan-intent-{uuid.uuid4().hex}"
    key = f"tool_call_intent:{agent_id}:{uuid.uuid4().hex}:read_vault_secret"
    entry = {
        "record_type": "decision_intent",
        "agent_id": agent_id,
        "timestamp": "2026-08-21T00:00:00",
        "tool_name": "read_vault_secret",
        "call_id": call_id,
        "input_sha256": "deadbeef",
        "policy_revision": "test-revision",
        "content_state": "present",
        "profile": "mediated",
    }
    write_resp = httpx.post(
        f"{VERIFIER_URL}/write",
        json={"key": b64(key), "value": b64(json.dumps(entry))},
        headers={"X-API-Key": VERIFIER_WRITE_KEY},
        timeout=15,
    )
    write_resp.raise_for_status()
    assert write_resp.json().get("verified"), write_resp.json()

    entries = httpx.get(
        f"{CONTROL_PLANE_URL}/audit",
        params={"limit": 500},
        headers={"X-API-Key": READ_API_KEY},
        timeout=90,
    ).json()["entries"]
    matching = [e for e in entries if e["call_id"] == call_id]
    assert matching, f"orphaned intent for call_id={call_id} not found in /audit at all"
    assert matching[0]["execution_state"] == "unknown", matching[0]
    assert matching[0]["outcome_type"] == "policy_allow", matching[0]
    assert matching[0]["tool_name"] == "read_vault_secret", matching[0]
