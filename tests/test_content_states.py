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

roadmap-commit, item 6: every `docker compose` invocation below passes
`-p COMPOSE_PROJECT` explicitly (see _compose_project_name()). Without it,
Compose falls back to the lowercased basename of the directory the command
runs from, and that guess silently diverges from the project name the
already-running stack actually has whenever the two are invoked from
directories with different basenames (e.g. a worktree) or the stack was
started under an explicit COMPOSE_PROJECT_NAME. `stop`/`start verifier`
then either no-op against a project with no such container, or - worse -
address a same-named container in an unrelated project, which is what
produced two false failures in p13-merge.
"""

import asyncio
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "interceptor"))
# content_store.py lives in ledger/, copied into decision_service's own
# image in Phase 2 (D12) - it is no longer reachable via a middleware.py
# side effect (the agent no longer imports it at all), but it still exists
# at this repo-relative path on the host, which is what pytest runs against.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "ledger"))

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
os.environ.setdefault("DECISION_SERVICE_URL", "http://localhost:8010/decide")
os.environ.setdefault("OPA_URL", "http://localhost:8181/v1/data/ail/main/evaluation")

import middleware  # noqa: E402
import content_store  # noqa: E402
decision_main = _load_decision_service_main()  # for the one test that must inject a fault in-process


def _decide(tool_name, tool_args, agent_id="content_state_test") -> dict:
    """See tests/test_outcome_types.py's identical helper - calling
    decision_service/main.py's decide() in-process is required for tests
    that need to monkeypatch something inside it (here, content_store);
    monkeypatching the host process's import has no effect on a real
    decision-service container reached over HTTP, which is what
    middleware.intercept_tool_call now is."""
    req = decision_main.DecideRequest(tool_name=tool_name, tool_args=tool_args, agent_id=agent_id)
    return asyncio.run(decision_main.decide(req))

CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL", "http://localhost:8002")
READ_API_KEY = os.getenv("CONTROL_PLANE_READ_KEY", "test-read-key")
WRITE_API_KEY = os.getenv("CONTROL_PLANE_WRITE_KEY", "test-write-key")
VERIFIER_URL = os.getenv("VERIFIER_URL", "http://localhost:8003")
VERIFIER_HEALTH_URL = VERIFIER_URL + "/health"
REPO_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = "docker-compose.test.yml"


def _default_compose_project_name() -> str:
    """Compose's own default when COMPOSE_PROJECT_NAME is not set: the
    lowercased basename of the project directory (here, REPO_ROOT, since
    that is the cwd every docker compose invocation in this project -
    Makefile included - runs from), with anything outside [a-z0-9_-]
    stripped and leading separators removed. This is exactly what an
    unmodified `docker compose -f docker-compose.test.yml ...` run from
    REPO_ROOT resolves to on its own, so it matches a stack started the
    ordinary way (e.g. `make test-integration`)."""
    name = re.sub(r"[^a-z0-9_-]", "", REPO_ROOT.name.lower())
    return name.lstrip("_-") or "default"


def _compose_project_name() -> str:
    """The Compose project name of the already-running stack this test file
    talks to. Prefers COMPOSE_PROJECT_NAME (set explicitly, or by a root
    .env - which `docker compose` itself auto-loads regardless of -f, per
    the Makefile's own comment) over Compose's directory-basename default,
    so a stack started under a non-default project name (a differently
    named worktree, an explicit override) is targeted correctly instead of
    silently talking to a project this test process guesses the name of."""
    env_name = os.getenv("COMPOSE_PROJECT_NAME")
    if env_name:
        return env_name
    dotenv_path = REPO_ROOT / ".env"
    if dotenv_path.exists():
        for line in dotenv_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line.startswith("COMPOSE_PROJECT_NAME="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return _default_compose_project_name()


COMPOSE_PROJECT = _compose_project_name()

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

# P13-5 (Phase 1.3, red-team U7): test_direct_sqlite_delete_produces_lost_not_erased
# and test_erasure_refused_when_tombstone_write_fails both shell out to the
# docker CLI directly (subprocess.run(["docker", "compose", ...])).
# requires_stack only checks HTTP reachability, which stays true even with
# the CLI binary itself absent from PATH (the containers were still up) -
# with docker removed, both tests raised a raw FileNotFoundError deep inside
# subprocess.Popen, reported by pytest as a plain failure, indistinguishable
# from a real regression in the erasure/tombstone logic they exist to guard.
# Project convention (P01-1, docs/reports/phase-0-1.md): an
# environment-dependent test gets a clean skipif, not a crash.
#
# R6 (Phase 1.3 completion pass, red-team V7 sub-attack 3): shutil.which
# alone is not enough - a file named "docker" on PATH that is not a valid
# Windows executable still satisfies shutil.which, and subprocess.run then
# raises an uncaught OSError (WinError 216) instead of returning a nonzero
# CompletedProcess. pytest reports that as ERROR, not a clean skip or a
# clean assertion failure. Actually invoking the CLI here, not just
# resolving it, turns that same OSError into a skip instead of a crash.
def _docker_cli_usable() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(["docker", "version"], capture_output=True, timeout=10)
        return True
    except OSError:
        return False


requires_docker_cli = pytest.mark.skipif(
    not _docker_cli_usable(),
    reason="docker CLI not on PATH or not runnable",
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
    """
    D12 (Phase 2): the content-store write now happens inside
    decision-service, reached over HTTP from the agent - monkeypatching
    content_store in this test process would no longer reach it if this
    went through middleware.intercept_tool_call as a real client call. Uses
    the in-process _decide() helper instead, same pattern
    tests/test_outcome_types.py established.
    """
    def _broken_store(call_id, payload):
        raise RuntimeError("content store down (simulated)")

    monkeypatch.setattr(content_store, "store_content", _broken_store)

    probe_agent_id = f"content_fault_probe_{uuid.uuid4().hex}"
    r = _decide("provision_cloud_server", _APPROVED_ARGS, probe_agent_id)

    assert r["status"] == "DENIED", f"Expected DENIED, got: {r}"
    assert r["outcome_type"] == "fault", f"Expected fault, got: {r}"
    assert r["fault_class"] == "content_store_unreachable", f"Expected content_store_unreachable, got: {r}"
    assert r["policy_revision"] is None
    assert "ledger_tx_id" not in r, f"Expected no ledger record when content write fails, got: {r}"

    # There is no ledger entry to contradict (D7) - confirm this probe's
    # marker agent_id never made it into /audit at all.
    matching = [e for e in _audit_entries() if e.get("agent_id") == probe_agent_id]
    assert not matching, f"Expected no /audit entry for a content-store fault, found: {matching}"


# ---------------------------------------------------------------------------
# D11 (Phase 1.2, P12-3): erasure is a recorded event, distinguishable from
# loss. Four payload states: present | unavailable | erased | lost.
# ---------------------------------------------------------------------------

def _metric_total() -> float:
    """Sum of every ail_policy_decisions_total series, scraped from
    decision-service's Prometheus endpoint (moved here from the agent
    process in Phase 2, D12 - the decision, and the metric that counts it,
    are both made here now). Published loopback-bound in
    docker-compose.test.yml for this test to reach from the host."""
    resp = httpx.get("http://localhost:8000/metrics", timeout=5)
    resp.raise_for_status()
    total = 0.0
    for line in resp.text.splitlines():
        if line.startswith("ail_policy_decisions_total{"):
            total += float(line.rsplit(" ", 1)[1])
    return total


@requires_stack
@requires_docker_cli
def test_direct_sqlite_delete_produces_lost_not_erased():
    """
    Attack to reproduce (docs/reports/phase-1-1-redteam.md, T5, verbatim):
    bypass DELETE /content entirely with a raw SQL delete inside the
    control plane's own container - no auth, no erasure semantics, no
    tombstone. Before D11 this rendered byte-for-byte identical to a
    legitimate erasure. payload_state must now read "lost", not "erased".
    """
    marker = f"LOST-MARKER-PHASE1-2-{uuid.uuid4().hex}"
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
    call_id = entry["call_id"]
    assert call_id, f"Expected a call_id on the entry, got: {entry}"

    delete_script = (
        "import sqlite3; "
        "c = sqlite3.connect('/data/control_plane.db'); "
        f"c.execute('DELETE FROM call_content WHERE call_id = ?', ('{call_id}',)); "
        "c.commit()"
    )
    result = subprocess.run(
        ["docker", "compose", "-p", COMPOSE_PROJECT, "-f", COMPOSE_FILE, "exec", "-T",
         "ail-control-plane", "python", "-c", delete_script],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, f"docker compose exec failed: {result.stdout}\n{result.stderr}"

    entry_after = _audit_entry_for_tx(tx_id)
    assert entry_after["payload_state"] == "lost", entry_after
    assert entry_after["payload"] is None
    assert entry_after["payload_state"] != "erased", (
        "A direct SQL delete bypassing the erasure endpoint must never render "
        "the same as a legitimate GDPR Article 17 erasure"
    )


@requires_stack
@requires_docker_cli
def test_erasure_refused_when_tombstone_write_fails():
    """
    D11: if the tombstone write fails, the erasure is refused and the row
    survives - same ordering discipline as D7 (content write before ledger
    write). Forced live by stopping the verifier the tombstone write
    depends on, then confirming DELETE /content/{call_id} refuses (503) and
    the row is still present afterward.
    """
    marker = f"REFUSED-ERASURE-MARKER-{uuid.uuid4().hex}"
    args = {
        "target_table": "pii_records",
        "query": f"SELECT * FROM pii_records WHERE marker='{marker}'",
        "processing_purpose": "customer_support",
        "masking_enabled": True,
    }
    r = middleware.intercept_tool_call("query_database", args, "content_state_test")
    assert "ledger_tx_id" in r, f"Expected a recorded call, got: {r}"
    entry = _audit_entry_for_tx(r["ledger_tx_id"])
    assert entry["payload_state"] == "present", entry
    call_id = entry["call_id"]

    stop = subprocess.run(
        ["docker", "compose", "-p", COMPOSE_PROJECT, "-f", COMPOSE_FILE, "stop", "verifier"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=30,
    )
    assert stop.returncode == 0, f"Failed to stop verifier: {stop.stdout}\n{stop.stderr}"
    try:
        del_resp = httpx.delete(
            f"{CONTROL_PLANE_URL}/content/{call_id}",
            headers={"X-API-Key": WRITE_API_KEY},
            timeout=15,
        )
        assert del_resp.status_code == 503, del_resp.text
    finally:
        start = subprocess.run(
            ["docker", "compose", "-p", COMPOSE_PROJECT, "-f", COMPOSE_FILE, "start", "verifier"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=30,
        )
        assert start.returncode == 0, f"Failed to restart verifier: {start.stdout}\n{start.stderr}"
        deadline = time.monotonic() + 30
        healthy = False
        while time.monotonic() < deadline:
            try:
                if httpx.get(VERIFIER_HEALTH_URL, timeout=2).status_code == 200:
                    healthy = True
                    break
            except Exception:
                pass
            time.sleep(1)
        assert healthy, "Verifier did not come back healthy after restart"

    entry_after = _audit_entry_for_tx(r["ledger_tx_id"])
    assert entry_after["payload_state"] == "present", (
        f"Erasure must be refused, not applied, when the tombstone write fails: {entry_after}"
    )
    assert entry_after["payload"] is not None


@requires_stack
def test_erasure_tombstone_not_a_second_decision_entry():
    """
    D11: a tombstone must not appear in /audit as a decision, and must not
    be counted in any decision metric. Confirmed two ways: the total
    /audit entry count is unchanged by an erasure (the tombstone never
    surfaces as a second entry), and ail_policy_decisions_total's total
    across all series is unchanged (the erasure never touches the
    interceptor's own metric - it runs entirely inside the control plane).
    """
    marker = f"TOMBSTONE-EXCLUSION-MARKER-{uuid.uuid4().hex}"
    args = {
        "target_table": "pii_records",
        "query": f"SELECT * FROM pii_records WHERE marker='{marker}'",
        "processing_purpose": "customer_support",
        "masking_enabled": True,
    }
    r = middleware.intercept_tool_call("query_database", args, "content_state_test")
    assert "ledger_tx_id" in r, f"Expected a recorded call, got: {r}"
    entry = _audit_entry_for_tx(r["ledger_tx_id"])
    call_id = entry["call_id"]

    before_entries = _audit_entries()
    before_total = len(before_entries)
    before_metric_total = _metric_total()

    del_resp = httpx.delete(
        f"{CONTROL_PLANE_URL}/content/{call_id}",
        headers={"X-API-Key": WRITE_API_KEY},
        timeout=10,
    )
    assert del_resp.status_code == 204, del_resp.text

    after_entries = _audit_entries()
    assert len(after_entries) == before_total, (
        f"Erasure must not add a new /audit entry (the tombstone must not appear "
        f"as a decision): before={before_total} after={len(after_entries)}"
    )
    matching = [e for e in after_entries if e["call_id"] == call_id]
    assert len(matching) == 1, f"Expected exactly one entry for call_id={call_id}, got {matching}"
    assert matching[0]["payload_state"] == "erased"

    after_metric_total = _metric_total()
    assert after_metric_total == before_metric_total, (
        f"Erasure must not be counted in any decision metric: "
        f"before={before_metric_total} after={after_metric_total}"
    )


# ---------------------------------------------------------------------------
# P13-4 (Phase 1.3, red-team U4): a tombstone must never be silently
# discarded, and an erasure must never be undoable through the ordinary
# write key.
# ---------------------------------------------------------------------------

def _write_tombstone_directly(call_id: str) -> None:
    """
    Forge a content_erasure tombstone via the verifier's own /write, the
    same way red-team U4/U5 did - bypassing DELETE /content/{call_id}, the
    control plane, and any auth entirely. Used here to construct
    combination 1 (a tombstone with the row still present), which the real
    endpoint's own ordering (tombstone, then delete) cannot produce on its
    own.
    """
    tombstone = {
        "record_type": "content_erasure",
        "call_id": call_id,
        "timestamp": datetime.utcnow().isoformat(),
        "actor": "test-forged-tombstone",
    }
    serialized = json.dumps(tombstone, separators=(",", ":"))
    key = f"content_erasure:{call_id}"
    resp = httpx.post(
        f"{VERIFIER_URL}/write",
        json={
            "key": base64.b64encode(key.encode()).decode(),
            "value": base64.b64encode(serialized.encode()).decode(),
        },
        timeout=15,
    )
    resp.raise_for_status()
    assert resp.json().get("verified"), f"Tombstone write not verified: {resp.json()}"


@requires_stack
def test_tombstone_coexisting_with_present_row_renders_erasure_conflict():
    """
    Attack to reproduce (docs/reports/phase-1-2-redteam.md, U4 combination
    1, verbatim): a content_erasure tombstone written for a call_id whose
    content-store row was never deleted used to render as plain "present",
    discarding the tombstone silently. Must now render "erasure_conflict" -
    distinct from both "present" (would hide that an erasure was ever
    recorded) and "erased" (would hide that the row is still there) - with
    payload withheld either way.
    """
    marker = f"CONFLICT-MARKER-PHASE1-3-{uuid.uuid4().hex}"
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
    call_id = entry["call_id"]
    assert call_id, f"Expected a call_id on the entry, got: {entry}"

    _write_tombstone_directly(call_id)

    entry_after = _audit_entry_for_tx(tx_id)
    assert entry_after["payload_state"] == "erasure_conflict", entry_after
    assert entry_after["payload"] is None, (
        "A tombstoned call_id must never return its payload, even if the row "
        "backing it still exists"
    )


@requires_stack
def test_resurrection_after_erasure_refused():
    """
    Attack to reproduce (docs/reports/phase-1-2-redteam.md, U4 combination
    2, verbatim): erase a call through the real endpoint, then POST
    /content again for the same call_id using nothing but the ordinary
    write key - no escalation. Before P13-4 this silently resurrected the
    row with attacker-chosen content and /audit showed no trace an erasure
    had ever happened. The write must now be refused and /audit must
    continue to report "erased".
    """
    marker = f"RESURRECT-MARKER-PHASE1-3-{uuid.uuid4().hex}"
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
    call_id = entry["call_id"]
    assert call_id, f"Expected a call_id on the entry, got: {entry}"

    del_resp = httpx.delete(
        f"{CONTROL_PLANE_URL}/content/{call_id}",
        headers={"X-API-Key": WRITE_API_KEY},
        timeout=10,
    )
    assert del_resp.status_code == 204, del_resp.text
    assert _audit_entry_for_tx(tx_id)["payload_state"] == "erased"

    resurrect_resp = httpx.post(
        f"{CONTROL_PLANE_URL}/content",
        json={"call_id": call_id, "payload": {"resurrected": "content that should be permanently gone"}},
        headers={"X-API-Key": WRITE_API_KEY},
        timeout=10,
    )
    assert resurrect_resp.status_code == 409, (
        f"Expected the ordinary write key to be refused on an erased call_id, "
        f"got {resurrect_resp.status_code}: {resurrect_resp.text}"
    )

    entry_after = _audit_entry_for_tx(tx_id)
    assert entry_after["payload_state"] == "erased", (
        f"An erasure must remain final after a refused resurrection attempt: {entry_after}"
    )
    assert entry_after["payload"] is None
