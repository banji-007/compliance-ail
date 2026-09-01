"""tests/test_reconciliation.py - Phase 3c-3c (P3c3c-3, P3c3c-4, P3c3c-7).

Reconciliation finds what it claims to find, and it runs.

The attacks these carry forward are red-team C6 and C10
(docs/reports/phase-3c3b-redteam.md), all reproduced on unmodified b9f6a1d
before anything here was written:

    wrote a DECISION record into the INTENT view
      -> {"state":"clean","allocated":6,"indexed":6,"missing_count":0}
      in the decision view: False   on any /audit page: False

    zadded 3 positions the counter never handed out
      -> {"state":"clean","allocated":6,"indexed":9,"missing_count":0}

    zadd score 0 into a view
      -> reconcile_once RAISED KeyError: 'score'

Two things made those possible. `collect_positions` unioned scores across
every view, so a record in the wrong view balanced the arithmetic while
being on no page; and `missing` was computed in one direction only, so
positions nobody allocated were never looked at. `min_score =
float(rows[-1]["score"])` sat two lines after a correct `.get("score",
0.0)`, and run_forever's handler turned the KeyError into one log line per
interval forever.

P3c3c-4: these run against the reconciler as a *service*. Until this phase
anchor-service was absent from docker-compose.test.yml entirely, so its copy
of every constant and the whole reconciliation path were exercised by no
test. It runs here in AIL_ANCHOR_MODE=reconcile-only, which never anchors,
so P3b-5's property - the suite running with anchoring entirely broken -
survives, and is asserted below rather than assumed.
"""

import base64
import importlib.util
import json
import os
import sys
import time
import uuid
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tests"))

CONTROL_PLANE_URL  = os.getenv("CONTROL_PLANE_URL",       "http://localhost:8002")
READ_API_KEY       = os.getenv("CONTROL_PLANE_READ_KEY",  "test-read-key")
VERIFIER_URL       = os.getenv("VERIFIER_URL",            "http://localhost:8003")
VERIFIER_WRITE_KEY = os.getenv("VERIFIER_WRITE_KEY",      "test-verifier-write-key")
IMMUDB_URL         = os.getenv("IMMUDB_URL",              "http://localhost:8080")
IMMUDB_USER        = os.getenv("IMMUDB_USER",             "immudb")
IMMUDB_PASSWORD    = os.getenv("IMMUDB_PASSWORD",         "immudb")

SEQUENCE_KEY  = "ail_seq:commit"
VIEW_DECISION = "ail_view:decision:v1"
VIEW_INTENT   = "ail_view:intent:v1"

# Where the running reconcile-only service writes each pass's verdict.
# Bind-mounted by docker-compose.test.yml.
REPORT_PATH = REPO_ROOT / "tests" / ".reconcile" / "last.json"
RECONCILE_INTERVAL = float(os.getenv("AIL_RECONCILE_INTERVAL_SECONDS", "5"))

requires_stack = pytest.mark.needs_stack("immudb", "verifier", "control_plane")

_CLIENT = httpx.Client(timeout=60.0)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _b64(value) -> str:
    return base64.b64encode(value if isinstance(value, bytes) else value.encode()).decode()


def _immudb_headers() -> dict:
    resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/login", json={
        "user": _b64(IMMUDB_USER), "password": _b64(IMMUDB_PASSWORD),
        "database": _b64("defaultdb"),
    })
    resp.raise_for_status()
    return {"Authorization": f"Bearer {resp.json()['token']}"}


def _decision_value(call_id: str, agent_id: str) -> str:
    return json.dumps({
        "record_type": "decision", "call_id": call_id, "agent_id": agent_id,
        "timestamp": "2026-08-31T00:00:00", "tool_name": "query_database",
        "outcome_type": "policy_allow", "fault_class": None,
        "policy_revision": "p3c3c-test", "reasons": [],
        "input_sha256": uuid.uuid4().hex, "content_state": "unavailable",
        "profile": "observed",
    }, separators=(",", ":"))


def _write_ordered(key: str, value: str, view: str = "decision") -> dict:
    resp = _CLIENT.post(f"{VERIFIER_URL}/write-ordered",
                        json={"key": _b64(key), "value": _b64(value), "view": view},
                        headers={"X-API-Key": VERIFIER_WRITE_KEY})
    resp.raise_for_status()
    body = resp.json()
    assert body.get("verified"), f"ordered write not verified: {body}"
    return body


def _write_historical(key: str, value: str) -> None:
    """A record straight into the ledger, with no position and no index
    entry - what an older build's write looks like to this phase."""
    resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/set",
                        json={"KVs": [{"key": _b64(key), "value": _b64(value)}]},
                        headers=_immudb_headers())
    resp.raise_for_status()


def _zadd(view_set: str, score: float, key: str) -> None:
    resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/zadd",
                        json={"set": _b64(view_set), "score": score, "key": _b64(key)},
                        headers=_immudb_headers())
    resp.raise_for_status()


def _positions_for_key(key: str) -> list[float]:
    """Every position the decision view holds for one key, paged past the
    2500-row ceiling.

    Paged for the reason tests/test_backfill_index.py pages: another module in
    this suite deliberately takes the decision view past 2600 rows, so a
    single zscan answers a plausible 2500 and says nothing about the rest.
    """
    headers = _immudb_headers()
    found: list[float] = []
    min_score = None
    while True:
        body = {"set": _b64(VIEW_DECISION), "desc": False, "limit": 2500}
        if min_score is not None:
            body["minScore"] = {"score": min_score}
        resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/zscan", json=body, headers=headers)
        resp.raise_for_status()
        rows = resp.json().get("entries", [])
        if not rows:
            return sorted(found)
        for row in rows:
            if base64.b64decode(row["entry"]["key"]).decode("utf-8", "replace") == key:
                found.append(float(row.get("score", 0.0)))
        next_score = float(rows[-1].get("score", 0.0))
        if len(rows) < 2500 or next_score == min_score:
            return sorted(found)
        min_score = next_score


def _counter() -> int:
    resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/getall",
                        json={"keys": [_b64(SEQUENCE_KEY)]}, headers=_immudb_headers())
    resp.raise_for_status()
    entries = resp.json().get("entries", [])
    assert entries, "the counter has never been written; no allocation has happened"
    return int(base64.b64decode(entries[0]["value"]).decode())


def _next_service_verdict(timeout_seconds: float = 90.0) -> dict:
    """The next verdict the *running* reconciler produces, not this
    process's own call of reconcile_once.

    Freshness is the whole point. A stale file would let this suite pass
    with the service removed, which is exactly what P3c3c-4's mutation must
    fail on, so the wait is for a report strictly newer than the one on disk
    when the wait began.
    """
    assert REPORT_PATH.parent.is_dir(), (
        f"{REPORT_PATH.parent} does not exist; docker-compose.test.yml binds it "
        "into the reconcile-only anchor-service"
    )
    started = REPORT_PATH.stat().st_mtime if REPORT_PATH.exists() else 0.0
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if REPORT_PATH.exists() and REPORT_PATH.stat().st_mtime > started:
            try:
                return json.loads(REPORT_PATH.read_text(encoding="utf-8"))
            except Exception:
                pass          # a half-written file; the writer renames atomically
        time.sleep(1)
    raise AssertionError(
        f"no reconciliation verdict newer than {started} appeared at {REPORT_PATH} "
        f"within {timeout_seconds}s. The reconcile-only anchor-service is not "
        "running, or it is not writing AIL_RECONCILE_REPORT_PATH."
    )


def _load_reconciler():
    """The same module the service runs, loaded in-process.

    Used only where a test needs a verdict for a condition it just created
    without waiting a whole interval for it. Every finding below is also
    asserted against the running service's own report.
    """
    spec = importlib.util.spec_from_file_location(
        "anchor_service_reconcile_p3c3c", REPO_ROOT / "anchor_service" / "main.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["anchor_service_reconcile_p3c3c"] = module
    spec.loader.exec_module(module)
    module.IMMUDB_URL = IMMUDB_URL
    module.IMMUDB_USER = IMMUDB_USER
    module.IMMUDB_PASSWORD = IMMUDB_PASSWORD
    module.RECONCILE_REPORT_PATH = ""      # never overwrite the service's report
    return module


# ---------------------------------------------------------------------------
# P3c3c-4: the reconciler runs, and anchoring is still absent
# ---------------------------------------------------------------------------

@requires_stack
def test_the_reconciler_runs_as_a_service_in_the_test_stack():
    """
    Not "the module can be imported and called" - that was true before this
    phase and the service was still absent from every stack the suite ran
    against, so its own copy of the reserve, the view names and the paging
    loop were never exercised.

    This waits for a verdict the running process produced. With the service
    removed there is no fresh verdict and this fails loudly, which is the
    mutation P3c3c-4 names.
    """
    verdict = _next_service_verdict()
    assert verdict["state"] in ("clean", "findings", "no_sequence", "reserve_mismatch"), verdict
    for field in ("allocated", "indexed", "missing_count", "unallocated_count",
                  "foreign_count", "shared_count", "malformed_count"):
        assert field in verdict, f"the running reconciler reports no {field}: {verdict}"


@requires_stack
def test_anchoring_is_still_entirely_absent_from_this_stack():
    """
    P3b-5, still standing.

    The suite's demonstration is that the whole system runs correctly with
    anchoring entirely broken. Adding the reconciler to this stack must not
    quietly add the anchoring loop with it, so this asserts the property
    from the outside: a bundle exported here says not_anchored, and a write
    still succeeds.
    """
    key = f"tool_call:p3c3c-p3b5-{uuid.uuid4().hex[:8]}:{uuid.uuid4().hex}:query_database"
    written = _write_ordered(key, _decision_value(uuid.uuid4().hex, "p3c3c-p3b5"))
    assert written["verified"] is True, written

    latest = _CLIENT.get(f"{CONTROL_PLANE_URL}/anchors/latest",
                         headers={"X-API-Key": READ_API_KEY})
    assert latest.status_code == 200, latest.text[:300]
    assert latest.json()["anchored"] is False, (
        "an anchor was recorded in this stack; the reconcile-only service is "
        f"anchoring, which destroys P3b-5's demonstration: {latest.text[:300]}"
    )

    bundle = _CLIENT.get(f"{CONTROL_PLANE_URL}/audit/bundle",
                         params={"key": _b64(key)},
                         headers={"X-API-Key": READ_API_KEY})
    assert bundle.status_code == 200, bundle.text[:300]
    assert bundle.json()["external_anchor"]["state"] == "not_anchored", (
        "a bundle exported from the test stack claims external corroboration"
    )


# ---------------------------------------------------------------------------
# P3c3c-3: the three findings C6 walked past
# ---------------------------------------------------------------------------

@requires_stack
def test_a_record_indexed_into_the_wrong_view_is_a_finding():
    """
    C6's first way. A decision record allocated a position and indexed into
    the intent view is absent from every /audit page - the decision page
    selects the decision view - and the old union-across-views arithmetic
    reported clean, because the position was present *somewhere*.
    """
    call_id = uuid.uuid4().hex
    key = f"tool_call:p3c3c-wrongview-{uuid.uuid4().hex[:8]}:{uuid.uuid4().hex}:query_database"
    written = _write_ordered(key, _decision_value(call_id, "p3c3c-wrongview"),
                             view="intent")

    reconciler = _load_reconciler()
    result = reconciler.reconcile_once()
    assert result["state"] == "findings", (
        f"a decision record indexed into the intent view reported clean: {result}"
    )
    offenders = [f for f in result["foreign"] if f["key"] == key]
    assert offenders, (
        f"the record is not named among the wrong-view findings: {result['foreign'][:5]}"
    )
    assert offenders[0]["position"] == float(written["seq"]), offenders
    assert offenders[0]["expected_prefix"] == "tool_call_intent:", offenders

    # And the thing the finding is about: it is on no page.
    page = _CLIENT.get(f"{CONTROL_PLANE_URL}/audit", params={"limit": 2500},
                       headers={"X-API-Key": READ_API_KEY})
    assert page.status_code == 200, page.text[:300]
    assert not [e for e in page.json()["entries"] if e["call_id"] == call_id], (
        "the record is on a page after all, so this test is not exercising the "
        "condition it describes"
    )

    # The running service says the same thing.
    verdict = _next_service_verdict()
    assert verdict["foreign_count"] >= 1, verdict


@requires_stack
def test_positions_the_counter_never_handed_out_are_a_finding():
    """
    C6's second way. `missing` was computed in one direction only, so 2510
    positions nobody allocated sat in a view and the verdict was clean. That
    matters because the ordering fault's own remediation tells an operator to
    run this reconciliation to find what else is affected.
    """
    # Half a position above the head, not thousands above it. Both are
    # positions the counter never handed out, and this one does not also
    # break every later page in the session: a position far above the head
    # stays at the top of the index while newer commits take lower positions
    # with higher transaction ids, which is a genuine D33 inversion and
    # would fault `/audit` for every test that runs after this one. What is
    # being tested here is the coverage check, not the order check.
    surplus = _counter() + 0.5
    key = f"tool_call:p3c3c-surplus-{uuid.uuid4().hex[:8]}:{uuid.uuid4().hex}:query_database"
    _write_historical(key, _decision_value(uuid.uuid4().hex, "p3c3c-surplus"))
    _zadd(VIEW_DECISION, surplus, key)

    reconciler = _load_reconciler()
    result = reconciler.reconcile_once()
    assert result["state"] == "findings", (
        f"a position the counter never handed out reported clean: {result}"
    )
    assert surplus in result["unallocated"], (
        f"position {surplus} is in a view and was never allocated, and is not "
        f"reported: {result['unallocated'][:10]}"
    )

    verdict = _next_service_verdict()
    assert verdict["unallocated_count"] >= 1, verdict


@requires_stack
def test_a_row_with_no_score_is_reported_and_does_not_stop_the_pass():
    """
    C6's third way, and the most serious of the three, because it turned the
    detector off rather than making it wrong.

    protobuf's JSON mapping omits a zero-valued field, so a row scored at
    exactly zero arrives with no `score` key. `min_score =
    float(rows[-1]["score"])` raised KeyError out of the entire pass, which
    run_forever swallowed into one log line per interval - permanently dark.

    The assertion is both halves: the row is reported, and the pass still
    produces a verdict for everything else.
    """
    key = f"tool_call:p3c3c-zero-{uuid.uuid4().hex[:8]}:{uuid.uuid4().hex}:query_database"
    _write_historical(key, _decision_value(uuid.uuid4().hex, "p3c3c-zero"))
    _zadd(VIEW_INTENT, 0, key)

    reconciler = _load_reconciler()
    result = reconciler.reconcile_once()          # must not raise
    assert result["malformed_count"] >= 1, (
        f"a zero-scored row was not reported: {result}"
    )
    assert any(m["reason"] == "score_absent_or_zero" for m in result["malformed"]), (
        result["malformed"][:5]
    )
    assert result["allocated"] >= 1, (
        f"the pass produced no arithmetic at all, so one bad row still stopped "
        f"it: {result}"
    )

    verdict = _next_service_verdict()
    assert verdict["malformed_count"] >= 1, (
        f"the running reconciler did not survive the bad row: {verdict}"
    )


# ---------------------------------------------------------------------------
# P3c3c-7: the durable finding is reconciliation's, not the page's
# ---------------------------------------------------------------------------

@requires_stack
def test_reconciliation_reports_a_disagreement_no_page_can_reach():
    """
    C5 and C10's point, from the other side.

    The page comparison's window is the top of the index at the requested
    limit, so a disagreement below it is unreachable at any limit and newer
    traffic clears the fault while the corruption stays. This is the same
    class of corruption placed where no page can ever reach it - a decision
    record in the intent view is not on the decision page at any limit, and
    never will be - and reconciliation still reports it.

    That is why the fault response points at this check and no longer claims
    a persistence it cannot observe.
    """
    call_id = uuid.uuid4().hex
    key = f"tool_call:p3c3c-unreachable-{uuid.uuid4().hex[:8]}:{uuid.uuid4().hex}:query_database"
    _write_ordered(key, _decision_value(call_id, "p3c3c-unreachable"), view="intent")

    for limit in (1, 200, 2500):
        page = _CLIENT.get(f"{CONTROL_PLANE_URL}/audit", params={"limit": limit},
                           headers={"X-API-Key": READ_API_KEY})
        assert page.status_code == 200, (
            f"limit={limit} did not serve a page: {page.status_code} {page.text[:200]}"
        )
        assert not [e for e in page.json()["entries"] if e["call_id"] == call_id], (
            f"limit={limit} reached the record, so no page-scoped check is "
            "being bypassed here"
        )

    result = _load_reconciler().reconcile_once()
    assert result["state"] == "findings", result
    assert [f for f in result["foreign"] if f["key"] == key], (
        "no page can reach this record and reconciliation does not report it "
        f"either, so nothing does: {result['foreign'][:5]}"
    )


# ---------------------------------------------------------------------------
# P3c3d-9 (Phase 3c-3d): a key at more than one position.
# ---------------------------------------------------------------------------

@requires_stack
def test_a_second_position_below_the_reserve_for_an_indexed_record_is_a_finding():
    """
    A5's fourth condition, which reconciled clean.

    Every score below the reserve was assumed to be history and was never
    checked against anything. Reproduced on a virgin ledger: three normal
    writes plus one injection giving an already-indexed record a second
    position at score 42.

        {"state": "clean", "allocated": 3, "indexed": 3, "backfilled": 1,
         "missing": [], "unallocated": [], "foreign": [], "shared": [],
         "malformed": [], "views": {"ail_view:decision:v1": 4, ...}}

        HTTP 200  rows 4  total 3
        call_ids appearing more than once on ONE page: ['a5c1-e0bc06']

    `clean`, every finding category empty, while the page showed the row
    twice. That is C2's duplication defect wearing history's clothes, and the
    ordering fault's own remediation points an operator at this check.

    A key at two positions is always wrong, in either range: history is
    scored at each record's own transaction, one position per record; the CAS
    allocates one position per commit; and since D39 a record key is written
    once. Two records SHARING a score is a different thing and is what
    `shared` reports.
    """
    call_id = uuid.uuid4().hex
    key = f"tool_call:p3c3d-dup-{uuid.uuid4().hex[:8]}:{uuid.uuid4().hex}:query_database"
    written = _write_ordered(key, _decision_value(call_id, "p3c3d-dup"))

    # Below the reserve, which is the range that was assumed to be history.
    _zadd(VIEW_DECISION, 42.0, key)

    result = _load_reconciler().reconcile_once()
    assert result["state"] == "findings", (
        f"a record holding two positions reconciled clean: {result}"
    )
    offenders = [f for f in result["duplicated"] if f["key"] == key]
    assert offenders, (
        "the record holding two positions is not named among the findings: "
        f"{result['duplicated'][:5]}"
    )
    assert sorted(offenders[0]["positions"]) == sorted([42.0, float(written["seq"])]), (
        f"the finding does not name both positions: {offenders[0]}"
    )

    # And the condition the finding is about, read from the index itself
    # rather than from a page.
    #
    # **Why not from the page.** The reproduction measured it there - HTTP 200,
    # rows 4, total 3, one call_id twice on a virgin ledger - and that is what
    # makes this a duplication defect rather than an accounting one. But the
    # page is bounded by `limit`, and `tests/test_backfill_index.py` takes the
    # decision view past 2600 rows on purpose, so in a full-suite run the
    # second position sits below the page's own bound and the row appears
    # once. A first draft asserted `== 2` here and failed in CI for exactly
    # that reason (run `33475430028`), which is `has_more` working, not a row
    # being dropped: measured directly, a duplicated key still renders twice
    # on any page that reaches it, at 2, 122 and 402 members.
    #
    # So the guard reads the index, which is where the condition lives and
    # what the reconciler walks. It is a stronger statement than the page one,
    # not a weaker one: it holds at every ledger size.
    indexed = _positions_for_key(key)
    assert indexed == sorted([42.0, float(written["seq"])]), (
        "this test is not exercising the condition it describes: the decision "
        f"view holds {indexed} for this key, not two positions"
    )

    # The running service says the same thing.
    verdict = _next_service_verdict()
    assert verdict["duplicated_count"] >= 1, verdict
