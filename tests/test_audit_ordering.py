"""
tests/test_audit_ordering.py - Phase 3c-3b (P3c3b-1 through P3c3b-7).

`/audit` used to page the ledger with a key walk under `desc: true`. A
`tool_call:` key leads with `agent_id`, so the page returned the
lexicographically-largest agent ids and called them recent, and a record
written seconds ago was absent once the ledger exceeded `limit` (observed at
211 entries during `p3c2-defer`: the newest transaction was 573 and the
page's first row was not it). ImmuDB's `scan` has no ordering parameter,
`TxScan` is not routed over REST, and no key this project writes is temporal
or monotonic, so no parameter fixes it. The ordering has to come from
somewhere the ledger enforces.

D32's answer: one `ExecAll` commits the record, an advanced counter and a
`zAdd` into a view index, gated by a `KeyNotModifiedAfterTX` precondition on
the counter. A writer that read a stale counter is rejected outright, so any
position that does commit is the unique next one from the state it read. The
score is neither a clock (globally comparable and wrong under skew) nor a
per-writer counter (`p3c3-scoring`: four writers each claiming positions 1
to 15, where signing only proves the writer *said* position 3).

What each group below holds in place:

  One transaction, or none.      Record, counter and index entry share a tx
                                 id, and a rejected precondition leaves all
                                 three absent.
  Positions are gapless.         Under concurrency, every allocated position
                                 is used exactly once and score order equals
                                 commit order.
  The page is ordered.           The newest record is on the first page
                                 whatever its agent id, and page order is
                                 commit order.
  Disagreement is a fault.       A score that does not agree with the
                                 transaction it resolves to raises, and is
                                 never quietly sorted away.
  History is reachable.          A record written before the index existed
                                 appears in the ordered page after backfill.
  A hole is evidence.            A consumed position with no index entry is
                                 detected and reported.
  Orphaned intents still show.   On a ledger larger than the page.

Requires the docker-compose.test.yml stack.
"""

import base64
import json
import os
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx
import pytest

CONTROL_PLANE_URL  = os.getenv("CONTROL_PLANE_URL",       "http://localhost:8002")
READ_API_KEY       = os.getenv("CONTROL_PLANE_READ_KEY",  "test-read-key")
VERIFIER_URL       = os.getenv("VERIFIER_URL",            "http://localhost:8003")
VERIFIER_WRITE_KEY = os.getenv("VERIFIER_WRITE_KEY",      "test-verifier-write-key")
IMMUDB_URL         = os.getenv("IMMUDB_URL",              "http://localhost:8080")
IMMUDB_USER        = os.getenv("IMMUDB_USER",             "immudb")
IMMUDB_PASSWORD    = os.getenv("IMMUDB_PASSWORD",         "immudb")

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))

SEQUENCE_KEY   = "ail_seq:commit"
VIEW_DECISION  = "ail_view:decision:v1"
VIEW_INTENT    = "ail_view:intent:v1"

# The seam. Positions 1..RESERVED belong to backfilled history, scored at each
# record's own transaction id; the CAS allocates from RESERVED + 1 upward.
RESERVED_POSITIONS = int(os.getenv("AIL_RESERVED_POSITIONS", "1000000000"))

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
        "timestamp": "2026-08-30T00:00:00", "tool_name": "query_database",
        "outcome_type": "policy_allow", "fault_class": None,
        "policy_revision": "p3c3b-test", "reasons": [],
        "input_sha256": uuid.uuid4().hex, "content_state": "unavailable",
        "profile": "observed",
    }, separators=(",", ":"))


def _write_ordered(key: str, value: str, view: str = "decision") -> dict:
    """The real ordered write path: ExecAll + verifiedGet, through the
    verifier's own route, with the write-scoped credential D21 requires."""
    resp = _CLIENT.post(
        f"{VERIFIER_URL}/write-ordered",
        json={"key": _b64(key), "value": _b64(value), "view": view},
        headers={"X-API-Key": VERIFIER_WRITE_KEY},
    )
    resp.raise_for_status()
    body = resp.json()
    assert body.get("verified"), f"ordered write not verified: {body}"
    return body


def _write_unordered(key: str, value: str) -> dict:
    """The pre-index write path: POST /write, no counter, no index entry.

    This is how a record written before Phase 3c-3b existed looks, and it is
    what P3c3b-5's backfill has to pick up."""
    resp = _CLIENT.post(
        f"{VERIFIER_URL}/write",
        json={"key": _b64(key), "value": _b64(value)},
        headers={"X-API-Key": VERIFIER_WRITE_KEY},
    )
    resp.raise_for_status()
    body = resp.json()
    assert body.get("verified"), f"write not verified: {body}"
    return body


def _new_decision(agent_id: str | None = None, call_id: str | None = None) -> tuple[str, dict]:
    agent = agent_id or f"p3c3b-{uuid.uuid4().hex[:8]}"
    cid = call_id or uuid.uuid4().hex
    key = f"tool_call:{agent}:{uuid.uuid4().hex}:query_database"
    return key, _write_ordered(key, _decision_value(cid, agent))


def _audit(limit: int = 200) -> dict:
    resp = _CLIENT.get(f"{CONTROL_PLANE_URL}/audit", params={"limit": limit},
                       headers={"X-API-Key": READ_API_KEY})
    resp.raise_for_status()
    return resp.json()


def _getall(headers: dict, keys: list[str]) -> dict:
    resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/getall",
                        json={"keys": [_b64(k) for k in keys]}, headers=headers)
    resp.raise_for_status()
    out = {}
    for entry in resp.json().get("entries", []):
        out[base64.b64decode(entry["key"]).decode()] = entry
    return out


def _zscan(headers: dict, view_set: str, limit: int = 2500, desc: bool = True) -> list[dict]:
    resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/zscan",
                        json={"set": _b64(view_set), "desc": desc, "limit": limit},
                        headers=headers)
    resp.raise_for_status()
    return resp.json().get("entries", [])


def _counter(headers: dict) -> tuple[int, int] | None:
    """(value, tx it was last modified at), or None if never written.

    getall, not get: ImmuDB has no POST /api/v2/db/get."""
    found = _getall(headers, [SEQUENCE_KEY])
    entry = found.get(SEQUENCE_KEY)
    if entry is None:
        return None
    return int(base64.b64decode(entry["value"]).decode()), int(entry["tx"])


# ---------------------------------------------------------------------------
# P3c3b-1: writes allocate a sequence atomically
# ---------------------------------------------------------------------------

@requires_stack
def test_one_execall_commits_record_counter_and_index_at_one_transaction():
    """
    D32's atomicity, checked from the ledger rather than from the response.

    The record, the advanced counter and the index entry must all name the
    same transaction id. This is what makes the pre-registered negative "any
    record committed without its index entry in the same transaction"
    unrepresentable rather than merely unlikely.
    """
    headers = _immudb_headers()
    key, result = _new_decision()
    tx_id, seq = result["tx_id"], result["seq"]

    found = _getall(headers, [key, SEQUENCE_KEY])

    assert key in found, "the record is not in the ledger"
    assert int(found[key]["tx"]) == tx_id, (
        f"the record landed at tx {found[key]['tx']}, the write reported {tx_id}"
    )
    assert int(found[SEQUENCE_KEY]["tx"]) == tx_id, (
        "the counter was not advanced in the same transaction as the record: "
        f"counter at tx {found[SEQUENCE_KEY]['tx']}, record at tx {tx_id}"
    )
    assert int(base64.b64decode(found[SEQUENCE_KEY]["value"]).decode()) == seq

    rows = _zscan(headers, VIEW_DECISION, limit=50)
    mine = [r for r in rows if base64.b64decode(r["key"]).decode() == key]
    assert mine, "the record is absent from the view index"
    assert int(mine[0]["score"]) == seq, (
        f"indexed at score {mine[0]['score']}, allocated {seq}"
    )
    assert int(mine[0]["entry"]["tx"]) == tx_id, (
        "the index entry resolves to a different transaction than the record"
    )


@requires_stack
def test_a_write_against_a_stale_counter_is_rejected():
    """
    The precondition itself, driven directly so the rejection is observed
    rather than inferred from the retry loop swallowing it.

    A writer that read a stale counter must not be able to commit at all -
    that is what makes a committed position "the unique next one from the
    state it read" instead of "whatever this writer decided to claim".
    """
    headers = _immudb_headers()
    observed = _counter(headers)
    assert observed is not None, "no sequence allocated yet; write one first"
    _last_seq, last_tx = observed

    # Move the counter on, so the tx we captured is now stale.
    _new_decision()

    key = f"tool_call:p3c3b-stale-{uuid.uuid4().hex[:8]}:{uuid.uuid4().hex}:query_database"
    resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/execall", json={
        "Operations": [
            {"kv": {"key": _b64(key), "value": _b64(_decision_value(uuid.uuid4().hex, "stale"))}},
            {"kv": {"key": _b64(SEQUENCE_KEY), "value": _b64("999999")}},
            {"zAdd": {"set": _b64(VIEW_DECISION), "score": 999999.0,
                      "key": _b64(key), "boundRef": False}},
        ],
        "preconditions": [
            {"keyNotModifiedAfterTX": {"key": _b64(SEQUENCE_KEY), "txID": str(last_tx)}}
        ],
        "noWait": False,
    }, headers=headers)

    assert resp.status_code != 200, (
        "a write built on a stale counter was accepted, so the position it "
        f"claimed was never contested: {resp.text[:300]}"
    )
    assert "precondition failed" in resp.text.lower(), (
        f"rejected, but not by the precondition: {resp.text[:300]}"
    )


@requires_stack
def test_the_sequence_is_gapless_under_concurrent_writes():
    """
    `p3c3-scoring`'s result, reproduced: every allocated position used
    exactly once, and score order equal to commit order.

    Gaplessness is not decoration. It is what makes P3c3b-6's reconciliation
    arithmetic over the index alone, because a rejected precondition
    consumes no position, so a hole is evidence rather than an unremarkable
    crash.
    """
    headers = _immudb_headers()
    before = _counter(headers)
    start_seq = before[0] if before else 0

    writers, per_writer = 8, 6

    def burst(worker: int) -> list[dict]:
        out = []
        for i in range(per_writer):
            key = f"tool_call:p3c3b-conc-{worker}:{uuid.uuid4().hex}:query_database"
            out.append(_write_ordered(key, _decision_value(uuid.uuid4().hex, f"w{worker}")))
        return out

    with ThreadPoolExecutor(max_workers=writers) as pool:
        results = [r for chunk in pool.map(burst, range(writers)) for r in chunk]

    seqs = sorted(r["seq"] for r in results)
    expected = list(range(start_seq + 1, start_seq + 1 + writers * per_writer))

    assert len(set(seqs)) == len(seqs), (
        f"a position was handed out twice under concurrency: {seqs}"
    )
    assert seqs == expected, (
        "the allocated positions are not gapless. Every rejection must "
        "consume nothing, so the committed positions must be exactly the "
        f"contiguous next block. expected {expected[0]}..{expected[-1]}, got {seqs}"
    )

    by_seq = sorted(results, key=lambda r: r["seq"])
    txs = [r["tx_id"] for r in by_seq]
    assert txs == sorted(txs), (
        "score order does not equal commit order: sorting by allocated "
        f"position gave transaction ids {txs}"
    )


# ---------------------------------------------------------------------------
# P3c3b-2: nothing partial is written
# ---------------------------------------------------------------------------

@requires_stack
def test_a_rejected_write_leaves_no_record_no_counter_advance_and_no_index_entry():
    """
    All three absent, checked individually.

    A rejected precondition refuses the whole ExecAll, so the failure mode is
    "no ledger write" - which the existing fail-closed rule already handles:
    no record, no execution. What must never happen is a record landing
    without its position, which would be invisible to every ordered page.
    """
    headers = _immudb_headers()
    observed = _counter(headers)
    assert observed is not None
    _seq, last_tx = observed
    _new_decision()                       # make last_tx stale
    counter_before = _counter(headers)

    key = f"tool_call:p3c3b-partial-{uuid.uuid4().hex[:8]}:{uuid.uuid4().hex}:query_database"
    marker_score = 987654.0
    resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/execall", json={
        "Operations": [
            {"kv": {"key": _b64(key), "value": _b64(_decision_value(uuid.uuid4().hex, "partial"))}},
            {"kv": {"key": _b64(SEQUENCE_KEY), "value": _b64("888888")}},
            {"zAdd": {"set": _b64(VIEW_DECISION), "score": marker_score,
                      "key": _b64(key), "boundRef": False}},
        ],
        "preconditions": [
            {"keyNotModifiedAfterTX": {"key": _b64(SEQUENCE_KEY), "txID": str(last_tx)}}
        ],
        "noWait": False,
    }, headers=headers)
    assert resp.status_code != 200, "the write was not rejected, so this proves nothing"

    found = _getall(headers, [key])
    assert key not in found, "the record was committed despite the rejection"

    counter_after = _counter(headers)
    assert counter_after == counter_before, (
        f"the counter moved on a rejected write: {counter_before} -> {counter_after}"
    )

    rows = _zscan(headers, VIEW_DECISION, limit=2500)
    assert not any(int(r["score"]) == int(marker_score) for r in rows), (
        "an index entry was written for a record that was never committed"
    )


@requires_stack
def test_a_retried_write_leaves_no_unindexed_record_behind():
    """
    P3c3b-2 through the real write path, where the retry loop lives.

    The test above drives a rejection directly, which establishes what
    ImmuDB does. This one establishes what the *writer* does with it. Under
    concurrency the CAS rejects most attempts and the verifier retries them,
    so if the record were committed outside the ExecAll - written first,
    with only the counter and the index entry inside the precondition - then
    every rejected attempt would leave a record in the ledger that no view
    indexes and no page can reach. Nothing in the response would say so.

    Asserted over the keys this test itself wrote, so a hole left by any
    earlier session cannot make it pass or fail.
    """
    headers = _immudb_headers()
    tag = f"p3c3b-retry-{uuid.uuid4().hex[:8]}"

    def burst(worker: int) -> list[str]:
        keys = []
        for _ in range(4):
            key = f"tool_call:{tag}-{worker}:{uuid.uuid4().hex}:query_database"
            _write_ordered(key, _decision_value(uuid.uuid4().hex, tag))
            keys.append(key)
        return keys

    with ThreadPoolExecutor(max_workers=6) as pool:
        written = {k for chunk in pool.map(burst, range(6)) for k in chunk}

    resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/scan", json={
        "prefix": _b64(f"tool_call:{tag}"), "desc": False, "limit": 2500,
    }, headers=headers)
    resp.raise_for_status()
    in_ledger = {base64.b64decode(e["key"]).decode() for e in resp.json().get("entries", [])}

    indexed = {base64.b64decode(r["key"]).decode()
               for r in _zscan(headers, VIEW_DECISION, limit=2500)}

    assert written <= in_ledger, "a write reported success and is not in the ledger"
    orphans = in_ledger - indexed
    assert not orphans, (
        f"{len(orphans)} record(s) are in the ledger with no index entry, so they "
        "are absent from every ordered page and nothing reported it. A retried "
        "attempt must leave nothing behind: "
        f"{sorted(orphans)[:3]}"
    )
    assert in_ledger == written, (
        f"the ledger holds {len(in_ledger)} records under this test's prefix but "
        f"only {len(written)} writes succeeded, so {len(in_ledger - written)} came "
        "from attempts that were supposed to have been refused entirely"
    )


# ---------------------------------------------------------------------------
# P3c3b-3: the page is ordered by the index
# ---------------------------------------------------------------------------

@requires_stack
def test_the_newest_record_is_on_the_first_page_whatever_its_agent_id():
    """
    The 3c-3a/3c-2 defect, as a behaviour.

    The old page was a key walk under `desc: true` and `tool_call:` keys lead
    with agent_id, so a record from a low-sorting agent was pushed off the
    page by lexicographically-larger agent ids no matter how recent it was.
    The agent id here sorts below every other id this suite writes.
    """
    for _ in range(12):
        _new_decision(agent_id=f"zzzz-p3c3b-{uuid.uuid4().hex[:8]}")

    newest_key, newest = _new_decision(agent_id="0000-p3c3b-lowest")

    page = _audit(limit=10)
    keys = [base64.b64decode(e["ledger_key"]).decode() for e in page["entries"]]

    assert keys, "empty page"
    assert keys[0] == newest_key, (
        "the newest record is not the first row. Under the key walk this is "
        "exactly what happened: the page returned the lexicographically "
        f"largest agent ids instead. first row tx={page['entries'][0]['tx_id']}, "
        f"newest tx={newest['tx_id']}"
    )


@requires_stack
def test_the_newest_record_is_on_the_page_even_when_the_ledger_exceeds_the_limit():
    """
    The case that produced the original finding, reproduced as a test: a
    ledger past `limit` where the newest transaction was absent from the
    page (`docs/reports/phase-3c2.md`, at 211 entries).
    """
    for _ in range(15):
        _new_decision(agent_id=f"zzzz-p3c3b-{uuid.uuid4().hex[:8]}")
    newest_key, newest = _new_decision(agent_id="0000-p3c3b-past-limit")

    page = _audit(limit=5)
    assert page["has_more"] is True, "the ledger is not past the limit; seed more"

    keys = [base64.b64decode(e["ledger_key"]).decode() for e in page["entries"]]
    assert newest_key in keys, (
        f"the newest record (tx {newest['tx_id']}) is absent from a page of "
        f"{len(keys)} rows drawn from a ledger of {page['total']} records"
    )


@requires_stack
def test_page_order_equals_commit_order():
    """
    Newest first, by the ledger's own transaction ids, with nothing
    re-sorting between the index and the response.

    Asserted over records this test wrote, in their relative order on the
    page, rather than over every row. Backfilled history is scored in (0, 1)
    by an offline pass and sits at the back of the page by position, but its
    transaction ids can be higher than live traffic's - a record written
    through the old path today gets a high tx and a low position. Comparing
    those two groups would be comparing positions the CAS allocated against
    positions it never touched, which is the same scoping D33's own check
    applies (see _assert_score_order_matches_commit_order).
    """
    mine = []
    for _ in range(6):
        key, result = _new_decision()
        mine.append((key, result["tx_id"]))

    page = _audit(limit=200)
    order = [base64.b64decode(e["ledger_key"]).decode() for e in page["entries"]]
    by_tx = {k: tx for k, tx in mine}

    positions = [order.index(k) for k, _ in mine if k in order]
    assert len(positions) == len(mine), (
        f"only {len(positions)} of {len(mine)} records written by this test are "
        "on the page"
    )

    on_page = sorted(((order.index(k), by_tx[k]) for k, _ in mine))
    txs = [tx for _pos, tx in on_page]
    assert txs == sorted(txs, reverse=True), (
        "the page does not present this test's own records in descending "
        f"commit order: {txs}"
    )


# ---------------------------------------------------------------------------
# P3c3b-4: score and transaction agree, or it is a fault
# ---------------------------------------------------------------------------

def _load_ordering_check():
    """control_plane/main.py's own comparator, loaded under its own module
    name - control_plane/main.py and decision_service/main.py are both
    main.py, and a bare `import main` clobbers whichever one sys.modules
    already holds (see tests/test_content_states.py).

    Its own directory goes on sys.path first: the module does `from bundle
    import ...` and `from database import ...`, which resolve as siblings
    when it runs in its container and not otherwise."""
    import importlib.util
    sys.path.insert(0, str(REPO_ROOT / "control_plane"))
    os.environ.setdefault("CONTROL_PLANE_READ_KEY", READ_API_KEY)
    os.environ.setdefault("CONTROL_PLANE_WRITE_KEY", "test-write-key")
    spec = importlib.util.spec_from_file_location(
        "control_plane_main_ordering", REPO_ROOT / "control_plane" / "main.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["control_plane_main_ordering"] = module
    spec.loader.exec_module(module)
    return module


def test_the_order_check_accepts_agreement_and_rejects_disagreement():
    """
    D33's comparator, both directions.

    zscan returns the score and the resolved `entry.tx` in the same response,
    so this costs no extra call. Under D32's CAS it is no longer a defence
    against a writer that can misorder - the ledger refuses to commit an
    out-of-order position at all. It is the assertion that the enforcement is
    still in place, and it is what would catch the precondition having been
    dropped.
    """
    cp = _load_ordering_check()

    R = cp._RESERVED_POSITIONS

    # Newest first, as zscan returns them: position descending, tx descending.
    cp._assert_score_order_matches_commit_order(
        [(R + 9.0, 900), (R + 8.0, 880), (R + 7.0, 12)])

    with pytest.raises(cp.OrderingFault) as caught:
        cp._assert_score_order_matches_commit_order([(R + 9.0, 100), (R + 8.0, 880)])
    assert "disagree" in str(caught.value)

    # A single row, and none, cannot disagree with anything.
    cp._assert_score_order_matches_commit_order([(R + 1.0, 1)])
    cp._assert_score_order_matches_commit_order([])

    # Backfilled history occupies the reserve, scored at each record's own
    # transaction id by an offline pass and never by the CAS, so a pre-index
    # record carrying a higher transaction id than a record indexed after it
    # is not a disagreement about any rule that applied to either. Those rows
    # are outside what D33 asserts, and a page mixing them with allocated
    # positions must still pass.
    cp._assert_score_order_matches_commit_order(
        [(R + 2.0, 500), (R + 1.0, 400), (900.0, 900), (20.0, 20)])

    # Scoping them out must not scope out a real inversion above them.
    with pytest.raises(cp.OrderingFault):
        cp._assert_score_order_matches_commit_order(
            [(R + 2.0, 100), (R + 1.0, 400), (20.0, 20)])


def test_a_disagreement_is_a_fault_and_never_a_reordering():
    """
    The comparator raises. It does not sort, drop a row, or pick a winner.

    Reordering the page to match the transaction ids would hide exactly the
    condition worth reporting: an index that no longer describes the ledger
    it indexes. This test is what stops a later "just sort it" fix.
    """
    cp = _load_ordering_check()
    R = cp._RESERVED_POSITIONS
    rows = [(R + 9.0, 100), (R + 8.0, 880)]
    snapshot = list(rows)

    with pytest.raises(cp.OrderingFault):
        cp._assert_score_order_matches_commit_order(rows)

    assert rows == snapshot, "the comparator mutated the rows it was given"
    assert issubclass(cp.OrderingFault, Exception)


def test_the_audit_read_path_runs_the_order_check_on_every_view():
    """
    The comparator is wired in, for both views.

    A static parse of the source, the idiom this project already uses where
    a live check would poison shared state (tests/test_dashboard_state_
    rendering.py, tests/test_deferred_verification.py). Here the shared state
    is the view index itself: ImmuDB zsets are append-only, so a test that
    fabricated a live disagreement would leave the audit page permanently
    faulted for every test after it. The live demonstration is a command in
    docs/reports/phase-3c3b.md instead.
    """
    source = (REPO_ROOT / "control_plane" / "main.py").read_text(encoding="utf-8")

    body = source[source.index("def get_audit("):]
    body = body[:body.index("\n@app.")]

    calls = body.count("_assert_score_order_matches_commit_order(")
    assert calls == 2, (
        "get_audit must run the order check on both the decision view and "
        f"the intent view; found {calls} call(s). Dropping one would leave a "
        "view whose disagreement with the ledger nothing would notice."
    )
    # What happens to the fault once raised is held by
    # test_the_ordering_fault_is_answered_and_never_escapes, which checks the
    # handler ordering and the exact response rather than a substring within
    # an arbitrary window. This test holds only that both views are checked.


@requires_stack
def test_a_real_page_passes_the_order_check():
    """The check is live on every request, so a served page is one that
    passed it."""
    for _ in range(3):
        _new_decision()
    page = _audit(limit=50)
    assert page["entries"], "empty page"


def test_the_ordering_fault_has_a_structured_face():
    """
    A disagreement is answered with a chosen response, not an escaping
    exception.

    The body names the error, the view, and the two positions that disagreed
    with the transactions they resolve to, and it says out loud that no page
    was served and that the condition will not heal. A caller must not be
    left inferring either from a bare status code.

    Tested through the body builder rather than by fabricating a live
    disagreement: ImmuDB zsets are append-only, so a bad score written into a
    real view would fault every subsequent page in the session.
    """
    cp = _load_ordering_check()
    R = cp._RESERVED_POSITIONS

    with pytest.raises(cp.OrderingFault) as caught:
        cp._assert_score_order_matches_commit_order(
            [(R + 9.0, 100), (R + 8.0, 880)], view="decision")

    body = cp._ordering_fault_body(caught.value)

    assert body["error"] == "audit_ordering_fault", body
    assert body["view"] == "decision", body
    assert body["page_served"] is False, (
        "a caller must not be able to read this as an empty ledger"
    )
    assert body["transient"] is False, (
        "the ledger is append-only and a written score cannot be withdrawn, "
        "so a caller must not be invited to retry"
    )
    assert body["disagreement"]["higher_position"] == {
        "position": R + 9.0, "transaction": 100}, body
    assert body["disagreement"]["lower_position"] == {
        "position": R + 8.0, "transaction": 880}, body
    assert body["remediation"], "a fault with no stated next step is a dead end"

    # The whole body must survive the JSON encoding the response goes through.
    json.dumps(body)


def test_the_ordering_fault_is_answered_and_never_escapes():
    """
    The handler catches OrderingFault before any broader handler, and answers
    500 with the structured body rather than letting it reach the framework.

    Static parse, for the same append-only reason as above. What it holds is
    the wiring: that the fault has a handler at all, that the handler is
    ahead of the generic ones (Python takes the first matching except, so an
    `except Exception` placed above this would swallow the fault into a 503
    "ImmuDB unavailable" and tell a reader something false), and that the
    body is the structured one.
    """
    source = (REPO_ROOT / "control_plane" / "main.py").read_text(encoding="utf-8")
    body = source[source.index("def get_audit("):]
    body = body[:body.index(chr(10) + "@app.")]

    handlers = [line.strip() for line in body.splitlines()
                if line.startswith("    except ")]
    assert handlers, "get_audit has no exception handlers at all"
    assert handlers[0].startswith("except OrderingFault"), (
        "the ordering fault must be the first handler; anything broader above "
        f"it would swallow the fault. handlers, in order: {handlers}"
    )
    assert "raise HTTPException(status_code=500, detail=_ordering_fault_body(exc))" in body, (
        "the fault must be answered with the structured body"
    )


# ---------------------------------------------------------------------------
# The two write routes, and what still uses each
# ---------------------------------------------------------------------------

@requires_stack
def test_the_plain_write_route_still_exists_and_still_works():
    """
    `POST /write` did not go away when the ordered route arrived, and it is
    not vestigial: `control_plane/main.py::_write_tombstone` is a live caller.

    Phase 3c-2's lesson was that quietly leaving a path uncovered is how a
    producer dies unnoticed. This is the direct check that the route still
    accepts a write and still verifies it.
    """
    key = f"content_erasure:p3c3b-route-{uuid.uuid4().hex}"
    body = _write_unordered(key, json.dumps({
        "record_type": "content_erasure", "call_id": uuid.uuid4().hex,
        "timestamp": "2026-08-30T00:00:00", "actor": "p3c3b-route-test",
    }, separators=(",", ":")))

    assert body["verified"] is True, body
    assert body["tx_id"], body

    headers = _immudb_headers()
    assert key in _getall(headers, [key]), "the write reported success and is not in the ledger"


@requires_stack
def test_a_plain_write_takes_no_position_and_a_tombstone_is_not_a_view_row():
    """
    The split between the two routes, asserted rather than assumed.

    A tombstone is not a decision and is never a row on the audit page - it
    is joined by keyed lookup - so it takes no commit position. That is a
    choice, and this is what stops it drifting: if a tombstone ever started
    allocating, it would consume positions that reconciliation expects to
    find in a view index and every pass would report holes.
    """
    headers = _immudb_headers()
    before = _counter(headers)

    key = f"content_erasure:p3c3b-nopos-{uuid.uuid4().hex}"
    _write_unordered(key, json.dumps({
        "record_type": "content_erasure", "call_id": uuid.uuid4().hex,
        "timestamp": "2026-08-30T00:00:00", "actor": "p3c3b-route-test",
    }, separators=(",", ":")))

    after = _counter(headers)
    assert after == before, (
        f"a plain /write moved the sequence counter: {before} -> {after}. "
        "Only the ordered route may allocate."
    )

    for view in (VIEW_DECISION, VIEW_INTENT):
        indexed = {base64.b64decode(r["key"]).decode()
                   for r in _zscan(headers, view, limit=2500)}
        assert key not in indexed, f"a tombstone was indexed into {view}"


def test_each_record_kind_is_written_through_the_route_that_matches_it():
    """
    Static parse of the production callers, so a record kind cannot quietly
    change routes.

    A decision and an intent must take the ordered route, because a record
    with no position is absent from every ordered page. A tombstone must take
    the plain one, because allocating for it would consume a position no view
    holds.
    """
    ledger = (REPO_ROOT / "ledger" / "immudb_ledger.py").read_text(encoding="utf-8")
    control = (REPO_ROOT / "control_plane" / "main.py").read_text(encoding="utf-8")

    assert ledger.count('/write-ordered"') == 2, (
        "the ledger client must write both the decision record and the intent "
        "record through the ordered route"
    )
    assert '"view": "decision"' in ledger, "the decision write must name its view"
    assert '"view": "intent"' in ledger, "the intent write must name its view"
    assert '{self.verifier_url}/write"' not in ledger, (
        "no ledger record kind may take the plain route from here"
    )

    tombstone = control[control.index("def _write_tombstone"):]
    tombstone = tombstone[:tombstone.index(chr(10) + "def ")]
    assert '/write"' in tombstone, "the tombstone write must take the plain route"
    assert "/write-ordered" not in tombstone, (
        "a tombstone must not allocate a commit position: it is never a row on "
        "the ordered page, and the position would be one reconciliation then "
        "reports as a hole forever"
    )


# ---------------------------------------------------------------------------
# P3c3b-5: history is backfilled
# ---------------------------------------------------------------------------

@requires_stack
def test_a_record_written_before_the_index_appears_in_the_ordered_page_after_backfill():
    """
    A record with no index entry is not merely unordered, it is absent from
    every page - so on an append-only ledger a deferred backfill is a
    permanently growing set of unreadable records, not a static debt.

    Written through POST /write, which is exactly what every record written
    before this phase looks like: no counter, no index entry.
    """
    import ail_backfill_index

    call_id = uuid.uuid4().hex
    agent = f"0000-p3c3b-preindex-{uuid.uuid4().hex[:8]}"
    key = f"tool_call:{agent}:{uuid.uuid4().hex}:query_database"
    _write_unordered(key, _decision_value(call_id, agent))

    encoded = _b64(key)

    # Deep enough to cover the whole ledger. Backfilled history is scored
    # below every allocated position because it *is* older, so on a
    # newest-first page it sits at the back - a shallow page not reaching it
    # would say nothing about whether it is indexed.
    before = _audit(limit=2500)
    assert before["has_more"] is False, (
        "the page does not cover the ledger, so absence from it would not "
        "establish that the record is unindexed"
    )
    assert encoded not in [e["ledger_key"] for e in before["entries"]], (
        "a record written with no index entry was already on the page, so "
        "this test cannot establish that the backfill is what put it there"
    )

    summary = ail_backfill_index.backfill()
    assert summary["total_indexed"] >= 1, summary

    after = _audit(limit=2500)
    assert encoded in [e["ledger_key"] for e in after["entries"]], (
        "a pre-index record is still absent from the ordered page after the "
        f"backfill ran. backfill reported: {summary}"
    )


@requires_stack
def test_the_seam_is_monotone_across_the_boundary():
    """
    Every backfilled position is below every allocated one, and each side is
    ordered by commit within itself.

    This is the property the reserve exists for. History is scored at each
    record's own `entry.tx`, which is at most RESERVED_POSITIONS; the counter
    is seeded above the reserve, so its allocations start at
    RESERVED_POSITIONS + 1. The boundary is a number, not a cursor, and it
    does not move when a second backfill pass runs.
    """
    import ail_backfill_index

    # A record from before the index, and one after it.
    agent = f"0000-p3c3b-seam-{uuid.uuid4().hex[:8]}"
    old_key = f"tool_call:{agent}:{uuid.uuid4().hex}:query_database"
    _write_unordered(old_key, _decision_value(uuid.uuid4().hex, agent))
    ail_backfill_index.backfill()
    _new_decision()

    headers = _immudb_headers()
    rows = _zscan(headers, VIEW_DECISION, limit=2500)
    scores = [float(r.get("score", 0.0)) for r in rows]

    history = [x for x in scores if x <= RESERVED_POSITIONS]
    live = [x for x in scores if x > RESERVED_POSITIONS]

    assert history, "no backfilled history to check the seam against"
    assert live, "no allocated positions to check the seam against"
    assert max(history) < min(live), (
        f"the seam is not monotone: highest historical position {max(history)} "
        f"is not below lowest allocated position {min(live)}"
    )
    assert all(float(x).is_integer() for x in live), (
        "an allocated position is not an integer, so it did not come from the counter"
    )

    # Within history, the position IS the transaction id, so score order and
    # commit order are the same order by construction.
    by_score = sorted(
        ((float(r.get("score", 0.0)), int(r["entry"]["tx"])) for r in rows
         if float(r.get("score", 0.0)) <= RESERVED_POSITIONS)
    )
    assert [score for score, _tx in by_score] == [float(tx) for _score, tx in by_score], (
        "a backfilled position is not its record's transaction id, so the "
        f"historical ordering is not the ledger's: {by_score[:5]}"
    )


@requires_stack
def test_the_counter_is_seeded_above_the_reserve():
    """
    A position the CAS hands out is never inside the range history is scored
    into, whether or not a backfill ever ran.

    Two ways that holds: a fresh counter starts at RESERVED_POSITIONS + 1
    (verifier/main.py), and a counter already running below the reserve is
    raised to it by the backfill before it writes any score
    (tools/ail_backfill_index.py::seed_counter_above_reserve). Without this,
    a deployment that had been allocating before the reserve existed would
    have live positions sitting on top of history.
    """
    headers = _immudb_headers()
    _key, result = _new_decision()

    assert result["seq"] > RESERVED_POSITIONS, (
        f"the CAS allocated position {result['seq']}, which is inside the "
        f"reserve of {RESERVED_POSITIONS} that backfilled history occupies"
    )
    observed = _counter(headers)
    assert observed is not None and observed[0] > RESERVED_POSITIONS, observed


@requires_stack
def test_the_backfill_is_idempotent():
    """A second pass indexes nothing, so an interrupted run can be finished
    by re-running it rather than by reasoning about where it stopped."""
    import ail_backfill_index

    ail_backfill_index.backfill()
    again = ail_backfill_index.backfill()
    assert again["total_indexed"] == 0, (
        f"a second backfill pass re-indexed {again['total_indexed']} record(s), "
        "so running it twice would give one record two positions"
    )


# ---------------------------------------------------------------------------
# P3c3b-6: reconciliation has a home
# ---------------------------------------------------------------------------

def _load_reconciler():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "anchor_service_reconcile", REPO_ROOT / "anchor_service" / "main.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["anchor_service_reconcile"] = module
    spec.loader.exec_module(module)
    module.IMMUDB_URL = IMMUDB_URL
    module.IMMUDB_USER = IMMUDB_USER
    module.IMMUDB_PASSWORD = IMMUDB_PASSWORD
    return module


@requires_stack
def test_a_correctly_indexed_write_introduces_no_hole():
    """
    The baseline. A detector that cannot distinguish a good write from a bad
    one says nothing when it says "holes".

    Stated as a difference across one write rather than as "the ledger is
    clean", deliberately. The hole the next test creates is permanent - an
    append-only ledger does not heal - so an absolute assertion here would
    pass exactly once and fail on every later run against the same volume,
    which would make this test a statement about how recently the ledger was
    wiped rather than about the write path.
    """
    reconciler = _load_reconciler()

    before = reconciler.reconcile_once()
    _new_decision()
    after = reconciler.reconcile_once()

    assert after["allocated"] == before["allocated"] + 1, (
        f"one write did not consume exactly one position: {before} -> {after}"
    )
    assert after["indexed"] == before["indexed"] + 1, (
        f"one write did not add exactly one indexed position: {before} -> {after}"
    )
    assert set(after["missing"]) == set(before["missing"]), (
        "a correctly indexed write introduced a hole: "
        f"{sorted(set(after['missing']) - set(before['missing']))}"
    )


@requires_stack
def test_a_consumed_position_with_no_index_entry_is_detected():
    """
    A hole is evidence, not noise.

    Built the way the defect would actually arise: the counter is advanced
    inside a properly preconditioned ExecAll that writes no zAdd, which is
    exactly what a dropped index operation looks like. The position is
    consumed and nothing indexes it.

    Runs after the clean case above on purpose - the hole it creates is
    permanent, because an append-only ledger does not heal.
    """
    reconciler = _load_reconciler()
    headers = _immudb_headers()

    observed = _counter(headers)
    assert observed is not None
    last_seq, last_tx = observed
    burned = last_seq + 1

    key = f"tool_call:p3c3b-hole-{uuid.uuid4().hex[:8]}:{uuid.uuid4().hex}:query_database"
    resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/execall", json={
        "Operations": [
            {"kv": {"key": _b64(key), "value": _b64(_decision_value(uuid.uuid4().hex, "hole"))}},
            {"kv": {"key": _b64(SEQUENCE_KEY), "value": _b64(str(burned))}},
        ],
        "preconditions": [
            {"keyNotModifiedAfterTX": {"key": _b64(SEQUENCE_KEY), "txID": str(last_tx)}}
        ],
        "noWait": False,
    }, headers=headers)
    assert resp.status_code == 200, f"could not create the hole: {resp.text[:300]}"

    result = reconciler.reconcile_once()
    assert result["state"] == "holes", (
        f"a consumed position with no index entry was reported clean: {result}"
    )
    assert burned in result["missing"], (
        f"position {burned} was consumed and never indexed, and is not in "
        f"the reported holes: {result}"
    )


# ---------------------------------------------------------------------------
# P3c3b-7: the intent join
# ---------------------------------------------------------------------------

@requires_stack
def test_an_orphaned_intent_surfaces_as_unknown_on_a_ledger_larger_than_the_page():
    """
    D16's gap flag survives the move to an ordered page.

    The intent key's uuid is generated fresh at immudb_ledger.py and exists
    nowhere but in the key, so no per-row lookup can construct it and the
    orphan direction has to enumerate. That needs a bound either way. Over a
    key walk the bound would be lexicographic agent id, which is the defect
    this phase removes; over the intent view it is the newest N intents, so
    the bound means recency.
    """
    call_id = uuid.uuid4().hex
    agent = f"0000-p3c3b-orphan-{uuid.uuid4().hex[:8]}"
    intent_key = f"tool_call_intent:{agent}:{uuid.uuid4().hex}:read_vault_secret"
    _write_ordered(intent_key, json.dumps({
        "record_type": "decision_intent", "call_id": call_id, "agent_id": agent,
        "timestamp": "2026-08-30T00:00:00", "tool_name": "read_vault_secret",
        "input_sha256": uuid.uuid4().hex, "policy_revision": "p3c3b-test",
        "content_state": "unavailable", "profile": "mediated",
    }, separators=(",", ":")), view="intent")

    # Push the ledger well past the page this test asks for.
    for _ in range(10):
        _new_decision(agent_id=f"zzzz-p3c3b-{uuid.uuid4().hex[:8]}")

    page = _audit(limit=5)
    assert page["has_more"] is True, "the ledger is not larger than the page"

    orphans = [e for e in page["entries"] if e["call_id"] == call_id]
    assert orphans, (
        "an intent with no completion record is absent from a page drawn "
        f"from a ledger of {page['total']} records, so the gap D16 exists to "
        "make visible is silent again"
    )
    assert orphans[0]["execution_state"] == "unknown", orphans[0]
