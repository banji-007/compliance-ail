"""tests/test_view_invariants.py - Phase 3c-3e (D44, P3c3e-10).

The ledger-wide statements the four order-dependent tests used to make,
made here instead - addressed to everything the suite did not deliberately
break, and loud about anything it did not expect.

**Why the ledger-wide claim is not simply dropped.** D44 scopes each victim's
assertions to the records that test wrote, because that is all those tests can
honestly say. Scoping alone would lose something real: three of the four
assertions were true statements about the whole view, and the only reason they
failed was three violations this suite creates on purpose to prove three
detectors fire. So they move here, with the deliberate violations named in
`tests/ledger_pollution.py` and everything else still held to the rule.

That makes this file stronger than what it replaces, in two directions. A new
violation nobody registered fails, wherever it came from. And a registered
entry that stops being produced fails too, so the exemption list cannot
outlive the tests it exempts.

**Order-dependence becomes loud rather than silent.** The failure this closes
was invisible in CI: alphabetical collection put the victims before the
polluters, so a real order dependence read as a green suite. A registered
violation here is a statement that this suite writes a row breaking a named
invariant, and it says so in every order.

**Phase 3c-3f (P3c3f-10): every invariant over every view, and the one that
skipped now seeds.** Two defects, both found by the Phase 3c-3e red team.

`VIEW_DECISION` was hard-coded and there are two views, so all four
ledger-wide invariants were unenforced on `ail_view:intent:v1` - half the rows
`/audit` pages, written by the same `_VIEW_SETS` through the same ExecAll by
the same allocator. The identical fractional position above the reserve left
this module at `7 passed, 1 skipped` in the intent view and failed by name in
the decision view. `VIEWS` is checked against the verifier's own `_VIEW_SETS`
by `test_this_module_walks_every_view_the_verifier_writes`, so a third view is
this module's failure rather than its blind spot.

And `test_the_seam_between_history_and_allocation_holds` was the one of the
four that seeded nothing: it called `pytest.skip` when either side of the seam
was empty, which was `1 skipped` on every clean-ledger run. Whether it
asserted anything depended on whether `tests/test_backfill_index.py` or
`tests/test_reconciliation.py` had run first, and the order sweep's method
cannot see that - it diffs failing sets, and a skip is never in one. That is
D44's own shape, a check over zero rows asserting nothing, in the file that
exists to guard against it. It seeds both sides now, and its docstring says
which of its assertions are falsifiable and which follow from the partition.

**And the reads themselves are bounded reads (P3c3f-3).** `_view_rows` pages
by `minScore` and decides how many rows every invariant below sees, and it did
not check that a returned row was at or above the score it asked for. It does
now, through `tests/bounded_read_checks.py`, and it is enumerated by
`tests/test_bounded_reads.py` like every other bounded read in the tree.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
import uuid
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
# Explicit, not inherited: verifier/main.py and control_plane/main.py both
# import `provenance`, which lives at the repository root. Relying on some
# earlier test module to have put it on the path is a dependence on
# collection order, which is the class D44 is about.
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from ledger_pollution import (  # noqa: E402
    DELIBERATE_VIOLATIONS, HISTORY_SCORE_IS_ITS_TRANSACTION, INTEGER_POSITION,
    MARKER_FIELD, ONE_POSITION_PER_KEY, TESTS_DIR, explains, marker_of,
    registered_for,
)
from bounded_read_checks import assert_at_or_above_min_score  # noqa: E402

IMMUDB_URL         = os.getenv("IMMUDB_URL",      "http://localhost:8080")
IMMUDB_USER        = os.getenv("IMMUDB_USER",     "immudb")
IMMUDB_PASSWORD    = os.getenv("IMMUDB_PASSWORD", "immudb")
VERIFIER_URL       = os.getenv("VERIFIER_URL",       "http://localhost:8003")
VERIFIER_WRITE_KEY = os.getenv("VERIFIER_WRITE_KEY", "test-verifier-write-key")

VIEW_DECISION = "ail_view:decision:v1"
VIEW_INTENT = "ail_view:intent:v1"

# P3c3f-10 (Phase 3c-3f): both views, because there are two.
#
# This file hard-coded `VIEW_DECISION` and walked nothing else, so all four
# ledger-wide invariants were unenforced on `ail_view:intent:v1` - which is
# half the rows `/audit` pages, written by the same `_VIEW_SETS` in the same
# ExecAll by the same allocator. Driven by the Phase 3c-3e red team: the
# identical fractional position above the reserve left this module at
# `7 passed, 1 skipped` in the intent view and failed by name in the decision
# view.
#
# The site list is not typed here twice either. `_VIEW_SETS` in
# `verifier/main.py` is the definition, `tests/test_ledger_vocabulary.py`
# already compares that set name across five modules, and the pair below is
# the same two names in the same order. A third view added to `_VIEW_SETS`
# and not here fails `test_this_module_walks_every_view_the_verifier_writes`.
VIEWS = (VIEW_DECISION, VIEW_INTENT)

# What the ordered route calls each view, and the key prefix each one indexes.
VIEW_SEEDS = {
    VIEW_DECISION: ("decision", "tool_call:", "decision"),
    VIEW_INTENT: ("intent", "tool_call_intent:", "intent"),
}

RESERVED_POSITIONS = int(os.getenv("AIL_RESERVED_POSITIONS", "1000000000"))

requires_stack = pytest.mark.needs_stack("immudb", "verifier")

_CLIENT = httpx.Client(timeout=120.0)


def _b64(value) -> str:
    return base64.b64encode(value if isinstance(value, bytes) else value.encode()).decode()


def _view_name(view_set: str) -> str:
    """The short name `tests/ledger_pollution.py` entries use for a view."""
    return "intent" if view_set == VIEW_INTENT else "decision"


def _markers_for(keys, headers) -> dict:
    """The deliberate-violation marker of each key, by one exact getAll.

    **Where the marker is read, and at what cost (P3c3g-3).** The invariant
    walk keeps `(key, score, tx)` from zscan and never reads record values, so
    a marker in the value is not free. It is read here only for rows that are
    **already violating an invariant**, by an exact `getAll` over that handful
    of keys, never per row over the view. A view of 2600 rows yields a
    violating set in the single digits, so this is one bounded read per
    assertion rather than a second walk.

    A key that does not come back, or whose value does not decode to an object
    carrying a string marker, is `None` here and therefore explains nothing.
    Failing to read a marker exempts no row.
    """
    keys = sorted(set(keys))
    if not keys:
        return {}
    resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/getall",
                        json={"keys": [_b64(key) for key in keys]},
                        headers=headers)
    resp.raise_for_status()
    markers = {}
    for item in resp.json().get("entries", []):
        key = base64.b64decode(item["key"]).decode("utf-8", "replace")
        try:
            value = json.loads(
                base64.b64decode(item.get("value", "")).decode("utf-8"))
        except Exception:
            value = None
        markers[key] = marker_of(value)
    return markers


def _headers() -> dict:
    resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/login", json={
        "user": _b64(IMMUDB_USER), "password": _b64(IMMUDB_PASSWORD),
        "database": _b64("defaultdb"),
    })
    resp.raise_for_status()
    return {"Authorization": f"Bearer {resp.json()['token']}"}


def _seed_one(view_set: str = VIEW_DECISION) -> str:
    """Put one ordinary record in a view, and return its key.

    **Every ledger-wide test below builds this precondition rather than
    assuming it, and that is not a formality.** Written against a virtually
    empty ledger these tests read zero rows, and a check over zero rows
    asserts nothing at all - so they guard on the view being non-empty. In
    reverse collection order this module runs before anything else writes a
    decision, and the guard fired: `the decision view is empty, so this
    asserts nothing`, three times.

    That is D44's own defect, in the file that enforces D44: an assertion
    resting on state some other module happened to leave. One write through
    the ordered route is all it takes, and it makes the invariant hold over a
    row this module put there whatever else has run.

    P3c3f-10: parameterised by view, because the invariants are.
    """
    view, prefix, record_type = VIEW_SEEDS[view_set]
    agent = f"p3c3f-view-{uuid.uuid4().hex[:8]}"
    key = f"{prefix}{agent}:{uuid.uuid4().hex}:query_database"
    value = json.dumps({
        "record_type": record_type, "call_id": uuid.uuid4().hex,
        "agent_id": agent, "timestamp": "2026-09-03T00:00:00",
        "tool_name": "query_database", "outcome_type": "policy_allow",
        "fault_class": None, "policy_revision": "p3c3f-view",
        "reasons": [], "input_sha256": uuid.uuid4().hex,
        "content_state": "unavailable", "profile": "observed",
    }, separators=(",", ":"))
    resp = _CLIENT.post(f"{VERIFIER_URL}/write-ordered",
                        json={"key": _b64(key), "value": _b64(value),
                              "view": view},
                        headers={"X-API-Key": VERIFIER_WRITE_KEY})
    assert resp.status_code == 200, resp.text[:300]
    body = resp.json()
    assert body.get("verified") is True and body.get("committed") is True, body
    return key


def _seed_one_history(headers: dict, view_set: str = VIEW_DECISION) -> str:
    """Put one record inside the reserve, the way the backfill writes it.

    P3c3f-10. `test_the_seam_between_history_and_allocation_holds` needs rows
    on both sides of the reserve, and it used to skip when either side was
    empty rather than building the side it needed - so on a clean ledger it
    asserted nothing, and whether it asserted anything at all depended on
    collection order.

    The offline pass (`tools/ail_backfill_index.py`) scores a historical row
    at the record's own `entry.tx`, which is below the reserve because a
    transaction id is. Written the same way here: the record straight to the
    ledger, then a zAdd at the transaction the ledger gave it. That breaks no
    invariant and needs no entry in `tests/ledger_pollution.py` - it is what a
    correctly backfilled row looks like.
    """
    _view, prefix, record_type = VIEW_SEEDS[view_set]
    agent = f"p3c3f-history-{uuid.uuid4().hex[:8]}"
    key = f"{prefix}{agent}:{uuid.uuid4().hex}:query_database"
    value = json.dumps({
        "record_type": record_type, "call_id": uuid.uuid4().hex,
        "agent_id": agent, "timestamp": "2026-09-03T00:00:00",
        "tool_name": "query_database", "outcome_type": "policy_allow",
        "policy_revision": "p3c3f-view", "input_sha256": uuid.uuid4().hex,
    }, separators=(",", ":"))
    written = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/set", json={
        "KVs": [{"key": _b64(key), "value": _b64(value)}]}, headers=headers)
    written.raise_for_status()

    read_back = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/getall",
                             json={"keys": [_b64(key)]}, headers=headers)
    read_back.raise_for_status()
    entries = read_back.json().get("entries", [])
    assert entries, f"the history seed for {view_set} is not in the ledger"
    tx = int(entries[0]["tx"])
    assert 0 < tx <= RESERVED_POSITIONS, (
        f"the ledger is past the reserve at transaction {tx}, so a record "
        "scored at its own transaction is no longer inside the historical "
        "range and this seed would break the seam it is building"
    )

    indexed = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/zadd", json={
        "set": _b64(view_set), "key": _b64(key), "score": float(tx),
        "boundRef": False}, headers=headers)
    indexed.raise_for_status()
    return key


def _view_rows(headers: dict, view_set: str = VIEW_DECISION
               ) -> list[tuple[str, float, int]]:
    """Every (key, position, transaction) in a view, paged past the 2500
    ceiling."""
    out: list[tuple[str, float, int]] = []
    seen: set[tuple[str, float]] = set()
    min_score = None
    while True:
        body = {"set": _b64(view_set), "desc": False, "limit": 2500}
        if min_score is not None:
            body["minScore"] = {"score": min_score}
        resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/zscan", json=body,
                            headers=headers)
        resp.raise_for_status()
        rows = resp.json().get("entries", [])
        if not rows:
            break
        before = len(seen)
        page = [(base64.b64decode(row["entry"]["key"]).decode("utf-8", "replace"),
                 float(row.get("score", 0.0))) for row in rows]
        # P3c3f-3 (D46): the bound this page asked for, asserted on what came
        # back. This walk decides how many rows all four ledger-wide
        # invariants below see, and an invariant over fewer rows than it
        # thinks is the condition D44 exists for.
        assert_at_or_above_min_score(
            page, min_score, f"_view_rows({view_set})")
        for row, (key, score) in zip(rows, page):
            if (key, score) in seen:
                continue
            seen.add((key, score))
            out.append((key, score, int(row["entry"].get("tx", 0))))
        min_score = float(rows[-1].get("score", 0.0))
        if len(rows) < 2500 or len(seen) == before:
            break
    return out


# ---------------------------------------------------------------------------
# The registry, checked in both directions.
# ---------------------------------------------------------------------------

def test_every_entry_is_produced_by_a_test():
    """A registered exemption that nothing creates any more is an exemption
    nothing can see, and the next row that happens to carry its marker
    inherits it.

    Checked against the source of the module each entry names, so an entry
    survives only as long as the test that needs it does.
    """
    stale = []
    for entry in DELIBERATE_VIOLATIONS:
        module = TESTS_DIR / entry.module
        if not module.exists():
            stale.append(f"{entry.marker!r}: {entry.module} does not exist")
            continue
        source = module.read_text(encoding="utf-8")
        # The call form, not a bare mention. `p3c3c-pad` appears in
        # test_backfill_index.py in key literals and in a substring filter as
        # well as in the write, so requiring the string alone would pass on a
        # module that had stopped writing the marker entirely. What has to be
        # there is the module passing it as one.
        written_as = f'marker="{entry.marker}"'
        if written_as not in source:
            stale.append(
                f"{entry.marker!r}: {entry.module} does not write "
                f"{written_as}, so nothing produces a row this entry can "
                "explain"
            )
    assert not stale, (
        f"the deliberate-violation registry has entries nothing produces: "
        f"{stale}. An exemption outliving its test is an exemption for "
        "whatever lands on that name next."
    )


def test_every_entry_says_what_it_breaks_and_why():
    """An entry with no reason is a suppression wearing a registry's clothes."""
    thin = [entry.marker for entry in DELIBERATE_VIOLATIONS
            if not entry.breaks or len(entry.why.strip()) < 80]
    assert not thin, f"registry entries with no argument behind them: {thin}"


# ---------------------------------------------------------------------------
# The site list this file asserts over, derived rather than typed.
# ---------------------------------------------------------------------------

def test_this_module_walks_every_view_the_verifier_writes():
    """`VIEWS` covers `verifier/main.py::_VIEW_SETS`.

    P3c3f-10. This module hard-coded one view name and there are two, so all
    four invariants below were unenforced on `ail_view:intent:v1` - half the
    rows `/audit` pages, allocated by the same counter through the same
    ExecAll. The set names were derivable the whole time:
    `tests/test_ledger_vocabulary.py::test_the_view_index_names_agree_everywhere`
    already compares the intent view's name across five modules.

    Static: it reads the verifier's source rather than importing it, so this
    runs with no stack and no signing key.
    """
    source = (REPO_ROOT / "verifier" / "main.py").read_text(encoding="utf-8")
    body = source.split("_VIEW_SETS = {", 1)
    assert len(body) == 2, "verifier/main.py no longer defines _VIEW_SETS"
    declared = set(re.findall(r'b"(ail_view:[^"]+)"',
                              body[1].split("}", 1)[0]))
    assert declared, "no view set names were parsed out of _VIEW_SETS"
    missing = sorted(declared - set(VIEWS))
    assert not missing, (
        f"the verifier writes view(s) {missing} that this module does not "
        "walk, so every ledger-wide invariant below is unenforced on them. "
        "Add the view to VIEWS and VIEW_SEEDS."
    )
    stale = sorted(set(VIEWS) - declared)
    assert not stale, (
        f"this module walks view(s) {stale} the verifier no longer writes, so "
        "the invariants over them assert over zero rows"
    )


# ---------------------------------------------------------------------------
# The ledger-wide invariants. Every one of them over every view.
# ---------------------------------------------------------------------------

@requires_stack
@pytest.mark.parametrize("view_set", VIEWS)
def test_every_allocated_position_is_an_integer_or_a_registered_violation(view_set):
    """Moved out of `test_the_seam_is_monotone_across_the_boundary`.

    A position above the reserve came from the compare-and-set allocator,
    which hands out consecutive integers, so a fractional one did not come
    from the counter. `tests/test_reconciliation.py` injects exactly one on
    purpose to prove the reconciler reports it; every other one is a defect.
    """
    mine = _seed_one(view_set)
    rows = _view_rows(_headers(), view_set)
    assert any(key == mine for key, _score, _tx in rows), (
        f"this test's own record is not in {view_set}, so the walk below is "
        "not reading what it thinks it is"
    )
    candidates = [(key, score) for key, score, _tx in rows
                  if score > RESERVED_POSITIONS
                  and not float(score).is_integer()]
    markers = _markers_for([key for key, _score in candidates], _headers())
    offenders = [(key, score) for key, score in candidates
                 if not registered_for(markers.get(key), INTEGER_POSITION,
                                       _view_name(view_set))]
    assert not offenders, (
        f"position(s) in {view_set} above the reserve that are not integers "
        f"and are not registered in tests/ledger_pollution.py: "
        f"{offenders[:10]}. An allocated position comes from the counter, and "
        "the counter hands out integers."
    )


@requires_stack
@pytest.mark.parametrize("view_set", VIEWS)
def test_every_record_holds_one_position_or_is_a_registered_violation(view_set):
    """Moved out of
    `test_one_pass_over_a_view_past_the_ceiling_leaves_no_record_at_two_positions`.

    A record at two positions is the condition that kills `/audit` with
    `audit_ordering_fault` at every limit, permanently: both entries resolve
    to the key's current transaction, and D33 requires strictly increasing
    transaction with increasing position.
    """
    mine = _seed_one(view_set)
    rows = _view_rows(_headers(), view_set)
    assert any(key == mine for key, _score, _tx in rows), (
        f"this test's own record is not in {view_set}, so the walk below is "
        "not reading what it thinks it is"
    )
    positions: dict[str, set[float]] = {}
    for key, score, _tx in rows:
        positions.setdefault(key, set()).add(score)
    candidates = {key: sorted(scores) for key, scores in positions.items()
                  if len(scores) > 1}
    markers = _markers_for(candidates, _headers())
    offenders = {key: scores for key, scores in candidates.items()
                 if not registered_for(markers.get(key), ONE_POSITION_PER_KEY,
                                       _view_name(view_set))}
    assert not offenders, (
        f"record(s) in {view_set} at more than one position that are not "
        f"registered in tests/ledger_pollution.py: "
        f"{dict(list(offenders.items())[:5])}"
    )


@requires_stack
@pytest.mark.parametrize("view_set", VIEWS)
def test_the_seam_between_history_and_allocation_holds(view_set):
    """Moved out of `test_the_seam_is_monotone_across_the_boundary`, and it
    needs no exemptions at all.

    Every backfilled position is below every allocated one. This is the
    property the reserve exists for, and it is a number rather than a cursor,
    so it survives anything the suite writes on either side of it - which the
    order sweep confirmed: `max(history) < min(live)` held in all five
    collection orders.

    **P3c3f-10: it seeds both sides of the seam rather than skipping.** This
    was the one invariant of the four that called `_seed_one()` for neither
    side and `pytest.skip`ped when either was empty, which was `1 skipped` on
    every clean-ledger run. Whether it asserted anything at all depended on
    whether `tests/test_backfill_index.py` or `tests/test_reconciliation.py`
    had run first and left rows inside the reserve - and the order sweep's
    method cannot see that, because it diffs failing sets and a skip is never
    in one. That is D44's own shape, a check over zero rows asserting nothing,
    sitting in the file that exists to guard against it.

    The historical side is seeded the way the backfill writes it: a record
    zAdded at its own transaction id, inside the reserve. It is registered in
    `tests/ledger_pollution.py` for nothing, because it breaks nothing - it is
    exactly what a backfilled row looks like.

    **What the ledger-wide half of this actually establishes, said plainly.**
    `max(history) < min(live)` where the two lists are partitioned BY the
    reserve follows from the partition once both sides are non-empty: every
    history score is at or below the reserve and every live score is above it,
    by the definition of the two lists. Writing that down rather than dropping
    it, because the sentence is still worth asserting - it fails if the walk
    returns a score that lands in neither list - and because a check that
    cannot fail is the thing this file exists to catch.

    The falsifiable content is the pair of writers, and it is asserted over
    this test's own two rows: the position the ORDERED ROUTE allocated is
    above the reserve, and the position the BACKFILL SHAPE carries is at or
    below it and equals its record's transaction. A writer that allocated
    inside the reserve fails the first, which is exactly what raising
    `AIL_RESERVED_POSITIONS` after allocation used to do (D36).
    """
    mine_live = _seed_one(view_set)
    mine_history = _seed_one_history(_headers(), view_set)
    rows = _view_rows(_headers(), view_set)
    by_key = {key: (score, tx) for key, score, tx in rows}

    assert mine_live in by_key, (
        f"the ordered write this test just made is not in {view_set}, so the "
        "seam below is not being read"
    )
    assert mine_history in by_key, (
        f"the backfill-shaped row this test just wrote is not in {view_set}, "
        "so the seam below is not being read"
    )

    live_score, _live_tx = by_key[mine_live]
    history_score, history_tx = by_key[mine_history]

    assert live_score > RESERVED_POSITIONS, (
        f"the ordered route allocated position {live_score} for a record "
        f"written now, and the reserve is {RESERVED_POSITIONS}. An allocated "
        "position inside the reserve is indistinguishable from backfilled "
        "history and sorts underneath every record the backfill has yet to "
        "reach."
    )
    assert history_score <= RESERVED_POSITIONS, (
        f"a row scored at its own transaction landed at {history_score}, above "
        f"the reserve at {RESERVED_POSITIONS}. The ledger has passed the "
        "reserve, so history and allocation are no longer separable by "
        "position at all."
    )
    assert history_score == float(history_tx), (
        f"the backfill-shaped row is at {history_score} and its record is at "
        f"transaction {history_tx}"
    )
    assert history_score < live_score, (
        f"the backfilled position {history_score} is not below the allocated "
        f"position {live_score}"
    )

    history = [score for _key, score, _tx in rows if score <= RESERVED_POSITIONS]
    live = [score for _key, score, _tx in rows if score > RESERVED_POSITIONS]
    assert history, (
        f"{view_set} has no record inside the reserve even though this test "
        "just wrote one, so the seam below is not being read"
    )
    assert live, (
        f"{view_set} has no allocated record even though this test just wrote "
        "one, so the seam below is not being read"
    )
    assert max(history) < min(live), (
        f"the seam in {view_set} is not monotone: highest historical position "
        f"{max(history)} is not below lowest allocated position {min(live)}"
    )


@requires_stack
@pytest.mark.parametrize("view_set", VIEWS)
def test_a_historical_position_is_its_transaction_or_a_registered_violation(view_set):
    """Moved out of `test_the_seam_is_monotone_across_the_boundary`.

    History is scored at each record's own `entry.tx` by the offline backfill,
    which is the ledger's own commit order for it and needs no reconstruction.
    Two tests write synthetic scores inside the reserve on purpose - one to
    reach the zscan ceiling cheaply, one to give a record a second position in
    the range that was assumed to be history - and both are registered.
    """
    mine = _seed_one(view_set)
    rows = _view_rows(_headers(), view_set)
    assert any(key == mine for key, _score, _tx in rows), (
        f"this test's own record is not in {view_set}, so the walk below is "
        "not reading what it thinks it is"
    )
    candidates = [(key, score, tx) for key, score, tx in rows
                  if score <= RESERVED_POSITIONS and score != float(tx)]
    markers = _markers_for([key for key, _s, _t in candidates], _headers())
    offenders = [(key, score, tx) for key, score, tx in candidates
                 if not registered_for(markers.get(key),
                                       HISTORY_SCORE_IS_ITS_TRANSACTION,
                                       _view_name(view_set))]
    assert not offenders, (
        f"backfilled position(s) in {view_set} that are not their record's "
        f"transaction id and are not registered in "
        f"tests/ledger_pollution.py: {offenders[:10]}"
    )


def _violating_rows(rows) -> list:
    """Every row breaking an invariant, with the invariant it breaks.

    The same three conditions the three assertions above use, in one place, so
    the registry check below looks at exactly the rows those assertions would
    report and no others. This is what keeps the marker read bounded: markers
    are fetched for this set, which is single digits in a view of thousands.
    """
    positions: dict = {}
    for key, score, _tx in rows:
        positions.setdefault(key, set()).add(score)
    out = []
    for key, score, tx in rows:
        if score > RESERVED_POSITIONS and not float(score).is_integer():
            out.append((key, score, tx, INTEGER_POSITION))
        if len(positions[key]) > 1:
            out.append((key, score, tx, ONE_POSITION_PER_KEY))
        if score <= RESERVED_POSITIONS and score != float(tx):
            out.append((key, score, tx, HISTORY_SCORE_IS_ITS_TRANSACTION))
    return out


@requires_stack
def test_the_registered_violations_are_the_only_exemptions_in_use():
    """What this suite is actually exempting, made visible.

    Not an assertion about correctness. An assertion that the registry is
    being used for what it says: a row carrying a registered marker and
    breaking an invariant must be breaking one the entry names, in the view
    the entry names.

    **P3c3g-3, closing red-team R5.** This test used to walk the decision view
    and require every entry to match a row there that breaks something. The
    `p3c3c-zero` entry's violation is a zero score in the INTENT view, and the
    backfill also indexes that same record into the decision view at its own
    transaction id, which is a completely ordinary row. So the test passed
    when `test_backfill_index.py` had already run and failed when it had not:
    alphabetically `b` sorts before `r`, CI collects alphabetically, and both
    green runs the phase cited were green for that reason. On a fresh ledger
    with `test_reconciliation.py` first it read `1 failed`. That is D44's own
    class, in a test D44's phase added.

    Two changes. Each entry is checked against the view it names, so the
    decision-view copy of a marked record is not evidence about an intent-view
    violation. And rows are matched on an exact marker in the record value
    rather than on a substring of a caller-supplied key segment, which is R4.

    **What this no longer claims, stated rather than quietly dropped.** The
    old spelling could say "this entry matches only ordinary rows", because a
    key fragment is free to test against every row in the view. A marker lives
    in the record value, and reading values for a whole view is the read the
    design constraint for this item forbids. So the check is scoped to rows
    that are already violating an invariant: an entry whose marked rows have
    all stopped violating anything is skipped here, and
    `test_every_entry_is_produced_by_a_test` is what keeps it honest. That is
    a real reduction in what this test sees and it is recorded in the phase
    report's Residual Limits.
    """
    _seed_one()
    wrong = []
    for view_set in VIEWS:
        view = _view_name(view_set)
        rows = _view_rows(_headers(), view_set)
        violating = _violating_rows(rows)
        markers = _markers_for([key for key, _s, _t, _i in violating],
                               _headers())
        for key, score, tx, invariant in violating:
            marker = markers.get(key)
            if marker is None:
                continue
            entry = explains(marker)
            if entry is None:
                continue
            if not registered_for(marker, invariant, view):
                wrong.append(
                    f"{view}: {key} at {score} (tx {tx}) carries marker "
                    f"{marker!r} and breaks {invariant!r}, which entry "
                    f"{entry.marker!r} does not claim in this view "
                    f"(it claims {entry.breaks} in {entry.view!r})"
                )
    assert not wrong, (
        "row(s) carrying a registered marker break an invariant the entry "
        f"does not name: {wrong[:5]}. A marker that travels with a record "
        "into a violation nobody registered is an exemption widening by "
        "itself."
    )


def test_a_key_with_no_registered_violation_is_not_explained_by_one():
    """The matcher itself, so the exemption cannot be accidentally universal."""
    assert explains(None) is None
    assert explains("p3c3c-surplus") is not None
    assert not registered_for("p3c3c-surplus", ONE_POSITION_PER_KEY), (
        "the surplus injection is registered for an invariant it does not "
        "break, so it exempts more than it should"
    )

    # R4, as a permanent test rather than a probe. The attack was a real
    # decision record through POST /write-ordered whose agent id was
    # `p3c3c-padded-batch-7`, which contains the registered fragment
    # `p3c3c-pad`. Under the old substring match it inherited that exemption
    # and a genuine HISTORY_SCORE_IS_ITS_TRANSACTION violation on it was never
    # reported; the control, the same record and injection under an ordinary
    # agent id, was reported.
    assert explains("p3c3c-padded-batch-7") is None, (
        "a marker that merely contains a registered one is treated as that "
        "registration. This is red-team R4: nine characters in a field the "
        "caller chooses buy an exemption from a ledger-wide invariant."
    )
    assert not registered_for("p3c3c-padded-batch-7",
                              HISTORY_SCORE_IS_ITS_TRANSACTION), (
        "the padded-batch agent id inherits the padding exemption"
    )

    # R5's half: a marker is only registered for the view its entry names.
    assert registered_for("p3c3c-zero", HISTORY_SCORE_IS_ITS_TRANSACTION,
                          "intent"), (
        "the zero-score entry does not cover its own violation, which is in "
        "the intent view"
    )
    assert not registered_for("p3c3c-zero", HISTORY_SCORE_IS_ITS_TRANSACTION,
                              "decision"), (
        "the zero-score entry exempts the decision view, where the backfill "
        "indexes the same record at its own transaction id as an ordinary "
        "row. That is what made this suite order dependent."
    )
