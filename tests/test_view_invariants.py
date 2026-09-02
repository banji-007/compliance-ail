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
"""

from __future__ import annotations

import base64
import os
import sys
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
    ONE_POSITION_PER_KEY, TESTS_DIR, explains, registered_for,
)

IMMUDB_URL      = os.getenv("IMMUDB_URL",      "http://localhost:8080")
IMMUDB_USER     = os.getenv("IMMUDB_USER",     "immudb")
IMMUDB_PASSWORD = os.getenv("IMMUDB_PASSWORD", "immudb")

VIEW_DECISION = "ail_view:decision:v1"
RESERVED_POSITIONS = int(os.getenv("AIL_RESERVED_POSITIONS", "1000000000"))

requires_stack = pytest.mark.needs_stack("immudb")

_CLIENT = httpx.Client(timeout=120.0)


def _b64(value) -> str:
    return base64.b64encode(value if isinstance(value, bytes) else value.encode()).decode()


def _headers() -> dict:
    resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/login", json={
        "user": _b64(IMMUDB_USER), "password": _b64(IMMUDB_PASSWORD),
        "database": _b64("defaultdb"),
    })
    resp.raise_for_status()
    return {"Authorization": f"Bearer {resp.json()['token']}"}


def _view_rows(headers: dict) -> list[tuple[str, float, int]]:
    """Every (key, position, transaction) in the decision view, paged past the
    2500 ceiling."""
    out: list[tuple[str, float, int]] = []
    seen: set[tuple[str, float]] = set()
    min_score = None
    while True:
        body = {"set": _b64(VIEW_DECISION), "desc": False, "limit": 2500}
        if min_score is not None:
            body["minScore"] = {"score": min_score}
        resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/zscan", json=body,
                            headers=headers)
        resp.raise_for_status()
        rows = resp.json().get("entries", [])
        if not rows:
            break
        before = len(seen)
        for row in rows:
            key = base64.b64decode(row["entry"]["key"]).decode("utf-8", "replace")
            score = float(row.get("score", 0.0))
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
    nothing can see, and the next row that happens to match its fragment
    inherits it.

    Checked against the source of the module each entry names, so an entry
    survives only as long as the test that needs it does.
    """
    stale = []
    for entry in DELIBERATE_VIOLATIONS:
        module = TESTS_DIR / entry.module
        if not module.exists():
            stale.append(f"{entry.key_fragment!r}: {entry.module} does not exist")
            continue
        if entry.key_fragment not in module.read_text(encoding="utf-8"):
            stale.append(
                f"{entry.key_fragment!r} does not appear in {entry.module}"
            )
    assert not stale, (
        f"the deliberate-violation registry has entries nothing produces: "
        f"{stale}. An exemption outliving its test is an exemption for "
        "whatever lands on that name next."
    )


def test_every_entry_says_what_it_breaks_and_why():
    """An entry with no reason is a suppression wearing a registry's clothes."""
    thin = [entry.key_fragment for entry in DELIBERATE_VIOLATIONS
            if not entry.breaks or len(entry.why.strip()) < 80]
    assert not thin, f"registry entries with no argument behind them: {thin}"


# ---------------------------------------------------------------------------
# The ledger-wide invariants.
# ---------------------------------------------------------------------------

@requires_stack
def test_every_allocated_position_is_an_integer_or_a_registered_violation():
    """Moved out of `test_the_seam_is_monotone_across_the_boundary`.

    A position above the reserve came from the compare-and-set allocator,
    which hands out consecutive integers, so a fractional one did not come
    from the counter. `tests/test_reconciliation.py` injects exactly one on
    purpose to prove the reconciler reports it; every other one is a defect.
    """
    rows = _view_rows(_headers())
    assert rows, "the decision view is empty, so this asserts nothing"
    offenders = [(key, score) for key, score, _tx in rows
                 if score > RESERVED_POSITIONS and not float(score).is_integer()
                 and not registered_for(key, INTEGER_POSITION)]
    assert not offenders, (
        f"position(s) above the reserve that are not integers and are not "
        f"registered in tests/ledger_pollution.py: {offenders[:10]}. An "
        "allocated position comes from the counter, and the counter hands out "
        "integers."
    )


@requires_stack
def test_every_record_holds_one_position_or_is_a_registered_violation():
    """Moved out of
    `test_one_pass_over_a_view_past_the_ceiling_leaves_no_record_at_two_positions`.

    A record at two positions is the condition that kills `/audit` with
    `audit_ordering_fault` at every limit, permanently: both entries resolve
    to the key's current transaction, and D33 requires strictly increasing
    transaction with increasing position.
    """
    rows = _view_rows(_headers())
    assert rows, "the decision view is empty, so this asserts nothing"
    positions: dict[str, set[float]] = {}
    for key, score, _tx in rows:
        positions.setdefault(key, set()).add(score)
    offenders = {key: sorted(scores) for key, scores in positions.items()
                 if len(scores) > 1 and not registered_for(key, ONE_POSITION_PER_KEY)}
    assert not offenders, (
        f"record(s) at more than one position that are not registered in "
        f"tests/ledger_pollution.py: {dict(list(offenders.items())[:5])}"
    )


@requires_stack
def test_the_seam_between_history_and_allocation_holds():
    """Moved out of `test_the_seam_is_monotone_across_the_boundary`, and it
    needs no exemptions at all.

    Every backfilled position is below every allocated one. This is the
    property the reserve exists for, and it is a number rather than a cursor,
    so it survives anything the suite writes on either side of it - which the
    order sweep confirmed: `max(history) < min(live)` held in all five
    collection orders.
    """
    rows = _view_rows(_headers())
    history = [score for _key, score, _tx in rows if score <= RESERVED_POSITIONS]
    live = [score for _key, score, _tx in rows if score > RESERVED_POSITIONS]
    if not history or not live:
        pytest.skip("this ledger has no records on one side of the seam yet")
    assert max(history) < min(live), (
        f"the seam is not monotone: highest historical position "
        f"{max(history)} is not below lowest allocated position {min(live)}"
    )
    assert min(live) > RESERVED_POSITIONS, min(live)


@requires_stack
def test_a_historical_position_is_its_transaction_or_a_registered_violation():
    """Moved out of `test_the_seam_is_monotone_across_the_boundary`.

    History is scored at each record's own `entry.tx` by the offline backfill,
    which is the ledger's own commit order for it and needs no reconstruction.
    Two tests write synthetic scores inside the reserve on purpose - one to
    reach the zscan ceiling cheaply, one to give a record a second position in
    the range that was assumed to be history - and both are registered.
    """
    rows = _view_rows(_headers())
    assert rows, "the decision view is empty, so this asserts nothing"
    offenders = [(key, score, tx) for key, score, tx in rows
                 if score <= RESERVED_POSITIONS and score != float(tx)
                 and not registered_for(key, HISTORY_SCORE_IS_ITS_TRANSACTION)]
    assert not offenders, (
        f"backfilled position(s) that are not their record's transaction id "
        f"and are not registered in tests/ledger_pollution.py: "
        f"{offenders[:10]}"
    )


@requires_stack
def test_the_registered_violations_are_the_only_exemptions_in_use():
    """What this suite is actually exempting, made visible.

    Not an assertion about correctness - an assertion that the registry is
    being used for what it says. A row matching a registered fragment must be
    breaking one of the invariants that entry names; a fragment that matches
    perfectly ordinary rows is an exemption with a blast radius nobody
    intended.
    """
    rows = _view_rows(_headers())
    for entry in DELIBERATE_VIOLATIONS:
        matched = [(key, score, tx) for key, score, tx in rows
                   if entry.key_fragment in key]
        if not matched:
            # The module that writes them has not run in this session. That is
            # not a failure: test_every_entry_is_produced_by_a_test is what
            # keeps the entry honest.
            continue
        keys = {key for key, _score, _tx in matched}
        positions: dict[str, set[float]] = {}
        for key, score, _tx in matched:
            positions.setdefault(key, set()).add(score)
        breaks_something = (
            any(score > RESERVED_POSITIONS and not float(score).is_integer()
                for _key, score, _tx in matched)
            or any(len(scores) > 1 for scores in positions.values())
            or any(score <= RESERVED_POSITIONS and score != float(tx)
                   for _key, score, tx in matched)
        )
        assert breaks_something, (
            f"the registry entry {entry.key_fragment!r} matches "
            f"{len(keys)} row(s) in the view and none of them breaks any of "
            "the invariants it claims to exempt. An exemption that covers "
            "ordinary rows exempts whatever lands on that name next."
        )


def test_a_key_with_no_registered_violation_is_not_explained_by_one():
    """The matcher itself, so the exemption cannot be accidentally universal."""
    assert explains("tool_call:ordinary:abcdef:query_database") is None
    assert explains("tool_call:p3c3c-surplus-deadbeef:x:query_database") is not None
    assert not registered_for("tool_call:p3c3c-surplus-deadbeef:x:query_database",
                              ONE_POSITION_PER_KEY), (
        "the surplus injection is registered for an invariant it does not "
        "break, so it exempts more than it should"
    )
