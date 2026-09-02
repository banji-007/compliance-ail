"""tests/ledger_pollution.py - Phase 3c-3e (D44, P3c3e-10).

The view-index violations this suite creates on purpose, named.

**The tension this exists for, and it is not test hygiene.** A test that
proves the reconciler finds a fractional position has to create one. A test
that proves the seam is monotone has to assert none exists. Both are correct
tests. What was missing is that the second stated its precondition as a
ledger-wide fact when it is not one - so the pair passed only because pytest
collects alphabetically, and failed permanently in reverse order, in two of
three shuffles, and on any second run without `down -v`
(docs/reports/phase-3c3d-order-sweep.md measured it: four tests, two
polluters, three polluting actions).

D44 scopes each victim's assertion to the records that test wrote. This file
is the other half, and it is what stops the scoping from being a loss: the
ledger-wide statement survives, addressed to everything the suite did NOT
deliberately break. `tests/test_view_invariants.py` walks the whole decision
view and requires every violating row to be explained by an entry here.

**Why a hand-listed registry is acceptable here, when this phase's rule is
that enumerations are derived.** What has to be enumerated is not a set of
code sites - it is a set of intentions, and an intention is not in the code.
The registry is checked in both directions instead: every entry must name a
key fragment that some test module in this directory actually produces
(`test_every_entry_is_produced_by_a_test` below), and every violating row in
the ledger must match an entry. An entry that stops being created fails; a
violation nobody registered fails.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent

# The invariants a row in the decision view is expected to satisfy. Named so a
# registry entry says which one it breaks rather than saying "this is fine".
INTEGER_POSITION = "an allocated position is an integer handed out by the counter"
ONE_POSITION_PER_KEY = "a record holds exactly one position"
HISTORY_SCORE_IS_ITS_TRANSACTION = (
    "a position inside the reserve is its record's own transaction id")


@dataclass(frozen=True)
class DeliberateViolation:
    """One violation this suite creates on purpose.

    `key_fragment` is what identifies the rows it produces, and it has to
    appear literally in the module that writes them - that is what
    `test_every_entry_is_produced_by_a_test` checks, and it is why the
    fragment is the agent-id segment rather than a whole key.
    """
    key_fragment: str
    module: str
    breaks: tuple[str, ...]
    why: str


DELIBERATE_VIOLATIONS = (
    DeliberateViolation(
        key_fragment="p3c3c-surplus-",
        module="test_reconciliation.py",
        breaks=(INTEGER_POSITION,),
        why=("proves the reconciler reports a position the counter never "
             "handed out. The position has to BE one the counter never handed "
             "out, so it is `counter + 0.5`, above the reserve and "
             "fractional. ImmuDB's zset has no remove, so it stays."),
    ),
    DeliberateViolation(
        key_fragment="p3c3d-dup-",
        module="test_reconciliation.py",
        breaks=(ONE_POSITION_PER_KEY, HISTORY_SCORE_IS_ITS_TRANSACTION),
        why=("proves the reconciler reports a record holding two positions "
             "when the second is below the reserve, which was assumed to be "
             "history and never checked. The record is written through the "
             "ordered route, so it holds a real allocated position, and the "
             "injection gives it a second at score 42 - which is also not "
             "that record's transaction id."),
    ),
    DeliberateViolation(
        key_fragment="p3c3c-pad",
        module="test_backfill_index.py",
        breaks=(HISTORY_SCORE_IS_ITS_TRANSACTION,),
        why=("takes the decision view past zscan's 2500-row ceiling so the "
             "backfill's index snapshot has to page, which is red-team C2. "
             "The rows are written by execall in batches at synthetic scores "
             "inside the reserve, because 2600 real writes is minutes and 26 "
             "batched transactions is seconds; a synthetic score is not the "
             "record's own transaction id."),
    ),
)


def explains(key: str) -> DeliberateViolation | None:
    """The registered violation that accounts for this key, or None."""
    for entry in DELIBERATE_VIOLATIONS:
        if entry.key_fragment in key:
            return entry
    return None


def registered_for(key: str, invariant: str) -> bool:
    """Is this key's violation of `invariant` one the suite created on purpose."""
    entry = explains(key)
    return entry is not None and invariant in entry.breaks
