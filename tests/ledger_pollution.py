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
marker that some test module in this directory actually writes
(`test_every_entry_is_produced_by_a_test` below), and every violating row in
the ledger must match an entry. An entry that stops being created fails; a
violation nobody registered fails.

**P3c3g-3, closing red-team R4 and R5, which are one fix.** Entries were
matched by `key_fragment in key`, and the key's agent-id segment is supplied
by whoever writes the record. A real decision record through
`POST /write-ordered` with agent id `p3c3c-padded-batch-7` contains the
registered fragment `p3c3c-pad`, so it inherited that exemption and a genuine
invariant violation on it went unreported; the control, the same record and
the same injection under an ordinary agent id, was reported. Entries are now
matched on an exact marker the polluting test writes into the record value,
and each entry names the view its violation lives in. The second half is R5:
`p3c3c-zero`'s violation is a zero score in the intent view, while the
backfill indexes the same record into the decision view at its own
transaction id, which is an ordinary row. A check that looked for every
entry's violation in the decision view passed or failed on whether the
backfill had run yet, which is collection order.
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

# The field a polluting test writes into the record value to claim its own
# exemption. A record arriving through the production write path does not
# carry it unless someone put it there deliberately, which is a weaker claim
# than "unforgeable" and the right one: this registry describes intentions
# inside this suite, and its job is to stop an ordinary record from drifting
# into an exemption by looking like one.
MARKER_FIELD = "ail_deliberate_violation"


@dataclass(frozen=True)
class DeliberateViolation:
    """One violation this suite creates on purpose.

    `marker` is the exact value the polluting module writes into the record's
    `MARKER_FIELD`, and it has to appear literally in that module, which is
    what `test_every_entry_is_produced_by_a_test` checks. Exact, not a
    substring: a substring match over anything a caller supplies is what R4
    exploited.

    `view` is where the violation this entry describes actually lives. An
    entry is only expected to explain rows in that view.
    """
    marker: str
    module: str
    breaks: tuple[str, ...]
    why: str
    view: str = "decision"


DELIBERATE_VIOLATIONS = (
    DeliberateViolation(
        marker="p3c3c-surplus",
        module="test_reconciliation.py",
        breaks=(INTEGER_POSITION,),
        why=("proves the reconciler reports a position the counter never "
             "handed out. The position has to BE one the counter never handed "
             "out, so it is `counter + 0.5`, above the reserve and "
             "fractional. ImmuDB's zset has no remove, so it stays."),
    ),
    DeliberateViolation(
        marker="p3c3d-dup",
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
        marker="p3c3c-zero",
        view="intent",
        module="test_reconciliation.py",
        breaks=(HISTORY_SCORE_IS_ITS_TRANSACTION,),
        why=("proves the reconciler survives a row scored at exactly zero. "
             "protobuf's JSON mapping omits a zero-valued field, so such a row "
             "arrives with no `score` key at all and "
             "`float(rows[-1]['score'])` raised KeyError out of the whole "
             "pass, which run_forever swallowed into one log line per "
             "interval: a detector turned off rather than made wrong. The "
             "score has to BE zero, which is inside the reserve and is not "
             "that record's transaction id. **Registered in Phase 3c-3f, and "
             "the registration is the finding:** the row goes into the INTENT "
             "view, and until P3c3f-10 no ledger-wide invariant was enforced "
             "there, so this violation existed for two phases with nothing "
             "able to see it."),
    ),
    DeliberateViolation(
        marker="p3c3c-pad",
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


def marker_of(value) -> str | None:
    """The deliberate-violation marker in a decoded record value, if any.

    Anything that is not a mapping carrying a string marker is None, so a
    record whose value failed to decode cannot be read as an exemption.
    """
    if not isinstance(value, dict):
        return None
    marker = value.get(MARKER_FIELD)
    return marker if isinstance(marker, str) else None


def explains(marker: str | None) -> DeliberateViolation | None:
    """The registered violation with this exact marker, or None.

    **Exact equality, not containment (P3c3g-3).** The previous spelling
    matched `entry.key_fragment in key` over a key whose agent-id segment the
    caller supplies. `p3c3c-padded-batch-7` contains `p3c3c-pad`, so a real
    record written through the ordered route inherited that exemption and a
    genuine violation on it was never reported.
    """
    if marker is None:
        return None
    for entry in DELIBERATE_VIOLATIONS:
        if entry.marker == marker:
            return entry
    return None


def registered_for(marker: str | None, invariant: str,
                   view: str = "decision") -> bool:
    """Is this violation of `invariant`, in this view, one the suite made.

    The view is part of the question. A record can carry a marker and sit in
    a view its entry says nothing about, which is exactly the `p3c3c-zero`
    record the backfill indexes into the decision view at its own transaction
    id: an ordinary row that happens to be marked.
    """
    entry = explains(marker)
    return (entry is not None
            and invariant in entry.breaks
            and entry.view == view)
