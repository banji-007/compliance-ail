"""tests/bounded_read_checks.py - Phase 3c-3f (D46, P3c3f-3).

What a bounded read in this suite checks about what came back.

**Why this module exists.** `tests/` was excluded from
`tests/test_bounded_reads.py::_module_files()`, and that exclusion was a
selector with no falsifier. D46 says an exclusion inherits the decision, so
the walk includes `tests/` now - and it finds nine bounded reads in this
directory, seven of them the same paged view walk copied about. Each one
decides how many rows some assertion sees, and none of them checked that the
rows it got back were inside the bound it asked for.

`tests/test_view_invariants.py::_view_rows` is the one the Phase 3c-3e red
team named: it pages `ail_view:decision:v1` by `minScore` and is what all four
ledger-wide invariants read. An under-read there does not hang - the `seen`
set breaks the loop - it just makes an invariant hold over fewer rows than it
thinks, which is the condition D44 exists for.

**One copy of each check, imported.** This repository has paid twice for a
rule with two copies and nothing comparing them: the ledger vocabulary
constants, and the Compose project-name derivation that cost a CI run. Seven
near-identical page walks each growing their own bound assertion would be the
same bet a third time.

The checks raise `AssertionError`, which is what a test's own failure is. The
production reads under `tools/`, `control_plane/` and `anchor_service/` raise
`SystemExit` or a `BoundedReadFault` or report a `malformed` finding instead,
each for a reason its own module states; a test has no caller to report to.
"""

from __future__ import annotations


def assert_at_or_above_min_score(rows, min_score, where: str) -> None:
    """Every row is at or above the `minScore` this page asked for.

    ImmuDB's REST route drops an unrecognised or misspelled parameter without
    comment and answers 200, so this is exactly what a bound that did not
    survive looks like from inside the caller. Measured on the wire:

        correct  minScore : the page starts where it was asked to
        misspelt minscore : the page starts at the beginning again
    """
    if min_score is None:
        return
    below = [(key, score) for key, score in rows if score < min_score]
    assert not below, (
        f"{where}: a read bounded to minScore={min_score} returned "
        f"{len(below)} row(s) scored below it, first {below[:3]}. The bound "
        "was not applied, which on this route is an unbounded read at HTTP "
        "200, and what this walk returns decides how many rows the assertion "
        "above it sees."
    )


def assert_inside_score_window(rows, low, high, where: str) -> None:
    """Every row is inside the `[minScore, maxScore]` window asked for."""
    outside = [(key, score) for key, score in rows
               if (low is not None and score < low)
               or (high is not None and score > high)]
    assert not outside, (
        f"{where}: a read bounded to [{low}, {high}] returned {len(outside)} "
        f"row(s) outside it, first {outside[:3]}. The bound was not applied, "
        "so 'this key is at this position' is not what the answer means."
    )


def assert_under_prefix(keys, prefix: str, where: str) -> None:
    """Every key returned is under the prefix this scan asked for."""
    outside = [key for key in keys if not key.startswith(prefix)]
    assert not outside, (
        f"{where}: a scan bounded to prefix {prefix!r} returned "
        f"{len(outside)} key(s) outside it, first {outside[:3]}. The bound "
        "was not applied, so this read is a walk of the whole ledger wearing "
        "a prefix's name."
    )
