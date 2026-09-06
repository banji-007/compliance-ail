"""
tests/test_bound_assertions_are_reached.py

P3c3g-2 (Phase 3c-3g), closing red-team R3: a bound assertion that never
compares a row.

**What R3 measured.** Sixteen calls to
`bounded_read_checks.assert_at_or_above_min_score` in a fully green run,
sixteen early returns on `min_score is None`, zero rows compared. Four of the
five sites are structurally vacuous: each is a page walk that opens with
`min_score = None`, passes it to the check, and terminates on the first page
short of the 2500 ceiling. Page one is the only page and page one carries no
bound. The fifth site is exercised only because
`tests/test_backfill_index.py::_pad_view_past_the_ceiling` takes the view past
2600 rows for an unrelated reason, and it compared 1148 rows on the strength
of that accident.

D46 enumerated the sites correctly and then wired them to a check that returns
before looking. Every one of them was green.

**The obvious fix is wrong.** Making the check run on page one checks nothing,
because page one carries no bound: the walk has not asked for anything yet, so
there is nothing for the answer to be outside of. Moving the `min_score`
update alone produces assertions that are no longer vacuous and still never
execute, because the walk still stops after one page.

**Non-vacuity requires the walk to actually page**, and today that happens
only when some other module has left more than 2500 rows in the view. That is
a fixture accident, not a guarantee, and it is exactly the collection-order
class D44 exists for. So each walk is driven here against a stub whose first
page fills to the ceiling, deterministically, with no ledger and no stack.

**The rule is over a walk's whole life, not per call.** An earlier draft of
this item said an assertion comparing zero rows is a failure. That breaks
every first page in the tree, forever, and would be implementable only by
weakening it back. `min_score` is None on the first iteration of every walk
and that is correct. The failure condition is a walk that never compares a
row **in any call, across its whole life**.

**What this does not establish.** That the five walks page against the real
ledger. They page here because a stub says so. What is enforced is that each
walk's second-page path exists, is reachable, and runs the assertion against
real rows when it is reached. Whether a given production view ever exceeds
2500 rows is a property of the ledger, not of the walk, and it is not asserted
anywhere.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import bounded_read_checks  # noqa: E402
from test_bounded_reads import _Answer, _b64, _load_test_module  # noqa: E402

# The ceiling every one of these walks pages at. Named once here rather than
# five times, and deliberately the same number the walks use: a stub that
# filled to a different ceiling would never trigger the second page and this
# whole file would pass while measuring nothing.
_CEILING = 2500


class _PagesAtOrAboveTheMinScore:
    """A zscan client that pages, and whose second page honours its bound.

    The sibling of `test_bounded_reads.py::_PagesBelowTheMinScore`, which
    answers *outside* the bound so the walk raises. This one answers inside
    it, so the walk completes and the assertion is reached with rows to
    compare. Both are needed and they check different things: that the check
    fires when the bound was dropped, and that the check runs at all.

    First-page scores ascend rather than being one repeated value. A walk
    takes its next `minScore` from the last row of the page it just read, so
    with a constant score the mutation this item names (moving the `min_score`
    update above the check) would compare every row against its own score and
    pass. Ascending scores make that mutation visible, which is the difference
    between a fixture and a fixture that can fail.
    """

    def __init__(self, page: int = _CEILING, key_field: str = "entry"):
        self._page = page
        self._key_field = key_field
        self.pages_served = 0

    def _row(self, name: str, score: float) -> dict:
        row = {"score": score, "entry": {"key": _b64(name), "tx": "1"}}
        if self._key_field == "flat":
            row["key"] = _b64(name)
        return row

    def post(self, url, json=None, headers=None):
        if "login" in url:
            return _Answer({"token": "t"})
        self.pages_served += 1
        requested = (json or {}).get("minScore")
        if requested is None:
            # Page one: full to the ceiling, so the walk asks for a second.
            return _Answer({"entries": [
                self._row(f"tool_call:{i}", float(i + 1))
                for i in range(self._page)]})
        # Page two: short, and every row at or above what was asked for, so
        # the walk terminates and the assertion has real rows to compare.
        floor = _min_score_of(requested)
        return _Answer({"entries": [
            self._row(f"tool_call:above{i}", floor + 1.0 + i)
            for i in range(8)]})

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _min_score_of(requested) -> float:
    """The score out of a `minScore`, in either spelling the walks use."""
    if isinstance(requested, dict):
        return float(requested.get("score", 0.0))
    return float(requested)


def _walk_view_invariants(module):
    return module._view_rows({}, module.VIEW_DECISION)


def _walk_backfill_index(module):
    return module._view_rows({})


def _walk_audit_ordering(module):
    return module._view_rows_paged({}, module.VIEW_DECISION)


def _walk_audit_read_correctness(module):
    return module._view_row_count(module.VIEW_DECISION)


def _walk_reconciliation(module):
    return module._positions_for_key("tool_call:x")


# One entry per `assert_at_or_above_min_score` call site in the tree. Five
# sites in five modules, hand-listed and checked against the source by
# `test_the_five_sites_are_the_sites_that_exist` below, so a sixth site added
# without an entry here fails rather than being silently uncovered.
WALKS = (
    ("tests/test_view_invariants.py::_view_rows",
     "test_view_invariants", _walk_view_invariants, "_CLIENT", {}),
    ("tests/test_backfill_index.py::_view_rows",
     "test_backfill_index", _walk_backfill_index, "_CLIENT", {}),
    ("tests/test_audit_ordering.py::_view_rows_paged",
     "test_audit_ordering", _walk_audit_ordering, "_CLIENT", {}),
    ("tests/test_audit_read_correctness.py::_view_row_count",
     "test_audit_read_correctness", _walk_audit_read_correctness, "httpx", {}),
    ("tests/test_reconciliation.py::_positions_for_key",
     "test_reconciliation", _walk_reconciliation, "_CLIENT",
     {"_immudb_headers": lambda: {}}),
)


def _drive(module_name: str, call, attribute: str, patches: dict,
           client=None):
    """Run one walk against a paging stub, and return what the check did."""
    module = _load_test_module(module_name)
    client = client if client is not None else _PagesAtOrAboveTheMinScore()

    saved = {name: getattr(module, name, None) for name in patches}
    original = getattr(module, attribute, None)
    for name, value in patches.items():
        setattr(module, name, value)
    if attribute == "httpx":
        from types import SimpleNamespace
        setattr(module, attribute,
                SimpleNamespace(Client=lambda **kw: client))
    else:
        setattr(module, attribute, client)
    try:
        with bounded_read_checks.recording() as tally:
            call(module)
    finally:
        setattr(module, attribute, original)
        for name, value in saved.items():
            setattr(module, name, value)
    return tally, client


@pytest.mark.parametrize(
    "name,module_name,call,attribute,patches", WALKS,
    ids=[entry[0] for entry in WALKS])
def test_the_walk_compares_a_row_somewhere_in_its_life(
        name, module_name, call, attribute, patches):
    """The whole-life rule. One vacuous call is fine; a walk of them is not.

    Driven against a stub that fills page one to the ceiling, so the second
    page is reached deterministically rather than because some other module
    left rows in a view.
    """
    tally, client = _drive(module_name, call, attribute, patches)

    assert client.pages_served >= 2, (
        f"{name}: the walk read {client.pages_served} page(s) against a stub "
        f"whose first page fills to {_CEILING}, so the second-page path never "
        "ran and this test is measuring nothing. The stub's ceiling and the "
        "walk's page limit have to be the same number."
    )
    assert tally.calls > 0, (
        f"{name}: the walk never called assert_at_or_above_min_score at all. "
        "It is recorded here as a site that asserts its bound."
    )
    assert tally.rows_compared > 0, (
        f"{name}: {tally}. Every call to the bound assertion returned early "
        "on min_score=None, so across this walk's whole life it compared no "
        "row against any bound. The assertion is enumerated, correct, and "
        "never executed, which is green either way."
    )


def test_the_five_sites_are_the_sites_that_exist():
    """The hand-list above against the source, so a sixth site fails here.

    Grepped rather than parsed, and that is a stated limit: a call reached
    through an alias of the check would not be found. Nothing in the tree
    spells it that way, and the alternative is an AST selector, which is one
    more selector needing its own falsifier.
    """
    called_in = set()
    for path in sorted((REPO_ROOT / "tests").glob("test_*.py")):
        text = path.read_text(encoding="utf-8")
        if "assert_at_or_above_min_score(" not in text:
            continue
        if path.name in ("test_bounded_reads.py",
                         "test_bound_assertions_are_reached.py"):
            continue
        called_in.add(path.name)

    listed = {entry[1] + ".py" for entry in WALKS}
    assert called_in == listed, (
        "the walks driven here and the modules that call the bound assertion "
        f"disagree. Calling it: {sorted(called_in)}. Driven: {sorted(listed)}. "
        "A site with no entry is a site whose assertion may never run."
    )
