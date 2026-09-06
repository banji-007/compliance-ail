"""
tests/test_selector_clauses.py

D48 (Phase 3c-3g): a falsifier must fail when its own selector's clause is
deliberately broken.

**The regress this is bounded against.** D43 generalised constants to
guarantees, D46 generalised guarantees to selectors, and neither checks that a
falsifier can fail. The obvious next generalisation, "every falsifier in the
tree carries this check", needs an enumeration of falsifiers, which needs a
selector, which is the D46 defect one level up inside the file written to
close it. So the coverage here is a hand-list and says so. It is the
falsifiers in `tests/test_route_parity.py` and `tests/test_bounded_reads.py`,
the two files that implement D46. A falsifier elsewhere in the tree is not
covered, and nothing in this repository enumerates falsifiers tree-wide. That
limit is stated in the phase report's Residual Limits rather than implied by
silence here.

**Per clause, not per selector.** The first draft of D48 said "break the
selector". Measured against `_service_routes`, gutting it to `return []`
already failed its falsifier before this phase began, while dropping one
conjunct left `tests/test_route_parity.py` at `13 passed`, byte-identical to
baseline. The coarsest break is the easiest to catch and the defect lived in
one clause, so the unit is the clause.

Two things a coarse break also showed, and that shape the check below:

  * Gutting `_service_routes` took the file from thirteen outcomes to eight.
    Five parametrised cases were never generated, because they parametrise
    over an empty `write_routes()`. A broken selector can delete the tests
    that would catch it rather than fail them, so this check pins a node id
    and requires it to run and fail. A node id that vanishes reports as
    "no tests ran", which is a failure of this check, not a pass.
  * One of that break's two failures was
    `test_the_write_routes_are_selected_by_their_gate_and_not_by_their_path`
    failing on its `assert gates`, which is not a falsifier. A check phrased
    as "break it and require some failure" is therefore satisfiable with no
    falsifier in existence. Counting failures is the wrong instrument; the
    pairing is by name.

**Three states, not two**, matching `tests/test_bounded_reads.py`. A clause
either has a falsifier that fails when it is broken, or it does not apply
with its measured reason recorded here, or it is missing, and missing fails.
`does_not_apply` is not a note: the check still runs the break and asserts
that the recorded outcome is the one that actually happens, so an exemption
that stops being true fails here.

**How this file's own coverage is established, and whether that was
mutation-driven.** It is not established by anything derived. `D48_CLAUSES`
below is typed out by hand, and
`test_every_clause_of_a_covered_selector_has_a_recorded_state` compares it
against a hand-typed second list of the clauses in each covered selector,
`CLAUSES_IN_THE_COVERED_SELECTORS`. Two hand-lists that must agree is weaker
than a derivation and stronger than one hand-list, and it is honest about
which it is: nothing here parses the selectors to find their conjuncts.
Deriving them would need a selector over selectors, which is the regress
above at level four. This is stated as the answer to D48's own failure
condition rather than left for a later pass to discover.
"""

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

_GATE_CLAUSE = '"_require_write_key" in _gate_names(route)'


@dataclass(frozen=True)
class Clause:
    """One discriminating clause of one selector, and its state."""

    id: str
    module: str           # the test module the selector lives in
    attribute: str        # the module attribute the plugin rebinds
    selector: str         # the selector this clause belongs to, for reading
    clause: str           # the clause itself, as written in the source
    broken: Callable      # original -> a replacement with the clause broken
    falsifier: str = ""   # pinned node id that must run and fail
    does_not_apply: str = ""
    expected_outcome: str = "failed"


# ---------------------------------------------------------------------------
# The breaks. Each takes the real function and returns one with a single
# clause removed or replaced, and nothing else changed.
# ---------------------------------------------------------------------------

def _drop_the_apiroute_conjunct(original):
    """`isinstance(route, APIRoute)` removed from `_service_routes`."""

    def broken(verifier):
        return list(verifier.app.routes)

    return broken


def _select_write_routes_by_path(original):
    """The gate conjunct in `write_routes` replaced by a path substring."""

    def broken(verifier):
        import test_route_parity as parity

        return {route.path: route
                for route in parity._service_routes(verifier)
                if "write" in route.path}

    return broken


D48_CLAUSES = (
    Clause(
        id="route_parity:_service_routes:isinstance",
        module="test_route_parity",
        attribute="_service_routes",
        selector="_service_routes",
        clause="isinstance(route, APIRoute)",
        broken=_drop_the_apiroute_conjunct,
        falsifier=("tests/test_route_parity.py::"
                   "test_a_framework_route_is_not_in_the_site_list"),
    ),
    Clause(
        id="route_parity:write_routes:gate",
        module="test_route_parity",
        attribute="write_routes",
        selector="write_routes",
        clause=_GATE_CLAUSE,
        broken=_select_write_routes_by_path,
        falsifier=("tests/test_route_parity.py::"
                   "test_the_selector_is_the_gate_and_not_the_path"),
    ),
)


# The second hand-list. Every discriminating clause of every selector this
# phase covers, typed out from the source rather than derived from it. Its
# only job is to disagree with D48_CLAUSES when a clause is added to a
# selector and no state is recorded for it.
CLAUSES_IN_THE_COVERED_SELECTORS = {
    "test_route_parity._service_routes": ("isinstance(route, APIRoute)",),
    "test_route_parity.write_routes": (_GATE_CLAUSE,),
}


def clause_by_id(clause_id: str) -> Clause:
    for clause in D48_CLAUSES:
        if clause.id == clause_id:
            return clause
    raise KeyError("no D48 clause with id " + repr(clause_id))


def _run_with_clause_broken(clause: Clause) -> subprocess.CompletedProcess:
    """Run the pinned node id in a subprocess with the clause broken."""
    env = dict(os.environ)
    env["AIL_D48_CLAUSE"] = clause.id
    env["PYTHONPATH"] = os.pathsep.join(
        [str(REPO_ROOT / "tests"), str(REPO_ROOT), env.get("PYTHONPATH", "")])
    target = clause.falsifier or ("tests/" + clause.module + ".py")
    return subprocess.run(
        [sys.executable, "-m", "pytest", target,
         "-q", "-p", "no:randomly", "-p", "d48_break"],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=900)


def _outcome_of(result: subprocess.CompletedProcess) -> str:
    text = result.stdout + result.stderr
    if "error during collection" in text or "errors during collection" in text:
        return "collection_error"
    if "no tests ran" in text:
        return "no_tests_ran"
    if " failed" in text:
        return "failed"
    if " passed" in text:
        return "passed"
    return "unknown"


@pytest.mark.parametrize("clause",
                         [c for c in D48_CLAUSES if c.falsifier],
                         ids=lambda c: getattr(c, "id", "no-clause-in-this-state"))
def test_breaking_a_clause_fails_its_pinned_falsifier(clause):
    """The check D48 is: break the clause, the named falsifier must fail.

    Both halves are asserted. The falsifier has to have run, and it has to
    have failed. A selector break that empties a parametrisation removes the
    cases that would have caught it, and "0 collected" is not a pass.
    """
    result = _run_with_clause_broken(clause)
    outcome = _outcome_of(result)
    transcript = (result.stdout + result.stderr)[-3000:]

    assert outcome != "no_tests_ran", (
        clause.id + ": with the clause broken, " + clause.falsifier + " did "
        "not run at all. A selector break that deletes the test which would "
        "catch it reads green by count. This is a failure of the check, not "
        "a pass.\n" + transcript)
    assert outcome == "failed", (
        clause.id + ": " + clause.falsifier + " did not fail with the clause "
        + clause.clause + " broken. It reported " + repr(outcome) + ". A "
        "falsifier that passes when the thing it falsifies is broken is not "
        "a falsifier.\n" + transcript)


@pytest.mark.parametrize("clause",
                         [c for c in D48_CLAUSES if c.does_not_apply],
                         ids=lambda c: getattr(c, "id", "no-clause-in-this-state"))
def test_a_clause_recorded_as_not_falsifiable_still_behaves_that_way(clause):
    """An exemption here is measured on every run, not described once.

    `tests/test_bounded_reads.py` records selector-true property-false sites
    with their reasons; this is the same three-state design, with the
    difference that the recorded state is re-established rather than trusted.
    If breaking this clause starts failing a falsifier, or starts passing,
    the recorded reason is out of date and this fails.
    """
    result = _run_with_clause_broken(clause)
    outcome = _outcome_of(result)
    transcript = (result.stdout + result.stderr)[-3000:]

    assert outcome == clause.expected_outcome, (
        clause.id + " is recorded as not falsifiable, with this reason:\n\n  "
        + clause.does_not_apply + "\n\nBreaking it was recorded as producing "
        + repr(clause.expected_outcome) + " and produced " + repr(outcome)
        + ". Either the exemption is stale or the clause now has a falsifier "
        "and should carry it.\n" + transcript)


def test_every_clause_of_a_covered_selector_has_a_recorded_state():
    """Missing is the third state, and missing fails.

    The two lists are both hand-typed. That is the honest description of this
    file's coverage and it is what the phase report says: nothing here parses
    a selector to find its conjuncts, because deriving them needs a selector
    over selectors.
    """
    recorded = {}
    for clause in D48_CLAUSES:
        key = clause.module + "." + clause.selector
        recorded.setdefault(key, set()).add(clause.clause)

    missing = []
    for selector, clauses in CLAUSES_IN_THE_COVERED_SELECTORS.items():
        for clause in clauses:
            if clause not in recorded.get(selector, set()):
                missing.append(selector + ": " + clause)
    assert not missing, (
        "clause(s) of a covered selector have no state in D48_CLAUSES: "
        + repr(missing) + ". A clause with no recorded state defaults "
        "silently to whichever state the author had in mind, which is how a "
        "selector acquires a discriminator nobody decided about.")

    stale = []
    for selector, clauses in recorded.items():
        known = set(CLAUSES_IN_THE_COVERED_SELECTORS.get(selector, ()))
        for clause in clauses - known:
            stale.append(selector + ": " + clause)
    assert not stale, (
        "D48_CLAUSES records clause(s) that the covered selectors no longer "
        "have: " + repr(stale) + ". An entry outliving its clause is an "
        "entry for whatever lands on that name next.")


def test_every_clause_has_exactly_one_state():
    """A clause carrying both a falsifier and an exemption records nothing."""
    both = [c.id for c in D48_CLAUSES if c.falsifier and c.does_not_apply]
    neither = [c.id for c in D48_CLAUSES
               if not c.falsifier and not c.does_not_apply]
    assert not both, "clause(s) recorded in two states at once: " + repr(both)
    assert not neither, (
        "clause(s) recorded in no state at all: " + repr(neither)
        + ". Missing is a state and it fails here.")
