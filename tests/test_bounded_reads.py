"""tests/test_bounded_reads.py - Phase 3c-3e (D43 applied to D42, P3c3e-4).

Every bounded read in this repository asserts on what came back, and the list
of bounded reads is derived from the source rather than typed here.

**The defect this closes is the enumeration, not the two reads.** D42 (Phase
3c-3d) established the rule - a read that asks the ledger for a bounded set
checks that what came back is inside the bound, because an unrecognised or
misspelled parameter is dropped by ImmuDB's REST route without comment and a
bounded read silently becomes an unbounded one at HTTP 200. Two reads were
given the assertion and the phase report claimed "both forms implemented; no
third thing invented". There were four, and the two that were missed are the
two that decide what a backfill pass writes into a view index:

    3. tools/ail_backfill_index.py::indexed_keys - the SAME minScore bound
       RETURNED, no complaint: ['tool_call:a', 'tool_call:b']
       (the second page's score is 1.0 for a minScore of 500.0)

    4. tools/ail_backfill_index.py::scan_all - bounded by a PREFIX
       asked for prefix 'tool_call:', RETURNED, no complaint:
          ail_seq:counter / ail_seq:reserve / ledger_fault:... / content_erasure:abc

`indexed_keys` is the snapshot of what a view already holds, and an
incomplete snapshot indexes records a second time: measured at 25 records
holding two positions each from one pass over 2535 rows, which is the
condition that kills `/audit` with `audit_ordering_fault` at every limit,
permanently. `scan_all`'s results are zAdded directly, so a dropped prefix
bound indexes the sequence counter, the reserve, fault records and erasure
tombstones into the decision view, each of which then becomes a page row.

**How the list is derived.** Every call in this repository to
`/api/v2/db/scan` or `/api/v2/db/zscan` whose request body carries at least
one selective bound - `prefix`, `seekKey`, `endKey`, `minScore`, `maxScore` -
is a bounded read. `set`, `limit` and `desc` are not selective bounds: `set`
names the collection, `desc` names an order, and `limit` truncates, which is
a bound whose violation is a superset the caller already handles by paging.
That discriminator is what makes this a derivation rather than a list:
`control_plane/main.py::_zscan_view` issues a zscan and is correctly absent,
because it asks for a whole view and a page limit and nothing else.

**Three states, as D43 requires.** A derived site is either driven here, or
recorded as not applicable with its reason, or missing - and missing fails.

**What this derivation does not see, stated rather than implied.** It reads
the call site, so a read issued through a local helper that takes its bound
as a keyword argument is invisible to it:
`tools/immudb_ordering_probe.py::zscan` posts a body it builds from
`payload.update(body)`, and its callers pass `minScore` in. That is one probe
script whose subject is ImmuDB's own behaviour, and the honest statement is
that a bounded read hidden behind an argument-taking helper would not be
enumerated here. Nothing in the four production reads has that shape.

**What a driver asserts.** The function is executed against a client that
answers with a row outside the bound it was asked for, which is exactly what
a dropped bound looks like from inside the function, and the function has to
complain. Complaining takes the form the function's own error handling
takes: raising for the two that raise, and a `malformed` finding for the
reconciler, which reports rather than raises because a pass that dies on one
row reports nothing about any of the others.
"""

from __future__ import annotations

import ast
import base64
import importlib.util
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
# Explicit, not inherited: verifier/main.py and control_plane/main.py both
# import `provenance`, which lives at the repository root. Relying on some
# earlier test module to have put it on the path is a dependence on
# collection order, which is the class D44 is about.
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tools"))

# The parameters that select a subset of the ledger. A read carrying one of
# these is asking for less than everything, and that request can be silently
# dropped on the wire.
SELECTIVE_BOUNDS = ("prefix", "seekKey", "endKey", "minScore", "maxScore")

# The routes a bounded read goes to. Both cap at 2500 rows and both answer
# 200 for a parameter they did not recognise.
BOUNDED_ROUTES = ("/api/v2/db/scan", "/api/v2/db/zscan")


# ---------------------------------------------------------------------------
# The site list, derived from the source.
# ---------------------------------------------------------------------------

def _module_files() -> list[Path]:
    """Every Python module in this repository that is not a test.

    Deliberately not a list of directories: a bounded read added in a new
    package is a site this file has to see, and a directory list is the same
    hand-maintained enumeration one level up.
    """
    skip = {".git", "tests", "__pycache__", "node_modules", ".venv", "venv"}
    return sorted(path for path in REPO_ROOT.rglob("*.py")
                  if not (set(path.relative_to(REPO_ROOT).parts) & skip))


def _string_of(node) -> str:
    """The literal text of a str or f-string node, with holes for the
    substitutions. `f"{IMMUDB_URL}/api/v2/db/scan"` has to match."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(_string_of(part) for part in node.values)
    return ""


def _bound_keys(call: ast.Call) -> set[str]:
    """Which selective bounds this call's request body carries.

    Read from the `json=` keyword, whether the body is written inline or
    assigned to a name first and then mutated - `body["minScore"] = ...` is
    how both of the reads in tools/ are written, so a check that only saw
    inline dict literals would miss exactly the two this file exists for.
    That is why the enclosing function is scanned rather than the call node
    alone.
    """
    keys: set[str] = set()
    for keyword in call.keywords:
        if keyword.arg != "json":
            continue
        if isinstance(keyword.value, ast.Dict):
            for key in keyword.value.keys:
                keys.add(_string_of(key))
    return keys & set(SELECTIVE_BOUNDS)


@dataclass(frozen=True)
class Site:
    module: str
    function: str
    line: int
    bounds: tuple[str, ...]

    @property
    def name(self) -> str:
        return f"{self.module}::{self.function}"


def bounded_read_sites() -> list[Site]:
    """Every bounded read in the repository, from the source."""
    sites: list[Site] = []
    for path in _module_files():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        relative = path.relative_to(REPO_ROOT).as_posix()

        # Which function each node is inside, innermost first, so a site is
        # attributed rather than merely counted. Innermost matters: both cost
        # probes wrap their reads in a nested helper inside `main`, and
        # attributing them to `main` collapses two distinct reads onto one
        # name and hides whichever is added next.
        enclosing: dict[int, str] = {}
        owners: dict[str, ast.AST] = {}

        def _attribute(node, name):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    owners[child.name] = child
                    _attribute(child, child.name)
                else:
                    enclosing[id(child)] = name
                    _attribute(child, name)

        _attribute(tree, "<module>")

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            target = ""
            if node.args:
                target = _string_of(node.args[0])
            if not any(route in target for route in BOUNDED_ROUTES):
                continue
            function = enclosing.get(id(node), "<module>")
            # The bounds may be set on a dict built earlier in the same
            # function, so the whole function is scanned for assignments into
            # the body as well as the call's own literal.
            keys = _bound_keys(node)
            owner = owners.get(function)
            if owner is not None:
                for inner in ast.walk(owner):
                    if isinstance(inner, ast.Assign):
                        for goal in inner.targets:
                            if (isinstance(goal, ast.Subscript)
                                    and _string_of(goal.slice) in SELECTIVE_BOUNDS):
                                keys.add(_string_of(goal.slice))
                    if isinstance(inner, ast.Dict):
                        for key in inner.keys:
                            if _string_of(key) in SELECTIVE_BOUNDS:
                                keys.add(_string_of(key))
            if not keys:
                continue
            sites.append(Site(relative, function, node.lineno,
                              tuple(sorted(keys))))
    return sites


# ---------------------------------------------------------------------------
# Loading the modules the drivers execute.
# ---------------------------------------------------------------------------

def _load(name: str, relative: str):
    """One module under its own name; same reasoning as
    tests/test_ledger_vocabulary.py::_load."""
    sys.path.insert(0, str(REPO_ROOT / "control_plane"))
    os.environ.setdefault("CONTROL_PLANE_READ_KEY", "test-read-key")
    os.environ.setdefault("CONTROL_PLANE_WRITE_KEY", "test-write-key")
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class _Answer:
    """One canned HTTP response."""

    def __init__(self, payload: dict, status: int = 200):
        self._payload = payload
        self.status_code = status
        self.text = json.dumps(payload)

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def _b64(value) -> str:
    raw = value if isinstance(value, bytes) else value.encode()
    return base64.b64encode(raw).decode()


# ---------------------------------------------------------------------------
# The drivers. One per bounded read, each answering outside the bound the
# function asked for.
# ---------------------------------------------------------------------------

def _drive_faults_in_tx_window():
    control_plane = _load("bounded_control_plane", "control_plane/main.py")
    outside = control_plane._fault_key_tx_bound(10 ** 6) + ":x:y"

    class _AnswersOutsideTheWindow:
        def post(self, url, json=None, headers=None):
            return _Answer({"entries": [{"key": _b64(outside), "value": "",
                                         "tx": "1"}]})

    with pytest.raises(control_plane.BoundedReadFault):
        control_plane._faults_in_tx_window(_AnswersOutsideTheWindow(), "token", 1, 2)


def _drive_collect_positions():
    anchor = _load("bounded_anchor", "anchor_service/main.py")
    pages = []

    class _AnswersBelowTheMinScore:
        def post(self, url, json=None, headers=None):
            requested = (json or {}).get("minScore")
            pages.append(requested)
            if requested is None:
                # First page: fills to the ceiling so the walk asks for a
                # second one with a minScore bound.
                rows = [{"score": 500.0,
                         "entry": {"key": _b64(f"tool_call:{i}"), "tx": "1"}}
                        for i in range(anchor._ZSCAN_PAGE)]
                return _Answer({"entries": rows})
            return _Answer({"entries": [
                {"score": 1.0, "entry": {"key": _b64("tool_call:below"),
                                         "tx": "1"}},
            ]})

    result = anchor.collect_positions(_AnswersBelowTheMinScore(), {})
    reasons = [finding["reason"] for view in result.values()
               for finding in view["malformed"]]
    assert "score_outside_requested_bound" in reasons, (
        "a row scored below the minScore this read asked for was accepted "
        f"without a finding: {result}"
    )


def _drive_indexed_keys():
    import ail_backfill_index as backfill

    class _AnswersBelowTheMinScore:
        def post(self, url, json=None, headers=None):
            if (json or {}).get("minScore") is None:
                rows = [{"score": 500.0, "entry": {"key": _b64(f"tool_call:{i}")},
                         "key": _b64(f"tool_call:{i}")}
                        for i in range(backfill.SCAN_PAGE)]
                return _Answer({"entries": rows})
            return _Answer({"entries": [
                {"score": 1.0, "key": _b64("tool_call:below"),
                 "entry": {"key": _b64("tool_call:below")}},
            ]})

    with pytest.raises(SystemExit) as refused:
        backfill.indexed_keys(_AnswersBelowTheMinScore(), {},
                              "ail_view:decision:v1")
    message = str(refused.value)
    assert "outside" in message or "bound" in message, (
        "the refusal does not say the bound was not applied: " + message
    )


def _drive_scan_all():
    import ail_backfill_index as backfill

    class _AnswersOutsideThePrefix:
        def post(self, url, json=None, headers=None):
            return _Answer({"entries": [
                {"key": _b64("ail_seq:commit"), "value": _b64("1"), "tx": "1"},
            ]})

    with pytest.raises(SystemExit) as refused:
        backfill.scan_all(_AnswersOutsideThePrefix(), {}, "tool_call:")
    message = str(refused.value)
    assert "outside" in message or "prefix" in message, (
        "the refusal does not say the bound was not applied: " + message
    )


@dataclass
class Coverage:
    """One bounded read's state: driven, or recorded as not applying."""
    driver: callable = None
    does_not_apply: str = ""


# One entry per derived site. A site with no entry fails the enumeration
# below, which is the whole point of deriving the sites.
COVERAGE: dict[str, Coverage] = {
    "control_plane/main.py::_faults_in_tx_window":
        Coverage(driver=_drive_faults_in_tx_window),
    "anchor_service/main.py::collect_positions":
        Coverage(driver=_drive_collect_positions),
    "tools/ail_backfill_index.py::indexed_keys":
        Coverage(driver=_drive_indexed_keys),
    "tools/ail_backfill_index.py::scan_all":
        Coverage(driver=_drive_scan_all),
    "tools/ail_ordering_cost_probe.py::key_walk":
        Coverage(does_not_apply=(
            "a timing probe. The response is raise_for_status()'d and "
            "discarded without a single row being read, so a bound that did "
            "not survive changes what the call costs and nothing else. "
            "Nothing downstream can be misled by rows this call never "
            "looks at.")),
    "tools/audit_read_cost_probe.py::scan":
        Coverage(does_not_apply=(
            "the same, in the read-cost probe: the lambda it returns "
            "raise_for_status()'es and discards. It exists to time the key "
            "walk `/audit` used to do against the ordered select that "
            "replaced it.")),
    "tools/immudb_ordering_probe.py::<module>":
        Coverage(does_not_apply=(
            "a probe script that measures ImmuDB's own behaviour and prints "
            "it - which scores zscan omits under desc, where the 2500 "
            "ceiling is, whether a prefix scan inflates with versions. Its "
            "subject IS what the bound does, so asserting the bound held "
            "would assert the answer it was written to find out.")),
    "tools/immudb_read_api_probe.py::<module>":
        Coverage(does_not_apply=(
            "the same: a probe recording which read routes exist and what "
            "their ceilings are. Its findings are the source of the 2500 "
            "constant three modules now hold, and it decides nothing at "
            "runtime.")),
}


# ---------------------------------------------------------------------------
# The enumeration.
# ---------------------------------------------------------------------------

def test_the_derivation_finds_the_reads_it_is_supposed_to_find():
    """The discriminator, asserted.

    A derivation that silently found nothing would make every test below
    vacuous, and one that swept in every read would make the coverage table
    a list of exemptions. Both halves are checked: the four production reads
    are found, and `_zscan_view` - a zscan carrying no selective bound - is
    not.
    """
    found = {site.name for site in bounded_read_sites()}
    for expected in ("control_plane/main.py::_faults_in_tx_window",
                     "anchor_service/main.py::collect_positions",
                     "tools/ail_backfill_index.py::indexed_keys",
                     "tools/ail_backfill_index.py::scan_all"):
        assert expected in found, (
            f"the derivation did not find {expected}, which is a bounded read. "
            f"It found: {sorted(found)}"
        )
    assert "control_plane/main.py::_zscan_view" not in found, (
        "_zscan_view asks for a whole view at a page limit and carries no "
        "selective bound, so sweeping it in would make this file's rule "
        "'every read' rather than 'every bounded read'"
    )


def test_every_bounded_read_has_a_recorded_state():
    """The enumeration. A bounded read with no entry fails here.

    This is the test the phase's own mutation targets from the other side: a
    new bounded read anywhere in the repository fails this file without it
    being edited.
    """
    missing = sorted({f"{site.name} (bounds: {', '.join(site.bounds)})"
                      for site in bounded_read_sites()
                      if site.name not in COVERAGE})
    assert not missing, (
        f"bounded read(s) with no recorded state: {missing}. Each one is "
        "either driven with a client that answers outside its bound, or "
        "recorded as not applying with a reason. D42 was claimed complete "
        "with two of four covered because nothing enumerated the four."
    )


def _driven():
    return sorted(name for name, cover in COVERAGE.items() if cover.driver)


@pytest.mark.parametrize("name", _driven())
def test_the_bounded_read_asserts_its_bound(name):
    """Each read, executed against a client answering outside its bound.

    An unrecognised or misspelled parameter is dropped by ImmuDB's REST
    route without comment, so this is exactly what a bound that did not
    survive looks like from inside the function. Measured on the wire:

        correct  endKey : ['00'..'06']
        misspelt endkey : ['00'..'09']
    """
    COVERAGE[name].driver()


def test_a_read_recorded_as_not_applying_says_why():
    """The third state is a recorded decision, not an omission."""
    thin = [name for name, cover in COVERAGE.items()
            if not cover.driver and len(cover.does_not_apply.strip()) < 80]
    assert not thin, (
        f"a bounded read recorded as not applying gives no reason worth the "
        f"name: {thin}"
    )


def test_no_entry_in_the_table_names_a_read_that_no_longer_exists():
    """The table cannot rot in the other direction either.

    An entry for a read that has been deleted or renamed is an exemption
    nothing can see, and the next read that lands on that name inherits it.
    """
    found = {site.name for site in bounded_read_sites()}
    stale = sorted(set(COVERAGE) - found)
    assert not stale, (
        f"the coverage table names bounded read(s) that no longer exist: "
        f"{stale}"
    )
