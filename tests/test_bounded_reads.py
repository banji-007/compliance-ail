"""tests/test_bounded_reads.py - Phase 3c-3e (D43/D42, P3c3e-4), 3c-3f (D46).

Every bounded read in this repository asserts on what came back, and the list
of bounded reads is derived from the source rather than typed here.

**The property, stated first and independently of the selector (D46).**

    A read is bounded when it asks the ledger for less than everything - a
    prefix, a key range, a score range. Every bounded read checks that what
    came back is inside the bound it asked for, because a bound that did not
    survive turns the read into an unbounded one with nothing saying so.

`BOUNDED_READ_PROPERTY` is that sentence as a value the tests quote. Note what
is not in it: HTTP, REST, a route name, a transport. The rule is about what a
read asks for, and the Phase 3c-3e selector was about how it asked.

**The selector, and its two falsifiers.** The selector below claims to cover
that property by walking the source for calls to ImmuDB's reads. It is a
claim, so both directions are falsified:

  * *satisfies the property, not the selector* - the Phase 3c-3e selector
    matched an `ast.Call` whose FIRST POSITIONAL argument was a string literal
    containing an ImmuDB REST scan route. **The verifier speaks gRPC only, so
    that selector produced zero sites in `verifier/main.py`** - including
    `_committed_position_for`, a bounded zScan added in the same phase under
    the same decision, which never read `entry.score` and returned the score
    it had asked for. Four spellings of an ordinary REST call were invisible
    too: `url=` as a keyword, the URL through a local name, the URL by
    concatenation, and the bound keyed by a name rather than a literal. And
    `tests/` was excluded outright, which hid
    `tests/test_view_invariants.py::_view_rows`, the read that decides how
    many rows all four ledger-wide invariants see.
    `test_the_derivation_finds_the_reads_no_route_literal_names` is that
    direction, and it names all three shapes.

  * *satisfies the selector, not the property* - the `does_not_apply` entries
    in `COVERAGE`. Each is a call the selector picks up and that the property
    does not reach, with the argument written down: timing and behaviour
    probes that discard every row they read, and the reads whose subject IS
    what the bound does. `test_a_read_recorded_as_not_applying_says_why` is
    that direction, and the three-state design it enforces is what D46 points
    at as the worked precedent for the other selector in this suite.

**Per bound, not per site (P3c3f-5).** `COVERAGE` used to be keyed by
`module::function` with nothing comparing the bounds a site carries against
the bounds its driver drives. `tools/ail_backfill_index.py::scan_all` carries
`prefix` and `seekKey`, had one driver for `prefix`, and was reported covered:
driven against a client that honoured the prefix and dropped the paging
parameter it returned 767 identical pages in eight seconds without refusing,
and its only loop exit is a short page. Each entry names the bounds it drives
now, and a bound with no driver fails the enumeration.

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

**How the list is derived.** Two shapes, because this repository reads the
ledger two ways.

  * **REST.** A call posting to `/api/v2/db/scan` or `/api/v2/db/zscan` whose
    request body carries at least one selective bound - `prefix`, `seekKey`,
    `endKey`, `minScore`, `maxScore`. The URL is read from the first
    positional argument or from `url=`, through f-strings, concatenation and
    one level of name resolution.
  * **gRPC.** A call to `scan`, `zScan` or `zscan` carrying one of the SDK's
    own bound keywords - `prefix`, `seekKey`, `seekScore`, `minscore`,
    `maxscore`.

`set`, `limit` and `desc` are not selective bounds in either spelling: `set`
names the collection, `desc` names an order, and `limit` truncates, which is
a bound whose violation is a superset the caller already handles by paging.
That discriminator is what makes this a derivation rather than a list:
`control_plane/main.py::_zscan_view` issues a zscan and is correctly absent,
because it asks for a whole view and a page limit and nothing else.

**Three states, as D43 requires.** A derived site is either driven here, or
recorded as not applicable with its reason, or missing - and missing fails.

**What this derivation does not see, stated rather than implied.**

  * It reads the call site, so a read issued through a local helper that takes
    its bound as a keyword argument is invisible to it:
    `tools/immudb_ordering_probe.py::zscan` posts a body it builds from
    `payload.update(body)`, and its callers pass `minScore` in. That is one
    probe script whose subject is ImmuDB's own behaviour, and the honest
    statement is that a bounded read hidden behind an argument-taking helper
    would not be enumerated here. Nothing in the production reads has that
    shape.
  * A gRPC bound passed positionally. `ImmudbClient.zScan` puts the bounds
    behind four other parameters, so nothing here writes one that way, and a
    walk that guessed at positions would attribute bounds that were not asked
    for.
  * Name resolution is one level. A URL or a bound key assigned from another
    name, rather than from a literal, resolves to nothing and the site is not
    attributed.

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
import functools
import importlib.util
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
# Explicit, not inherited: verifier/main.py and control_plane/main.py both
# import `provenance`, which lives at the repository root. Relying on some
# earlier test module to have put it on the path is a dependence on
# collection order, which is the class D44 is about.
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT / "tests"))

BOUNDED_READ_PROPERTY = (
    "A read is bounded when it asks the ledger for less than everything - a "
    "prefix, a key range, a score range. Every bounded read checks that what "
    "came back is inside the bound it asked for, because a bound that did not "
    "survive turns the read into an unbounded one with nothing saying so."
)

# The parameters that select a subset of the ledger. A read carrying one of
# these is asking for less than everything, and that request can be silently
# dropped on the wire.
#
# Two spellings of one set, because this repository reads the ledger two ways
# and the wire names differ. REST takes them in a JSON body; the gRPC SDK
# takes them as keyword arguments to ImmudbClient.scan / .zScan, where the
# score bounds are lower-cased and `endKey` does not exist.
REST_BOUNDS = ("prefix", "seekKey", "endKey", "minScore", "maxScore")
GRPC_BOUNDS = ("prefix", "seekKey", "seekScore", "minscore", "maxscore")
SELECTIVE_BOUNDS = tuple(sorted(set(REST_BOUNDS) | set(GRPC_BOUNDS)))

# The routes a bounded read goes to over REST. Both cap at 2500 rows and both
# answer 200 for a parameter they did not recognise.
BOUNDED_ROUTES = ("/api/v2/db/scan", "/api/v2/db/zscan")

# And the SDK methods that are the same reads over gRPC. Matched on the
# attribute name, because the object they are called on is a client this
# repository never names consistently (`client`, `self._client`, a parameter).
GRPC_READS = ("scan", "zScan", "zscan")


# ---------------------------------------------------------------------------
# The site list, derived from the source.
# ---------------------------------------------------------------------------

def _module_files() -> list[Path]:
    """Every Python module in this repository.

    Deliberately not a list of directories: a bounded read added in a new
    package is a site this file has to see, and a directory list is the same
    hand-maintained enumeration one level up.

    **`tests/` is walked (P3c3f-3, Phase 3c-3f).** It used to be excluded, and
    that exclusion was a selector with no falsifier: D46 says an exclusion
    inherits the decision. `tests/test_view_invariants.py::_view_rows` pages a
    view with `minScore` and never checked that a returned row was at or above
    the score it asked for, and that read decides how many rows all four
    ledger-wide invariants see - an invariant over fewer rows than it thinks
    is the condition D44 exists for. A read in a test is still a read.
    """
    skip = {".git", "__pycache__", "node_modules", ".venv", "venv"}
    return sorted(path for path in REPO_ROOT.rglob("*.py")
                  if not (set(path.relative_to(REPO_ROOT).parts) & skip))


def _string_of(node, names: dict[str, str] | None = None) -> str:
    """The literal text of a string-valued expression, with holes for the
    substitutions.

    `f"{IMMUDB_URL}/api/v2/db/scan"` has to match, and so do the three
    spellings the Phase 3c-3e red team used to hide a REST read from this
    walk, each of which returned `""` here:

        endpoint = f"{IMMUDB_URL}/api/v2/db/scan"   a Name
        IMMUDB_URL + "/api/v2/db/scan"              a BinOp
        body[_BOUND] = ...                          a Name as a subscript

    `names` is what a Name resolves against: the string-valued assignments in
    the module and in the enclosing function. Resolution is one level and
    deliberately so - a name assigned from another name is not followed, and
    a read hidden behind two hops is in the stated limits below rather than
    silently attributed.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(_string_of(part, names) for part in node.values)
    if isinstance(node, ast.FormattedValue):
        return ""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _string_of(node.left, names) + _string_of(node.right, names)
    if isinstance(node, ast.Name) and names:
        return names.get(node.id, "")
    return ""


def _string_bindings(tree, names: dict[str, str]) -> None:
    """Every `name = <string expression>` under `tree`, into `names`."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        text = _string_of(node.value, names)
        if not text:
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                names[target.id] = text


def _rest_target(call: ast.Call, names: dict[str, str]) -> str:
    """Where this call posts: the first positional argument, or `url=`.

    `httpx.Client.post` takes the URL either way and this repository uses
    both, so reading only `args[0]` made a keyword spelling of the same call
    invisible.
    """
    if call.args:
        target = _string_of(call.args[0], names)
        if target:
            return target
    for keyword in call.keywords:
        if keyword.arg == "url":
            return _string_of(keyword.value, names)
    return ""


def _bound_keys(call: ast.Call, names: dict[str, str]) -> set[str]:
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
                keys.add(_string_of(key, names))
    return keys & set(REST_BOUNDS)


def _grpc_bound_keys(call: ast.Call) -> set[str]:
    """Which selective bounds a gRPC scan/zScan call carries, by keyword.

    Keywords only. The SDK's positional order puts `zset` and `key` first and
    the bounds behind four other parameters, so a positional bound would be
    unreadable here as well as unreadable to anyone; nothing in this
    repository writes one, and that is a stated limit rather than an
    assumption.
    """
    return {keyword.arg for keyword in call.keywords
            if keyword.arg in GRPC_BOUNDS}


@dataclass(frozen=True)
class Site:
    module: str
    function: str
    line: int
    bounds: tuple[str, ...]
    transport: str = "rest"

    @property
    def name(self) -> str:
        return f"{self.module}::{self.function}"


@functools.lru_cache(maxsize=1)
def bounded_read_sites() -> tuple[Site, ...]:
    """Every bounded read in the repository, from the source.

    Two transports, one property. A REST site is a call posting to one of
    `BOUNDED_ROUTES` with a selective bound in its body; a gRPC site is a call
    to one of `GRPC_READS` carrying a selective bound as a keyword. The second
    half is P3c3f-3: the verifier reads the ledger over gRPC only, so a
    REST-shaped selector could not see any read it makes.

    Cached because the walk now covers `tests/` as well, which is about twelve
    seconds of parsing per pass and five passes in this module alone. `Site`
    is frozen and the result is a tuple, so the cache cannot be mutated by a
    caller.
    """
    sites: list[Site] = []
    for path in _module_files():
        try:
            source = path.read_text(encoding="utf-8")
        except OSError:
            continue
        sites.extend(_sites_in_source(source,
                                      path.relative_to(REPO_ROOT).as_posix()))
    return tuple(sites)


def _sites_in_source(source: str, relative: str) -> list[Site]:
    """The same derivation over one module's text.

    Separate from the walk so the falsifier below can run it over source
    written in the test rather than over a file in the tree: the four REST
    spellings the Phase 3c-3e derivation could not attribute are not how this
    repository writes its reads today, and putting them in the tree to test
    for them would be putting them in the tree.
    """
    sites: list[Site] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return sites

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

    # Module-level string constants first, so `IMMUDB_URL` and `_BOUND`
    # resolve wherever they are used.
    module_names: dict[str, str] = {}
    _string_bindings(tree, module_names)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = enclosing.get(id(node), "<module>")
        owner = owners.get(function)
        names = dict(module_names)
        if owner is not None:
            _string_bindings(owner, names)

        # --- gRPC: client.zScan(minscore=..., maxscore=...) ------------
        attribute = getattr(node.func, "attr", None)
        if attribute in GRPC_READS:
            keys = _grpc_bound_keys(node)
            if keys:
                sites.append(Site(relative, function, node.lineno,
                                  tuple(sorted(keys)), "grpc"))
            continue

        # --- REST: a post to one of the two scan routes ----------------
        target = _rest_target(node, names)
        if not any(route in target for route in BOUNDED_ROUTES):
            continue
        # The bounds may be set on a dict built earlier in the same
        # function, so the whole function is scanned for assignments into
        # the body as well as the call's own literal.
        keys = _bound_keys(node, names)
        if owner is not None:
            for inner in ast.walk(owner):
                if isinstance(inner, ast.Assign):
                    for goal in inner.targets:
                        if (isinstance(goal, ast.Subscript)
                                and _string_of(goal.slice, names) in REST_BOUNDS):
                            keys.add(_string_of(goal.slice, names))
                if isinstance(inner, ast.Dict):
                    for key in inner.keys:
                        if _string_of(key, names) in REST_BOUNDS:
                            keys.add(_string_of(key, names))
        if not keys:
            continue
        sites.append(Site(relative, function, node.lineno,
                          tuple(sorted(keys)), "rest"))
    return sites


# ---------------------------------------------------------------------------
# Loading the modules the drivers execute.
# ---------------------------------------------------------------------------

def _derivation_over(source: str) -> set[str]:
    """The derivation, over source written here rather than over the tree."""
    return {site.name for site in _sites_in_source(source, "<probe>")}


# The four spellings the Phase 3c-3e derivation could not attribute. Each one
# is an ordinary bounded read, and each one defeated a different part of the
# old walk: three of them made `_string_of(node.args[0])` return "" (a Name, a
# BinOp, an absent positional), and the fourth spelled the URL exactly as the
# walk expected and was dropped because the BOUND was keyed by a name.
#
# Written as a string, not as functions in this module, so the test asserts
# that the derivation attributes them rather than that this file contains
# them. A red team injected them into `control_plane/main.py` and the suite
# read `8 passed` with none attributed.
_SPELLINGS_SOURCE = '''
IMMUDB_URL = "http://immudb:8080"
_BOUND = "prefix"


def redteam_read_kwarg_url(client, headers):
    return client.post(url=f"{IMMUDB_URL}/api/v2/db/scan",
                       json={"prefix": "x", "limit": 100})


def redteam_read_named_url(client, headers):
    endpoint = f"{IMMUDB_URL}/api/v2/db/scan"
    return client.post(endpoint, json={"prefix": "x", "limit": 100})


def redteam_read_concat_url(client, headers):
    return client.post(IMMUDB_URL + "/api/v2/db/scan",
                       json={"prefix": "x", "limit": 100})


def redteam_read_named_bound(client, headers):
    body = {"limit": 100}
    body[_BOUND] = "x"
    return client.post(f"{IMMUDB_URL}/api/v2/db/scan", json=body)
'''


def _load_verifier_module():
    """The verifier, imported under its own name.

    The same technique `tests/test_route_parity.py::_load_verifier` uses and
    for the same reason: the module reads its writer key path once, at import,
    and exporting that into this process would change what every other
    in-process import of it does.
    """
    writer_key = REPO_ROOT / "keys" / "writer-verifier.key"
    os.environ.setdefault("VERIFIER_READ_KEY", "test-verifier-read-key")
    os.environ.setdefault("VERIFIER_WRITE_KEY", "test-verifier-write-key")
    previous = os.environ.get("AIL_WRITER_SIGNING_KEY")
    os.environ["AIL_WRITER_SIGNING_KEY"] = str(writer_key)
    try:
        return _load("bounded_verifier", "verifier/main.py")
    finally:
        if previous is None:
            os.environ.pop("AIL_WRITER_SIGNING_KEY", None)
        else:
            os.environ["AIL_WRITER_SIGNING_KEY"] = previous


def _load_test_module(name: str):
    """One of this directory's own modules, for the reads inside it.

    Imported rather than re-implemented: a driver that reproduced the read
    would be asserting about its own copy, which is the defect one level up
    from the one this file exists for.
    """
    if name in sys.modules:
        return sys.modules[name]
    return _load(name, f"tests/{name}.py")


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


def _drive_scan_all_seek_key():
    """`scan_all`'s SECOND bound, which nothing drove (P3c3f-5).

    A client that honours `prefix` and drops `seekKey` returns the same full
    page forever, and the loop's only exit is a short page. Measured before
    the assertion existed: 767 identical pages in eight seconds, no refusal,
    no termination, every row of every page accumulated into the list this
    function returns and zAdded into a view index by its caller.
    """
    import ail_backfill_index as backfill

    class _IgnoresSeekKey:
        """Honours `prefix`, drops `seekKey`, and gives up after 50 pages.

        The page budget is the difference between this test failing and this
        test hanging: without the assertion the walk never terminates, and a
        driver that hangs is a driver nobody can run the mutation against.
        """

        def __init__(self):
            self.pages = 0

        def post(self, url, json=None, headers=None):
            self.pages += 1
            if self.pages > 50:
                raise RuntimeError(
                    "scan_all asked for 50 identical pages without refusing, "
                    "so the seekKey bound is not asserted on and the walk does "
                    "not terminate"
                )
            return _Answer({"entries": [
                {"key": _b64("tool_call:%06d" % i), "value": "", "tx": "1"}
                for i in range(backfill.SCAN_PAGE)]})

    client = _IgnoresSeekKey()
    with pytest.raises(SystemExit) as refused:
        backfill.scan_all(client, {}, "tool_call:")
    message = str(refused.value)
    assert "seekKey" in message or "sort above" in message, (
        "the refusal does not say the paging bound was not applied: " + message
    )
    assert client.pages == 2, (
        "the refusal did not come on the second page, which is the first one "
        f"that carries a seekKey at all: {client.pages} pages"
    )


def _drive_committed_position_for():
    """The verifier's bounded zScan, over gRPC (P3c3f-3, P3c3f-4).

    Not a REST call at all, which is why the Phase 3c-3e derivation produced
    zero sites in `verifier/main.py` and this read - added by that same phase
    under D45 - was never enumerated.
    """
    verifier = _load_verifier_module()
    key = b"tool_call:bounded:abc:query_database"

    class _AnswersAtAnotherScore:
        def __init__(self):
            self.asked = None

        def zScan(self, **kwargs):
            self.asked = kwargs
            entry = type("Entry", (), {"key": key})()
            row = type("ZEntry", (), {"key": key, "entry": entry,
                                      "score": 1000000007.0})()
            return type("ZEntries", (), {"entries": [row]})()

    client = _AnswersAtAnotherScore()
    answer = verifier._committed_position_for(
        client, b"ail_view:decision:v1", key, 1000000042)
    assert client.asked.get("minscore") == 1000000042.0, client.asked
    assert answer is None, (
        "a zScan bounded to [1000000042, 1000000042] answered with this key "
        f"at 1000000007 and the position reported was {answer}. The position "
        "a record holds is read from what came back, never from what was "
        "asked for."
    )

    class _Agrees(_AnswersAtAnotherScore):
        def zScan(self, **kwargs):
            self.asked = kwargs
            entry = type("Entry", (), {"key": key})()
            row = type("ZEntry", (), {"key": key, "entry": entry,
                                      "score": 1000000042.0})()
            return type("ZEntries", (), {"entries": [row]})()

    assert verifier._committed_position_for(
        _Agrees(), b"ail_view:decision:v1", key, 1000000042) == 1000000042, (
        "the control does not pass: a view that agrees reports no position, "
        "so the check above would pass against a function that always "
        "answers None"
    )


# --- the nine reads in tests/ ----------------------------------------------
#
# Each one is driven by replacing the HTTP client its own module uses and
# answering outside the bound it asked for. The modules are imported rather
# than re-implemented, so a read that stops calling the check fails here.

class _PagesBelowTheMinScore:
    """A zscan client whose second page is scored below what it asked for."""

    def __init__(self, page=2500, key_field="entry"):
        self._page = page
        self._key_field = key_field

    def _row(self, name, score):
        row = {"score": score, "entry": {"key": _b64(name), "tx": "1"}}
        if self._key_field == "flat":
            row["key"] = _b64(name)
        return row

    def post(self, url, json=None, headers=None):
        if "login" in url:
            return _Answer({"token": "t"})
        if (json or {}).get("minScore") is None:
            return _Answer({"entries": [
                self._row(f"tool_call:{i}", 500.0) for i in range(self._page)]})
        return _Answer({"entries": [self._row("tool_call:below", 1.0)]})

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _AnswersOutsideThePrefix:
    """A scan client that returns a key from outside the prefix asked for."""

    def post(self, url, json=None, headers=None):
        if "login" in url:
            return _Answer({"token": "t"})
        return _Answer({"entries": [
            {"key": _b64("ail_seq:commit"), "value": _b64("{}"), "tx": "1",
             "entry": {"key": _b64("ail_seq:commit"), "tx": "1"}}]})

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _drive_with(module_name: str, call, client, *, attribute="_CLIENT"):
    """Run `call(module)` with the module's HTTP client replaced, and require
    an AssertionError naming the bound."""
    module = _load_test_module(module_name)
    original = getattr(module, attribute, None)
    if attribute == "httpx":
        setattr(module, attribute, SimpleNamespace(Client=lambda **kw: client))
    else:
        setattr(module, attribute, client)
    try:
        with pytest.raises(AssertionError) as refused:
            call(module)
    finally:
        setattr(module, attribute, original)
    message = str(refused.value)
    assert "bound was not applied" in message, (
        f"{module_name}: the refusal does not say the bound was not applied: "
        + message[:400]
    )


def _drive_view_invariants_view_rows():
    _drive_with("test_view_invariants",
                lambda m: m._view_rows({}, m.VIEW_DECISION),
                _PagesBelowTheMinScore())


def _drive_backfill_index_view_rows():
    _drive_with("test_backfill_index", lambda m: m._view_rows({}),
                _PagesBelowTheMinScore())


def _drive_audit_ordering_view_rows_paged():
    _drive_with("test_audit_ordering",
                lambda m: m._view_rows_paged({}, m.VIEW_DECISION),
                _PagesBelowTheMinScore())


def _drive_audit_ordering_keys_under_prefix():
    _drive_with("test_audit_ordering",
                lambda m: m._keys_under_prefix({}, "tool_call:p3c3f"),
                _AnswersOutsideThePrefix())


def _drive_audit_read_correctness_view_row_count():
    _drive_with("test_audit_read_correctness",
                lambda m: m._view_row_count(m.VIEW_DECISION),
                _PagesBelowTheMinScore(), attribute="httpx")


def _drive_reconciliation_positions_for_key():
    module = _load_test_module("test_reconciliation")
    original_headers = module._immudb_headers
    module._immudb_headers = lambda: {}
    try:
        _drive_with("test_reconciliation",
                    lambda m: m._positions_for_key("tool_call:x"),
                    _PagesBelowTheMinScore())
    finally:
        module._immudb_headers = original_headers


def _drive_committed_is_a_fact_members_at_position():
    class _AnswersOutsideTheWindow:
        def post(self, url, json=None, headers=None):
            return _Answer({"entries": [
                {"score": 1.0, "entry": {"key": _b64("tool_call:elsewhere"),
                                         "tx": "1"}}]})

    _drive_with("test_committed_is_a_fact",
                lambda m: m._members_at_position({}, m.VIEW_DECISION,
                                                 1000000042.0),
                _AnswersOutsideTheWindow())


def _drive_raw_ledger_fields_raw_scan():
    _drive_with("test_raw_ledger_fields", lambda m: m._raw_scan(),
                _AnswersOutsideThePrefix(), attribute="httpx")


def _drive_record_profile_raw_scan():
    _drive_with("test_record_profile", lambda m: m._raw_scan("tool_call:"),
                _AnswersOutsideThePrefix(), attribute="httpx")


@dataclass
class Coverage:
    """One bounded read's state: driven per bound, or recorded as not applying.

    **Per bound (P3c3f-5).** `drivers` pairs each driver with the bounds it
    drives, and `test_every_bound_at_a_driven_read_has_a_driver` compares that
    against the bounds the derivation attributes to the site. A site was
    "covered" before with one of its two bounds undriven, which is how
    `scan_all` kept a `seekKey` nothing tested through a phase whose subject
    was coverage.
    """
    drivers: tuple = ()
    does_not_apply: str = ""

    @property
    def driven_bounds(self) -> set:
        return {bound for _driver, bounds in self.drivers for bound in bounds}


# One entry per derived site. A site with no entry fails the enumeration
# below, which is the whole point of deriving the sites.
COVERAGE: dict[str, Coverage] = {
    "control_plane/main.py::_faults_in_tx_window":
        Coverage(drivers=((_drive_faults_in_tx_window, ("endKey", "seekKey")),)),
    "anchor_service/main.py::collect_positions":
        Coverage(drivers=((_drive_collect_positions, ("minScore",)),)),
    "verifier/main.py::_committed_position_for":
        Coverage(drivers=((_drive_committed_position_for,
                           ("minscore", "maxscore")),)),
    "tools/ail_backfill_index.py::indexed_keys":
        Coverage(drivers=((_drive_indexed_keys, ("minScore",)),)),
    "tools/ail_backfill_index.py::scan_all":
        Coverage(drivers=((_drive_scan_all, ("prefix",)),
                          (_drive_scan_all_seek_key, ("seekKey",)))),

    # The reads in tests/. `tests/` was excluded from the walk until Phase
    # 3c-3f, and the exclusion was a selector with no falsifier (D46).
    "tests/test_view_invariants.py::_view_rows":
        Coverage(drivers=((_drive_view_invariants_view_rows, ("minScore",)),)),
    "tests/test_backfill_index.py::_view_rows":
        Coverage(drivers=((_drive_backfill_index_view_rows, ("minScore",)),)),
    "tests/test_audit_ordering.py::_view_rows_paged":
        Coverage(drivers=((_drive_audit_ordering_view_rows_paged,
                           ("minScore",)),)),
    "tests/test_audit_ordering.py::_keys_under_prefix":
        Coverage(drivers=((_drive_audit_ordering_keys_under_prefix,
                           ("prefix",)),)),
    "tests/test_audit_read_correctness.py::_view_row_count":
        Coverage(drivers=((_drive_audit_read_correctness_view_row_count,
                           ("minScore",)),)),
    "tests/test_reconciliation.py::_positions_for_key":
        Coverage(drivers=((_drive_reconciliation_positions_for_key,
                           ("minScore",)),)),
    "tests/test_committed_is_a_fact.py::_members_at_position":
        Coverage(drivers=((_drive_committed_is_a_fact_members_at_position,
                           ("minScore", "maxScore")),)),
    "tests/test_raw_ledger_fields.py::_raw_scan":
        Coverage(drivers=((_drive_raw_ledger_fields_raw_scan, ("prefix",)),)),
    "tests/test_record_profile.py::_raw_scan":
        Coverage(drivers=((_drive_record_profile_raw_scan, ("prefix",)),)),

    # Direction two of D46: selector-true, property-false. Each of these is a
    # call the selector picks up and that the property does not reach.
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


def _derived_bounds() -> dict:
    """Every bound the derivation attributes to each site name."""
    bounds: dict = {}
    for site in bounded_read_sites():
        bounds.setdefault(site.name, set()).update(site.bounds)
    return bounds


# ---------------------------------------------------------------------------
# The enumeration.
# ---------------------------------------------------------------------------

def test_the_derivation_finds_the_reads_it_is_supposed_to_find():
    """The discriminator, asserted.

    A derivation that silently found nothing would make every test below
    vacuous, and one that swept in every read would make the coverage table
    a list of exemptions. Both halves are checked: the four production REST
    reads are found, and `_zscan_view` - a zscan carrying no selective bound -
    is not.
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


def test_the_derivation_finds_the_reads_no_route_literal_names():
    """D46 direction one: reads satisfying the property that the Phase 3c-3e
    selector could not see.

    Three shapes, all of them real:

      * **gRPC.** `verifier/main.py::_committed_position_for` is a zScan
        bounded to one score. The old selector matched a REST route literal in
        the first positional argument, and the verifier makes no REST calls at
        all, so it produced zero sites in that file - including this read,
        added by the same phase, in the same decision, returning the score it
        had asked for.
      * **`tests/`.** Excluded by `_module_files()`, which hid
        `tests/test_view_invariants.py::_view_rows`, the read that decides how
        many rows all four ledger-wide invariants see.
      * **The four REST spellings.** A URL passed as `url=`, through a local
        name, or by concatenation, and a bound keyed by a name rather than a
        literal. Asserted against source written here rather than against a
        production read, because none of the four is how this repository
        spells its reads today - which is exactly why nothing would notice if
        the next one were.
    """
    found = {site.name for site in bounded_read_sites()}
    assert "verifier/main.py::_committed_position_for" in found, (
        "the derivation finds no gRPC bounded read in verifier/main.py. The "
        "verifier speaks gRPC only, so a REST-shaped selector produces zero "
        "sites in the file that carries the route parity work."
    )
    assert "tests/test_view_invariants.py::_view_rows" in found, (
        "the derivation does not walk tests/. That exclusion is a selector "
        "and D46 says it inherits the decision: _view_rows is a bounded read "
        "that decides what four ledger-wide invariants assert over."
    )

    spellings = _derivation_over(_SPELLINGS_SOURCE)
    for expected in ("kwarg_url", "named_url", "concat_url", "named_bound"):
        assert f"<probe>::redteam_read_{expected}" in spellings, (
            f"the derivation cannot attribute redteam_read_{expected}, which "
            "is an ordinary bounded read spelled a way this repository does "
            f"not happen to use today. It found: {sorted(spellings)}"
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


def test_every_bound_at_a_driven_read_has_a_driver():
    """P3c3f-5: coverage is per bound, not per site.

    `tools/ail_backfill_index.py::scan_all` carries `prefix` and `seekKey`,
    had a driver for `prefix`, and was reported covered. Driven against a
    client that honoured the prefix and dropped the paging parameter it
    returned 767 identical pages in eight seconds and never refused or
    terminated.
    """
    derived = _derived_bounds()
    undriven = []
    for name, cover in COVERAGE.items():
        if not cover.drivers:
            continue
        for bound in sorted(derived.get(name, set()) - cover.driven_bounds):
            undriven.append(f"{name} :: {bound}")
    assert not undriven, (
        f"bound(s) carried by a driven read with no driver: {undriven}. A "
        "site is covered per bound: one driver for one of two bounds is a "
        "site whose other bound nothing has ever exercised."
    )

    phantom = []
    for name, cover in COVERAGE.items():
        for bound in sorted(cover.driven_bounds - derived.get(name, set())):
            phantom.append(f"{name} :: {bound}")
    assert not phantom, (
        f"the table claims to drive bound(s) the read does not carry: "
        f"{phantom}. Either the read dropped a bound, or the table is naming "
        "one it never had, and both make the count above meaningless."
    )


def _driven():
    return sorted((name, index)
                  for name, cover in COVERAGE.items()
                  for index in range(len(cover.drivers)))


@pytest.mark.parametrize("name,index", _driven(),
                         ids=[f"{name}[{index}]" for name, index in _driven()])
def test_the_bounded_read_asserts_its_bound(name, index):
    """Each read, executed against a client answering outside its bound.

    An unrecognised or misspelled parameter is dropped by ImmuDB's REST
    route without comment, so this is exactly what a bound that did not
    survive looks like from inside the function. Measured on the wire:

        correct  endKey : ['00'..'06']
        misspelt endkey : ['00'..'09']
    """
    COVERAGE[name].drivers[index][0]()


def test_a_read_recorded_as_not_applying_says_why():
    """The third state is a recorded decision, not an omission.

    This is also D46's direction two for this selector: every entry here is a
    call the selector picks up and the property does not reach, and the reason
    is the argument for that. An entry with no argument is an exemption
    wearing a decision's clothes.
    """
    thin = [name for name, cover in COVERAGE.items()
            if not cover.drivers and len(cover.does_not_apply.strip()) < 80]
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
