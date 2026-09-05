"""tests/test_route_parity.py - Phase 3c-3e (D43, P3c3e-1), 3c-3f (D46).

Every property this service claims about a write is asserted against every
write route, and the list of write routes is derived from the application
object rather than typed here.

**The property, stated first and independently of the selector (D46).** This
paragraph is load-bearing, and it is where Phase 3c-3e went wrong. The file
claimed "every property this service claims about a write" and implemented
"takes the write key", and nothing in it said which of those two sets it
meant. A property defined as whatever its selector picks up cannot be
falsified in either direction: both checks below would pass by construction.
So the property is written down here, in its own words, before anything
selects for it, and `WRITE_ROUTE_PROPERTY` is that sentence as a value the
tests quote:

    A route of this service is a write route when calling it durably changes
    what this service holds - a record written into the ledger on the
    caller's behalf, or the persisted trust anchor every later proof is
    measured against.

The anchor is in that sentence and it is not decoration. `POST /verify`
advanced it on the READ key until D47, which made a read-gated route a route
with durable effects: it was inside this property's set and outside every
selector this file has ever had. It is outside the set now because the route
no longer moves the anchor, and
`test_no_route_outside_the_site_list_durably_changes_state` drives that rather
than assuming it.

**The selector, and its two falsifiers.** `write_routes()` claims to cover
that property by naming the routes gated by `_require_write_key`. A selector
is itself a claim, so it is falsified in both directions:

  * *satisfies the property, not the selector* -
    `test_a_write_route_is_selected_under_any_verb` builds a write route under
    PUT, PATCH and DELETE. Until Phase 3c-3f the selector also filtered on
    `"POST" in route.methods`, and the Phase 3c-3e red team moved one
    character, `@app.post` to `@app.put`, to make a route holding none of the
    four properties below leave this suite at `10 passed`. The anchor test
    named above is the other half of this direction.

  * *satisfies the selector, not the property* -
    `test_every_selected_route_durably_changes_state` drives each selected
    route and requires it to attempt a ledger write. **This direction has no
    instance in the tree today**: no route that `_require_write_key` selects
    writes nothing. That is recorded here rather than the direction being
    omitted, because "no instance today" and "not checked" are the same green
    otherwise. The worked precedent for the other outcome is in
    `tests/test_bounded_reads.py`, whose `does_not_apply` entries are exactly
    selector-true, property-false sites, each carrying its reason.

**Why this file exists at all.** The Phase 3c-3d red team refuted six of ten
claims and the shape underneath the six was one thing: a rule that has to
hold at N sites, with nothing enumerating the sites. Two write routes covered
at one. Four bounded reads covered at two. N key encodings covered at one.
The individual fixes were correct; what was missing was anything that fails
when a site is added or missed. `tests/test_ledger_vocabulary.py` built that
control once for constants. This generalises it to guarantees.

A4 is the worked example. D40 (Phase 3c-3d) made `committed` a fact about the
ledger and every one of `tests/test_committed_is_a_fact.py`'s four tests
drives `POST /write`. `POST /write-ordered` - the route every decision and
every intent record takes - still answered `committed: false` from a generic
handler that asked the ledger nothing. It survived a full phase and a
red-team brief that named the route by name, because the enforcing test was
written pointing at the route that was already correct.

**The route list is derived and the discriminator is named.** `app.routes`
carries POST `/write`, POST `/write-ordered` and POST `/verify`, and the last
is a read. The write routes are the ones whose dependency is
`_require_write_key`, under any verb; `/verify` takes `_require_read_key`.
Hand-listing which routes are writes would sweep `/verify` in or out by
judgement, which is this test failing on its own terms at the first step.

**Three states per cell, not two.** A property either holds on a route, or
does not apply to it *with its reason recorded here*, or is missing - and
missing fails. A property that simply did not apply would otherwise default
silently to whichever state the author had in mind, which is how a route gets
added with no decision made about it.

That distinction is load-bearing rather than tidy. `KeyMustNotExist` does not
belong on `POST /write`: D39's reason for it is that a second write gives the
key a second entry in the view index at a second position, and the plain
route allocates no position. Applying it there would refuse a second erasure
attempt after a partial failure, on the GDPR path, which is the harm P3c3e-3
exists to close.

**Driven, not pattern-matched.** Every property below is asserted by
executing the route function against a stub client and looking at what it
answered and at what it asked the ledger for. A property asserted by reading
the source is a property about how the source is spelled; the Phase 3c-3d red
team defeated two such checks in one session.

No stack required: the routes are executed in-process.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute

REPO_ROOT = Path(__file__).resolve().parents[1]
# Explicit, not inherited: verifier/main.py and control_plane/main.py both
# import `provenance`, which lives at the repository root. Relying on some
# earlier test module to have put it on the path is a dependence on
# collection order, which is the class D44 is about.
sys.path.insert(0, str(REPO_ROOT))

os.environ.setdefault("VERIFIER_READ_KEY", "test-verifier-read-key")
os.environ.setdefault("VERIFIER_WRITE_KEY", "test-verifier-write-key")


# The verifier reads its writer key path once, at import. Set for the
# duration of the import and restored afterwards, rather than exported into
# this process: a module-level `os.environ[...] = ...` here would change what
# every other in-process import of verifier/main.py does, and which of them
# ran first. That is the order dependence D44 is about, introduced by the
# file enforcing D43.
_WRITER_KEY = REPO_ROOT / "keys" / "writer-verifier.key"


def _load_verifier():
    """A fresh verifier module, so one driver's module-level caches
    (`_seq_cache`, `_reserve_cache`, the writer key) cannot reach another."""
    name = f"parity_verifier_{uuid.uuid4().hex[:8]}"
    spec = importlib.util.spec_from_file_location(
        name, REPO_ROOT / "verifier" / "main.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    previous = os.environ.get("AIL_WRITER_SIGNING_KEY")
    os.environ["AIL_WRITER_SIGNING_KEY"] = str(_WRITER_KEY)
    try:
        spec.loader.exec_module(module)
    finally:
        if previous is None:
            os.environ.pop("AIL_WRITER_SIGNING_KEY", None)
        else:
            os.environ["AIL_WRITER_SIGNING_KEY"] = previous
    return module


def _b64(value) -> str:
    raw = value if isinstance(value, bytes) else value.encode()
    return base64.b64encode(raw).decode()


# ---------------------------------------------------------------------------
# The property, then the selector. In that order, per D46.
# ---------------------------------------------------------------------------

WRITE_ROUTE_PROPERTY = (
    "A route of this service is a write route when calling it durably changes "
    "what this service holds - a record written into the ledger on the "
    "caller's behalf, or the persisted trust anchor every later proof is "
    "measured against."
)

# Routes this service deliberately leaves ungated, and why. D21 gates every
# route that reads or writes anything; a route in neither tier has to be a
# recorded decision, because otherwise a second ungated route is
# indistinguishable from this one.
UNGATED_BY_DESIGN = {
    "/health":
        "a liveness probe returning a fixed body. Compose, Kubernetes and "
        "tests/compose_helpers.py::wait_for_health all poll it before any "
        "credential exists in the calling context, and it discloses nothing "
        "about the ledger and changes nothing.",
}


def _service_routes(verifier) -> list[APIRoute]:
    """Every route this service registers, under any verb.

    FastAPI adds `/openapi.json`, `/docs`, `/docs/oauth2-redirect` and
    `/redoc` to every application it builds. They are the framework's routes
    and not this service's, and they are excluded by where their endpoint
    function is defined rather than by a list of paths - a path list here
    would be one more hand-maintained enumeration inside the file whose
    subject is hand-maintained enumerations.
    """
    return [route for route in verifier.app.routes
            if isinstance(route, APIRoute)
            and getattr(route.endpoint, "__module__", "") == verifier.__name__]


def _gate_names(route: APIRoute) -> set[str]:
    return {dep.call.__name__ for dep in route.dependant.dependencies}


def write_routes(verifier) -> dict[str, APIRoute]:
    """Every route gated by `_require_write_key`, under any verb, by path.

    **The selector, and it is a claim about covering WRITE_ROUTE_PROPERTY
    rather than a restatement of it.** The discriminator is the dependency
    and nothing else: `POST /verify` is a read and takes `_require_read_key`,
    so a rule about "the POST routes" would either sweep it in or leave it
    out by judgement.

    The method is deliberately not part of it (P3c3f-2, Phase 3c-3f). It used
    to be - `"POST" in route.methods` - and that was a hand-list wearing a
    derivation's clothes: FastAPI registers a route under whatever verb its
    decorator names, so `@app.put` on the identical handler produced a
    registered, gated, reachable write route that this file could not see.
    Driven by the Phase 3c-3e red team at `10 passed` with the route present
    and `2 failed` with the same handler under `@app.post`.
    """
    return {route.path: route for route in _service_routes(verifier)
            if "_require_write_key" in _gate_names(route)}


# ---------------------------------------------------------------------------
# Stub clients. Each one answers the narrow set of calls the route under test
# makes, and records what it was asked to do.
# ---------------------------------------------------------------------------

class _Got:
    def __init__(self, tx: int, value: bytes):
        self.tx = tx
        self.value = value


# The head every stub below reports, deliberately unequal to any transaction
# a driver writes at, so "the anchor moved to the head" and "the anchor moved
# to this write's transaction" are different numbers.
_HEAD_TX = 4242


class _HeadOnlyStub:
    """The gRPC stub, answering the one RPC `head_state()` makes.

    Reporting the head through this stub writes nothing, which is D47's whole
    point: `_StubBase.currentState` above is the SDK's way of asking the same
    question, and it persists what it reports.
    """

    def __init__(self, owner):
        self._owner = owner
        self.current_state_calls = 0

    def CurrentState(self, _request):
        self.current_state_calls += 1
        return type("GrpcState", (), {
            "db": "defaultdb", "txId": _HEAD_TX, "txHash": b"\x00" * 32,
            "signature": type("Sig", (), {"publicKey": b"", "signature": b""})(),
        })()


class _StubBase:
    """Records every unverified `set`, which is what D35's no-proof path uses.

    Nothing here answers a call it was not given an answer for: an
    unanticipated call raises, so a driver cannot pass because the route took
    a path the stub silently absorbed.
    """

    def __init__(self):
        self.unverified_sets: list[tuple[bytes, bytes]] = []
        # D46 direction two: what the route asked the LEDGER to write, of any
        # kind. A route the selector picks up and that never appears here is
        # selector-true and property-false.
        self.ledger_write_attempts: list[str] = []
        # D47: every state this route asked to be persisted as the trust
        # anchor, and the SDK's own currentState() is reproduced faithfully
        # below so a route that calls it lands here.
        self.anchor_sets: list[int] = []
        self._vk = None
        self._stub = _HeadOnlyStub(self)

    def set(self, key, value):
        self.unverified_sets.append((key, value))
        self.ledger_write_attempts.append("set")
        return type("Resp", (), {"id": 909})()

    def currentState(self):
        """`immudb/handler/currentRoot.py::call`, faithfully.

        It reads the head and then calls `rs.set(state)` unconditionally - no
        signature check, no monotonicity check, no comparison against what it
        overwrites - so a route that reports the head this way persists it.
        Reproduced rather than stubbed out, so `anchor_sets` records exactly
        what the real SDK would have written had the route called it.
        """
        self.anchor_sets.append(_HEAD_TX)
        return type("State", (), {"txId": _HEAD_TX})()


class _PlainWriteClient(_StubBase):
    """`POST /write`'s client. `verifiedSet` fails; the ledger holds `stored`."""

    def __init__(self, stored: dict[bytes, _Got], raise_on_set=None,
                 unreadable: tuple[bytes, ...] = (), succeed: int | None = None):
        super().__init__()
        self._stored = stored
        self._unreadable = unreadable
        self._succeed = succeed
        self._raise = raise_on_set or RuntimeError(
            "StatusCode.UNAVAILABLE: Stream removed (Socket closed)")

    def verifiedSet(self, key, value):
        self.ledger_write_attempts.append("verifiedSet")
        if self._succeed is not None:
            # The proved write's own state, which is what the SDK persists
            # under `newstate.Verify(verifying_key)` before returning.
            self.anchor_sets.append(self._succeed)
            return type("Resp", (), {"id": self._succeed})()
        raise self._raise

    def get(self, key):
        if key in self._unreadable:
            raise RuntimeError("StatusCode.UNAVAILABLE: connection refused")
        return self._stored.get(key)


class _OrderedWriteClient(_StubBase):
    """`POST /write-ordered`'s client.

    The ordered write is one `ExecAll` issued on `client._stub`, so the cut
    the red team drove - the ExecAll commits and its response is dropped - is
    reproduced by raising a transport error out of `_stub.ExecAll` while the
    ledger holds the record. `zScan` answers for the view index, which is
    where the allocated position is.

    The counter and reserve keys are read from the module rather than spelled
    here, so a rename cannot make this stub answer `None` to the counter read
    and quietly change which position the route was going to allocate.
    """

    def __init__(self, verifier, stored: dict[bytes, _Got],
                 counter=(1000000016, 40), reserve=b"1000000000",
                 execall_error=None, view_member=None,
                 unreadable: tuple[bytes, ...] = ()):
        super().__init__()
        self._sequence_key = verifier.SEQUENCE_KEY
        self._reserve_key = verifier.RESERVE_KEY
        self._stored = dict(stored)
        self._counter = counter
        self._reserve = reserve
        self._view_member = view_member
        self._unreadable = unreadable
        self.execall_requests: list = []
        outer = self

        class _Stub(_HeadOnlyStub):
            def ExecAll(self, request):
                outer.execall_requests.append(request)
                outer.ledger_write_attempts.append("ExecAll")
                raise execall_error or RuntimeError(
                    "StatusCode.UNAVAILABLE: Stream removed (Socket closed)")

        self._stub = _Stub(self)

    def get(self, key):
        if key in self._unreadable:
            raise RuntimeError("StatusCode.UNAVAILABLE: connection refused")
        if key == self._reserve_key:
            return None if self._reserve is None else _Got(1, self._reserve)
        if key == self._sequence_key:
            if self._counter is None:
                return None
            return _Got(self._counter[1], str(self._counter[0]).encode())
        return self._stored.get(key)

    def zScan(self, **kwargs):
        entries = []
        if self._view_member is not None:
            key, score = self._view_member
            lo = kwargs.get("minscore")
            hi = kwargs.get("maxscore")
            if (lo is None or score >= lo) and (hi is None or score <= hi):
                entry = type("Entry", (), {"key": key})()
                entries.append(type("ZEntry", (), {"key": key, "entry": entry,
                                                   "score": score})())
        return type("ZEntries", (), {"entries": entries})()

    def verifiedGet(self, key):
        return _Got(1, b"{}")


# ---------------------------------------------------------------------------
# Records the drivers write.
# ---------------------------------------------------------------------------

def _decision_record(call_id: str) -> bytes:
    return json.dumps({"record_type": "decision", "call_id": call_id,
                       "outcome_type": "policy_allow"},
                      separators=(",", ":")).encode()


def _fault_record(call_id: str) -> bytes:
    return json.dumps({"record_type": "ledger_fault", "call_id": call_id,
                       "fault_class": "write_verification_failed"},
                      separators=(",", ":")).encode()


def _tombstone_record(call_id: str) -> bytes:
    return json.dumps({"record_type": "content_erasure", "call_id": call_id},
                      separators=(",", ":")).encode()


def _call(verifier, path: str, key: bytes, value: bytes):
    """Execute the route function behind `path` with this key and value."""
    if path == "/write":
        return verifier.write(verifier.WriteRequest(key=_b64(key), value=_b64(value)))
    if path == "/write-ordered":
        return verifier.write_ordered(verifier.OrderedWriteRequest(
            key=_b64(key), value=_b64(value), view="decision"))
    raise AssertionError(
        f"no driver knows how to call {path!r}. A write route was added and "
        "this file was not told how to execute it, so none of the properties "
        "below can be asserted against it."
    )


def _record_for(path: str, call_id: str) -> tuple[bytes, bytes]:
    """A record each route accepts, so a driver about something else is not
    refused for an unrelated reason."""
    if path == "/write":
        return (f"content_erasure:{call_id}".encode(), _tombstone_record(call_id))
    return (f"tool_call:parity:{call_id}:query_database".encode(),
            _decision_record(call_id))


# ---------------------------------------------------------------------------
# The properties.
# ---------------------------------------------------------------------------

def _drive_refuses_a_fault_record(verifier, path: str):
    """A `ledger_fault` from a caller is refused, by key prefix and by
    record_type independently."""
    call_id = uuid.uuid4().hex
    ordinary_key, _ = _record_for(path, call_id)

    with pytest.raises(HTTPException) as by_prefix:
        _call(verifier, path,
              f"ledger_fault:00000000000000000042:{call_id}:abc".encode(),
              _tombstone_record(call_id))
    assert by_prefix.value.status_code == 400, by_prefix.value.detail

    with pytest.raises(HTTPException) as by_type:
        _call(verifier, path, ordinary_key, _fault_record(call_id))
    assert by_type.value.status_code == 400, by_type.value.detail


def _drive_refuses_the_other_route_s_records(verifier, path: str):
    """A record that belongs on the ordered route is refused here."""
    call_id = uuid.uuid4().hex
    with pytest.raises(HTTPException) as by_type:
        _call(verifier, path, f"probe:{call_id}".encode(),
              _decision_record(call_id))
    assert by_type.value.status_code == 400, by_type.value.detail

    with pytest.raises(HTTPException) as by_prefix:
        _call(verifier, path,
              f"tool_call:parity:{call_id}:query_database".encode(),
              json.dumps({"call_id": call_id}).encode())
    assert by_prefix.value.status_code == 400, by_prefix.value.detail


def _drive_key_must_not_exist(verifier, path: str):
    """The record key is written once, enforced inside the same transaction
    that would do the writing rather than by a read-then-write check."""
    call_id = uuid.uuid4().hex
    key, value = _record_for(path, call_id)

    rejected = RuntimeError("precondition failed: KeyMustNotExist")
    client = _OrderedWriteClient(verifier, {key: _Got(55, value)},
                                 execall_error=rejected)
    verifier._get_client = lambda: client

    with pytest.raises(HTTPException) as refused:
        _call(verifier, path, key, value)
    assert refused.value.status_code == 409, refused.value.detail

    assert client.execall_requests, "no ExecAll was issued at all"
    request = client.execall_requests[0]
    named = [pre.keyMustNotExist.key for pre in request.preconditions
             if pre.HasField("keyMustNotExist")]
    assert key in named, (
        "the transaction that would write this record carried no "
        f"KeyMustNotExist precondition naming its key: {named}"
    )


def _drive_committed_is_a_fact(verifier, path: str):
    """A response says `committed` about the ledger, never about whether the
    call that would have told us succeeded.

    Both directions. The bytes are in the ledger under this key: committed,
    with the transaction the ledger holds them at. Different bytes are under
    it: not committed, and not this write's transaction.
    """
    call_id = uuid.uuid4().hex
    key, value = _record_for(path, call_id)

    def _client(stored, view_member=None, unreadable=()):
        if path == "/write":
            return _PlainWriteClient(stored, unreadable=unreadable)
        return _OrderedWriteClient(verifier, stored, view_member=view_member,
                                   unreadable=unreadable)

    landed = _client({key: _Got(77, value)}, view_member=(key, 1000000017.0))
    verifier._get_client = lambda: landed
    committed = _call(verifier, path, key, value)
    assert committed.committed is True, (
        f"{path}: the bytes are in the ledger at transaction 77 and the "
        f"response says the write never happened: {committed}"
    )
    assert committed.tx_id == 77, (
        f"{path}: the response names transaction {committed.tx_id} and the "
        f"ledger holds this record at 77: {committed}"
    )
    assert committed.verified is False, (
        f"{path}: no proof ran, so nothing verified: {committed}"
    )

    other = _client({key: _Got(77, b"a different record")})
    verifier._get_client = lambda: other
    absent = _call(verifier, path, key, value)
    assert absent.committed is False and absent.tx_id is None, (
        f"{path}: a different record already under this key was reported as "
        f"this write: {absent}"
    )

    # D45: and the third answer. When the confirming read cannot run either,
    # neither `true` nor `false` is a fact, and `false` is the one that
    # produced a tombstone in the ledger with the payload still in the store.
    # Only the record key is unreadable: on the ordered route the counter and
    # reserve reads happen before the ExecAll, and a client that failed those
    # too would be exercising the branch where nothing was written.
    blind = _client({}, unreadable=(key,))
    verifier._get_client = lambda: blind
    unknown = _call(verifier, path, key, value)
    assert unknown.committed is None, (
        f"{path}: the write raised and the ledger could not be read back, and "
        f"the response states a fact it does not have: {unknown}"
    )
    assert unknown.verified is False, unknown


@dataclass
class Property:
    """One guarantee, and its state on every write route.

    `holds_on` and `does_not_apply_to` are read together: a route in neither
    is the failure this file exists to produce.
    """
    name: str
    claim: str
    driver: callable
    holds_on: tuple[str, ...]
    does_not_apply_to: dict[str, str] = field(default_factory=dict)

    def state(self, path: str) -> str | None:
        if path in self.holds_on:
            return "holds"
        if path in self.does_not_apply_to:
            return "does not apply"
        return None


PROPERTIES = (
    Property(
        name="refuses a ledger_fault record from a caller",
        claim="a caller holding the write key cannot author this service's own "
              "account of another record's standing, on any route",
        driver=_drive_refuses_a_fault_record,
        holds_on=("/write", "/write-ordered"),
    ),
    Property(
        name="refuses a record that belongs on the ordered route",
        claim="a decision or intent record written with no commit position is "
              "absent from every ordered page permanently, so the plain route "
              "refuses one",
        driver=_drive_refuses_the_other_route_s_records,
        holds_on=("/write",),
        does_not_apply_to={
            "/write-ordered":
                "this route exists to write exactly those records, so the "
                "plain route's set applied here would refuse the route's own "
                "purpose. The symmetric refusal - that a record's key prefix "
                "match the view it is being indexed into - is a standing "
                "residual limit and not this property: refusing it would "
                "refuse the deliberately mismatched writes "
                "tests/test_reconciliation.py uses to prove D37 finds a "
                "record in the wrong view (README section 5, TODO.md, "
                "ADR-0014 Consequences).",
        },
    ),
    Property(
        name="KeyMustNotExist on the record key",
        claim="the record key is written once, so a second write cannot give "
              "it a second index entry at a second position",
        driver=_drive_key_must_not_exist,
        holds_on=("/write-ordered",),
        does_not_apply_to={
            "/write":
                "D39's reason for the precondition is that a second write "
                "gives the key a second entry in the view index at a second "
                "position, and this route allocates no position and writes no "
                "index entry. Applying it here would refuse a second erasure "
                "attempt after a partial failure - the control plane's "
                "tombstone is the one production write left on this route - "
                "which is the GDPR harm P3c3e-3 exists to close, produced by "
                "the control that was supposed to prevent a different one.",
        },
    ),
    Property(
        name="committed is a fact about the ledger",
        claim="a response reports `committed` from what the ledger holds, "
              "never from whether the call that would have told us succeeded",
        driver=_drive_committed_is_a_fact,
        holds_on=("/write", "/write-ordered"),
    ),
)


# ---------------------------------------------------------------------------
# The enumeration.
# ---------------------------------------------------------------------------

def test_the_write_routes_are_selected_by_their_gate_and_not_by_their_path():
    """The discriminator itself, asserted.

    If `_require_write_key` stopped selecting the write routes this file
    would enumerate the wrong sites and every property below would pass
    against nothing.

    P3c3f-2: over every route this service registers, not the POST ones. The
    old spelling asked "which POST route declares no gate", so a `PUT` route
    gated by neither key was outside both halves of the check as well as
    outside the site list.
    """
    verifier = _load_verifier()
    gates = {route.path: _gate_names(route)
             for route in _service_routes(verifier)}
    assert gates, "the verifier registered no routes of its own at all"

    ungated = sorted(path for path, names in gates.items()
                     if not ({"_require_write_key", "_require_read_key"} & names)
                     and path not in UNGATED_BY_DESIGN)
    assert not ungated, (
        f"route(s) {ungated} are gated by neither _require_write_key nor "
        "_require_read_key, so this file cannot say whether they are writes. "
        "D21 gates every route; a new one has to declare which tier it is in, "
        "or be recorded in UNGATED_BY_DESIGN with the argument for it."
    )

    stale = sorted(set(UNGATED_BY_DESIGN) - set(gates))
    assert not stale, (
        f"UNGATED_BY_DESIGN names route(s) that no longer exist: {stale}. An "
        "exemption outliving its route is an exemption for whatever lands on "
        "that path next."
    )
    thin = sorted(path for path, reason in UNGATED_BY_DESIGN.items()
                  if len(reason.strip()) < 80)
    assert not thin, (
        f"a route recorded as ungated by design gives no reason worth the "
        f"name: {thin}"
    )

    writes = write_routes(verifier)
    assert writes, "no route is gated by _require_write_key"
    assert "/verify" not in writes, (
        "POST /verify is gated by the write key. It is a read, and every "
        "property in this file would now be asserted against it."
    )


# ---------------------------------------------------------------------------
# D46: the selector, falsified in both directions.
# ---------------------------------------------------------------------------

def test_a_write_route_is_selected_under_any_verb():
    """Direction one: a case satisfying WRITE_ROUTE_PROPERTY and not the
    selector, if the selector were narrower than the property.

    The Phase 3c-3e red team changed `@app.post` to `@app.put` on a handler
    holding none of the four properties below and this suite read `10 passed`.
    The route was registered, gated and reachable; the selector filtered on
    the method as well as the gate, and the method half was a hand-list.

    Built here rather than injected into `verifier/main.py`, so it is a
    permanent falsifier rather than a probe someone ran once. Three verbs,
    because "any verb but POST" is the claim and PUT alone would be a second
    hand-list one item longer.
    """
    from fastapi import Depends, FastAPI

    verifier = _load_verifier()
    app = FastAPI()

    for verb, path in (("put", "/write-express"),
                       ("patch", "/write-amend"),
                       ("delete", "/write-retract")):
        decorator = getattr(app, verb)

        @decorator(path)
        def _handler(_: None = Depends(verifier._require_write_key)):
            return {}

    # The same shape write_routes() takes from a module: an `app`, and a
    # `__name__` the endpoint functions were defined under.
    stand_in = SimpleNamespace(app=app, __name__=_handler.__module__)
    selected = sorted(write_routes(stand_in))
    assert selected == ["/write-amend", "/write-express", "/write-retract"], (
        "a route gated by _require_write_key is not in the site list because "
        f"of the verb it is registered under. Selected: {selected}. Every one "
        "of these writes on the caller's behalf and holds none of the "
        "properties below, and the enumeration cannot see it."
    )


def test_every_selected_route_durably_changes_state():
    """Direction two: a case satisfying the selector and not the property.

    **There is no such route in the tree today, and that is the result rather
    than the reason to leave the direction out.** What is asserted is the
    positive form: every route the selector picks up, driven, asks the ledger
    to write something. A route gated by the write key that writes nothing is
    a route this file would assert four write properties against for no
    reason, and it fails here.

    The worked precedent for the other outcome is
    `tests/test_bounded_reads.py`: four of its derived sites are selector-true
    and property-false, each carrying its recorded reason, and its three-state
    design is what this direction looks like once it has an instance.
    """
    verifier = _load_verifier()
    original = verifier._get_client
    silent = []
    try:
        for path in sorted(write_routes(verifier)):
            call_id = uuid.uuid4().hex
            key, value = _record_for(path, call_id)
            if path == "/write":
                client = _PlainWriteClient({key: _Got(77, value)})
            else:
                client = _OrderedWriteClient(verifier, {key: _Got(77, value)})
            verifier._get_client = lambda c=client: c
            _call(verifier, path, key, value)
            if not client.ledger_write_attempts:
                silent.append(path)
    finally:
        verifier._get_client = original
    assert not silent, (
        f"route(s) {silent} are gated by _require_write_key and asked the "
        "ledger to write nothing, so the selector covers something the write "
        f"property does not: {WRITE_ROUTE_PROPERTY}"
    )


def test_no_route_outside_the_site_list_durably_changes_state():
    """The other half of direction one, for the anchor rather than the verb.

    `POST /verify` is gated by `_require_read_key`, so no selector in this
    file has ever picked it up - and until D47 it advanced the persisted trust
    anchor on every call, which is inside WRITE_ROUTE_PROPERTY. Property-true
    and selector-false: the exact shape this direction exists to catch, on a
    production route, reachable with the read credential.

    That route runs the SDK's own `verifiedGet.call` against a real
    VerifiableEntry, so it cannot be driven from a stub client here. It is
    driven live in `tests/test_trust_anchor.py`, one test per call site plus
    the cold-boot seed, and that module is this direction's falsifier.

    What IS drivable in process is the same question on `POST /write`, whose
    whole path is stubbable: the route reports the head after a proved write,
    and it used to report it with `client.currentState()`, which persists what
    it reports. `_StubBase.currentState` reproduces the SDK's handler exactly,
    so a route that calls it records an anchor set here.
    """
    verifier = _load_verifier()
    original = verifier._get_client
    try:
        call_id = uuid.uuid4().hex
        key, value = _record_for("/write", call_id)
        client = _PlainWriteClient({}, succeed=77)
        verifier._get_client = lambda: client
        answer = _call(verifier, "/write", key, value)
        assert answer.verified is True and answer.tx_id == 77, answer
        assert client.anchor_sets == [77], (
            "POST /write moved the persisted trust anchor to something other "
            f"than the transaction its own proof ran to: {client.anchor_sets}. "
            f"The head this stub reports is {_HEAD_TX}; the write committed at "
            "77. Reporting the head does not require persisting it (D47)."
        )
        assert client._stub.current_state_calls == 1, (
            "the route did not read the head at all, so this test is not "
            "exercising the line it describes"
        )
    finally:
        verifier._get_client = original


def test_every_write_route_has_a_recorded_state_for_every_property():
    """The enumeration. A write route with no decision recorded about a
    property fails here, before any property is driven.

    This is the test the phase's own mutation targets: adding a third write
    route with none of the properties must fail this without anything in this
    file being edited.
    """
    verifier = _load_verifier()
    missing = []
    for path in sorted(write_routes(verifier)):
        for prop in PROPERTIES:
            if prop.state(path) is None:
                missing.append(f"{path} x {prop.name!r}")
    assert not missing, (
        "a write route carries no recorded state for a property this service "
        f"claims: {missing}. Each cell is one of three states - the property "
        "holds on that route, or it does not apply and this file records why, "
        "or it is missing. Missing is this failure. Defaulting silently to "
        "either of the other two is how POST /write-ordered went a whole "
        "phase without D40."
    )


def _cells():
    verifier = _load_verifier()
    paths = sorted(write_routes(verifier))
    return [(prop, path) for prop in PROPERTIES for path in paths
            if prop.state(path) == "holds"]


@pytest.mark.parametrize(
    "prop,path",
    _cells(),
    ids=[f"{path}-{prop.name}".replace(" ", "_") for prop, path in _cells()],
)
def test_the_property_holds_on_the_route(prop, path):
    """Every cell recorded as holding, driven against the route."""
    verifier = _load_verifier()
    original = verifier._get_client
    try:
        prop.driver(verifier, path)
    finally:
        verifier._get_client = original


def test_a_property_that_does_not_apply_says_why():
    """The third state is a recorded decision, not an omission.

    A reason that is absent, or short enough to be a label rather than an
    argument, is the same silence as a missing cell wearing a different coat.
    """
    thin = []
    for prop in PROPERTIES:
        for path, reason in prop.does_not_apply_to.items():
            if len(reason.strip()) < 80:
                thin.append(f"{path} x {prop.name!r}: {reason!r}")
    assert not thin, (
        "a property recorded as not applying to a route gives no reason worth "
        f"the name: {thin}"
    )


# ---------------------------------------------------------------------------
# D43: the no-proof path is one assertion, not a column.
# ---------------------------------------------------------------------------

def test_no_write_route_reaches_the_unverified_path_with_anything_but_a_fault_record():
    """`_set_without_verification` is module-level and no route selects it, so
    "route by no-proof guard" is not a cell in the matrix above. What is
    assertable is this, and it is one assertion over every write route.

    Driven rather than parsed. The stub client records every unverified `set`
    it is asked to make, so what is checked is what the route actually wrote,
    not how the source spells a name. Both of the Phase 3c-3d red team's
    second callers - `globals()[...]` and
    `getattr(sys.modules[__name__], ...)` - are invisible to a parse and
    would be recorded here.

    Two conditions, on every write route: a write whose proof did not fail
    makes no unverified write at all, and a write whose proof did fail makes
    exactly one, whose bytes are a `ledger_fault` record about the record the
    route just committed.
    """
    verifier = _load_verifier()
    from ecdsa.keys import BadSignatureError  # noqa: F401
    from immudb.exceptions import ErrCorruptedData

    original = verifier._get_client
    try:
        for path in sorted(write_routes(verifier)):
            call_id = uuid.uuid4().hex
            key, value = _record_for(path, call_id)

            # 1. A transport failure. The proof did not fail, it could not be
            #    attempted, so nothing is tamper evidence and nothing is
            #    written without proof.
            if path == "/write":
                client = _PlainWriteClient({key: _Got(77, value)})
            else:
                client = _OrderedWriteClient(verifier, {key: _Got(77, value)})
            verifier._get_client = lambda c=client: c
            _call(verifier, path, key, value)
            assert not client.unverified_sets, (
                f"{path}: a write whose proof could not be attempted took the "
                f"no-proof path: {client.unverified_sets}"
            )

            # 2. A proof failure. Exactly one unverified write, and it is a
            #    fault record about this record.
            call_id = uuid.uuid4().hex
            key, value = _record_for(path, call_id)
            corrupt = ErrCorruptedData()
            if path == "/write":
                client = _PlainWriteClient({key: _Got(88, value)},
                                           raise_on_set=corrupt)
            else:
                client = _OrderedWriteClient(verifier, {key: _Got(88, value)})

                def _fails_the_proof(_key, _client=client):
                    raise corrupt

                client.verifiedGet = _fails_the_proof

                class _Committed:
                    def ExecAll(self, request):
                        client.execall_requests.append(request)
                        return type("Resp", (), {"id": 88})()

                client._stub = _Committed()
            verifier._get_client = lambda c=client: c
            _call(verifier, path, key, value)

            assert len(client.unverified_sets) == 1, (
                f"{path}: a failed proof made {len(client.unverified_sets)} "
                "unverified write(s); it may make exactly one, the fault "
                f"record: {client.unverified_sets}"
            )
            written_key, written_value = client.unverified_sets[0]
            assert written_key.startswith(b"ledger_fault:"), (
                f"{path}: the no-proof path wrote under {written_key!r}, which "
                "is not a fault key"
            )
            body = json.loads(written_value.decode())
            assert body.get("record_type") == "ledger_fault", (
                f"{path}: the no-proof path wrote a "
                f"{body.get('record_type')!r} record"
            )
            assert body.get("committed_key") == key.decode(), (
                f"{path}: the fault names {body.get('committed_key')!r} and the "
                f"record this route just committed is {key.decode()!r}"
            )
    finally:
        verifier._get_client = original
