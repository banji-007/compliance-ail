"""tests/test_route_parity.py - Phase 3c-3e (D43, P3c3e-1).

Every property this service claims about a write is asserted against every
write route, and the list of write routes is derived from the application
object rather than typed here.

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
`_require_write_key`; `/verify` takes `_require_read_key`. Hand-listing which
POST routes are writes would sweep `/verify` in or out by judgement, which is
this test failing on its own terms at the first step.

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
# The site list, derived.
# ---------------------------------------------------------------------------

def _post_routes(verifier) -> list[APIRoute]:
    return [route for route in verifier.app.routes
            if isinstance(route, APIRoute) and "POST" in route.methods]


def _gate_names(route: APIRoute) -> set[str]:
    return {dep.call.__name__ for dep in route.dependant.dependencies}


def write_routes(verifier) -> dict[str, APIRoute]:
    """Every POST route gated by `_require_write_key`, keyed by path.

    The discriminator is the dependency and not the path or the method:
    `POST /verify` is a read and takes `_require_read_key`, so a rule about
    "the POST routes" would either sweep it in or leave it out by judgement.
    """
    return {route.path: route for route in _post_routes(verifier)
            if "_require_write_key" in _gate_names(route)}


# ---------------------------------------------------------------------------
# Stub clients. Each one answers the narrow set of calls the route under test
# makes, and records what it was asked to do.
# ---------------------------------------------------------------------------

class _Got:
    def __init__(self, tx: int, value: bytes):
        self.tx = tx
        self.value = value


class _StubBase:
    """Records every unverified `set`, which is what D35's no-proof path uses.

    Nothing here answers a call it was not given an answer for: an
    unanticipated call raises, so a driver cannot pass because the route took
    a path the stub silently absorbed.
    """

    def __init__(self):
        self.unverified_sets: list[tuple[bytes, bytes]] = []

    def set(self, key, value):
        self.unverified_sets.append((key, value))
        return type("Resp", (), {"id": 909})()


class _PlainWriteClient(_StubBase):
    """`POST /write`'s client. `verifiedSet` fails; the ledger holds `stored`."""

    def __init__(self, stored: dict[bytes, _Got], raise_on_set=None,
                 unreadable: tuple[bytes, ...] = ()):
        super().__init__()
        self._stored = stored
        self._unreadable = unreadable
        self._raise = raise_on_set or RuntimeError(
            "StatusCode.UNAVAILABLE: Stream removed (Socket closed)")

    def verifiedSet(self, key, value):
        raise self._raise

    def get(self, key):
        if key in self._unreadable:
            raise RuntimeError("StatusCode.UNAVAILABLE: connection refused")
        return self._stored.get(key)

    def currentState(self):
        return type("State", (), {"txId": 1})()


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

        class _Stub:
            def ExecAll(self, request):
                outer.execall_requests.append(request)
                raise execall_error or RuntimeError(
                    "StatusCode.UNAVAILABLE: Stream removed (Socket closed)")

        self._stub = _Stub()

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
    """
    verifier = _load_verifier()
    posts = {route.path: _gate_names(route) for route in _post_routes(verifier)}
    assert posts, "the verifier registered no POST routes at all"

    ungated = [path for path, gates in posts.items()
               if not ({"_require_write_key", "_require_read_key"} & gates)]
    assert not ungated, (
        f"POST route(s) {ungated} are gated by neither _require_write_key nor "
        "_require_read_key, so this file cannot say whether they are writes. "
        "D21 gates every route; a new one has to declare which it is."
    )

    writes = write_routes(verifier)
    assert writes, "no POST route is gated by _require_write_key"
    assert "/verify" not in writes, (
        "POST /verify is gated by the write key. It is a read, and every "
        "property in this file would now be asserted against it."
    )


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
