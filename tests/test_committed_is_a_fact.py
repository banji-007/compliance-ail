"""tests/test_committed_is_a_fact.py - Phase 3c-3d (P3c3d-6, P3c3d-7, D40).

`committed` describes what is in the ledger, not whether a later call
succeeded. And the GDPR erasure path, which is where that mattered.

The attack, red-team A1 and A8, reproduced live on `e3d8284` before anything
here was written. A TCP relay between the verifier and ImmuDB passes the
write through - so it commits, its response returns, and the SDK persists the
new trust anchor - and then cuts the connection, so the client's NEXT RPC
fails. `POST /write` issued `currentState()` as that next RPC, inside the same
`try` as `verifiedSet`, under a broad `except Exception` that answered
`committed: false`:

    STATE BEFORE: {... "cutproxy:3399/b'defaultdb'": 13}
    WRITE -> (200, {'tx_id': None, 'verified': False, 'committed': False,
                    'detail': 'StatusCode.UNAVAILABLE ... Socket closed'})
    LEDGER-> {"probe:ZZCUTZZ-a1-5172ec": {"tx": "14", "revision": "1"}}
    STATE AFTER : {... "cutproxy:3399/b'defaultdb'": 14}

The anchor advanced to 14, the transaction the response says never happened.
`{"tx_id": null, "verified": false}` is the exact shape
`ledger/immudb_ledger.py` reads as "the write did not happen".

A8 is the same defect on the GDPR path. `_write_tombstone` raised on
not-committed and `erase_content` turned that into a 503 without deleting, so
a tombstone that committed while the response said `committed: false`
produced exactly the `erasure_conflict` P3c3c-12 claimed to remove:

    DELETE -> 503 {"detail":"Tombstone write failed; erasure refused: ...
                    Tombstone write not verified: ... UNAVAILABLE ..."}
    is the tombstone in the ledger? {"content_erasure:a8ZZCUTZZ007":
                                     {"tx": "16", "rev": "1"}}
    control-plane store row: a8ZZCUTZZ007 -> [('a8ZZCUTZZ007', 22)]
    re-POST /content -> 409 "has been erased; content writes are refused"

The ledger says erased, the store still holds the payload, the caller was
told the erasure was refused, and content writes for that call_id are frozen
at 409: the subject's data is unerasable through the documented route and
unwritable.

The relay is the test fixture below rather than a described mechanism, so the
attack itself is what runs. It is also driven a second way that needs no
container - the route executed against a client whose `currentState` raises -
because that is the branch the named mutation moves and a test that can only
observe it through a race is a poor place to put a mutation.

Requires the docker CLI: the fixture starts a container on the compose
network and recreates the verifier pointed at it.
"""

import base64
import contextlib
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tests"))

from bounded_read_checks import assert_inside_score_window  # noqa: E402

from compose_helpers import (  # noqa: E402
    COMPOSE_PROJECT, compose, requires_docker_cli, wait_for_health,
)

CONTROL_PLANE_URL  = os.getenv("CONTROL_PLANE_URL",       "http://localhost:8002")
WRITE_API_KEY      = os.getenv("CONTROL_PLANE_WRITE_KEY", "test-write-key")
VERIFIER_URL       = os.getenv("VERIFIER_URL",            "http://localhost:8003")
VERIFIER_WRITE_KEY = os.getenv("VERIFIER_WRITE_KEY",      "test-verifier-write-key")
IMMUDB_URL         = os.getenv("IMMUDB_URL",              "http://localhost:8080")
IMMUDB_USER        = os.getenv("IMMUDB_USER",             "immudb")
IMMUDB_PASSWORD    = os.getenv("IMMUDB_PASSWORD",         "immudb")

MARKER = "ZZCUTZZ"
PROXY_NAME = f"{COMPOSE_PROJECT}-p3c3d-cutproxy"
PROXY_ALIAS = "cutproxy"

requires_stack = pytest.mark.needs_stack("immudb", "verifier", "control_plane")

_CLIENT = httpx.Client(timeout=60.0)


# The relay. Written as a string and passed to `python -c`, so the fixture
# needs no bind mount and no host path translation.
#
# Four modes (P3c3e-2, Phase 3c-3e), because the Phase 3c-3d red team drove
# three different cuts and each lands on a different RPC. One relay, because
# it is one fixture: what varies is which frame is dropped.
#
#   next-rpc   Relay the marked request AND its response, then drop the
#              client's NEXT request of at least CUT_MIN_FRAME bytes and close,
#              so the flow-control frames in between do not count as that RPC.
#              "ImmuDB went away right after the write returned." P3c3d-6 and
#              P3c3d-7 drive this one.
#
#   response   Relay the marked request upstream so it commits, then drop its
#              OWN response and close. "Connection reset after commit, on the
#              commit's own RPC." Red-team A4.1: the ordered write's ExecAll
#              landed whole - record, counter advance and index entry - and
#              the response said the write did not happen.
#
#   blackhole  `response`, and then refuse every connection for
#              CUT_BLACKHOLE_SECONDS, so the read that would confirm the
#              commit cannot run either. Red-team A4.2, the cut that
#              reproduced the GDPR erasure_conflict in full.
#
#   drop-request  Relay everything until the marked request arrives, then drop
#              that request WITHOUT relaying it and blackhole. Nothing about
#              this write reaches the ledger, so its key is still free - the
#              control for P3c3e-3, where the retry the caller is told to make
#              has to succeed. A relay that refused every connection from the
#              start would do instead, except that the verifier logs into
#              ImmuDB in its lifespan and would never come up healthy.
#
# Arming is on a request frame carrying the marker AND at least CUT_ARM_MIN
# bytes, which distinguishes a write (key plus a signed record) from the small
# reads the same connection also carries. **Arming happens after the frame has
# been relayed upstream**, not before: in `response` mode the down pump closes
# both sockets as soon as it is armed, and arming first raced the up pump's
# own `sendall` of the very request that is supposed to commit.
_PROXY_SOURCE = """
import os, socket, threading, time

LISTEN = 3399
UPSTREAM = ("immudb", 3322)
MARKER = os.environ.get("CUT_MARKER", "ZZCUTZZ").encode()
ARM_MIN = int(os.environ.get("CUT_ARM_MIN", "600"))
MIN_FRAME = int(os.environ.get("CUT_MIN_FRAME", "40"))
MODE = os.environ.get("CUT_MODE", "next-rpc")
BLACKHOLE_SECONDS = float(os.environ.get("CUT_BLACKHOLE_SECONDS", "25"))

blackhole_until = [0.0]


# The `response` and `blackhole` cuts fire on ONE frame and no other: a
# HEADERS or DATA frame, on the stream the marked request was sent on.
#
# Both halves are load-bearing, and each was learned by getting it wrong.
#
# Frame TYPE, because "the first frame back after arming" is wrong: ImmuDB
# answers on the same connection with SETTINGS, WINDOW_UPDATE and PING frames
# that have nothing to do with the request, and cutting on one of those closes
# the connection while the write is still in flight, so it never commits and
# the test measures nothing. Observed on a Linux CI runner, where the same
# relay that cut correctly on the development host produced
# `attempts: 1, committed: false` with the record absent from the ledger.
#
# Frame STREAM, because the SDK multiplexes: a login, a state read and the
# write share one connection, so a HEADERS frame answering some other RPC
# arrives on another stream and is not evidence that this write committed.
# Observed on this host after the type check was added, on the plain route:
# the relay cut and blackholed, and the record was still absent.
#
# grpc-go writes response HEADERS when the handler returns, so HEADERS or DATA
# on the request's own stream means ImmuDB finished it, which is the condition
# these tests need. A frame header is 3 bytes of length, 1 of type, 1 of flags
# and 4 of stream id, and one recv can carry several, so they are walked.
def frame_stream(data):
    if len(data) < 9:
        return None
    return int.from_bytes(data[5:9], "big") & 0x7FFFFFFF


def carries_a_response(data, stream):
    at = 0
    while at + 9 <= len(data):
        length = int.from_bytes(data[at:at + 3], "big")
        if data[at + 3] in (0, 1):
            if stream is None or frame_stream(data[at:]) == stream:
                return True
        at += 9 + length
    return False


def pump(src, dst, state, direction):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            if (direction == "down" and state.get("armed")
                    and MODE in ("response", "blackhole")
                    and carries_a_response(data, state.get("stream"))):
                print("CUT: dropping the %dB response to the marked request "
                      "and closing" % len(data), flush=True)
                if MODE == "blackhole":
                    blackhole_until[0] = time.time() + BLACKHOLE_SECONDS
                    print("CUT: blackholing immudb for %ss" % BLACKHOLE_SECONDS,
                          flush=True)
                break
            if (direction == "up" and state.get("relayed")
                    and len(data) >= MIN_FRAME):
                print("CUT: the marked response was relayed; cutting the NEXT RPC",
                      flush=True)
                break
            if (direction == "up" and MODE == "drop-request"
                    and MARKER in data and len(data) >= ARM_MIN):
                print("CUT: dropping the %dB marked request without relaying it"
                      % len(data), flush=True)
                blackhole_until[0] = time.time() + BLACKHOLE_SECONDS
                print("CUT: blackholing immudb for %ss" % BLACKHOLE_SECONDS,
                      flush=True)
                break
            dst.sendall(data)
            if (direction == "up" and MARKER in data and len(data) >= ARM_MIN
                    and not state.get("armed")):
                state["armed"] = True
                state["stream"] = frame_stream(data)
                print("CUT: armed on a %dB request carrying the marker, stream %s"
                      % (len(data), state["stream"]), flush=True)
            if direction == "down" and state.get("armed"):
                state["relayed"] = True
    except Exception as exc:
        print("CUT: %s pump ended: %s" % (direction, exc), flush=True)
    finally:
        for sock in (src, dst):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass


def handle(client):
    upstream = socket.create_connection(UPSTREAM)
    state = {}
    threading.Thread(target=pump, args=(client, upstream, state, "up"),
                     daemon=True).start()
    threading.Thread(target=pump, args=(upstream, client, state, "down"),
                     daemon=True).start()


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", LISTEN))
server.listen(64)
print("CUT: listening on %d -> %s:%d mode=%s"
      % (LISTEN, UPSTREAM[0], UPSTREAM[1], MODE), flush=True)
while True:
    conn, _ = server.accept()
    if time.time() < blackhole_until[0]:
        print("CUT: refusing a connection", flush=True)
        try:
            conn.close()
        except Exception:
            pass
        continue
    handle(conn)
"""

_ANCHOR_SCRIPT = """
import pickle
with open("/data/verifier-state/immudb.state", "rb") as handle:
    print({db: state.txId for db, state in pickle.load(handle).items()})
"""


def _b64(value) -> str:
    return base64.b64encode(value if isinstance(value, bytes) else value.encode()).decode()


def _immudb_headers() -> dict:
    resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/login", json={
        "user": _b64(IMMUDB_USER), "password": _b64(IMMUDB_PASSWORD),
        "database": _b64("defaultdb"),
    })
    resp.raise_for_status()
    return {"Authorization": f"Bearer {resp.json()['token']}"}


def _getall(headers: dict, keys: list[str]) -> dict:
    resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/getall",
                        json={"keys": [_b64(k) for k in keys]}, headers=headers)
    resp.raise_for_status()
    return {base64.b64decode(e["key"]).decode(): e
            for e in resp.json().get("entries", [])}


def _proxy_log(name: str = PROXY_NAME) -> str:
    return subprocess.run(["docker", "logs", name],
                          capture_output=True, text=True).stdout


def _verifier_container_id() -> str:
    """Which container is serving the verifier right now."""
    result = compose("ps", "-q", "verifier", check=False)
    return (result.stdout or "").strip()


def _wait_for_a_new_verifier(previous: str, timeout_seconds: float = 120.0) -> bool:
    """Block until the verifier is a DIFFERENT container than `previous`.

    **`wait_for_health` alone is not enough, and this is why.** `compose up -d
    --force-recreate` returns before the replacement is serving, and the
    outgoing container answers `/health` while it is on its way out - so a
    health poll issued immediately can pass against the container that is
    about to die. The test then writes through a verifier still pointed at
    ImmuDB, the relay never sees a connection at all, and the write lands
    with the relay log holding nothing but its own startup line.

    Observed exactly that in a full-suite run: `the relay never dropped a
    response ... Relay log: CUT: listening on 3399 -> immudb:3322
    mode=response`. The retry above could not help, because the write had
    landed - by going around the fixture.
    """
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        current = _verifier_container_id()
        if current and current != previous:
            return True
        time.sleep(1)
    return False


def cut_until_it_lands(build, drive, landed, attempts: int = 4):
    """Drive a cut until the write it was aimed at actually reached the ledger.

    **This retries the FIXTURE, never the assertion.** Every test below draws a
    distinction its own message states: a write that reached the ledger and was
    misreported is the defect under test, and a write that never reached the
    ledger means the relay cut too early and the test exercised nothing. The
    second is a miss, and a miss is what this retries.

    Why a miss is possible at all. The cut fires on a HEADERS or DATA frame on
    the marked request's own stream, which is the tightest signal available
    from outside the process, and it is still a signal about frames rather
    than about the commit. Measured over full-suite runs on this host it
    misses roughly one attempt in thirty; observed once as
    `attempts: 1, committed: false` with the record absent. Leaving that as a
    failure would put a fixture's timing into the suite's order-dependence
    measurement, which is the one thing this phase is trying to measure
    cleanly.

    `build` returns whatever a fresh attempt needs - a new key, so an attempt
    that half-landed cannot poison the next one. `drive` performs the write
    behind the relay and returns whatever the assertions need. `landed` is
    given both, and answers whether the FIXTURE did its job: the relay cut and
    the write reached the ledger. Both halves, because either one alone has a
    failure mode the other hides - a write that never landed means the cut was
    too early, and a write that landed with a relay log holding nothing means
    it went around the relay entirely.

    The last attempt's result is returned whether it worked or not, so the
    caller's own guards are what report a fixture that never managed it.
    """
    for attempt in range(attempts):
        subject = build()
        result = drive(subject)
        if landed(subject, result):
            return subject, result, attempt + 1
    return subject, result, attempts


def confirming_read_could_not_run(response) -> bool:
    """Whether `committed: null` means the FIXTURE missed, rather than the
    route lying.

    **P3c3f-1 (Phase 3c-3f). This is the retry predicate's third conjunct, and
    it is a function so the enforcing test can drive the same one the call
    site uses.**

    The predicate at the ordered-write call site read
    `r[0].json().get("committed") is True`, which is the assertion twenty
    lines below it. `cut_until_it_lands`'s docstring says in bold that it
    retries the fixture and never the assertion, and `is True` excludes `null`
    AND `false`. `false` is the defect: the Phase 3c-3e red team injected A4.1
    intermittently, the route answered `committed=false tx_id=null` for a
    record present at transaction 8, the predicate called that a miss, drove
    the whole write again, and the suite read `1 passed`. Reproduced here at
    `attempts: 2` with the lie discarded.

    `is not None` is the condition, and it is not the correction the
    instruction named. `is not False` was proposed, on the argument that null
    is honest and false is the only lie - which is right about the assertion
    and backwards here, because a predicate answering False is what causes a
    retry:

        committed  true  -> the fixture worked            -> stop, and assert
        committed  false -> the fixture worked, route lied -> STOP, and assert
        committed  null  -> the confirming read could not run -> retry

    `is not False` stops on null and retries on false, which is wrong in both
    of the two rows that matter.

    Null is a fixture condition on these tests specifically: the relay closes
    the connection it cut, so the read the route makes to settle `committed`
    can hit a dead socket. That is D45 being honest and it is asserted in its
    own right by
    `test_a_plain_write_states_no_fact_when_the_confirming_read_is_cut_too`.
    """
    return response.json().get("committed") is None


@contextlib.contextmanager
def relay(mode: str, name: str, alias: str, marker: str = MARKER, **env: str):
    """The verifier talking to ImmuDB through a relay in one of the modes above.

    A context manager rather than a fixture, because more than one mode is
    driven in this module and two module-scoped fixtures that each recreate
    the verifier would leave it pointed at whichever ran last. Teardown is
    unconditional and includes the verifier's address: a session that left it
    pointed at a stopped relay would fail every later test in a way that
    reads as a code regression.
    """
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    arguments = [
        "docker", "run", "-d", "--name", name,
        "--network", f"{COMPOSE_PROJECT}_default",
        "--network-alias", alias,
        "-e", f"CUT_MARKER={marker}",
        "-e", f"CUT_MODE={mode}",
    ]
    for key, value in env.items():
        arguments += ["-e", f"{key}={value}"]
    arguments += ["python:3.11-slim", "python", "-c", _PROXY_SOURCE]
    started = subprocess.run(arguments, capture_output=True, text=True)
    assert started.returncode == 0, (
        f"could not start the {mode} relay: {started.stderr[-400:]}"
    )
    outgoing = _verifier_container_id()
    try:
        compose("up", "-d", "--force-recreate", "verifier",
                env={"IMMUDB_ADDR": f"{alias}:3399"})
        assert _wait_for_a_new_verifier(outgoing), (
            f"the verifier was not replaced, so it is not pointed at the {mode} "
            "relay"
        )
        assert wait_for_health(f"{VERIFIER_URL}/health"), (
            f"the verifier did not come back pointed at the {mode} relay"
        )
        yield name
    finally:
        replaced = _verifier_container_id()
        compose("up", "-d", "--force-recreate", "verifier", check=False)
        _wait_for_a_new_verifier(replaced)
        wait_for_health(f"{VERIFIER_URL}/health")
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def _anchor_state() -> str:
    result = compose("exec", "-T", "verifier", "python", "-",
                     stdin=_ANCHOR_SCRIPT, check=False)
    return (result.stdout or result.stderr).strip()


@pytest.fixture(scope="module")
def cut_proxy():
    """The verifier talking to ImmuDB through a relay that cuts after a write.

    Torn down unconditionally, including the verifier's address: a session
    that left the verifier pointed at a stopped relay would fail every later
    test in a way that reads as a code regression.
    """
    with relay("next-rpc", PROXY_NAME, PROXY_ALIAS):
        yield


# ---------------------------------------------------------------------------
# P3c3d-6: committed is a fact about the ledger.
# ---------------------------------------------------------------------------

@requires_stack
@requires_docker_cli
def test_a_write_that_committed_is_reported_as_committed_when_the_state_call_fails(
        cut_proxy):
    """
    The probe's cut case, on the plain route. The write commits and its proof
    checks out; the RPC after it does not. The response has to describe the
    ledger.
    """
    headers = _immudb_headers()
    key = f"probe:{MARKER}-p3c3d6-{uuid.uuid4().hex[:6]}"
    value = json.dumps({"record_type": "probe", "note": "x" * 600},
                       separators=(",", ":"))

    before = _anchor_state()
    resp = _CLIENT.post(f"{VERIFIER_URL}/write",
                        json={"key": _b64(key), "value": _b64(value)},
                        headers={"X-API-Key": VERIFIER_WRITE_KEY})
    assert resp.status_code == 200, resp.text[:300]
    body = resp.json()
    after = _anchor_state()

    assert "cutting the NEXT RPC" in _proxy_log(), (
        "the relay never cut a connection, so this test is not exercising the "
        f"condition it describes. Relay log: {_proxy_log()[-400:]}"
    )

    stored = _getall(headers, [key])
    assert key in stored, (
        "the write did not reach the ledger, so this test is not exercising "
        "the condition it describes"
    )
    ledger_tx = int(stored[key]["tx"])

    assert body["committed"] is True, (
        f"a write that committed at transaction {ledger_tx} reported itself as "
        f"never having happened: {body}. Anchor before {before}, after {after}."
    )
    assert body["tx_id"] == ledger_tx, (
        f"the response names transaction {body['tx_id']} and the ledger holds "
        f"this key at {ledger_tx}: {body}"
    )
    if body["verified"]:
        assert str(ledger_tx) in after, (
            "the response says the proof checked out and the persisted anchor "
            f"does not carry that transaction: {after}"
        )


def test_the_state_call_cannot_describe_the_write():
    """
    The same property, driven directly, because this is the branch the named
    mutation moves.

    The route is executed against a client whose `verifiedSet` succeeds and
    whose `currentState` raises. Before D40 both calls sat in one `try` under
    a broad `except Exception` that answered `{"tx_id": null, "verified":
    false, "committed": false}` - the exact shape ledger/immudb_ledger.py
    reads as "the write did not happen".
    """
    import importlib.util

    os.environ.setdefault("VERIFIER_WRITE_KEY", VERIFIER_WRITE_KEY)
    spec = importlib.util.spec_from_file_location(
        "p3c3d_verifier", REPO_ROOT / "verifier" / "main.py")
    verifier = importlib.util.module_from_spec(spec)
    sys.modules["p3c3d_verifier"] = verifier
    spec.loader.exec_module(verifier)

    class _StateCallFails:
        def verifiedSet(self, key, value):
            return type("Resp", (), {"id": 4242})()

        def currentState(self):
            raise RuntimeError("StatusCode.UNAVAILABLE: Socket closed")

    original = verifier._get_client
    verifier._get_client = lambda: _StateCallFails()
    try:
        payload = verifier.WriteRequest(
            key=_b64("probe:p3c3d-state-call"),
            value=_b64(json.dumps({"record_type": "probe"})),
        )
        response = verifier.write(payload)
    finally:
        verifier._get_client = original

    assert response.committed is True, (
        f"a failing state call reported the write as never having happened: "
        f"{response}"
    )
    assert response.tx_id == 4242, response
    assert response.verified is True, (
        "the proof checked out and the response says otherwise, so the state "
        f"call is still describing the proof: {response}"
    )


def test_a_transport_failure_on_the_write_itself_asks_the_ledger():
    """
    The other half of D40, and the reason the fix is not only moving one line.

    A transport error raised by `verifiedSet` itself is ambiguous: the commit
    may or may not have happened. Answering `committed: false` is a guess, and
    it is the guess that produced the reproduction above. The ledger is asked,
    with the value as well as the key, so a record that was already under this
    key is not reported as this write.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "p3c3d_verifier_b", REPO_ROOT / "verifier" / "main.py")
    verifier = importlib.util.module_from_spec(spec)
    sys.modules["p3c3d_verifier_b"] = verifier
    spec.loader.exec_module(verifier)

    written = json.dumps({"record_type": "probe"}).encode()

    class _CommittedThenCut:
        def verifiedSet(self, key, value):
            raise RuntimeError("StatusCode.UNAVAILABLE: Socket closed")

        def get(self, key):
            return type("Got", (), {"tx": 77, "value": written})()

    class _NeverCommitted:
        def verifiedSet(self, key, value):
            raise RuntimeError("StatusCode.UNAVAILABLE: Socket closed")

        def get(self, key):
            return type("Got", (), {"tx": 77, "value": b"some other record"})()

    payload = verifier.WriteRequest(key=_b64("probe:p3c3d-transport"),
                                    value=_b64(written.decode()))
    original = verifier._get_client
    try:
        verifier._get_client = lambda: _CommittedThenCut()
        landed = verifier.write(payload)
        verifier._get_client = lambda: _NeverCommitted()
        did_not = verifier.write(payload)
    finally:
        verifier._get_client = original

    assert landed.committed is True and landed.tx_id == 77, (
        f"the bytes are in the ledger and the response says otherwise: {landed}"
    )
    assert landed.verified is False, (
        f"no proof ran, so nothing verified: {landed}"
    )
    assert did_not.committed is False and did_not.tx_id is None, (
        "a different record under the same key was reported as this write: "
        f"{did_not}"
    )


# ---------------------------------------------------------------------------
# P3c3d-7: the GDPR erasure path.
# ---------------------------------------------------------------------------

@requires_stack
@requires_docker_cli
def test_an_erasure_completes_when_its_tombstone_commits_and_the_state_call_fails(
        cut_proxy):
    """
    A8's attack sequence, with the erasure completing.

    Before D40 this answered 503, left the tombstone in the ledger, left the
    payload in the store, and froze content writes for that call_id at 409 -
    the subject's data unerasable through the documented route and
    unwritable, which is the `erasure_conflict` P3c3c-12 claimed to remove.
    """
    headers = _immudb_headers()
    call_id = f"a8{MARKER}{uuid.uuid4().hex[:6]}"

    wrote = _CLIENT.post(f"{CONTROL_PLANE_URL}/content",
                         json={"call_id": call_id, "payload": {"q": "personal data"}},
                         headers={"X-API-Key": WRITE_API_KEY})
    assert wrote.status_code == 204, wrote.text[:300]

    deleted = _CLIENT.delete(f"{CONTROL_PLANE_URL}/content/{call_id}",
                             headers={"X-API-Key": WRITE_API_KEY})

    assert "cutting the NEXT RPC" in _proxy_log(), (
        "the relay never cut a connection, so this test is not exercising the "
        f"condition it describes. Relay log: {_proxy_log()[-400:]}"
    )
    tombstone_key = f"content_erasure:{call_id}"
    assert tombstone_key in _getall(headers, [tombstone_key]), (
        "no tombstone reached the ledger, so this test is not exercising the "
        "condition it describes: the attack is about a tombstone that "
        "committed while the response said it had not"
    )

    assert deleted.status_code == 204, (
        f"the erasure was refused while its tombstone was in the ledger: "
        f"{deleted.status_code} {deleted.text[:300]}. The ledger says this "
        "call_id was erased, the store still holds the payload, and content "
        "writes for it are now frozen at 409."
    )

    # And the row is gone, which is what the caller asked for and what the
    # ledger now says happened.
    again = _CLIENT.delete(f"{CONTROL_PLANE_URL}/content/{call_id}",
                           headers={"X-API-Key": WRITE_API_KEY})
    assert again.status_code == 204, again.text[:300]


# ---------------------------------------------------------------------------
# P3c3e-2 (Phase 3c-3e): the same property, on the route that never got it.
# ---------------------------------------------------------------------------
#
# Red-team A4.1, verbatim. This file had four tests when it was written in
# Phase 3c-3d and every one of them drove `POST /write`. `POST /write-ordered`
# - the route ledger/immudb_ledger.py takes for every decision and every
# intent - still answered `committed: false` from a generic handler that asked
# the ledger nothing:
#
#     WRITE -> 200 {"tx_id": null, "seq": null, "verified": false,
#                   "committed": false, "attempts": 0,
#                   "detail": "StatusCode.UNAVAILABLE ... Socket closed"}
#     LEDGER-> {"tool_call:p3c3dred-a4:...": {"tx": "55", "revision": "1"}}
#     view   -> (1000000017, 'tool_call:p3c3dred-a4:...', '55')
#     /audit -> 1 row for this call_id, "outcome_type": "policy_allow"
#
# The whole ExecAll landed - record, counter advance, index entry - and the
# response said the write did not happen. log_tool_call raises on anything
# but verified: true, so the decision service denied a call whose allow
# decision is on the audit page.

_ORDERED_MARKER = "ZZORDZZ"
_ORDERED_PROXY = f"{COMPOSE_PROJECT}-p3c3e-cutresponse"
_BLACKHOLE_PROXY = f"{COMPOSE_PROJECT}-p3c3e-blackhole"
_DROP_REQUEST_PROXY = f"{COMPOSE_PROJECT}-p3c3e-droprequest"

VIEW_DECISION = "ail_view:decision:v1"


def _ordered_record(call_id: str, agent: str) -> str:
    """A decision record big enough for the relay to arm on.

    The relay arms on a request frame of at least CUT_ARM_MIN bytes carrying
    the marker, which is how a write is told apart from the small reads the
    same connection carries. A real decision record is comfortably past that;
    `note` makes it so regardless of what the record's own fields cost.
    """
    return json.dumps({
        "record_type": "decision", "call_id": call_id, "agent_id": agent,
        "timestamp": "2026-09-02T00:00:00", "tool_name": "query_database",
        "outcome_type": "policy_allow", "fault_class": None,
        "policy_revision": "p3c3e-test", "reasons": [],
        "input_sha256": uuid.uuid4().hex, "content_state": "unavailable",
        "profile": "observed", "note": "x" * 700,
    }, separators=(",", ":"))


def _ordered_write(key: str, value: str, view: str = "decision"):
    return _CLIENT.post(f"{VERIFIER_URL}/write-ordered",
                        json={"key": _b64(key), "value": _b64(value),
                              "view": view},
                        headers={"X-API-Key": VERIFIER_WRITE_KEY})


def _members_at_position(headers: dict, view_set: str, score: float):
    """Which keys the view holds at exactly this position."""
    resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/zscan", json={
        "set": _b64(view_set), "desc": False, "limit": 100,
        "minScore": {"score": score}, "maxScore": {"score": score},
    }, headers=headers)
    resp.raise_for_status()
    rows = resp.json().get("entries", [])
    page = [(base64.b64decode(row["entry"]["key"]).decode(),
             float(row.get("score", 0.0))) for row in rows]
    # P3c3f-3 (D46): the window, asserted on what came back. Without it a
    # dropped bound makes "this key is at this position" true of every
    # position the view holds.
    assert_inside_score_window(page, score, score,
                               f"_members_at_position({view_set})")
    return [member for member, _score in page]


@requires_stack
@requires_docker_cli
def test_an_ordered_write_that_committed_is_reported_as_committed_when_its_response_is_dropped():
    """
    A4.1, driven. The ExecAll's own response is dropped after it commits.

    Everything the ExecAll carries is in the ledger afterwards - the record,
    the advanced counter and the index entry at the allocated position - so a
    response saying the write did not happen is a false statement about the
    ledger, and it is the statement ledger/immudb_ledger.py acts on.
    """
    headers = _immudb_headers()
    agent = f"p3c3e-{_ORDERED_MARKER}"

    def _build():
        return f"tool_call:{agent}:{uuid.uuid4().hex}:query_database"

    def _drive(key):
        value = _ordered_record(uuid.uuid4().hex, agent)
        with relay("response", _ORDERED_PROXY, "cutresponse",
                   marker=_ORDERED_MARKER):
            written = _ordered_write(key, value)
            # Read inside the block: the relay container is removed on the way
            # out, and a log read after that is empty, which would turn this
            # guard into one that can never fire.
            return written, _proxy_log(_ORDERED_PROXY)

    # The fixture is retried until the cut landed AND the verifier's own
    # confirming read could run. Both are fixture conditions: the relay closes
    # the connection it cut, so the read that follows can hit a dead socket
    # and answer `committed: null` - which is D45 being honest, asserted in
    # its own right by test_a_plain_write_states_no_fact_when_the_confirming_
    # read_is_cut_too below, and not the state this test is about.
    #
    # P3c3f-1: `confirming_read_could_not_run`, not `committed is True`. The
    # third conjunct used to be the assertion below, so a route answering
    # `committed: false` about a record in the ledger was retried past instead
    # of failing. See that function for the transcript.
    key, (response, log), _tries = cut_until_it_lands(
        _build, _drive,
        lambda k, r: "dropping the" in r[1] and k in _getall(headers, [k])
        and not confirming_read_could_not_run(r[0]))

    assert response.status_code == 200, response.text[:300]
    body = response.json()
    assert "dropping the" in log, (
        "the relay never dropped a response, so this test is not exercising "
        f"the condition it describes. Relay log: {log[-500:]}"
    )

    stored = _getall(headers, [key])
    assert key in stored, (
        "the ExecAll did not reach the ledger, so this test is not exercising "
        f"the condition it describes. Response was {body}. Relay log: "
        f"{log[-500:]}"
    )
    ledger_tx = int(stored[key]["tx"])

    assert body["committed"] is True, (
        f"the record is in the ledger at transaction {ledger_tx} and the "
        f"ordered route says the write never happened: {body}"
    )
    assert body["tx_id"] == ledger_tx, (
        f"the response names transaction {body['tx_id']} and the ledger holds "
        f"this record at {ledger_tx}: {body}"
    )
    assert body["verified"] is False, (
        f"no proof ran on this write, so nothing verified: {body}"
    )
    assert body["attempts"] >= 1, (
        f"the commit took at least one attempt and the response reports "
        f"{body['attempts']}: {body}"
    )

    # The position, confirmed against the view rather than taken from the
    # response. A response naming a position the index does not hold would be
    # the same class of claim in a different field.
    assert body["seq"] is not None, (
        "the ExecAll that committed the record committed its zAdd too, and "
        f"the response reports no position: {body}"
    )
    members = _members_at_position(headers, VIEW_DECISION, float(body["seq"]))
    assert key in members, (
        f"the response says this record holds position {body['seq']} and the "
        f"decision view at that position holds {members}"
    )


@requires_stack
@requires_docker_cli
def test_a_plain_write_states_no_fact_when_the_confirming_read_is_cut_too():
    """
    A4.2 on `POST /write`. The write's response is dropped and ImmuDB is then
    unreachable, so the read D40 added cannot run either.

    Before D45 the route answered `committed: false` here - one RPC further
    along than the guess D40 removed, and the same guess. The record was at
    transaction 118.

    `committed: null` is the whole fix: this service says what it knows. It is
    refused exactly as `false` is, because every caller keys on `verified`.
    """
    headers = _immudb_headers()
    value = json.dumps({"record_type": "probe", "note": "x" * 900},
                       separators=(",", ":"))

    def _build():
        return f"probe:{_ORDERED_MARKER}-plain-{uuid.uuid4().hex[:6]}"

    def _drive(key):
        with relay("blackhole", _BLACKHOLE_PROXY, "cutblackhole",
                   marker=_ORDERED_MARKER, CUT_BLACKHOLE_SECONDS="25"):
            written = _CLIENT.post(f"{VERIFIER_URL}/write",
                                   json={"key": _b64(key), "value": _b64(value)},
                                   headers={"X-API-Key": VERIFIER_WRITE_KEY})
            return written, _proxy_log(_BLACKHOLE_PROXY)

    key, (response, log), _tries = cut_until_it_lands(
        _build, _drive,
        lambda k, r: "blackholing immudb" in r[1] and k in _getall(headers, [k]))

    assert response.status_code == 200, response.text[:300]
    body = response.json()
    assert "blackholing immudb" in log, (
        "the relay never blackholed ImmuDB, so this test is not exercising the "
        f"condition it describes. Relay log: {log[-500:]}"
    )

    stored = _getall(headers, [key])
    assert key in stored, (
        "the write did not reach the ledger, so this test is not exercising "
        f"the condition it describes. Response was {body}. Relay log: "
        f"{log[-500:]}"
    )

    assert body["committed"] is not False, (
        f"the record is in the ledger at transaction {stored[key]['tx']} and "
        f"the response says the write did not happen: {body}"
    )
    assert body["committed"] is None, (
        "the confirming read could not run, so `committed: true` is not a fact "
        f"this service has either: {body}"
    )
    assert body["verified"] is False, body


@requires_stack
@requires_docker_cli
def test_an_erasure_completes_when_the_ledger_goes_away_after_the_tombstone_commits():
    """
    A4.2's consequence, which is the one that matters: the GDPR path.

    The same cut on `POST /write` reproduced Phase 3c-3c's `erasure_conflict`
    verbatim against the head that reported it closed - DELETE 503, the
    tombstone committed at transaction 121, 772 bytes of payload still in
    `call_content`, and content writes for that call_id frozen at 409. The
    subject's data unerasable through the documented route and unwritable.

    The control plane has its own path to ImmuDB, which this relay does not
    sit on, so when the verifier says the outcome is not established it asks
    the ledger itself (D45).
    """
    headers = _immudb_headers()

    def _build():
        call_id = f"e2{_ORDERED_MARKER}{uuid.uuid4().hex[:6]}"
        wrote = _CLIENT.post(f"{CONTROL_PLANE_URL}/content",
                             json={"call_id": call_id,
                                   "payload": {"q": "personal data " + "x" * 900}},
                             headers={"X-API-Key": WRITE_API_KEY})
        assert wrote.status_code == 204, wrote.text[:300]
        return call_id

    def _drive(call_id):
        with relay("blackhole", _BLACKHOLE_PROXY, "cutblackhole",
                   marker=_ORDERED_MARKER, CUT_BLACKHOLE_SECONDS="20"):
            removed = _CLIENT.delete(f"{CONTROL_PLANE_URL}/content/{call_id}",
                                     headers={"X-API-Key": WRITE_API_KEY})
            return removed, _proxy_log(_BLACKHOLE_PROXY)

    call_id, (deleted, log), _tries = cut_until_it_lands(
        _build, _drive,
        lambda cid, r: "blackholing immudb" in r[1]
        and f"content_erasure:{cid}" in _getall(
            headers, [f"content_erasure:{cid}"]))

    assert "blackholing immudb" in log, (
        "the relay never blackholed ImmuDB, so this test is not exercising the "
        f"condition it describes. Relay log: {log[-500:]}"
    )
    tombstone_key = f"content_erasure:{call_id}"
    assert tombstone_key in _getall(headers, [tombstone_key]), (
        "no tombstone reached the ledger, so this test is not exercising the "
        "condition it describes: the attack is about a tombstone that "
        f"committed while the response could not say so. Relay log: {log[-500:]}"
    )

    assert deleted.status_code == 204, (
        f"the erasure was refused while its tombstone was in the ledger: "
        f"{deleted.status_code} {deleted.text[:300]}. The ledger says this "
        "call_id was erased, the store still holds the payload, and content "
        "writes for it are now frozen at 409."
    )
    again = _CLIENT.delete(f"{CONTROL_PLANE_URL}/content/{call_id}",
                           headers={"X-API-Key": WRITE_API_KEY})
    assert again.status_code == 204, again.text[:300]


# ---------------------------------------------------------------------------
# P3c3e-3: a retry the caller was wrongly told to make.
# ---------------------------------------------------------------------------
#
# D39 and D40 are each correct and their interaction was not. A caller told
# `committed: false` about a write that committed has two options and both are
# wrong: believe the response and retry, which D39's KeyMustNotExist refuses
# with 409 forever, or disbelieve it. The red team drove exactly that:
#
#     RETRY (relay gone) -> 409 {"detail": "a record is already committed
#                                under this key (tool_call:p3c3dred-a4:...)"}
#
# P3c3e-2 removes the cause: the caller is no longer told that a write which
# committed did not. These two tests establish the interaction is closed from
# both ends - a caller who retries anyway is told plainly that the record
# exists, and a caller whose write genuinely did not land is not refused.

@requires_stack
@requires_docker_cli
def test_a_retry_after_a_dropped_response_is_told_the_record_already_exists():
    """The retry the caller should no longer make, made anyway.

    A 409 naming the key and saying a record is already committed under it is
    an answer a caller can act on. `committed: false` followed by a bare
    conflict is not - that pair is what D39 and D40 produced between them, and
    it is the sequence this test walks end to end.
    """
    headers = _immudb_headers()
    agent = f"p3c3e-retry-{_ORDERED_MARKER}"
    value = _ordered_record(uuid.uuid4().hex, agent)

    def _build():
        return f"tool_call:{agent}:{uuid.uuid4().hex}:query_database"

    def _drive(key):
        with relay("response", _ORDERED_PROXY, "cutresponse",
                   marker=_ORDERED_MARKER):
            written = _ordered_write(key, value)
            return written, _proxy_log(_ORDERED_PROXY)

    key, (first, log), _tries = cut_until_it_lands(
        _build, _drive,
        lambda k, r: "dropping the" in r[1] and k in _getall(headers, [k]))

    body = first.json()
    assert "dropping the" in log, (
        "the relay never dropped a response, so this test is not exercising "
        f"the condition it describes. Relay log: {log[-500:]}"
    )
    assert key in _getall(headers, [key]), (
        f"the ExecAll did not reach the ledger: {body}. Relay log: {log[-500:]}"
    )
    # **`is not False`, and that is the whole claim rather than a softened
    # one.** The record is in the ledger. Two answers are honest about that:
    # `true`, when the verifier read it back, and `null`, when the relay had
    # closed the connection the confirming read needed - D45's fourth state,
    # asserted in its own right below. The third answer, `false`, is the lie
    # that sends a caller into D39's permanent 409, and it is the one this
    # test exists to keep out. CI produced the `null` case here where this
    # host produced `true`; both are the caller being told the truth.
    assert body["committed"] is not False, (
        f"the caller is being told a write that committed did not happen, "
        f"which is the retry D39 refuses forever: {body}"
    )

    retried = _ordered_write(key, value)
    assert retried.status_code == 409, (
        f"a second write under a key the ledger already holds answered "
        f"{retried.status_code}: {retried.text[:300]}"
    )
    detail = retried.json().get("detail", "")
    assert key in detail and "already committed" in detail, (
        "the refusal does not tell the caller that the record they are "
        f"retrying already exists: {detail!r}"
    )


@requires_stack
@requires_docker_cli
def test_a_write_that_genuinely_did_not_land_can_be_retried():
    """The other end of it: no legitimate retry is permanently denied.

    The relay refuses every connection, so the ordered write fails before its
    ExecAll reaches the wire. `committed: false` is a fact on that branch and
    on no other, and the key is free. With the ledger back, the same key
    written again succeeds - which is what makes `committed: false` an
    instruction a caller can follow.
    """
    headers = _immudb_headers()
    agent = f"p3c3e-legit-{uuid.uuid4().hex[:6]}"
    call_id = uuid.uuid4().hex
    key = f"tool_call:{agent}:{uuid.uuid4().hex}:query_database"
    value = _ordered_record(call_id, agent)

    with relay("drop-request", _DROP_REQUEST_PROXY, "cutdroprequest",
               marker=agent, CUT_BLACKHOLE_SECONDS="5"):
        failed = _ordered_write(key, value)
        log = _proxy_log(_DROP_REQUEST_PROXY)

    assert failed.status_code == 200, failed.text[:300]
    body = failed.json()
    assert "without relaying it" in log, (
        "the relay never dropped the write request, so this test is not "
        f"exercising the condition it describes. Relay log: {log[-500:]}"
    )
    assert body["verified"] is False, body
    assert body["committed"] is not True, (
        f"nothing reached the ledger and the response says it committed: {body}"
    )
    assert key not in _getall(headers, [key]), (
        "the record reached the ledger through a relay that refuses every "
        f"connection, so this test is not exercising its condition: {body}"
    )

    retried = _ordered_write(key, value)
    assert retried.status_code == 200, (
        f"the retry of a write that never landed was refused: "
        f"{retried.status_code} {retried.text[:300]}"
    )
    again = retried.json()
    assert again["verified"] is True and again["committed"] is True, (
        f"a legitimate retry did not succeed: {again}"
    )
    assert key in _getall(headers, [key]), again


# ---------------------------------------------------------------------------
# P3c3f-1: the retry helper, driven. No stack, no containers, no relay.
# ---------------------------------------------------------------------------

class _Answered:
    """One response from a route, with the two fields the predicate reads."""

    def __init__(self, body: dict):
        self._body = body
        self.status_code = 200
        self.text = json.dumps(body)

    def json(self) -> dict:
        return self._body


# The three answers a write route can give about the ledger, and what the
# fixture is supposed to do with each. Written down here because the whole
# defect was that one of these rows was treated as another.
_A41 = {"tx_id": None, "seq": None, "verified": False, "committed": False,
        "attempts": 1}
_HONEST = {"tx_id": 8, "seq": 1000000004, "verified": False,
           "committed": True, "attempts": 1}
_UNKNOWN = {"tx_id": None, "seq": None, "verified": False, "committed": None,
            "attempts": 1}


def _replaying(answers):
    """A `drive` that returns each answer in turn, then repeats the last."""
    calls = []

    def drive(_subject):
        answer = answers[min(len(calls), len(answers) - 1)]
        calls.append(answer)
        return _Answered(answer), "dropping the response for the marked stream"

    return drive, calls


def _landed(subject, result):
    """The predicate the ordered-write test above uses, minus the ledger read.

    The `_getall` conjunct is a live ledger query; the two conjuncts kept here
    are the ones that decide what the helper does with an answer.
    """
    return ("dropping the" in result[1]
            and not confirming_read_could_not_run(result[0]))


def test_the_retry_helper_does_not_retry_past_a_route_that_says_committed_false():
    """P3c3f-1. `cut_until_it_lands` retries the fixture and never the
    assertion, and this is what makes that sentence true rather than aspirational.

    The route answers the A4.1 shape once - `committed: false, tx_id: null`
    about a record that is in the ledger - and then correctly. The helper must
    stop at the first answer and hand it to the caller's assertions, which is
    where it fails. Retrying past it is how a real, intermittent A4.1 injection
    left the suite at `1 passed` while the route lied on attempt one:

        call 1: route ANSWERED committed=false tx_id=null;
                ledger state=present tx=21
        call 2: route told the truth; tx=22
        1 passed, 8 deselected in 127.86s

    Behavioural, not a parse. P3c3e-9 retired a source parse over this
    directory after it was defeated three times, and a check retired for cause
    does not come back as an acceptance criterion. Nothing here is read from
    the source: the real helper is called with the real predicate.
    """
    drive, calls = _replaying([_A41, _HONEST])
    _subject, (response, _log), tries = cut_until_it_lands(
        lambda: "tool_call:p3c3f:probe:query_database", drive, _landed)

    assert tries == 1, (
        f"the helper drove {tries} attempts. The route answered "
        f"{calls[0]} on the first one, which is a record in the ledger "
        "reported as never written, and the predicate treated that as a "
        "fixture miss and retried past it. The assertion this test's live "
        "counterpart makes never saw the answer that would have failed it."
    )
    assert response.json()["committed"] is False, (
        "the caller was handed something other than the answer the route "
        f"actually gave first: {response.json()}"
    )


def test_the_retry_helper_still_retries_when_the_confirming_read_could_not_run():
    """The other half, so the fix above is not just 'never retry'.

    `committed: null` is D45 being honest: the relay closes the connection it
    cut, so the read the route makes to settle whether the record committed
    can hit a dead socket. That is a fixture condition and it is what this
    helper exists to retry. A predicate that stopped on it would hand the
    caller `null` and fail an assertion about the route on a fact about the
    fixture.
    """
    drive, calls = _replaying([_UNKNOWN, _HONEST])
    _subject, (response, _log), tries = cut_until_it_lands(
        lambda: "tool_call:p3c3f:probe:query_database", drive, _landed)

    assert tries == 2, (
        f"the helper stopped after {tries} attempt(s) on {calls[0]}, which is "
        "the confirming read not having run rather than the route saying "
        "anything about the ledger"
    )
    assert response.json()["committed"] is True, response.json()


def test_the_retry_helper_stops_on_an_honest_answer():
    """And the control, so neither test above passes against a helper that
    always stops or always retries."""
    drive, _calls = _replaying([_HONEST])
    _subject, (response, _log), tries = cut_until_it_lands(
        lambda: "tool_call:p3c3f:probe:query_database", drive, _landed)
    assert tries == 1, tries
    assert response.json()["committed"] is True, response.json()


# ---------------------------------------------------------------------------
# P3c3h-4 (Phase 3c-3h). The committed-false branch, closed at the property.
# ---------------------------------------------------------------------------

def _p3c3h_verifier():
    """A fresh verifier module, so `_seq_cache` and `_reserve_cache` from one
    driver cannot reach another. These are module globals and the ordered
    commit drops both on a precondition refusal, which is the retry this
    branch turns on."""
    import importlib.util
    import uuid as _uuid

    os.environ.setdefault("VERIFIER_WRITE_KEY", VERIFIER_WRITE_KEY)
    os.environ.setdefault(
        "AIL_WRITER_SIGNING_KEY", str(REPO_ROOT / "keys" / "writer-decision.key"))
    name = "p3c3h_verifier_" + _uuid.uuid4().hex[:8]
    spec = importlib.util.spec_from_file_location(
        name, REPO_ROOT / "verifier" / "main.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class _Got:
    def __init__(self, tx, value):
        self.tx = tx
        self.value = value


_DEAD_CHANNEL = (
    "<_InactiveRpcError of RPC that terminated with: "
    "status = StatusCode.UNAVAILABLE details = \"Socket closed\">"
)


class _DyingChannel:
    """The ledger serves `dies_after` reads, then every call raises.

    The ExecAll is refused on a PRECONDITION, which is the whole subject: the
    request reached the wire and came back saying one of three preconditions
    failed, and one of the three - `KeyMustNotExist` on the record key - is
    true exactly when the record is already committed. The read that would
    tell the three apart is `_record_key_present`, and it is the read this
    fixture starves.

    The reads in one attempt are, in order: the bound reserve, the counter,
    and then, after the refusal, the record key. `dies_after` is therefore the
    knob that moves the failure between the two halves of the window and, at
    3 with the record present, produces the honest 409 control.
    """

    def __init__(self, verifier, key, value, dies_after, record_present=True):
        self._seq_key = verifier.SEQUENCE_KEY
        self._reserve_key = verifier.RESERVE_KEY
        self._key = key
        self._value = value
        self.dies_after = dies_after
        self.record_present = record_present
        self.reads = 0
        self.execalls = 0
        self._vk = None
        outer = self

        class _Stub:
            def ExecAll(self, request):
                outer.execalls += 1
                raise RuntimeError("precondition failed: KeyMustNotExist")

            def CurrentState(self, _request):
                raise RuntimeError(_DEAD_CHANNEL)

        self._stub = _Stub()

    def _alive(self):
        if self.reads > self.dies_after:
            raise RuntimeError(_DEAD_CHANNEL)

    def get(self, key):
        self.reads += 1
        self._alive()
        if key == self._reserve_key:
            return _Got(1, b"1000000000")
        if key == self._seq_key:
            return _Got(40, b"1000000016")
        if key == self._key and self.record_present:
            return _Got(2, self._value)
        return None

    def zScan(self, **_kwargs):
        self._alive()
        return type("ZEntries", (), {"entries": []})()

    def verifiedGet(self, _key):
        raise RuntimeError(_DEAD_CHANNEL)

    def set(self, _key, _value):
        raise RuntimeError(_DEAD_CHANNEL)


def _drive_ordered_through_a_dying_channel(dies_after, record_present=True):
    """One `POST /write-ordered`, in process, against `_DyingChannel`."""
    verifier = _p3c3h_verifier()
    call_id = "p3c3h-call-0001"
    key = f"tool_call:p3c3h-agent:{call_id}:query_database".encode()
    value = json.dumps({"record_type": "decision", "call_id": call_id,
                        "outcome_type": "policy_allow"},
                       separators=(",", ":")).encode()
    client = _DyingChannel(verifier, key, value, dies_after, record_present)
    original = verifier._get_client
    verifier._get_client = lambda: client
    try:
        payload = verifier.OrderedWriteRequest(
            key=base64.b64encode(key).decode(),
            value=base64.b64encode(value).decode(), view="decision")
        return verifier.write_ordered(payload), client
    finally:
        verifier._get_client = original


def test_an_ordered_write_whose_execall_reached_the_wire_never_says_committed_false():
    """P3c3h-4, half one: the read that tells the preconditions apart cannot
    run.

    **The branch, and it is not one of D45's four states.** The ExecAll comes
    back `precondition failed`. `_record_key_present` is the read that says
    which precondition it was, and it swallows a read failure and answers
    `False`, which retries. The next attempt's first act is
    `_read_bound_reserve`, which is not guarded, and on the same dead channel
    it raises something that is not `OrderedCommitUncertain` - so
    `write_ordered`'s bottom handler, whose comment says "Nothing reached the
    wire", answered `committed: false` about a record that can be in the
    ledger. It refutes P3c3e-2, whose rule was that the exception TYPE carries
    whether the request reached the wire.

    Measured before the fix in this phase, and it is the CI failure's exact
    shape: `committed: false`, `attempts: 0`, one ExecAll issued, four reads
    attempted, `StatusCode.UNAVAILABLE` in the detail.

    **What is pinned here is `not false`, not a particular answer.** On this
    branch the record-key read is exactly what cannot run, so the service has
    no evidence for a 409's "already committed" claim either; asserting that
    would be the same lie pointed the other way, plus a permanent refusal. The
    honest answers are D45's existing two: `true` when the read-back finds the
    record, `null` when it cannot.
    """
    response, client = _drive_ordered_through_a_dying_channel(dies_after=2)

    assert client.execalls == 1, (
        "the fixture did not put an ExecAll on the wire, so this test is not "
        f"exercising the branch it describes: {client.execalls} ExecAlls")
    assert response.committed is not False, (
        "an ordered write whose ExecAll reached the wire and came back on a "
        "precondition reported that the record is not in the ledger. One of "
        "the three preconditions that produce that refusal is KeyMustNotExist "
        "on the record key, which is true exactly when the record IS "
        f"committed: {response}")
    assert response.committed is None, (
        "the read-back could not run either, so the honest answer is that "
        f"whether the record committed is not established: {response}")
    assert response.attempts == 2, (
        "the response understates the work the ledger did. `attempts: 0` on "
        f"this branch was part of the original finding: {response}")


def test_the_second_half_of_the_window_is_closed_too():
    """P3c3h-4, half two: the record-key read RUNS and the channel dies after
    it, for an unrelated reason.

    This is why the fix is the property and not the named read. Guarding
    `_record_key_present` alone would close the half above and leave this one
    open: here that read works and honestly answers "no record", the loop
    continues because the refusal was one of the two retryable preconditions,
    and the next attempt's unguarded `_read_bound_reserve` is what meets the
    dead channel. Nothing about `_record_key_present` is involved, and before
    the fix this answered `committed: false` with one ExecAll issued, exactly
    as half one did.

    The flag covers both because it is a fact about the call rather than about
    which read failed: once an ExecAll has been issued, an exception leaving
    `_ordered_commit` carries that, and `committed: false` is unreachable from
    every caller.
    """
    response, client = _drive_ordered_through_a_dying_channel(
        dies_after=3, record_present=False)

    assert client.execalls == 1, client.execalls
    assert client.reads > 3, (
        "the channel did not survive the record-key read, so this is half one "
        f"again rather than the second half: {client.reads} reads")
    assert response.committed is not False, (
        "the channel died between attempts for a reason that has nothing to "
        "do with the record-key read, and the route still reported that the "
        f"record is not in the ledger: {response}")
    assert response.committed is None, response


def test_the_ordered_route_still_refuses_a_key_it_can_see_is_committed():
    """P3c3h-4, the control. The 409 is the answer on the branch where the
    read WORKS, and it is unbroken.

    One read's difference from half one. `RecordKeyExists` passes through
    `_ordered_commit`'s new handler unconverted on purpose: it is the branch
    where the record-key read ran and answered yes, so the refusal is
    established rather than guessed. Without this the two tests above would
    pass against a route that had simply stopped refusing anything.
    """
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as refused:
        _drive_ordered_through_a_dying_channel(dies_after=3,
                                               record_present=True)

    assert refused.value.status_code == 409, (
        f"the ordered route answered {refused.value.status_code} where the "
        f"record key is present in the ledger: {refused.value.detail}")
    assert "already committed under this key" in str(refused.value.detail), (
        f"the refusal does not say why: {refused.value.detail}")


def test_a_write_that_never_reached_the_wire_still_says_committed_false():
    """P3c3h-4, the other control, and it is the one that stops the fix from
    being "never answer false".

    `committed: false` is a real state and D45 keeps it: when nothing was
    issued, the write did not happen and saying so is a fact. The reserve
    disagreement is the cleanest instance - `_read_bound_reserve` raises
    `ReserveMismatch` on the first attempt, before any ExecAll - and the flag
    must leave it exactly where it was. A fix that answered `null` here would
    have replaced one dishonest answer with another.
    """
    verifier = _p3c3h_verifier()
    call_id = "p3c3h-call-0002"
    key = f"tool_call:p3c3h-agent:{call_id}:query_database".encode()
    value = json.dumps({"record_type": "decision", "call_id": call_id,
                        "outcome_type": "policy_allow"},
                       separators=(",", ":")).encode()

    class _DisagreeingReserve(_DyingChannel):
        def get(self, key):
            self.reads += 1
            if key == self._reserve_key:
                # A reserve that is not this service's configured value.
                return _Got(1, str(verifier.RESERVED_POSITIONS + 1).encode())
            return super().get(key)

    client = _DisagreeingReserve(verifier, key, value, dies_after=99)
    original = verifier._get_client
    verifier._get_client = lambda: client
    try:
        response = verifier.write_ordered(verifier.OrderedWriteRequest(
            key=base64.b64encode(key).decode(),
            value=base64.b64encode(value).decode(), view="decision"))
    finally:
        verifier._get_client = original

    assert client.execalls == 0, (
        "the fixture issued an ExecAll, so this is not the nothing-reached-"
        f"the-wire branch: {client.execalls}")
    assert response.committed is False, (
        "a write refused before anything reached the wire is a write that did "
        "not happen, and the route no longer says so. The flag was applied to "
        f"a branch it does not belong on: {response}")


def test_an_exhausted_retry_budget_reports_committed_false_from_the_ledger():
    """P3c3h-4, the consequence, pinned rather than left to be discovered.

    The flag changes this path and it is worth saying which way. When the CAS
    budget runs out, every attempt was refused whole on a precondition, so
    nothing was written and `committed: false` is the right answer - and it
    used to be reached by the bottom handler assuming it, on the same rule
    the branch above refuted. Under the flag an ExecAll HAS been issued, so
    the exception becomes `OrderedCommitUncertain`, the route asks the ledger,
    the record is genuinely absent, and the answer is the same `false`
    established from a read instead of from a guess.

    Two things move with it, both in the honest direction: one extra read on a
    failure path that has already made `MAX_CAS_ATTEMPTS` round trips, and
    `attempts` reported as what it was rather than as 0.

    The pre-registered negative for this phase names exactly this case as the
    one that stays: `_committed_tx_for_value` answering ABSENT is an answer,
    not a guess.
    """
    verifier = _p3c3h_verifier()
    verifier.MAX_CAS_ATTEMPTS = 3
    call_id = "p3c3h-call-0003"
    key = f"tool_call:p3c3h-agent:{call_id}:query_database".encode()
    value = json.dumps({"record_type": "decision", "call_id": call_id,
                        "outcome_type": "policy_allow"},
                       separators=(",", ":")).encode()

    class _AlwaysRefused(_DyingChannel):
        """Every ExecAll refused on a RETRYABLE precondition, and the record
        genuinely absent, so the loop runs the budget out."""

        def get(self, key):
            self.reads += 1
            if key == self._reserve_key:
                return _Got(1, b"1000000000")
            if key == self._seq_key:
                return _Got(40, b"1000000016")
            return None

    client = _AlwaysRefused(verifier, key, value, dies_after=10 ** 6,
                            record_present=False)
    original = verifier._get_client
    verifier._get_client = lambda: client
    try:
        response = verifier.write_ordered(verifier.OrderedWriteRequest(
            key=base64.b64encode(key).decode(),
            value=base64.b64encode(value).decode(), view="decision"))
    finally:
        verifier._get_client = original

    assert client.execalls == 3, (
        f"the budget did not run out, so this is a different branch: "
        f"{client.execalls} ExecAlls")
    assert response.committed is False, (
        "every attempt was refused whole and the record is absent from the "
        f"ledger, so the write did not happen and the route must say so: "
        f"{response}")
    assert response.attempts == 3, (
        "the response understates the attempts the ledger actually served: "
        f"{response}")


def test_the_retry_helper_terminates_when_every_attempt_answers_null():
    """D49's interaction with the fixture, driven rather than assumed.

    **Why this needed checking.** The retry predicate is
    `committed is not None`: it stops on `true` and on `false`, and retries on
    `null`, because null is the confirming read not having run, which is a
    fixture condition. D49 converts a branch that used to answer `false` into
    `null`. Everything that branch produced therefore moves from "stop and
    assert" to "retry the fixture", and that is the correct move - the route is
    no longer lying, and the answer genuinely does mean the read could not
    establish it.

    What that changes is how many attempts the one call site using this
    predicate makes, so "it should still terminate" is driven here. It does,
    and structurally: `cut_until_it_lands` is a bounded `for` over `attempts`,
    not a while loop, and it returns the last result whether it worked or not
    so the caller's own guards report a fixture that never managed it.

    The pathological input is the one D49 makes newly reachable: every attempt
    answering null.
    """
    drive, calls = _replaying([_UNKNOWN])
    _subject, (response, _log), tries = cut_until_it_lands(
        lambda: "tool_call:d49:probe:query_database", drive, _landed)

    assert tries == 4, (
        f"the helper made {tries} attempts against a route answering null "
        "every time. The bound is what makes this terminate at all.")
    assert len(calls) == 4, calls
    assert response.json()["committed"] is None, (
        "the helper did not hand the last answer back, so a caller's guards "
        f"cannot report a fixture that never managed it: {response.json()}")


def test_the_retry_helper_still_stops_on_the_answers_d49_did_not_change():
    """The control for the test above, so it is not passing against a helper
    that simply always runs to the bound.

    Neither of these two answers is affected by D49: `true` is the fixture
    working, and `false` from a route that can still honestly say it - a
    different record under the key, or every attempt refused by the ledger -
    is an answer the caller must see rather than retry past.
    """
    drive, _calls = _replaying([_HONEST])
    _subject, _result, tries = cut_until_it_lands(
        lambda: "tool_call:d49:probe:query_database", drive, _landed)
    assert tries == 1, tries

    drive, _calls = _replaying([_A41])
    _subject, (response, _log), tries = cut_until_it_lands(
        lambda: "tool_call:d49:probe:query_database", drive, _landed)
    assert tries == 1, (
        f"the helper retried past a `committed: false` answer: {tries}")
    assert response.json()["committed"] is False, response.json()


# ---------------------------------------------------------------------------
# D49 (run `d49-absent`). A not-found from the confirmation read, taken in the
# window right after a commit was issued, is not evidence of absence.
# ---------------------------------------------------------------------------

class _CommittedButNotYetVisible:
    """The ledger commits, its response is lost, and the read-back sees nothing.

    This is the CI failure's shape and the whole subject of D49. The record IS
    in the ledger; the confirmation read answers not-found because the index
    has not caught up, and a not-found on a key this call just wrote is
    indistinguishable from lag at the moment it is taken.

    `ordered=False` drives the plain route instead, where `verifiedSet` raises
    a transport error after committing.
    """

    _LOST = ('<_InactiveRpcError of RPC that terminated with: '
             'status = StatusCode.UNAVAILABLE '
             'details = "Stream removed (Socket closed)">')

    def __init__(self, verifier, *, proof_failure=None, under_key=None):
        self._seq_key = verifier.SEQUENCE_KEY
        self._reserve_key = verifier.RESERVE_KEY
        self._under_key = under_key      # what the read finds, or None
        self.execalls = 0
        self._vk = None
        outer = self

        class _Stub:
            def ExecAll(self, request):
                outer.execalls += 1
                raise RuntimeError(outer._LOST)

        self._stub = _Stub()
        self._proof_failure = proof_failure

    def get(self, key):
        if key == self._reserve_key:
            return _Got(1, b"1000000000")
        if key == self._seq_key:
            return _Got(40, b"1000000016")
        return self._under_key

    def zScan(self, **_kwargs):
        return type("ZEntries", (), {"entries": []})()

    def verifiedSet(self, _key, _value):
        if self._proof_failure is not None:
            raise self._proof_failure
        raise RuntimeError(self._LOST)

    def set(self, _key, _value):
        raise RuntimeError(self._LOST)


def _plain_write(verifier, client, key, value):
    original = verifier._get_client
    verifier._get_client = lambda: client
    try:
        return verifier.write(verifier.WriteRequest(
            key=base64.b64encode(key).decode(),
            value=base64.b64encode(value).decode()))
    finally:
        verifier._get_client = original


def _ordered_write_inproc(verifier, client, key, value):
    original = verifier._get_client
    verifier._get_client = lambda: client
    try:
        return verifier.write_ordered(verifier.OrderedWriteRequest(
            key=base64.b64encode(key).decode(),
            value=base64.b64encode(value).decode(), view="decision"))
    finally:
        verifier._get_client = original


def _d49_record(call_id, ordered=True):
    """A record each route accepts.

    D39 refuses a `tool_call:` key on the plain route - those allocate a
    commit position and must take `POST /write-ordered` - so the plain-route
    cases use the control plane's erasure tombstone, which is the one
    production write left on that route.
    """
    if ordered:
        key = f"tool_call:d49-agent:{call_id}:query_database".encode()
        value = json.dumps({"record_type": "decision", "call_id": call_id,
                            "outcome_type": "policy_allow"},
                           separators=(",", ":")).encode()
    else:
        key = f"content_erasure:{call_id}".encode()
        value = json.dumps({"record_type": "content_erasure",
                            "call_id": call_id},
                           separators=(",", ":")).encode()
    return key, value


def test_a_not_found_readback_after_an_issued_ordered_commit_is_not_absence():
    """D49, site three: the branch CI was failing on.

    **The measured failure.** Twice on this branch, at the same transaction:

        AssertionError: the record is in the ledger at transaction 255 and the
        ordered route says the write never happened:
        {'committed': False, 'attempts': 1, ...
         StatusCode.UNAVAILABLE ... "Stream removed (Socket closed)"}

    `attempts: 1` is what identified it. The bottom handler passes no
    `attempts` and the field defaults to 0, so that body came from the
    `OrderedCommitUncertain` handler on the ABSENT path - not from the branch
    P3c3h-4's flag closed, which is why that fix did not touch it.

    D45 separated "the read could not run" (`null`) from "the read ran and
    answered" (`false`). This is a third case: the read ran, answered
    not-found, and the answer was not evidence, because a key this call just
    wrote is invisible until the index catches up.

    Reproduced in process at `committed: False, attempts: 1` before the fix
    and `committed: None, attempts: 1` after.
    """
    verifier = _p3c3h_verifier()
    key, value = _d49_record("d49-ordered-0001")
    client = _CommittedButNotYetVisible(verifier)
    response = _ordered_write_inproc(verifier, client, key, value)

    assert client.execalls == 1, (
        f"no ExecAll reached the wire, so this is a different branch: "
        f"{client.execalls}")
    assert response.committed is not False, (
        "the ledger reported nothing under a key whose write was issued and "
        "whose response was lost, and the route turned that into a positive "
        f"claim that the record is not there: {response}")
    assert response.committed is None, response
    assert response.attempts == 1, (
        f"the branch changed: this is no longer the CI shape: {response}")


def test_a_not_found_readback_after_an_issued_plain_write_is_not_absence():
    """D49, site two: the plain route's transport-failure branch.

    `_committed_tx_for_value` is called from `write` as well, after a
    `verifiedSet` transport error. Same epistemics, same window, same answer.
    Fixing one of two identical branches is the P3c3e-2 shape, so both moved.
    """
    verifier = _p3c3h_verifier()
    key, value = _d49_record("d49-plain-0001", ordered=False)
    client = _CommittedButNotYetVisible(verifier)
    response = _plain_write(verifier, client, key, value)

    assert response.committed is not False, (
        "the plain route turned a not-found read taken right after a write "
        f"that may have committed into a claim of absence: {response}")
    assert response.committed is None, response
    assert response.verified is False, response


def test_a_not_found_readback_after_a_failed_proof_is_not_absence():
    """D49, site one, and the sharpest of the three.

    Here the commit is not merely possible, it is **known**: `verifiedSet`
    commits at `service.VerifiableSet` and every proof failure is raised after
    that line. So a read answering nothing under the key can only be the index
    lagging, and `committed: false` there was the false claim D40 removed one
    branch over.

    `_committed_tx_for`'s own docstring said exactly that, and its caller went
    on making the claim anyway, under a comment reading "the write genuinely
    did not land" three lines below the UNKNOWN branch's comment saying the
    commit already happened. D45 fixed the read and left the caller. Both
    comments were corrected with this change.
    """
    from immudb.exceptions import ErrCorruptedData

    verifier = _p3c3h_verifier()
    key, value = _d49_record("d49-proof-0001", ordered=False)
    client = _CommittedButNotYetVisible(verifier,
                                        proof_failure=ErrCorruptedData())
    response = _plain_write(verifier, client, key, value)

    assert response.error_class == "consistency_failure", (
        f"this is not the proof-failure branch: {response}")
    assert response.committed is not False, (
        "the proof failed, which means the commit already happened, and the "
        "route reported the record as never having been written because a "
        f"read answered nothing: {response}")
    assert response.committed is None, response


def test_a_different_record_under_the_key_is_still_honest_absence():
    """D49's other direction, and the reason the split is `got is None` rather
    than the whole of ABSENT.

    A read that answers with a record holding *different bytes* is a positive
    read: the ledger answered, something is there, and it is not what this
    call wrote. That is evidence, it is not lag, and Phase 3c-3h's
    pre-registered negatives preserved it explicitly. Sweeping it into `null`
    would have revoked a negative from the preceding phase silently, and would
    have thrown away a fact the service actually holds.

    Both routes, because both call `_committed_tx_for_value`.
    """
    verifier = _p3c3h_verifier()
    other = _Got(9, b'{"record_type":"decision","call_id":"somebody-else"}')

    key, value = _d49_record("d49-other-0001")
    ordered = _ordered_write_inproc(
        verifier, _CommittedButNotYetVisible(verifier, under_key=other),
        key, value)
    assert ordered.committed is False, (
        "a different record holds this key, which is a positive read saying "
        f"this write did not land, and the route hedged it: {ordered}")

    key, value = _d49_record("d49-other-0002", ordered=False)
    plain = _plain_write(
        verifier, _CommittedButNotYetVisible(verifier, under_key=other),
        key, value)
    assert plain.committed is False, (
        f"the same positive read on the plain route: {plain}")


def test_every_attempt_refused_by_the_ledger_is_still_committed_false():
    """D49's exception, and the one case where an issued ExecAll leaves an
    established outcome.

    When the CAS budget runs out, every attempt came back with an explicit
    `precondition failed` **response**. The ledger refused each one, nothing
    was written by any of them, and there is therefore no window for anything
    to become visible in. `committed: false` is knowledge here, and D49's rule
    about a not-found read does not apply because there is nothing to be late.

    Carried by type, `SequenceBudgetExhausted`, raised at exactly one line,
    rather than by restructuring P3c3h-4's flag. The first wording of D49's
    condition was "an ExecAll was issued whose outcome is not known", and
    implemented faithfully that makes the outcome established whenever
    `_record_key_present`'s read ran, which turns P3c3h-4's second half from
    `null` back into `false`. Measured: that spelling failed
    `test_the_second_half_of_the_window_is_closed_too`. It is wrong for D49's
    own reason one level in, and this test plus that one pin both halves of
    the distinction.
    """
    verifier = _p3c3h_verifier()
    verifier.MAX_CAS_ATTEMPTS = 3
    key, value = _d49_record("d49-budget-0001")

    class _AlwaysRefused(_DyingChannel):
        def get(self, key):
            self.reads += 1
            if key == self._reserve_key:
                return _Got(1, b"1000000000")
            if key == self._seq_key:
                return _Got(40, b"1000000016")
            return None

    client = _AlwaysRefused(verifier, key, value, dies_after=10 ** 6,
                            record_present=False)
    response = _ordered_write_inproc(verifier, client, key, value)

    assert client.execalls == 3, client.execalls
    assert response.committed is False, (
        "every attempt was refused by the ledger on a precondition, so "
        "nothing was written and nothing can be late; the route may state "
        f"that as a fact: {response}")
    assert response.attempts == 3, (
        f"the response understates what the ledger served: {response}")
