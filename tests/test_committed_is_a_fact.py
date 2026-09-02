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
import uuid
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tests"))

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
    behind the relay and returns whatever the assertions need. `landed` says
    whether the ledger has it. The last attempt's result is returned whether
    it landed or not, so the caller's own guard is what reports a fixture that
    never managed to cut.
    """
    for attempt in range(attempts):
        subject = build()
        result = drive(subject)
        if landed(subject):
            return subject, result, attempt + 1
    return subject, result, attempts


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
    try:
        compose("up", "-d", "--force-recreate", "verifier",
                env={"IMMUDB_ADDR": f"{alias}:3399"})
        assert wait_for_health(f"{VERIFIER_URL}/health"), (
            f"the verifier did not come back pointed at the {mode} relay"
        )
        yield name
    finally:
        compose("up", "-d", "--force-recreate", "verifier", check=False)
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
    return [base64.b64decode(row["entry"]["key"]).decode()
            for row in resp.json().get("entries", [])]


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

    key, (response, log), _tries = cut_until_it_lands(
        _build, _drive, lambda k: k in _getall(headers, [k]))

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
        _build, _drive, lambda k: k in _getall(headers, [k]))

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
        lambda cid: f"content_erasure:{cid}" in _getall(
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
    conflict is not.
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
        _build, _drive, lambda k: k in _getall(headers, [k]))

    body = first.json()
    assert "dropping the" in log, (
        "the relay never dropped a response, so this test is not exercising "
        f"the condition it describes. Relay log: {log[-500:]}"
    )
    assert key in _getall(headers, [key]), (
        f"the ExecAll did not reach the ledger: {body}. Relay log: {log[-500:]}"
    )
    assert body["committed"] is True, (
        f"the caller is being told to retry a write that committed: {body}"
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
