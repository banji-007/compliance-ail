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
# What it does, and why each condition is there. It arms on a request frame
# carrying the marker AND at least CUT_ARM_MIN bytes, which is what
# distinguishes a write (key plus a signed record) from the small reads the
# same connection also carries. It relays that request and its response
# untouched, so the write commits and the SDK sees its answer. It then drops
# the next request frame of at least CUT_MIN_FRAME bytes and closes the
# connection, so the client's next RPC fails and the HTTP/2 flow-control
# frames in between do not count as that RPC.
_PROXY_SOURCE = """
import os, socket, threading

LISTEN = 3399
UPSTREAM = ("immudb", 3322)
MARKER = os.environ.get("CUT_MARKER", "ZZCUTZZ").encode()
ARM_MIN = int(os.environ.get("CUT_ARM_MIN", "600"))
MIN_FRAME = int(os.environ.get("CUT_MIN_FRAME", "40"))


def pump(src, dst, state, direction):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            if (direction == "up" and MARKER in data and len(data) >= ARM_MIN
                    and not state.get("armed")):
                state["armed"] = True
                print("CUT: armed on a %dB request carrying the marker" % len(data),
                      flush=True)
            if (direction == "up" and state.get("relayed")
                    and len(data) >= MIN_FRAME):
                print("CUT: the marked response was relayed; cutting the NEXT RPC",
                      flush=True)
                break
            dst.sendall(data)
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
print("CUT: listening on %d -> %s:%d" % (LISTEN, UPSTREAM[0], UPSTREAM[1]),
      flush=True)
while True:
    conn, _ = server.accept()
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


def _proxy_log() -> str:
    return subprocess.run(["docker", "logs", PROXY_NAME],
                          capture_output=True, text=True).stdout


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
    subprocess.run(["docker", "rm", "-f", PROXY_NAME], capture_output=True)
    started = subprocess.run([
        "docker", "run", "-d", "--name", PROXY_NAME,
        "--network", f"{COMPOSE_PROJECT}_default",
        "--network-alias", PROXY_ALIAS,
        "-e", f"CUT_MARKER={MARKER}",
        "python:3.11-slim", "python", "-c", _PROXY_SOURCE,
    ], capture_output=True, text=True)
    assert started.returncode == 0, (
        f"could not start the relay: {started.stderr[-400:]}"
    )
    try:
        compose("up", "-d", "--force-recreate", "verifier",
                env={"IMMUDB_ADDR": f"{PROXY_ALIAS}:3399"})
        assert wait_for_health(f"{VERIFIER_URL}/health"), (
            "the verifier did not come back pointed at the relay"
        )
        yield
    finally:
        compose("up", "-d", "--force-recreate", "verifier", check=False)
        wait_for_health(f"{VERIFIER_URL}/health")
        subprocess.run(["docker", "rm", "-f", PROXY_NAME], capture_output=True)


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
