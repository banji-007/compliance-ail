"""tests/test_trust_anchor.py - Phase 3c-3f (D47, P3c3f-6).

The verifier's persisted trust anchor is never written or seeded from a state
nothing verified.

**The attack, driven by the Phase 3c-3e red team (B1.2) before anything here
was written.** `POST /verify` is gated by `_require_read_key`. Four writes made
straight to ImmuDB moved the ledger head from 11 to 15; the anchor stayed at
11, because nothing had asked the verifier anything; one `POST /verify` with
the read credential and no write credential at all moved it to 15:

    5. POST /verify with the READ key only - no write credential at all
        200 {'verified': True, 'tx_id': 11, 'state_id': 15}
    6. the persisted trust anchor AFTER the read
        {"immudb:3322/b'defaultdb'": 15}
       the read-gated route changed durable state: True

Re-run against this session's stack before the fix, verbatim: head 1 to 5,
anchor 1, one read, anchor 5.

**Why it happened, and why it is a class rather than a line.**
`client.currentState()` reaches `immudb/handler/currentRoot.py::call`, which
reads the head and then calls `rs.set(state)` unconditionally - no signature
check, no monotonicity check, no comparison against what it overwrites, with
the SDK's own `# IMPROVEMENT: we could check here, if state is valid` sitting
on the line above. It runs last, so it overwrites the state `verifiedSet.call`
or `verifiedGet.call` had just persisted under `newstate.Verify(verifying_key)`.
Two call sites had it, in two credential tiers: `verify` on the unanchored
path and `write` on D40's state read.

Reporting the head does not require persisting it, and `GET /state` reached
that conclusion about the same mutation in the same tier in Phase 3b and wrote
the argument down. `verifier/main.py::head_state` is that argument applied to
all three.

**Seeding is covered too, and there are two seeding paths.** The SDK's
`PersistentRootService.init` sets its cache from `CurrentState` when the state
file is absent or unreadable - the first boot of any deployment - and `get()`
does the same when the cache is `None`. Neither is a `set`, so a rule about
writes would catch neither, and the first proof after a fresh boot runs from
whatever the server said. `verifier/main.py::_VerifiedRootService` implements
`init`, `get` and `set`, so one class covers both seeds and the write.

Requires the stack: the mutation this file is about is a file on the
verifier's own volume, and the proof path the state feeds runs the SDK's
verification against a real VerifiableEntry.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import uuid
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tests"))

from compose_helpers import (  # noqa: E402
    compose, requires_docker_cli, wait_for_health,
)

IMMUDB_URL         = os.getenv("IMMUDB_URL",          "http://localhost:8080")
IMMUDB_USER        = os.getenv("IMMUDB_USER",         "immudb")
IMMUDB_PASSWORD    = os.getenv("IMMUDB_PASSWORD",     "immudb")
VERIFIER_URL       = os.getenv("VERIFIER_URL",        "http://localhost:8003")
VERIFIER_READ_KEY  = os.getenv("VERIFIER_READ_KEY",   "test-verifier-read-key")
VERIFIER_WRITE_KEY = os.getenv("VERIFIER_WRITE_KEY",  "test-verifier-write-key")

requires_stack = pytest.mark.needs_stack("immudb", "verifier")

_CLIENT = httpx.Client(timeout=120.0)

STATE_PATH = "/data/verifier-state/immudb.state"

# Read inside the container, because the file is on the verifier's own volume.
_READ_ANCHOR = (
    "import pickle\n"
    "try:\n"
    "    with open('" + STATE_PATH + "', 'rb') as handle:\n"
    "        print({db: st.txId for db, st in pickle.load(handle).items()})\n"
    "except FileNotFoundError:\n"
    "    print('{}')\n"
)

_REMOVE_ANCHOR = (
    "import os\n"
    "os.remove('" + STATE_PATH + "')\n"
    "print('removed')\n"
)


def _b64(value) -> str:
    return base64.b64encode(
        value if isinstance(value, bytes) else value.encode()).decode()


def _immudb_headers() -> dict:
    resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/login", json={
        "user": _b64(IMMUDB_USER), "password": _b64(IMMUDB_PASSWORD),
        "database": _b64("defaultdb"),
    })
    resp.raise_for_status()
    return {"Authorization": f"Bearer {resp.json()['token']}"}


def _in_verifier(script: str) -> str:
    result = compose("exec", "-T", "verifier", "python", "-", stdin=script,
                     check=False)
    assert result.returncode == 0, (
        f"could not run in the verifier container: {result.stdout[-400:]} "
        f"{result.stderr[-400:]}"
    )
    return result.stdout.strip()


def _anchor() -> int | None:
    """The transaction the verifier's persisted anchor sits at, or None."""
    held = eval(_in_verifier(_READ_ANCHOR))          # noqa: S307 - a dict repr
    if not held:
        return None
    return int(next(iter(held.values())))


def _move_the_head(headers: dict, count: int = 4) -> None:
    """Advance the ledger without the verifier seeing it.

    Written straight to ImmuDB's own REST route, which the verifier is not on,
    so the anchor and the head are different numbers rather than
    coincidentally equal.
    """
    tag = uuid.uuid4().hex[:8]
    for index in range(count):
        resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/set", json={"KVs": [
            {"key": _b64(f"probe:p3c3f-anchor-{tag}:{index}"),
             "value": _b64("x")}]}, headers=headers)
        resp.raise_for_status()


def _write_one_record() -> tuple[str, int]:
    """One ordered write through the verifier, so there is something to
    verify. Returns its key and the transaction it committed at."""
    agent = f"p3c3f-anchor-{uuid.uuid4().hex[:8]}"
    key = f"tool_call:{agent}:{uuid.uuid4().hex}:query_database"
    value = json.dumps({
        "record_type": "decision", "call_id": uuid.uuid4().hex,
        "agent_id": agent, "timestamp": "2026-09-03T00:00:00",
        "tool_name": "query_database", "outcome_type": "policy_allow",
        "fault_class": None, "policy_revision": "p3c3f-anchor",
        "reasons": [], "input_sha256": uuid.uuid4().hex,
        "content_state": "unavailable", "profile": "observed",
    }, separators=(",", ":"))
    resp = _CLIENT.post(f"{VERIFIER_URL}/write-ordered",
                        json={"key": _b64(key), "value": _b64(value),
                              "view": "decision"},
                        headers={"X-API-Key": VERIFIER_WRITE_KEY})
    assert resp.status_code == 200, resp.text[:300]
    body = resp.json()
    assert body.get("verified") is True and body.get("committed") is True, body
    return key, int(body["tx_id"])


# ---------------------------------------------------------------------------
# Call site one: POST /verify, on the read key.
# ---------------------------------------------------------------------------

@requires_stack
@requires_docker_cli
def test_a_read_does_not_move_the_persisted_trust_anchor():
    """The red team's B1.2, as a test.

    Everything here runs on the READ credential, which is the point: ADR-0011
    validates the tier split with "the read key does not open `/write`", and
    that is route separation rather than a claim that the read tier has no
    side effects. This is the test that makes the second claim true.
    """
    headers = _immudb_headers()
    key, record_tx = _write_one_record()

    before = _anchor()
    assert before is not None, (
        "the verifier holds no persisted anchor at all, so this test cannot "
        "tell whether a read moves it"
    )

    _move_the_head(headers)
    unmoved = _anchor()
    assert unmoved == before, (
        f"the anchor moved from {before} to {unmoved} with nothing asking the "
        "verifier anything, so the reads below are not what moves it"
    )

    read = _CLIENT.post(f"{VERIFIER_URL}/verify", json={"key": _b64(key)},
                        headers={"X-API-Key": VERIFIER_READ_KEY})
    assert read.status_code == 200, read.text[:300]
    body = read.json()
    assert body.get("verified") is True, body
    assert body.get("tx_id") == record_tx, body
    assert body.get("state_id", 0) > before, (
        "the response does not report a head above the anchor, so this test "
        f"is not exercising the line it describes: {body}"
    )

    after = _anchor()
    assert after == before, (
        f"POST /verify moved the persisted trust anchor from {before} to "
        f"{after} on the READ key. It reported the head as state_id "
        f"{body.get('state_id')} and persisted it: reporting the head does not "
        "require persisting it (D47), and every later proof is measured "
        "against what this file holds."
    )

    # And the control: the route still works afterwards, so "never moves the
    # anchor" was not achieved by the route failing.
    again = _CLIENT.post(f"{VERIFIER_URL}/verify", json={"key": _b64(key)},
                         headers={"X-API-Key": VERIFIER_READ_KEY})
    assert again.json().get("verified") is True, again.text[:300]


# ---------------------------------------------------------------------------
# Call site two: POST /write, on the write key.
# ---------------------------------------------------------------------------

@requires_stack
@requires_docker_cli
def test_a_write_moves_the_anchor_to_its_own_proof_and_not_to_the_head():
    """D40's state read, which had the same call in the write tier.

    A write SHOULD move the anchor: `verifiedSet.call` persists the state its
    own proof ran to, under `newstate.Verify(verifying_key)`. What it must not
    do is then overwrite that with the head, which is a state no proof
    reached.

    **What this test cannot discriminate, stated rather than implied.** Telling
    the two apart from outside requires the head to move BETWEEN this write's
    commit and its own state read, which is a race no external driver can aim
    at: the write is the newest transaction at the moment it commits, so "the
    head" and "this write's transaction" are the same number and the assertion
    below holds either way. Measured: the phase's own `p6-write-current-state`
    mutation left this module at `4 passed`.

    The discriminating test for this call site is in process and is
    `tests/test_route_parity.py::test_no_route_outside_the_site_list_durably_changes_state`,
    where the stub client reports a head of 4242 for a write that commits at
    77 and records every anchor set. That one fails at `[77, 4242]` under the
    same mutation. This test holds the live end of the same claim: the anchor
    after a write is the write's own transaction, over the real SDK and the
    real state file.
    """
    headers = _immudb_headers()
    _key, record_tx = _write_one_record()
    proved = _anchor()
    assert proved is not None and proved >= record_tx, (
        f"the anchor is at {proved} and this write's proof ran to {record_tx}"
    )

    _move_the_head(headers, count=6)

    tombstone = f"content_erasure:{uuid.uuid4().hex}"
    written = _CLIENT.post(
        f"{VERIFIER_URL}/write",
        json={"key": _b64(tombstone),
              "value": _b64(json.dumps({"record_type": "content_erasure",
                                        "call_id": uuid.uuid4().hex}))},
        headers={"X-API-Key": VERIFIER_WRITE_KEY})
    assert written.status_code == 200, written.text[:300]
    body = written.json()
    assert body.get("verified") is True and body.get("committed") is True, body

    after = _anchor()
    assert after == int(body["tx_id"]), (
        f"POST /write left the anchor at {after} and its own proof ran to "
        f"transaction {body['tx_id']}. D40's state read reports the head for a "
        "log line, and the SDK's way of reporting it overwrites the state the "
        "proof just persisted with one nothing verified."
    )


# ---------------------------------------------------------------------------
# The seed: a fresh boot with no state file.
# ---------------------------------------------------------------------------

@requires_stack
@requires_docker_cli
def test_the_first_proof_after_a_cold_boot_runs_from_a_verified_state():
    """`PersistentRootService.init`'s seed, which is not a `set`.

    With no state file the SDK's implementation sets its cache from
    `CurrentState` and checks nothing, so the first proof after a fresh boot -
    every deployment's first proof - runs from a state this service took the
    server's word for. `_VerifiedRootService` checks the signature before
    accepting it, and this drives that: the file is removed, the verifier is
    restarted, and a proof is run.

    The teardown is unconditional and restarts the verifier either way: a
    session that left it without an anchor would fail every later test in a
    way that reads as a code regression.
    """
    key, record_tx = _write_one_record()
    _in_verifier(_REMOVE_ANCHOR)
    try:
        compose("restart", "verifier")
        assert wait_for_health(f"{VERIFIER_URL}/health"), (
            "the verifier did not come back after its state file was removed, "
            "which is the cold-boot seed refusing rather than checking"
        )

        assert _anchor() is None, (
            "the state file is back before any proof has run, so the read "
            "below is not the first one after a cold boot"
        )

        read = _CLIENT.post(f"{VERIFIER_URL}/verify", json={"key": _b64(key)},
                            headers={"X-API-Key": VERIFIER_READ_KEY})
        assert read.status_code == 200, read.text[:300]
        body = read.json()
        assert body.get("verified") is True, (
            "the first proof after a cold boot did not verify, so the state it "
            f"was seeded from is not one a proof can run from: {body}"
        )
        assert body.get("tx_id") == record_tx, body

        # The seed lives in memory; the file appears when a proof persists the
        # state it ran to. That state is the record's, not the head's.
        persisted = _anchor()
        assert persisted is not None and persisted >= record_tx, (
            f"the first proof after a cold boot left the anchor at {persisted} "
            f"and it ran to transaction {record_tx}"
        )
    finally:
        compose("restart", "verifier")
        wait_for_health(f"{VERIFIER_URL}/health")


@requires_stack
@requires_docker_cli
def test_both_seeds_and_the_write_refuse_a_state_nothing_verified():
    """The three ways a state reaches the anchor, each handed one that does
    not check out.

    `_VerifiedRootService` is the class D47 asks for precisely because there
    are three: `init`'s seed when the state file is absent, `get`'s seed when
    the cache is empty, and `set`. The first two are not writes, so a rule
    about writes would have covered neither, and the first proof after any
    deployment's first boot runs from `init`'s.

    Driven inside the image against the class the service actually runs,
    rather than against a re-implementation here, because a rule asserted
    somewhere other than where it runs is the defect class this whole phase is
    about. The stand-in service answers the one RPC a root service makes.
    """
    script = (
        "import sys\n"
        "sys.path.insert(0, '/app')\n"
        "import main\n"
        "from immudb.rootService import State\n"
        "\n"
        "client = main._get_client()\n"
        "good = main.head_state(client)\n"
        "key = main._state_verifying_key()\n"
        "assert key is not None, 'no ImmuDB signing key is configured'\n"
        "\n"
        "class _Reports:\n"
        "    def __init__(self, state):\n"
        "        self._state = state\n"
        "    def CurrentState(self, _empty):\n"
        "        class _Sig:\n"
        "            publicKey = self._state.publicKey\n"
        "            signature = self._state.signature\n"
        "        class _Grpc:\n"
        "            db = self._state.db\n"
        "            txId = self._state.txId\n"
        "            txHash = self._state.txHash\n"
        "            signature = _Sig()\n"
        "        return _Grpc()\n"
        "\n"
        "def _tampered():\n"
        "    return State(db=good.db, txId=good.txId + 1, txHash=good.txHash,\n"
        "                 publicKey=good.publicKey, signature=good.signature)\n"
        "\n"
        "def _report(label, fn):\n"
        "    try:\n"
        "        fn()\n"
        "        print(label + ': ACCEPTED')\n"
        "    except main.UnverifiedState as exc:\n"
        "        print(label + ': refused - ' + str(exc)[:100])\n"
        "\n"
        "# init's seed, with no state file to load from.\n"
        "rs = main._VerifiedRootService('/tmp/p3c3f-absent.state', key)\n"
        "_report('init-good', lambda: rs.init('db', _Reports(good)))\n"
        "rs = main._VerifiedRootService('/tmp/p3c3f-absent.state', key)\n"
        "_report('init-tampered',\n"
        "        lambda: rs.init('db', _Reports(_tampered())))\n"
        "\n"
        "# get's seed, with the cache empty.\n"
        "rs = main._VerifiedRootService('/tmp/p3c3f-absent2.state', key)\n"
        "rs._service = _Reports(good)\n"
        "_report('get-good', rs.get)\n"
        "rs = main._VerifiedRootService('/tmp/p3c3f-absent2.state', key)\n"
        "rs._service = _Reports(_tampered())\n"
        "_report('get-tampered', rs.get)\n"
        "\n"
        "# set, and set backwards.\n"
        "rs = main._VerifiedRootService('/tmp/p3c3f-set.state', key)\n"
        "rs._dbname = 'db'\n"
        "_report('set-good', lambda: rs.set(good))\n"
        "_report('set-tampered', lambda: rs.set(_tampered()))\n"
        "backwards = State(db=good.db, txId=1, txHash=good.txHash,\n"
        "                  publicKey=good.publicKey, signature=good.signature)\n"
        "_report('set-backwards', lambda: rs.set(backwards))\n"
    )
    output = _in_verifier(script)
    lines = dict(line.split(":", 1) for line in output.splitlines()
                 if ":" in line)

    for control in ("init-good", "get-good", "set-good"):
        assert control in lines and "ACCEPTED" in lines[control], (
            f"the {control} control did not pass: a state this ImmuDB signed "
            "was refused, so the refusals below would hold against a class "
            f"that refuses everything. Output:\n{output}"
        )

    for refused in ("init-tampered", "get-tampered", "set-tampered"):
        assert refused in lines and "refused" in lines[refused], (
            f"{refused}: a state whose signature does not cover it became the "
            f"trust anchor. Output:\n{output}"
        )

    assert "refused" in lines.get("set-backwards", ""), (
        "the anchor was moved backwards, and an anchor that can go backwards "
        f"can be replayed to a point before a record was written. Output:\n"
        f"{output}"
    )
