"""tests/test_fault_key_and_page_read.py - Phase 3c-3d.

P3c3d-2, P3c3d-3, P3c3d-4, P3c3d-5, P3c3d-8 and P3c3d-11: the fault key, the
bounded page read, the legacy read beside it, the signature check in front of
it, the record with no call_id, and the count.

What was reproduced on `e3d8284` before any of this was written.

**Two faults about one record were one row and one hidden.** Under
`ledger_fault:{call_id}` a second fault was a new version of the same key:

    three faults for one call_id -> 1 row(s), head detail='tombstone fault',
                                    revision=3

**D38 as originally written closed nothing.** The only transaction available
when the key is built is the qualified record's own, which is fixed per
record, so `ledger_fault:{call_id}:{tx_id}` produced the same key twice:

    key   = ledger_fault:00000000000000004242:3d10361b...
    head  = SECOND  revision=2
    range read over the record's transaction returns 1 key(s)

**A fault with no writer signature at all rendered as a record's standing.**

    page row ledger_fault: {'fault_class': 'UNSIGNED-BY-ANYONE',
                            'committed_tx_id': 1, 'count': 1, ...}

**The count was the number of writes to a key, not the number of faults.**

    three writes to one fault key -> count: 3
    distinct fault keys in the ledger for that record: 1

**A fault for a record with no call_id was never joined onto its page row**,
under any key shape including the old one, while the record itself did reach
a page and the digest the fault is keyed by was derivable from the row:

    the record reaches a page: True
    row call_id: None | row ledger_fault: None
    sha256(ledger_key raw)[:32] derivable from the row: f5c13ca8...

**A bounded read whose bound is misspelled is an unbounded read at 200:**

    correct  endKey : ['00'..'06']
    misspelt endkey : ['00'..'09']

The faults here are written straight to the ledger rather than induced by
corrupting the trust anchor, because the conditions under test are about how
many faults exist for one record and where they sort - and a record key is
written once (D39), so the real path produces at most one fault per record.
They are built by the verifier's OWN key-construction and signed with the
verifier's OWN writer key, so a change to either is a change to what these
assert.
"""

import base64
import hashlib
import json
import logging
import os
import sys
import time
import uuid
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tests"))
sys.path.insert(0, str(REPO_ROOT))

from compose_helpers import requires_docker_cli  # noqa: E402,F401
from provenance.record_signature import load_signing_key, sign_record  # noqa: E402

CONTROL_PLANE_URL  = os.getenv("CONTROL_PLANE_URL",       "http://localhost:8002")
READ_API_KEY       = os.getenv("CONTROL_PLANE_READ_KEY",  "test-read-key")
VERIFIER_URL       = os.getenv("VERIFIER_URL",            "http://localhost:8003")
VERIFIER_WRITE_KEY = os.getenv("VERIFIER_WRITE_KEY",      "test-verifier-write-key")
IMMUDB_URL         = os.getenv("IMMUDB_URL",              "http://localhost:8080")
IMMUDB_USER        = os.getenv("IMMUDB_USER",             "immudb")
IMMUDB_PASSWORD    = os.getenv("IMMUDB_PASSWORD",         "immudb")
WRITER_VERIFIER_KEY = os.getenv("AIL_VERIFIER_WRITER_KEY",
                                str(REPO_ROOT / "keys" / "writer-verifier.key"))

requires_stack = pytest.mark.needs_stack("immudb", "verifier", "control_plane")

_CLIENT = httpx.Client(timeout=60.0)


# ---------------------------------------------------------------------------
# The modules under test, loaded the way tests/test_ledger_vocabulary.py does
# ---------------------------------------------------------------------------

def _load(name: str, relative: str):
    import importlib.util

    sys.path.insert(0, str(REPO_ROOT / "control_plane"))
    os.environ.setdefault("CONTROL_PLANE_READ_KEY", "test-read-key")
    os.environ.setdefault("CONTROL_PLANE_WRITE_KEY", "test-write-key")
    os.environ.setdefault("IMMUDB_URL", IMMUDB_URL)
    os.environ.setdefault("IMMUDB_USER", IMMUDB_USER)
    os.environ.setdefault("IMMUDB_PASSWORD", IMMUDB_PASSWORD)
    os.environ.setdefault("AIL_FAULT_WRITER_PUBLIC_KEY",
                          str(REPO_ROOT / "keys" / "writer-verifier.pub"))
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _control_plane():
    return _load("p3c3d_control_plane", "control_plane/main.py")


def _verifier_module():
    """The whole verifier module, for the tests that execute its functions.

    `_verifier_fault_key` below slices the key-construction block out of the
    source instead, because that one is about the key FORMAT and wants no
    live client near it. The Phase 3c-3e tests drive `_write_fault_record`
    itself against a stub, which needs the module's own imports, its writer
    key and its ledger-state constants - so it is loaded rather than sliced.

    The writer key path is set for the duration of the import and restored,
    not exported: the verifier reads it once at import, and leaving it set
    would change what every other in-process import of verifier/main.py in
    this session does, and which of them ran first.
    """
    import importlib.util

    previous = os.environ.get("AIL_WRITER_SIGNING_KEY")
    os.environ["AIL_WRITER_SIGNING_KEY"] = WRITER_VERIFIER_KEY
    try:
        spec = importlib.util.spec_from_file_location(
            "p3c3e_verifier", REPO_ROOT / "verifier" / "main.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules["p3c3e_verifier"] = module
        spec.loader.exec_module(module)
    finally:
        if previous is None:
            os.environ.pop("AIL_WRITER_SIGNING_KEY", None)
        else:
            os.environ["AIL_WRITER_SIGNING_KEY"] = previous
    return module


def _verifier_fault_key(record_value: bytes, record_key: bytes,
                        committed_tx_id: int, nonce: str) -> str:
    """The verifier's own key construction, executed rather than restated.

    Parsed out of the module instead of imported, for the reason
    tests/test_ledger_faults.py gives: verifier/main.py imports immudb at
    module scope and this is about the key format, not about a live client.
    """
    source = (REPO_ROOT / "verifier" / "main.py").read_text(encoding="utf-8")
    start = source.index("FAULT_KEY_TX_PAD = 20")
    end = source.index("def _write_fault_record")
    namespace = {"json": json, "hashlib": hashlib, "logger": logging.getLogger(
        "p3c3d_fault_key_slice"), "FAULT_KEY_PREFIX": "ledger_fault:"}
    exec(compile(source[start:end], "verifier/main.py", "exec"), namespace)  # noqa: S102
    return namespace["_fault_key"](record_value, record_key, committed_tx_id, nonce)


# ---------------------------------------------------------------------------
# Plumbing
# ---------------------------------------------------------------------------

def _b64(value) -> str:
    return base64.b64encode(value if isinstance(value, bytes) else value.encode()).decode()


def _immudb_headers() -> dict:
    resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/login", json={
        "user": _b64(IMMUDB_USER), "password": _b64(IMMUDB_PASSWORD),
        "database": _b64("defaultdb"),
    })
    resp.raise_for_status()
    return {"Authorization": f"Bearer {resp.json()['token']}"}


def _raw_set(headers: dict, pairs: list[tuple[str, str]]) -> int:
    resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/set", json={
        "KVs": [{"key": _b64(key), "value": _b64(value)} for key, value in pairs]},
        headers=headers)
    resp.raise_for_status()
    return int(resp.json().get("id", 0))


def _getall(headers: dict, keys: list[str]) -> dict:
    resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/getall",
                        json={"keys": [_b64(k) for k in keys]}, headers=headers)
    resp.raise_for_status()
    return {base64.b64decode(e["key"]).decode(): e
            for e in resp.json().get("entries", [])}


def _decision_value(call_id: str | None, agent_id: str) -> str:
    record = {
        "record_type": "decision", "agent_id": agent_id,
        "timestamp": "2026-09-01T00:00:00", "tool_name": "query_database",
        "outcome_type": "policy_allow", "fault_class": None,
        "policy_revision": "p3c3d-test", "reasons": [],
        "input_sha256": uuid.uuid4().hex, "content_state": "unavailable",
        "profile": "observed",
    }
    if call_id is not None:
        record["call_id"] = call_id
    return json.dumps(record, separators=(",", ":"))


def _write_ordered(key: str, value: str, view: str = "decision") -> dict:
    resp = _CLIENT.post(f"{VERIFIER_URL}/write-ordered",
                        json={"key": _b64(key), "value": _b64(value), "view": view},
                        headers={"X-API-Key": VERIFIER_WRITE_KEY})
    assert resp.status_code == 200, resp.text[:300]
    body = resp.json()
    assert body["committed"], body
    return body


def _tool_key(tag: str) -> str:
    return f"tool_call:{tag}-{uuid.uuid4().hex[:8]}:{uuid.uuid4().hex}:query_database"


def _fault_record(record_key: str, record_value: str, committed_tx_id: int,
                  seq: int | None, detail: str, sign: bool = True) -> dict:
    """A fault record shaped exactly as verifier/main.py writes one."""
    try:
        call_id = json.loads(record_value).get("call_id")
    except Exception:
        call_id = None
    identity = call_id or "key:" + hashlib.sha256(record_key.encode()).hexdigest()[:32]
    fault = {
        "record_type": "ledger_fault",
        "fault_class": "write_verification_failed",
        "call_id": identity,
        "committed_key": record_key,
        "committed_tx_id": committed_tx_id,
        "committed_position": seq,
        "view": "decision",
        "error_class": "consistency_failure",
        "detail": detail,
        "timestamp": "2026-09-01T00:00:00",
        "writer": "verifier",
        "remediation": "seeded by tests/test_fault_key_and_page_read.py",
    }
    if not sign:
        return fault
    signing_key, verifying_key = load_signing_key(WRITER_VERIFIER_KEY)
    return sign_record(fault, signing_key, verifying_key)


def _seed_fault(headers: dict, record_key: str, record_value: str,
                committed_tx_id: int, seq: int | None, detail: str,
                sign: bool = True, key_override: str | None = None) -> tuple[str, int]:
    """Write one fault under the key the verifier would use. Returns (key, tx)."""
    nonce = uuid.uuid4().hex[:16]
    key = key_override or _verifier_fault_key(
        record_value.encode(), record_key.encode(), committed_tx_id, nonce)
    fault = _fault_record(record_key, record_value, committed_tx_id, seq, detail,
                          sign=sign)
    tx = _raw_set(headers, [(key, json.dumps(fault, separators=(",", ":")))])
    return key, tx


def _audit(limit: int = 200) -> dict:
    resp = _CLIENT.get(f"{CONTROL_PLANE_URL}/audit", params={"limit": limit},
                       headers={"X-API-Key": READ_API_KEY})
    assert resp.status_code == 200, f"{resp.status_code} {resp.text[:300]}"
    return resp.json()


def _row_for(page: dict, ledger_key: str) -> dict:
    rows = [e for e in page["entries"] if e["ledger_key"] == _b64(ledger_key)]
    assert rows, f"the record is absent from the page: {ledger_key}"
    return rows[0]


# ---------------------------------------------------------------------------
# P3c3d-2: two faults about one record both survive, and three record kinds
# do not collide.
# ---------------------------------------------------------------------------

@requires_stack
def test_three_faults_about_one_record_all_survive_and_none_is_shadowed():
    """
    The defect D38's nonce exists for. Under `ledger_fault:{call_id}`, and
    under `ledger_fault:{call_id}:{committed_tx_id}` too, three faults about
    one record were three writes to one key: `getall` returned the head and a
    prefix scan returned one row.

    Ordered by the `scan` entry's own `tx`, which is what the read that
    already ran returns - no timestamp component is needed for it and none is
    in the key.
    """
    headers = _immudb_headers()
    call_id = uuid.uuid4().hex
    record_key = _tool_key("p3c3d-three")
    record_value = _decision_value(call_id, "p3c3d-three")
    written = _write_ordered(record_key, record_value)

    seeded = [
        _seed_fault(headers, record_key, record_value, written["tx_id"],
                    written["seq"], f"fault {n}")
        for n in ("one", "two", "three")
    ]
    keys = [key for key, _tx in seeded]
    assert len(set(keys)) == 3, (
        f"three faults about one record produced {len(set(keys))} distinct "
        f"key(s); the second is a new version of the first: {keys}"
    )

    control_plane = _control_plane()
    with httpx.Client(timeout=30.0) as client:
        token = _immudb_headers()["Authorization"].split()[1]
        entries = control_plane._faults_in_tx_window(
            client, token, written["tx_id"], written["tx_id"])

    found = {base64.b64decode(e["key"]).decode(): int(e["tx"]) for e in entries}
    for key in keys:
        assert key in found, (
            f"the range read over this record's transaction did not return "
            f"{key}; it returned {sorted(found)}"
        )

    order = [found[key] for key in keys]
    assert order == sorted(order) and len(set(order)) == 3, (
        f"the faults do not order by the scan entry's own tx: {order}"
    )


@requires_stack
def test_faults_about_an_intent_a_decision_and_a_tombstone_do_not_collide():
    """
    The non-adversarial case, which is what the transaction component closes
    and what the nonce alone would not.

    `tool_call_intent:` and `tool_call:` for one call carry the same
    `call_id`, and the erasure tombstone carries it too. All three can fault.
    Under `ledger_fault:{call_id}` the three faults collided and silently
    replaced each other, with no second writer involved: the page then showed
    the LAST fault written for one call as though it qualified whichever
    record the row happened to be.

    Asserted on the page, not only on the ledger, because a key shape that
    made the three distinct without leading on the transaction - keyed
    `{call_id}:{nonce}`, say - would also drop the bounded page read, and the
    row would carry no fault at all.
    """
    headers = _immudb_headers()
    call_id = uuid.uuid4().hex

    intent_key = f"tool_call_intent:p3c3d-kinds:{uuid.uuid4().hex}:read_vault_secret"
    intent_value = json.dumps({
        "record_type": "decision_intent", "call_id": call_id,
        "agent_id": "p3c3d-kinds", "timestamp": "2026-09-01T00:00:00",
        "tool_name": "read_vault_secret", "policy_revision": "p3c3d-test",
        "input_sha256": uuid.uuid4().hex, "content_state": "unavailable",
        "profile": "observed",
    }, separators=(",", ":"))
    intent = _write_ordered(intent_key, intent_value, view="intent")

    decision_key = _tool_key("p3c3d-kinds")
    decision_value = _decision_value(call_id, "p3c3d-kinds")
    decision = _write_ordered(decision_key, decision_value)

    tombstone_key = f"content_erasure:{call_id}"
    tombstone_value = json.dumps({
        "record_type": "content_erasure", "call_id": call_id,
        "timestamp": "2026-09-01T00:00:00", "actor": "p3c3d-test",
    }, separators=(",", ":"))
    tombstone_tx = _raw_set(headers, [(tombstone_key, tombstone_value)])

    # Written in this order on purpose: the tombstone's fault is last, so
    # under the old shape it is the one the page would show for every one of
    # the three records.
    faults = {
        "intent": _seed_fault(headers, intent_key, intent_value,
                              intent["tx_id"], intent["seq"], "intent fault"),
        "decision": _seed_fault(headers, decision_key, decision_value,
                                decision["tx_id"], decision["seq"], "decision fault"),
        "tombstone": _seed_fault(headers, tombstone_key, tombstone_value,
                                 tombstone_tx, None, "tombstone fault"),
    }
    keys = [key for key, _tx in faults.values()]
    assert len(set(keys)) == 3, (
        f"three faults about three records sharing one call_id produced "
        f"{len(set(keys))} distinct key(s): {keys}"
    )
    stored = _getall(headers, keys)
    assert set(stored) == set(keys), (
        f"the ledger does not hold all three: {sorted(stored)}"
    )

    row = _row_for(_audit(2500), decision_key)
    assert row["ledger_fault"] is not None, (
        "the decision row carries no fault at all, so the page read did not "
        "find it: a key that does not lead with the qualified record's "
        "transaction is not reachable from the page's own window"
    )
    assert row["ledger_fault"]["committed_tx_id"] == decision["tx_id"], (
        "the decision row names a fault about a different record: expected "
        f"transaction {decision['tx_id']}, row says "
        f"{row['ledger_fault']['committed_tx_id']}"
    )
    assert row["ledger_fault"]["count"] == 1, (
        f"the decision row counts more than its own fault: {row['ledger_fault']}"
    )


# ---------------------------------------------------------------------------
# P3c3d-3: the page read is bounded by the page.
# ---------------------------------------------------------------------------

@requires_stack
def test_the_bounded_read_returns_the_window_and_nothing_outside_it():
    """
    A window with faults on both sides of it. The half-open upper bound is
    what makes the last transaction in the window return its own faults: an
    `endKey` of the bare padded `hi` sorts before `hi`'s composite keys and
    silently drops them.
    """
    headers = _immudb_headers()
    control_plane = _control_plane()
    base = 10 ** 12 + int(uuid.uuid4().int % 10 ** 6) * 1000

    wanted, unwanted = {}, {}
    for offset in (-1, 0, 1, 2, 3):
        record_key = _tool_key(f"p3c3d-window{offset}")
        record_value = _decision_value(uuid.uuid4().hex, "p3c3d-window")
        key, _tx = _seed_fault(headers, record_key, record_value,
                               base + offset, None, f"window {offset}")
        (wanted if 0 <= offset <= 3 else unwanted)[key] = base + offset
    key, _tx = _seed_fault(headers, _tool_key("p3c3d-window4"),
                           _decision_value(uuid.uuid4().hex, "p3c3d-window"),
                           base + 4, None, "window 4")
    unwanted[key] = base + 4

    with httpx.Client(timeout=30.0) as client:
        token = _immudb_headers()["Authorization"].split()[1]
        entries = control_plane._faults_in_tx_window(client, token, base, base + 3)

    returned = {base64.b64decode(e["key"]).decode() for e in entries}
    missing = set(wanted) - returned
    assert not missing, (
        f"the bounded read did not return every fault in its window: {missing}"
    )
    leaked = set(unwanted) & returned
    assert not leaked, (
        f"the bounded read returned faults outside its window: {leaked}"
    )


@requires_stack
def test_a_single_transaction_window():
    """`lo == hi`. The case the bare inclusive end bound answers empty for."""
    headers = _immudb_headers()
    control_plane = _control_plane()
    tx = 10 ** 12 + int(uuid.uuid4().int % 10 ** 6) * 1000 + 7
    key, _ = _seed_fault(headers, _tool_key("p3c3d-single"),
                         _decision_value(uuid.uuid4().hex, "p3c3d-single"),
                         tx, None, "single")

    with httpx.Client(timeout=30.0) as client:
        token = _immudb_headers()["Authorization"].split()[1]
        entries = control_plane._faults_in_tx_window(client, token, tx, tx)

    returned = {base64.b64decode(e["key"]).decode() for e in entries}
    assert key in returned, (
        "a single-transaction window returned nothing for the transaction it "
        f"names: asked for [{tx}, {tx}], got {sorted(returned)}"
    )


@requires_stack
def test_a_window_needing_more_than_one_page_terminates_and_is_gap_free():
    """
    ImmuDB caps a scan result at 2500 with a 200 and no truncation flag, so a
    single-shot read returns a plausible answer and says nothing. The read
    pages on `seekKey` and stops when a page comes back short.
    """
    headers = _immudb_headers()
    control_plane = _control_plane()
    base = 10 ** 13 + int(uuid.uuid4().int % 10 ** 6) * 10000
    total = 2600

    pairs = []
    expected = set()
    for n in range(total):
        record_key = f"tool_call:p3c3d-pages:{n:06d}"
        record_value = _decision_value(uuid.uuid4().hex, "p3c3d-pages")
        nonce = f"{n:016x}"
        key = _verifier_fault_key(record_value.encode(), record_key.encode(),
                                  base + n, nonce)
        fault = _fault_record(record_key, record_value, base + n, None,
                              f"page seed {n}")
        pairs.append((key, json.dumps(fault, separators=(",", ":"))))
        expected.add(key)
    for start in range(0, total, 200):
        _raw_set(headers, pairs[start:start + 200])

    with httpx.Client(timeout=120.0) as client:
        token = _immudb_headers()["Authorization"].split()[1]
        entries = control_plane._faults_in_tx_window(client, token, base,
                                                     base + total - 1)

    returned = [base64.b64decode(e["key"]).decode() for e in entries]
    assert len(returned) == len(set(returned)), (
        "the paginated read returned a key twice, so its cursor overlaps"
    )
    assert expected <= set(returned), (
        f"the paginated read stopped early: {len(expected - set(returned))} of "
        f"{total} faults were never returned"
    )


@requires_stack
def test_an_empty_page_issues_no_range_read():
    """
    Zero rows means the window is undefined, so the read is skipped rather
    than run with a degenerate or invented bound.

    Asserted by handing it a client that raises on any use: if the read is
    issued at all, this fails with that raise rather than with an assertion
    about a result.
    """
    control_plane = _control_plane()

    class _RefusesEverything:
        def __getattr__(self, name):
            raise AssertionError(
                f"a range read was issued for a page with no rows (client.{name})"
            )

    assert control_plane._page_faults(_RefusesEverything(), "token", []) == {}


def test_a_bounded_read_asserts_on_what_came_back():
    """
    D42. An unrecognised or misspelled parameter is dropped by the REST route
    without comment, so a bounded read whose bound did not survive becomes an
    unbounded read at HTTP 200 and nothing in the response says so. Measured:

        correct  endKey : ['00'..'06']
        misspelt endkey : ['00'..'09']

    The assertion is therefore on the returned keys, and this drives it with
    a client that answers with a key outside the requested range - which is
    exactly what a dropped bound looks like from here.
    """
    control_plane = _control_plane()

    class _AnswersOutsideTheWindow:
        def post(self, url, json=None, headers=None):
            outside = control_plane._fault_key_tx_bound(10 ** 6) + ":x:y"

            class _Resp:
                @staticmethod
                def raise_for_status():
                    return None

                @staticmethod
                def json():
                    return {"entries": [{"key": base64.b64encode(outside.encode()).decode(),
                                         "value": "", "tx": "1"}]}
            return _Resp()

    with pytest.raises(control_plane.BoundedReadFault):
        control_plane._faults_in_tx_window(_AnswersOutsideTheWindow(), "token", 1, 2)


# ---------------------------------------------------------------------------
# P3c3e-8 (Phase 3c-3e): the legacy fault-key read path is gone.
# ---------------------------------------------------------------------------
#
# `test_a_page_carrying_an_old_shape_and_a_new_shape_fault_renders_both` lived
# here and asserted that a fault committed under the pre-D38
# `ledger_fault:{call_id}` shape still rendered. That read is deleted, so the
# test enforcing it is deleted with it rather than left passing against a path
# that no longer exists.
#
# The path protected nothing. Every ledger that has ever held a fault record
# in this project is a CI stack or a scratch stack destroyed by
# `docker compose down -v`, and
# tests/test_ledger_state_does_not_survive_teardown.py asserts that no volume
# in either compose file survives that. What it cost was a caller-influenced
# code path, and that is red-team A7.

@requires_stack
def test_a_crafted_call_id_no_longer_makes_one_fault_count_twice():
    """A7, no longer constructible.

    The attack, from the write credential alone. A new-shape fault key is
    `ledger_fault:{tx:020d}:{identity}:{nonce}` and the write response hands
    the whole key to whoever produced the fault. A second record whose
    `call_id` is spelled exactly `{tx:020d}:{identity}:{nonce}` made the
    page's legacy `getall` ask for `ledger_fault:` + that string, which is
    byte-identical to the first record's fault key. The getall returned it,
    `_merge_fault` folded it in, and the range read folded the same entry in
    again:

        BEFORE, one fault exists : {"committed_tx_id": 106, "count": 1}
        second record's call_id  : 00000000000000000106:11a19025...:4ea2f03d
        AFTER, still one fault   : {"committed_tx_id": 106, "count": 2}
        faults in the ledger for it : 1

    Driven exactly that way. The count has to stay 1, and the second record
    has to be a page row of its own carrying no fault, because it has none.
    """
    headers = _immudb_headers()

    victim_call_id = uuid.uuid4().hex
    victim_key = _tool_key("p3c3e-a7-victim")
    victim_value = _decision_value(victim_call_id, "p3c3e-a7-victim")
    victim = _write_ordered(victim_key, victim_value)
    fault_key, _tx = _seed_fault(headers, victim_key, victim_value,
                                 victim["tx_id"], victim["seq"],
                                 "the one fault that exists")

    before = _row_for(_audit(2500), victim_key)
    assert before["ledger_fault"] is not None, before
    assert before["ledger_fault"]["count"] == 1, (
        f"one fault exists and the page already counts more: {before}"
    )

    # The whole attack: a second, ordinary record whose call_id is spelled as
    # the tail of the victim's fault key.
    crafted = fault_key[len("ledger_fault:"):]
    attacker_key = _tool_key("p3c3e-a7-attacker")
    attacker_value = _decision_value(crafted, "p3c3e-a7-attacker")
    _write_ordered(attacker_key, attacker_value)

    page = _audit(2500)
    after = _row_for(page, victim_key)
    assert after["ledger_fault"]["count"] == 1, (
        "one fault is in the ledger and the page counts "
        f"{after['ledger_fault']['count']} for it, from a call_id the "
        f"attacker chose: {after}"
    )
    attacker_row = _row_for(page, attacker_key)
    assert attacker_row["ledger_fault"] is None, (
        "the attacker's own record carries a fault that was written about a "
        f"different record: {attacker_row}"
    )


# ---------------------------------------------------------------------------
# P3c3e-6 (Phase 3c-3e): a fault key is bounded and its call_id is validated.
# ---------------------------------------------------------------------------

def test_an_over_long_call_id_is_refused_as_an_identity_and_the_fault_is_still_written():
    """A1, closed at key construction.

    ImmuDB refuses a key of 1024 bytes (measured on the running stack: 1023
    accepted, 1024 answers "max key length exceeded"), and the fault key
    inherited its length from an unvalidated caller-supplied `call_id`. Past
    about a thousand characters NO FAULT RECORD WAS WRITTEN: the record
    committed, its proof failed, and the audit page showed it reading
    `policy_allow` with `ledger_fault: null`.

    The call_id is refused as a key component now and the digest fallback is
    used, so the fault still exists. Nothing is lost by the substitution - the
    join onto a page row is `committed_key`, and the fallback is derivable
    from the row's own `ledger_key`.
    """
    verifier = _verifier_module()
    record_key = b"tool_call:p3c3e-long:abc:query_database"

    ordinary = json.dumps({"record_type": "decision", "call_id": "a" * 32},
                          separators=(",", ":")).encode()
    assert verifier._fault_identity(ordinary, record_key) == "a" * 32

    over_long = json.dumps(
        {"record_type": "decision", "call_id": "a" * 1200},
        separators=(",", ":")).encode()
    identity = verifier._fault_identity(over_long, record_key)
    assert identity.startswith("key:"), (
        f"an over-long call_id was accepted as a key component: {identity[:80]}"
    )
    assert identity == "key:" + hashlib.sha256(record_key).hexdigest()[:32], (
        "the fallback is not the digest a reader can derive from a page row: "
        f"{identity}"
    )

    key = verifier._fault_key(over_long, record_key, 42, "0123456789abcdef")
    assert len(key.encode()) <= verifier.MAX_LEDGER_KEY_BYTES, (
        f"the assembled fault key is {len(key.encode())} bytes and this "
        f"ledger refuses anything above {verifier.MAX_LEDGER_KEY_BYTES}: {key}"
    )


def test_a_call_id_that_cannot_be_encoded_is_refused_as_an_identity_too():
    """P3c3f-8 (Phase 3c-3f). A1's outcome, reached past the budget rather
    than through it.

    Both length checks measure with `errors="replace"` and the write is a
    plain strict `.encode()`, so a `call_id` of lone surrogates is one
    character to every check here and unencodable at the ledger. It is
    caller-supplied and it arrives as well-formed JSON: a `\\ud800` escape on
    the wire, and `json.loads` hands back a `str` holding the surrogate.

    Driven by the Phase 3c-3e red team through the real `POST /write` against
    a client whose proof fails, which is the condition a fault record exists
    for:

        committed        : True   tx_id: 77
        fault_record     : None
        fault_record_err : UnicodeEncodeError ... surrogates not allowed
        unverified writes the route actually made: 0

    A committed record, its proof failed, and nothing durable recording why -
    the page row reading `ledger_fault: null` that this record type exists to
    prevent, selected by the caller by choosing its own call_id.

    **The defect was not loudness.** `fault_record_error` carried the
    exception and `_fault_failure_detail`'s sentence was already in `detail`
    on unmodified head, so "or it fails loudly" was closed by running the
    existing code. The defect is that `_fault_identity` judged the call_id on
    length alone, so an identity that could never be written was never judged
    unusable and the digest fallback - which exists for exactly this - was
    never reached.
    """
    verifier = _verifier_module()
    record_key = b"tool_call:p3c3f-surrogate:abc:query_database"

    # The record value as it arrives: ASCII on the wire, carrying the
    # surrogate as a JSON escape. `chr(92)` rather than a backslash literal so
    # nothing between this source and the file can eat it.
    escape = chr(92) + "ud800"
    surrogate_record = (
        '{"record_type":"decision","call_id":"' + escape * 300 + '"}'
    ).encode("ascii")
    assert len(json.loads(surrogate_record.decode())["call_id"]) == 300, (
        "the probe record does not carry 300 lone surrogates, so it is not "
        "the input this test is about"
    )

    identity = verifier._fault_identity(surrogate_record, record_key)
    assert identity.startswith("key:"), (
        "a call_id that cannot be encoded for the ledger was accepted as a "
        f"key component: {identity[:80]!r}"
    )
    assert identity == "key:" + hashlib.sha256(record_key).hexdigest()[:32], (
        f"the fallback is not the digest derivable from a page row: {identity}"
    )

    # The whole point: the key the write hands the ledger encodes.
    key = verifier._fault_key(surrogate_record, record_key, 77,
                              "0123456789abcdef")
    assert key.encode(), key
    assert len(key.encode()) <= verifier.MAX_LEDGER_KEY_BYTES, key

    # And the control, so this passes for the right reason: the same 300
    # characters that CAN be encoded are still accepted as the identity.
    encodable = ('{"record_type":"decision","call_id":"' + "a" * 300
                 + '"}').encode()
    assert verifier._fault_identity(encodable, record_key) == "a" * 300, (
        "an ordinary 300-character call_id was refused as an identity, so the "
        "refusal above is about length rather than about encodability"
    )


def test_a_fault_key_that_would_exceed_the_ledgers_maximum_fails_at_construction():
    """The bound is asserted where the key is built, not at the ledger.

    A key the ledger will refuse used to be discovered by the ledger refusing
    it, on a response field the middleware discards. It raises here instead,
    which is what makes the failure loud.

    `_fault_identity` bounds the one caller-supplied component, so this raise
    is unreachable through it by construction - which is exactly why the test
    replaces `_fault_identity` to reach it. An invariant that can only be
    checked by breaking another one still has to be checked.
    """
    verifier = _verifier_module()
    record_key = b"tool_call:p3c3e-bound:abc:query_database"
    original = verifier._fault_identity
    verifier._fault_identity = lambda value, key: "z" * (
        verifier.MAX_FAULT_IDENTITY_BYTES + 1)
    try:
        with pytest.raises(ValueError) as raised:
            verifier._fault_key(b"{}", record_key, 42, "0123456789abcdef")
    finally:
        verifier._fault_identity = original
    assert str(verifier.MAX_LEDGER_KEY_BYTES) in str(raised.value), raised.value


def test_an_unwritable_fault_is_reported_rather_than_silently_absent():
    """A fault that could not be written says so in the response `detail`.

    `fault_record_error` has always been on the response and the middleware
    discards the response, so the only place an unwritten fault was visible
    was the verifier's own log. The sentence in `detail` says what the absence
    means: nothing durable records why this record's proof failed.
    """
    verifier = _verifier_module()
    detail = verifier._fault_failure_detail("RuntimeError: max key length exceeded")
    assert "NO FAULT RECORD WAS WRITTEN" in detail, detail
    assert "ledger_fault null" in detail, detail
    assert verifier._fault_failure_detail(None) == ""


# ---------------------------------------------------------------------------
# P3c3e-7 (Phase 3c-3e): a fault key's transaction is not caller-supplied.
# ---------------------------------------------------------------------------

def test_the_fault_keys_transaction_is_derived_from_the_committed_record():
    """A2's writing half.

    The key's leading component places a fault inside a page's transaction
    window, and the body carries `committed_tx_id` as well. Nothing compared
    them, and a fault keyed at a transaction its record does not occupy is
    invisible at HTTP 200 - outside the window, never fetched, page row
    `ledger_fault: null`, no error and no log line.

    The transaction is read back from the ledger now, so the two numbers
    cannot disagree: there is one, and it comes from the ledger. Driven with a
    client whose ledger holds the record at a different transaction than the
    caller passes.
    """
    verifier = _verifier_module()
    record_key = b"tool_call:p3c3e-derive:abc:query_database"
    record_value = json.dumps({"record_type": "decision",
                               "call_id": "p3c3e-derive"},
                              separators=(",", ":")).encode()

    class _LedgerHoldsItAt:
        def __init__(self, tx):
            self.tx = tx
            self.written = []

        def get(self, key):
            if key != record_key:
                return None
            return type("Got", (), {"tx": self.tx, "value": record_value})()

        def set(self, key, value):
            self.written.append((key, value))
            return type("Resp", (), {"id": 999})()

    # The caller's number agrees with the ledger: the fault is written, and
    # its key names that transaction.
    agrees = _LedgerHoldsItAt(1234)
    key, error = verifier._write_fault_record(
        agrees, record_key=record_key, record_value=record_value,
        tx_id=1234, seq=None, view="decision",
        error_class="consistency_failure", detail="probe")
    assert error is None, error
    assert key.startswith(verifier.fault_key_tx_bound(1234) + ":"), key
    assert len(agrees.written) == 1, agrees.written

    # The caller's number disagrees. Refused, and it says which two numbers.
    disagrees = _LedgerHoldsItAt(1234)
    key, error = verifier._write_fault_record(
        disagrees, record_key=record_key, record_value=record_value,
        tx_id=99999, seq=None, view="decision",
        error_class="consistency_failure", detail="probe")
    assert key is None, key
    assert error is not None and "99999" in error and "1234" in error, error
    assert not disagrees.written, (
        "a fault was written under a transaction the record does not occupy: "
        f"{disagrees.written}"
    )


def test_a_fault_whose_key_and_body_disagree_is_not_rendered():
    """A2's reading half.

    The writer cannot produce such a pair any more. This is the other end of
    the same rule, on the page: a fault that arrives inside a window carrying
    a body about a record at a different transaction is refused rather than
    attributed to a row by `committed_key` alone.
    """
    control_plane = _control_plane()
    body = _fault_record("tool_call:p3c3e-mismatch:abc:query_database",
                         "unused", 500, None, "a mismatched fault")
    encoded_body = _b64(json.dumps(body, separators=(",", ":")))
    raw_matching = {
        "key": _b64(control_plane._fault_key_tx_bound(500) + ":x:y"),
        "value": encoded_body,
        "tx": "500",
    }
    assert control_plane._rendered_fault(raw_matching) is not None, (
        "the control shape does not render, so this test cannot show that the "
        "mismatched one is what is refused"
    )

    raw_mismatched = {
        "key": _b64(control_plane._fault_key_tx_bound(501) + ":x:y"),
        "value": encoded_body,
        "tx": "501",
    }
    assert control_plane._rendered_fault(raw_mismatched) is None, (
        "a fault whose key names one transaction and whose body names another "
        "was rendered as a record's standing"
    )


def test_the_key_transaction_reader_is_the_inverse_of_the_bound_builder():
    """The two halves of the format agree, at the boundaries.

    A reader parsing a different number of digits than the writer pads would
    place every fault at the wrong transaction, silently, at HTTP 200.
    """
    control_plane = _control_plane()
    for tx_id in (0, 1, 999999, 2 ** 53, 2 ** 64 - 1):
        encoded = _b64(control_plane._fault_key_tx_bound(tx_id) + ":identity:nonce")
        assert control_plane._fault_key_transaction(encoded) == tx_id, tx_id

    assert control_plane._fault_key_transaction(_b64("content_erasure:abc")) is None
    assert control_plane._fault_key_transaction(_b64("ledger_fault:12:x:y")) is None, (
        "a transaction component narrower than the pad was read as a "
        "transaction"
    )
    assert control_plane._fault_key_transaction("not base64 at all") is None


# ---------------------------------------------------------------------------
# P3c3d-5: a fault is verified before it is rendered.
# ---------------------------------------------------------------------------

@requires_stack
def test_a_fault_with_no_writer_signature_is_not_rendered_as_a_standing():
    """
    D41. Nothing on the read path checked `writer_signature` or
    `writer_key_fingerprint` before `/audit` rendered a fault, so a fault that
    arrived some other way was presented as the ledger's own account of
    another record's standing.

    D39 closes the write path; this is the read path, for a fault that got
    into the ledger by some route this service does not control.
    """
    headers = _immudb_headers()
    call_id = uuid.uuid4().hex
    record_key = _tool_key("p3c3d-unsigned")
    record_value = _decision_value(call_id, "p3c3d-unsigned")
    written = _write_ordered(record_key, record_value)

    _seed_fault(headers, record_key, record_value, written["tx_id"],
                written["seq"], "no signature at all", sign=False)

    row = _row_for(_audit(2500), record_key)
    assert row["ledger_fault"] is None, (
        "a fault with no writer signature is rendered as this record's "
        f"standing: {row['ledger_fault']}"
    )


@requires_stack
def test_a_fault_whose_signature_does_not_check_out_is_not_rendered():
    """The other half: a signature field that is present and wrong. A record
    signed under some other key, or edited after signing, must not be
    presented either - `writer_signature_missing` and
    `writer_signature_failure` are two results and one consequence."""
    headers = _immudb_headers()
    call_id = uuid.uuid4().hex
    record_key = _tool_key("p3c3d-badsig")
    record_value = _decision_value(call_id, "p3c3d-badsig")
    written = _write_ordered(record_key, record_value)

    fault = _fault_record(record_key, record_value, written["tx_id"],
                          written["seq"], "signed, then edited")
    fault["fault_class"] = "EDITED-AFTER-SIGNING"
    nonce = uuid.uuid4().hex[:16]
    key = _verifier_fault_key(record_value.encode(), record_key.encode(),
                              written["tx_id"], nonce)
    _raw_set(headers, [(key, json.dumps(fault, separators=(",", ":")))])

    row = _row_for(_audit(2500), record_key)
    assert row["ledger_fault"] is None, (
        "a fault edited after it was signed is rendered as this record's "
        f"standing: {row['ledger_fault']}"
    )


# ---------------------------------------------------------------------------
# P3c3d-8: a fault for a record with no call_id.
# ---------------------------------------------------------------------------

@requires_stack
def test_a_fault_for_a_record_with_no_call_id_is_joined_onto_its_page_row():
    """
    Two things were wrong and neither was the probe's question.

    `verifier/main.py` justified the digest fallback with "a record with no
    call_id never reaches a page". Measured false: such a record reaches a
    page, and the row's `ledger_key` is the base64 raw key, so the digest is
    derivable from a page row today.

    And the join never had it. `_tombstones_and_faults` was only ever handed
    `page_call_ids`, built under `if log_entry.get("call_id")`, so a fault for
    a record with no call_id was joined onto no page under any key shape,
    including the old one. The transaction-window read closes it for free,
    because it selects on the window rather than on an identity the row may
    not have.
    """
    headers = _immudb_headers()
    record_key = _tool_key("p3c3d-nocid")
    record_value = _decision_value(None, "p3c3d-nocid")
    assert "call_id" not in json.loads(record_value)
    written = _write_ordered(record_key, record_value)

    fault_key, _tx = _seed_fault(headers, record_key, record_value,
                                 written["tx_id"], written["seq"],
                                 "a fault for a record with no call_id")
    digest = hashlib.sha256(record_key.encode()).hexdigest()[:32]
    assert f":key:{digest}:" in fault_key, fault_key

    row = _row_for(_audit(2500), record_key)
    assert row["call_id"] is None, (
        "this test needs a record with no call_id and the row has one"
    )
    assert row["ledger_fault"] is not None, (
        "a fault for a record with no call_id is joined onto no page row"
    )
    assert row["ledger_fault"]["committed_tx_id"] == written["tx_id"], row


# ---------------------------------------------------------------------------
# P3c3d-11: the fault count is a count of faults.
# ---------------------------------------------------------------------------

@requires_stack
def test_a_record_with_three_faults_reports_three():
    """
    D35's free count was `revision` on the head entry, the number of times a
    key had been written. That was right only because the single key was
    rewritten in place. Under D38 each fault is its own key written once, so
    `revision` is permanently 1 and the field would report one fault where
    three exist - the failure D38 exists to fix, surviving inside the field
    that describes it.

    The contract this settles: `ledger_fault` stays ONE object, the most
    recent fault by the ledger's own transaction for the fault record, with
    `count` reporting how many exist.
    """
    headers = _immudb_headers()
    call_id = uuid.uuid4().hex
    record_key = _tool_key("p3c3d-count")
    record_value = _decision_value(call_id, "p3c3d-count")
    written = _write_ordered(record_key, record_value)

    for n in ("first", "second", "third"):
        _seed_fault(headers, record_key, record_value, written["tx_id"],
                    written["seq"], f"the {n} fault")
        time.sleep(0.05)

    row = _row_for(_audit(2500), record_key)
    assert row["ledger_fault"] is not None, row
    assert row["ledger_fault"]["count"] == 3, (
        f"three faults exist for this record and the row reports "
        f"{row['ledger_fault']['count']}"
    )
    assert isinstance(row["ledger_fault"], dict), (
        "the contract is one object with a count, not a list"
    )
    assert "_tx" not in row["ledger_fault"], (
        "the ordering bookkeeping leaked into the response contract"
    )
