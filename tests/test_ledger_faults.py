"""tests/test_ledger_faults.py - Phase 3c-3c (P3c3c-1, P3c3c-2, P3c3c-12).

A committed write is reported as committed, and its standing is durable.

The attack these carry forward is red-team C7
(docs/reports/phase-3c3b-redteam.md), reproduced verbatim on unmodified
b9f6a1d before anything here was written:

    verifier response   : {"tx_id": null, "seq": null, "verified": false,
                           "attempts": 0, "detail": "proof verification failed"}
    counter before/after: (1000000004, 4) -> (1000000005, 7)
    record in ledger    : True
    indexed in view     : True at [1000000005]

`{"tx_id": null, "verified": false}` is the exact shape
ledger/immudb_ledger.py reads as "the write did not happen". It happened.
Both routes had it - verifiedSet commits at service.VerifiableSet and every
ErrCorruptedData raise is after that line - and on the plain route it is the
erasure tombstone that gets described as never written.

The fault is injected the way the red team injected it: one byte of the
verifier's persisted trust anchor's txHash, which is ADR-0006's
`consistency_failure`. Not a mocked exception - the point of the finding was
that a real proof failure arrives after a real commit.

Requires the docker-compose.test.yml stack and the docker CLI, because the
trust anchor is a file inside the verifier container and is only re-read at
process start.
"""

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

from anchor_helpers import anchor as _anchor  # noqa: E402
from compose_helpers import (  # noqa: E402
    COMPOSE_PROJECT, compose, requires_docker_cli, wait_for_health,
)

CONTROL_PLANE_URL  = os.getenv("CONTROL_PLANE_URL",       "http://localhost:8002")
READ_API_KEY       = os.getenv("CONTROL_PLANE_READ_KEY",  "test-read-key")
WRITE_API_KEY      = os.getenv("CONTROL_PLANE_WRITE_KEY", "test-write-key")
VERIFIER_URL       = os.getenv("VERIFIER_URL",            "http://localhost:8003")
VERIFIER_WRITE_KEY = os.getenv("VERIFIER_WRITE_KEY",      "test-verifier-write-key")
IMMUDB_URL         = os.getenv("IMMUDB_URL",              "http://localhost:8080")
IMMUDB_USER        = os.getenv("IMMUDB_USER",             "immudb")
IMMUDB_PASSWORD    = os.getenv("IMMUDB_PASSWORD",         "immudb")

SEQUENCE_KEY  = "ail_seq:commit"
VIEW_DECISION = "ail_view:decision:v1"

requires_stack = pytest.mark.needs_stack("immudb", "verifier", "control_plane")

_CLIENT = httpx.Client(timeout=60.0)


# ---------------------------------------------------------------------------
# Helpers
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


def _getall(headers: dict, keys: list[str]) -> dict:
    resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/getall",
                        json={"keys": [_b64(k) for k in keys]}, headers=headers)
    resp.raise_for_status()
    out = {}
    for entry in resp.json().get("entries", []):
        out[base64.b64decode(entry["key"]).decode()] = entry
    return out


def _counter(headers: dict):
    entry = _getall(headers, [SEQUENCE_KEY]).get(SEQUENCE_KEY)
    if entry is None:
        return None
    return int(base64.b64decode(entry["value"]).decode()), int(entry["tx"])


def _zscan(headers: dict, view_set: str, limit: int = 2500) -> list[dict]:
    resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/zscan",
                        json={"set": _b64(view_set), "desc": True, "limit": limit},
                        headers=headers)
    resp.raise_for_status()
    return resp.json().get("entries", [])


def _decision_value(call_id: str, agent_id: str) -> str:
    return json.dumps({
        "record_type": "decision", "call_id": call_id, "agent_id": agent_id,
        "timestamp": "2026-08-31T00:00:00", "tool_name": "query_database",
        "outcome_type": "policy_allow", "fault_class": None,
        "policy_revision": "p3c3c-test", "reasons": [],
        "input_sha256": uuid.uuid4().hex, "content_state": "unavailable",
        "profile": "observed",
    }, separators=(",", ":"))


def _tombstone_value(call_id: str) -> str:
    return json.dumps({
        "record_type": "content_erasure", "call_id": call_id,
        "timestamp": "2026-08-31T00:00:00", "actor": "p3c3c-test",
    }, separators=(",", ":"))


def _write_ordered(key: str, value: str, view: str = "decision") -> httpx.Response:
    return _CLIENT.post(f"{VERIFIER_URL}/write-ordered",
                        json={"key": _b64(key), "value": _b64(value), "view": view},
                        headers={"X-API-Key": VERIFIER_WRITE_KEY})


def _write_plain(key: str, value: str) -> httpx.Response:
    return _CLIENT.post(f"{VERIFIER_URL}/write",
                        json={"key": _b64(key), "value": _b64(value)},
                        headers={"X-API-Key": VERIFIER_WRITE_KEY})


@pytest.fixture(scope="module")
def corrupt_trust_anchor():
    """A live ADR-0006 consistency_failure for the length of this module.

    Module-scoped because each transition costs a container restart, and
    torn down unconditionally: a session that left the anchor corrupt would
    fail every later test in a way that looks like a code regression.
    """
    # A write first, so the state file exists to corrupt.
    key = f"tool_call:p3c3c-seed-{uuid.uuid4().hex[:8]}:{uuid.uuid4().hex}:query_database"
    seed = _write_ordered(key, _decision_value(uuid.uuid4().hex, "p3c3c-seed"))
    assert seed.status_code == 200 and seed.json()["verified"], seed.text[:300]
    _anchor("corrupt")
    try:
        yield
    finally:
        _anchor("restore")


# ---------------------------------------------------------------------------
# P3c3c-1: a committed write is never reported as not having happened
# ---------------------------------------------------------------------------

@requires_stack
@requires_docker_cli
def test_a_committed_ordered_write_is_reported_as_committed(corrupt_trust_anchor):
    """
    C7, carried forward. The ordered route commits the record, the counter
    advance and the index entry in one ExecAll, and runs its proof after
    that. When the proof fails, the response must describe the ledger that
    exists rather than the one that would exist if the proof had run first.

    Every number in the response is checked against the ledger itself, not
    against another field of the same response - a response that agreed only
    with itself is what the old one did.
    """
    headers = _immudb_headers()
    before = _counter(headers)
    call_id = uuid.uuid4().hex
    key = f"tool_call:p3c3c-c7a-{uuid.uuid4().hex[:8]}:{uuid.uuid4().hex}:query_database"

    resp = _write_ordered(key, _decision_value(call_id, "p3c3c-c7a"))
    assert resp.status_code == 200, resp.text[:300]
    body = resp.json()

    assert body["verified"] is False, (
        "the trust anchor is corrupt; this write must not report a verified proof"
    )
    assert body["committed"] is True, (
        f"a write that committed reported itself as not having happened: {body}"
    )
    assert body["tx_id"], f"no transaction reported for a committed write: {body}"
    assert body["seq"], f"no position reported for a committed write: {body}"
    assert body["error_class"] == "consistency_failure", body
    assert body["attempts"] >= 1, (
        f"the commit took at least one attempt and the response says {body['attempts']}"
    )

    # The ledger's own account of the same write.
    after = _counter(headers)
    assert after is not None and before is not None
    assert after[0] == before[0] + 1, (
        f"the counter did not advance by exactly one: {before} -> {after}"
    )
    assert body["seq"] == after[0], (
        f"the response reports position {body['seq']} and the counter says {after[0]}"
    )

    found = _getall(headers, [key])
    assert key in found, "the response reports a committed record the ledger does not hold"
    assert int(found[key]["tx"]) == body["tx_id"], (
        f"the response reports transaction {body['tx_id']} and the ledger holds "
        f"this key at {found[key]['tx']}"
    )

    indexed = {base64.b64decode(r["entry"]["key"]).decode(): float(r.get("score", 0.0))
               for r in _zscan(headers, VIEW_DECISION, limit=50)}
    assert key in indexed, "the record committed and is not in the view index"
    assert indexed[key] == float(body["seq"]), (
        f"the index holds this record at {indexed[key]} and the response says "
        f"{body['seq']}"
    )


@requires_stack
@requires_docker_cli
def test_a_committed_plain_write_is_reported_as_committed(corrupt_trust_anchor):
    """
    The same defect on POST /write, which is the route the erasure tombstone
    takes. `verifiedSet` commits at service.VerifiableSet(rawRequest) and
    every ErrCorruptedData raise is after that line, so a tombstone reported
    as never written is in the ledger.
    """
    headers = _immudb_headers()
    call_id = uuid.uuid4().hex
    key = f"content_erasure:{call_id}"

    resp = _write_plain(key, _tombstone_value(call_id))
    assert resp.status_code == 200, resp.text[:300]
    body = resp.json()

    assert body["verified"] is False, body
    assert body["committed"] is True, (
        f"a tombstone that committed reported itself as never written: {body}"
    )
    assert body["tx_id"], body

    found = _getall(headers, [key])
    assert key in found, "the response reports a committed tombstone the ledger does not hold"
    assert int(found[key]["tx"]) == body["tx_id"], (
        f"the response reports transaction {body['tx_id']} and the ledger holds "
        f"this key at {found[key]['tx']}"
    )


@requires_stack
@requires_docker_cli
def test_a_committed_unverified_record_is_qualified_by_a_fault_record(corrupt_trust_anchor):
    """
    The durable half. A response is not durable and the page's verification
    state is recomputed on every read, so repairing the anchor makes the same
    record read `verified` with nothing recording that its write-time proof
    failed. The fault record is what persists, and it is joined to the page
    row by the same exact getall the tombstone join uses.
    """
    headers = _immudb_headers()
    call_id = uuid.uuid4().hex
    key = f"tool_call:p3c3c-fault-{uuid.uuid4().hex[:8]}:{uuid.uuid4().hex}:query_database"

    body = _write_ordered(key, _decision_value(call_id, "p3c3c-fault")).json()
    assert body["committed"] is True and body["verified"] is False, body
    assert body["fault_record_error"] is None, (
        f"the fault record could not be written: {body['fault_record_error']}"
    )
    assert body["fault_record"] == f"ledger_fault:{call_id}", body

    stored = _getall(headers, [f"ledger_fault:{call_id}"])
    assert f"ledger_fault:{call_id}" in stored, "the fault record is not in the ledger"
    fault = json.loads(base64.b64decode(stored[f"ledger_fault:{call_id}"]["value"]).decode())
    assert fault["record_type"] == "ledger_fault", fault
    assert fault["committed_key"] == key, fault
    assert fault["committed_tx_id"] == body["tx_id"], fault
    assert fault["committed_position"] == body["seq"], fault
    assert fault["error_class"] == "consistency_failure", fault
    # D22: a record this project's own checker will not refuse.
    assert fault.get("writer_signature"), (
        "the fault record carries no writer signature; tools/ail_verify_bundle.py "
        "refuses such a record outright"
    )
    assert fault.get("writer_key_fingerprint"), fault


@requires_stack
@requires_docker_cli
def test_a_second_fault_for_one_call_id_does_not_lose_the_first(corrupt_trust_anchor):
    """
    A fault is written by an unconditional set, so a second one is a new
    version of the same key rather than a replacement. Measured on this
    project's own REST route: a prior version stays readable, and getall
    reports the head entry's `revision`, which is the number of writes.
    """
    headers = _immudb_headers()
    call_id = uuid.uuid4().hex
    fault_key = f"ledger_fault:{call_id}"

    for suffix in ("a", "b"):
        key = f"tool_call:p3c3c-two{suffix}-{uuid.uuid4().hex[:8]}:{uuid.uuid4().hex}:query_database"
        body = _write_ordered(key, _decision_value(call_id, f"p3c3c-two{suffix}")).json()
        assert body["committed"] is True and body["fault_record"] == fault_key, body

    head = _getall(headers, [fault_key])[fault_key]
    assert int(head["revision"]) == 2, (
        f"two faults for one call_id left revision {head['revision']}; the second "
        "replaced the first instead of appending"
    )

    prior = _CLIENT.get(
        f"{IMMUDB_URL}/api/v2/db/get/{_b64(fault_key)}?atRevision=1",
        headers=headers,
    )
    assert prior.status_code == 200, (
        f"the first fault is no longer readable: {prior.status_code} {prior.text[:200]}"
    )
    first = json.loads(base64.b64decode(prior.json()["value"]).decode())
    assert first["record_type"] == "ledger_fault", first
    assert first["committed_tx_id"] != json.loads(
        base64.b64decode(head["value"]).decode())["committed_tx_id"], (
        "the two revisions describe the same commit, so nothing was retained"
    )


@requires_stack
@requires_docker_cli
def test_repairing_the_trust_anchor_does_not_erase_the_fault(corrupt_trust_anchor):
    """
    The reason the qualification is a record and not a response field, and
    not the page's `unverifiable` either.

    `_verify_one_key` computes the verification state fresh on every read.
    So a record whose write-time proof failed reads `verified` again the
    moment the trust anchor is repaired, and every field derived from that
    check agrees - which means the page would have no trace at all that this
    record's write was never proven. Reproduced on b9f6a1d: after repair the
    same record exported a clean `ail-evidence-bundle/2` and `/audit/verify`
    said `verified`.

    This test drives the repair itself rather than leaning on the fixture's
    teardown, because a module-scoped fixture is finalized after the last
    test in the module and the assertion here is specifically about what
    survives the transition. It leaves the anchor corrupt again so the
    module's other tests see the state they were written against.
    """
    call_id = uuid.uuid4().hex
    key = f"tool_call:p3c3c-page-{uuid.uuid4().hex[:8]}:{uuid.uuid4().hex}:query_database"
    body = _write_ordered(key, _decision_value(call_id, "p3c3c-page")).json()
    assert body["committed"] is True and body["fault_record"], body

    def _row():
        page = _CLIENT.get(f"{CONTROL_PLANE_URL}/audit", params={"limit": 200},
                           headers={"X-API-Key": READ_API_KEY})
        assert page.status_code == 200, page.text[:300]
        rows = [e for e in page.json()["entries"] if e["call_id"] == call_id]
        assert rows, "the committed record is absent from the page"
        return rows[0]

    before = _row()
    assert before["ledger_fault"] is not None, (
        f"the page does not name the fault qualifying this record: {before}"
    )
    assert before["ledger_fault"]["committed_tx_id"] == body["tx_id"], before

    _anchor("restore")
    try:
        after = _row()
        assert after["ledger_fault"] is not None, (
            "repairing the trust anchor erased every trace that this record's "
            "write-time proof failed, which is the condition the fault record "
            f"exists to make durable: {after}"
        )
        assert after["ledger_fault"]["committed_tx_id"] == body["tx_id"], after

        verified = _CLIENT.get(f"{CONTROL_PLANE_URL}/audit/verify",
                               params={"key": after["ledger_key"]},
                               headers={"X-API-Key": READ_API_KEY})
        assert verified.status_code == 200, verified.text[:300]
        # Asserted, not worked around: the read-time state is healthy again.
        # That is exactly why it is not the record's standing.
        assert verified.json()["verification"]["state"] == "verified", (
            "the record does not verify after the anchor is repaired, so this "
            f"test is not exercising the condition it describes: {verified.json()}"
        )
    finally:
        _anchor("corrupt")


# ---------------------------------------------------------------------------
# P3c3c-2: a decision record cannot reach the ledger without a position
# ---------------------------------------------------------------------------

@requires_stack
def test_a_decision_record_is_refused_at_the_plain_write_route():
    """
    C8, carried forward, refused at the route rather than by convention.

    Reproduced on b9f6a1d: the plain route accepted a decision record
    (`tx_id 9, verified true`), the counter did not move, the decision view
    did not hold it, and `/audit` never showed it - permanently, because the
    page selects through the index.
    """
    headers = _immudb_headers()
    before = _counter(headers)
    call_id = uuid.uuid4().hex
    key = f"tool_call:p3c3c-c8-{uuid.uuid4().hex[:8]}:{uuid.uuid4().hex}:query_database"

    resp = _write_plain(key, _decision_value(call_id, "p3c3c-c8"))
    assert resp.status_code == 400, (
        f"the plain route accepted a decision record: {resp.status_code} "
        f"{resp.text[:300]}"
    )
    assert "write-ordered" in resp.text, resp.text[:300]

    assert _getall(headers, [key]) == {}, (
        "the route refused and the record is in the ledger anyway"
    )
    assert _counter(headers) == before, "a refused write moved the sequence counter"


@requires_stack
def test_an_intent_record_is_refused_at_the_plain_write_route():
    """The same rule for the other record kind that must carry a position."""
    call_id = uuid.uuid4().hex
    key = f"tool_call_intent:p3c3c-c8i-{uuid.uuid4().hex[:8]}:{uuid.uuid4().hex}:read_vault_secret"
    value = json.dumps({
        "record_type": "decision_intent", "call_id": call_id,
        "agent_id": "p3c3c-c8i", "timestamp": "2026-08-31T00:00:00",
        "tool_name": "read_vault_secret", "input_sha256": uuid.uuid4().hex,
        "policy_revision": "p3c3c-test", "content_state": "unavailable",
        "profile": "mediated",
    }, separators=(",", ":"))

    resp = _write_plain(key, value)
    assert resp.status_code == 400, resp.text[:300]


@requires_stack
def test_a_decision_record_under_a_disguised_key_is_still_refused():
    """
    The two conditions are independent on purpose, and this is the one the
    key-prefix check alone would miss: a decision record written under a key
    that looks like anything else.
    """
    call_id = uuid.uuid4().hex
    key = f"content_erasure:p3c3c-disguise-{call_id}"
    resp = _write_plain(key, _decision_value(call_id, "p3c3c-disguise"))
    assert resp.status_code == 400, (
        f"a decision record disguised under another key prefix was accepted: "
        f"{resp.status_code} {resp.text[:300]}"
    )
    assert "decision" in resp.text, resp.text[:300]


@requires_stack
def test_a_record_with_no_record_type_under_a_decision_key_is_still_refused():
    """And the one the record_type check alone would miss."""
    key = f"tool_call:p3c3c-notype-{uuid.uuid4().hex[:8]}:{uuid.uuid4().hex}:query_database"
    resp = _write_plain(key, json.dumps({"call_id": uuid.uuid4().hex}))
    assert resp.status_code == 400, (
        f"a record under a decision key with its record_type omitted was "
        f"accepted: {resp.status_code} {resp.text[:300]}"
    )


@requires_stack
def test_a_fault_record_is_never_accepted_from_a_caller():
    """
    A fault record says another record's proof failed. One arriving from
    outside would be an unverified assertion about a record's standing, so
    the route refuses it and the only writer is this service itself.
    """
    call_id = uuid.uuid4().hex
    resp = _write_plain(f"ledger_fault:{call_id}", json.dumps({
        "record_type": "ledger_fault", "call_id": call_id,
        "fault_class": "write_verification_failed",
    }, separators=(",", ":")))
    assert resp.status_code == 400, resp.text[:300]


def test_the_unverified_write_path_refuses_a_decision_record():
    """
    D35's structural constraint, asserted directly on the function.

    The decision path must be *unable* to reach the one write in this system
    whose success does not require write-time proof, not merely not reach it
    today. _set_without_verification refuses anything that is not a fault
    record, so there is no argument a caller could arrange that puts a
    decision record through it.

    Parsed rather than imported: verifier/main.py imports immudb at module
    scope and this assertion is about the guard, not about a live client.
    """
    source = (REPO_ROOT / "verifier" / "main.py").read_text(encoding="utf-8")
    body = source[source.index("def _set_without_verification"):]
    body = body[:body.index(chr(10) + "def ")]
    assert 'record.get("record_type") != FAULT_RECORD_TYPE' in body, (
        "the unverified write path does not check what kind of record it is "
        "being asked to write"
    )
    assert "raise RuntimeError" in body, (
        "the guard does not refuse; it must raise rather than log and continue"
    )
    callers = [line for line in source.splitlines()
               if "_set_without_verification(" in line and "def " not in line]
    assert len(callers) == 1, (
        f"the unverified write path has {len(callers)} callers; it must have "
        f"exactly one, the fault writer: {callers}"
    )


# ---------------------------------------------------------------------------
# P3c3c-12: an erasure completes against a committed-unverified tombstone
# ---------------------------------------------------------------------------

@requires_stack
@requires_docker_cli
def test_an_erasure_completes_against_a_committed_unverified_tombstone(
        corrupt_trust_anchor):
    """
    The GDPR path, under the same live proof failure.

    Reproduced on b9f6a1d: DELETE answered 503 while the tombstone was
    committed at tx 6 and the content row survived, so the ledger said erased
    and the store said present - the `erasure_conflict` face of
    _payload_state, which is P13-4's own finding manufactured by the refusal.

    The delete completes because the tombstone is confirmed present in the
    ledger by an exact read, not because a response said so. The thing that
    must never happen - a row deleted with no tombstone behind it - is the
    subject of the next test.
    """
    headers = _immudb_headers()
    call_id = uuid.uuid4().hex

    wrote = _CLIENT.post(f"{CONTROL_PLANE_URL}/content",
                         json={"call_id": call_id, "payload": {"q": "select 1"}},
                         headers={"X-API-Key": WRITE_API_KEY})
    assert wrote.status_code == 204, wrote.text[:300]

    deleted = _CLIENT.delete(f"{CONTROL_PLANE_URL}/content/{call_id}",
                             headers={"X-API-Key": WRITE_API_KEY})
    assert deleted.status_code == 204, (
        f"the erasure was refused against a tombstone that committed: "
        f"{deleted.status_code} {deleted.text[:300]}"
    )

    tombstone_key = f"content_erasure:{call_id}"
    assert tombstone_key in _getall(headers, [tombstone_key]), (
        "the erasure completed with no tombstone in the ledger"
    )

    # And the row is gone, which is what the caller asked for.
    again = _CLIENT.delete(f"{CONTROL_PLANE_URL}/content/{call_id}",
                           headers={"X-API-Key": WRITE_API_KEY})
    assert again.status_code == 204, again.text[:300]


def test_an_erasure_is_refused_when_the_tombstone_is_not_in_the_ledger():
    """
    The other side of P3c3c-12, and the invariant that must not move.

    A committed-unverified tombstone completes the erasure only because it
    was confirmed present. If that confirmation fails - the record genuinely
    is not in the tree, or the check itself could not run - the erasure is
    refused and the row survives. Asserted on the code, because the
    condition needs a ledger that reports a commit it does not hold, which
    is not a state a test can produce against a correct server.
    """
    source = (REPO_ROOT / "control_plane" / "main.py").read_text(encoding="utf-8")
    body = source[source.index("def _write_tombstone"):]
    body = body[:body.index(chr(10) + "def _tombstone_present_in_ledger")]
    assert "_tombstone_present_in_ledger(call_id)" in body, (
        "the committed-unverified branch completes without confirming the "
        "tombstone against the ledger"
    )
    assert "refusing the erasure" in body, (
        "an unconfirmed tombstone does not refuse the erasure"
    )
    check = source[source.index("def _tombstone_present_in_ledger"):]
    check = check[:check.index(chr(10) + "@app.")]
    assert "return False" in check.split("except Exception")[1], (
        "the confirmation fails open: a check that could not run must not be "
        "read as a tombstone that exists"
    )
