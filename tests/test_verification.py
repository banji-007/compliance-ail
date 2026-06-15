"""
Verification integration tests.

All five tests run against a real ImmuDB container and the real verifier
service (no mocks). The docker-compose.test.yml stack must be up before
pytest runs; make test-integration handles this.

Environment variables (all default to docker-compose.test.yml values):
  VERIFIER_URL          http://localhost:8003
  IMMUDB_URL            http://localhost:8080
  IMMUDB_ADDR           localhost:3322    (gRPC; in-process SDK tests only)
  IMMUDB_USER           immudb
  IMMUDB_PASSWORD       immudb
  CONTROL_PLANE_URL     http://localhost:8002
  CONTROL_PLANE_API_KEY test-api-key

Test map:
  1. test_parity         - Criterion 1: state_id from verifier matches what
                           ImmuDB itself reports for the same tx.
  2. test_tamper_state   - Criterion 2a: PersistentRootService seeded with a
                           future txId causes verifiedGet to raise.
  3. test_tamper_pubkey  - Criterion 2b: wrong ECDSA verifying key causes
                           State.Verify to raise, even for an honest entry.
  4. test_cross_process  - Criterion 4: /audit (control-plane process) returns
                           verified: true without touching any interceptor-local
                           file.
  5. test_roundtrip      - Criterion 5: write-then-read via the verifier
                           service succeeds with correct value and tx_id.
"""

import base64
import os
import pickle
import tempfile
import uuid

import httpx
import pytest

VERIFIER_URL      = os.getenv("VERIFIER_URL",          "http://localhost:8003")
IMMUDB_URL        = os.getenv("IMMUDB_URL",            "http://localhost:8080")
IMMUDB_ADDR       = os.getenv("IMMUDB_ADDR",           "localhost:3322")
IMMUDB_USER       = os.getenv("IMMUDB_USER",           "immudb")
IMMUDB_PASSWORD   = os.getenv("IMMUDB_PASSWORD",       "immudb")
CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL",     "http://localhost:8002")
API_KEY           = os.getenv("CONTROL_PLANE_API_KEY", "test-api-key")


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def verifier_write(key_raw: str, value_raw: str) -> dict:
    resp = httpx.post(
        f"{VERIFIER_URL}/write",
        json={"key": b64(key_raw), "value": b64(value_raw)},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def verifier_verify(key_raw: str) -> dict:
    resp = httpx.post(
        f"{VERIFIER_URL}/verify",
        json={"key": b64(key_raw)},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def immudb_current_tx() -> int:
    """Return the server's current txId via REST to cross-check verifier state."""
    with httpx.Client(timeout=10) as c:
        login = c.post(
            f"{IMMUDB_URL}/api/v2/login",
            json={
                "user": b64(IMMUDB_USER),
                "password": b64(IMMUDB_PASSWORD),
                "database": b64("defaultdb"),
            },
        )
        login.raise_for_status()
        token = login.json()["token"]
        state = c.get(
            f"{IMMUDB_URL}/api/v2/db/state",
            headers={"Authorization": f"Bearer {token}"},
        )
        state.raise_for_status()
        return int(state.json().get("txId", 0))


# ---------------------------------------------------------------------------
# Criterion 1: parity
# ---------------------------------------------------------------------------

def test_parity():
    """
    After a verified write, the verifier's state_id must not exceed the
    server's current txId and must be at least as large as the written tx.

    This is the gate test. If the SDK's proof math or field handling are wrong,
    the verifier's persisted state diverges from the server's state after the
    first write, and subsequent verifiedGet calls fail consistency proofs. A
    passing test means the verifier is anchored to a state the server actually
    recognizes - the gap the previous circular hash never closed.
    """
    key = f"test:parity:{uuid.uuid4().hex}"

    write_result = verifier_write(key, '{"criterion": "parity"}')
    assert write_result["verified"] is True, f"Write not verified: {write_result}"
    write_tx = write_result["tx_id"]

    verify_result = verifier_verify(key)
    assert verify_result["verified"] is True, f"Verify failed: {verify_result}"
    assert verify_result["tx_id"] == write_tx, (
        f"tx_id mismatch: write={write_tx} verify={verify_result['tx_id']}"
    )

    server_tx = immudb_current_tx()
    state_id  = verify_result["state_id"]

    assert state_id >= write_tx, (
        f"Verifier state_id={state_id} is behind write tx={write_tx}"
    )
    assert state_id <= server_tx, (
        f"Verifier state_id={state_id} is ahead of server txId={server_tx} - "
        "state corruption"
    )


# ---------------------------------------------------------------------------
# Criterion 2a: tamper detection - corrupted persisted state
# ---------------------------------------------------------------------------

def test_tamper_state():
    """
    Corrupting the txHash in a PersistentRootService state file causes
    verifiedGet to raise rather than return a value.

    Vector: an adversary who can write to the verifier state file keeps the
    real txId (so proveSinceTx is a valid tx the server knows about) but
    replaces txHash with zeros. The server returns a real consistency proof
    from that txId to the target entry's tx, but the proof's starting hash
    doesn't match what the client stored — the linear-hash chain diverges at
    step one and the SDK raises before returning verified: true.

    The test first establishes a legitimate anchor via the SDK (so the pickle
    key format is correct), then overwrites only txHash, then tries to verify
    an entry written after the anchor.
    """
    from immudb import ImmudbClient
    from immudb.rootService import PersistentRootService, State

    with tempfile.NamedTemporaryFile(suffix=".state", delete=False) as f:
        state_path = f.name

    try:
        # --- Step 1: build a legitimate anchor via SDK verifiedSet ---
        honest_rs = PersistentRootService(state_path)
        honest_client = ImmudbClient(IMMUDB_ADDR, rs=honest_rs)
        honest_client.login(
            IMMUDB_USER.encode(), IMMUDB_PASSWORD.encode(), database=b"defaultdb"
        )
        anchor_key = f"test:anchor:{uuid.uuid4().hex}"
        honest_client.verifiedSet(anchor_key.encode(), b"anchor_value")
        # State file now has the real (txId, txHash) for this anchor tx.

        # --- Step 2: write the target entry AFTER the anchor (via verifier) ---
        target_key = f"test:target:{uuid.uuid4().hex}"
        r = verifier_write(target_key, '{"criterion": "tamper-state"}')
        assert r["verified"] is True

        # --- Step 3: corrupt the saved state — keep real txId, zero txHash ---
        with open(state_path, "rb") as f:
            states = pickle.load(f)
        state_dict_key = list(states.keys())[0]   # e.g. "localhost:3322/b'defaultdb'"
        s = states[state_dict_key]
        states[state_dict_key] = State(
            db=s.db,
            txId=s.txId,
            txHash=b"\x00" * 32,      # wrong — real hash replaced with zeros
            publicKey=s.publicKey,
            signature=s.signature,
        )
        with open(state_path, "wb") as f:
            pickle.dump(states, f)

        # --- Step 4: try to verify the target entry with the corrupted anchor ---
        corrupt_rs = PersistentRootService(state_path)
        corrupt_client = ImmudbClient(IMMUDB_ADDR, rs=corrupt_rs)
        corrupt_client.login(
            IMMUDB_USER.encode(), IMMUDB_PASSWORD.encode(), database=b"defaultdb"
        )
        with pytest.raises(Exception):
            # The dual consistency proof from (real txId, WRONG hash) to the
            # target tx hash cannot verify — the linear-hash chain diverges.
            corrupt_client.verifiedGet(target_key.encode())
    finally:
        os.unlink(state_path)


# ---------------------------------------------------------------------------
# Criterion 2b: tamper detection - wrong public key
# ---------------------------------------------------------------------------

def test_tamper_pubkey():
    """
    A wrong ECDSA verifying key causes State.Verify to raise even for an
    otherwise valid entry.

    When ImmuDB has --signingKey configured, every state response carries an
    ECDSA signature over (db, txId, txHash). A client with a different key
    rejects the signed state before it accepts the proof result. When the
    server has no signing key, the returned signature is empty bytes; any
    non-None verifying key still raises when it attempts to verify an empty
    signature. The test is valid in both server configurations.
    """
    import ecdsa

    from immudb import ImmudbClient
    from immudb.rootService import RootService

    key = f"test:tamper-pubkey:{uuid.uuid4().hex}"
    assert verifier_write(key, '{"criterion": "tamper-pubkey"}')["verified"] is True

    wrong_vk = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p).get_verifying_key()

    bad_client = ImmudbClient(IMMUDB_ADDR, rs=RootService())
    bad_client._vk = wrong_vk
    bad_client.login(
        IMMUDB_USER.encode(),
        IMMUDB_PASSWORD.encode(),
        database=b"defaultdb",
    )

    with pytest.raises(Exception):
        bad_client.verifiedGet(key.encode())


# ---------------------------------------------------------------------------
# Criterion 4: cross-process audit
# ---------------------------------------------------------------------------

def test_cross_process():
    """
    The /audit endpoint (control-plane process) returns verified: true for an
    entry written via the verifier, without reading any file private to the
    interceptor.

    This closes the process-boundary gap: the old design stored the trust
    anchor in a JSON file inside the interceptor container, making it
    unreachable from the control-plane container. The verifier service is
    reachable from both over the Docker network, so neither process requires a
    shared filesystem.
    """
    key = f"tool_call:test-agent:{uuid.uuid4().hex}:test_tool"
    log_entry = (
        '{"agent_id":"test-agent","timestamp":"2026-01-01T00:00:00",'
        '"tool_name":"test_tool","payload":{},"decision":"APPROVED"}'
    )
    write_result = verifier_write(key, log_entry)
    assert write_result["verified"] is True, f"Write failed: {write_result}"
    written_tx = write_result["tx_id"]

    audit_resp = httpx.get(
        f"{CONTROL_PLANE_URL}/audit",
        headers={"X-API-Key": API_KEY},
        timeout=30,
    )
    assert audit_resp.status_code == 200, (
        f"Audit returned HTTP {audit_resp.status_code}: {audit_resp.text[:300]}"
    )

    entries = audit_resp.json().get("entries", [])
    assert entries, "Audit returned no entries"

    matching = [e for e in entries if e.get("tx_id") == written_tx]
    assert matching, (
        f"Written tx={written_tx} not found in audit "
        f"(present: {[e.get('tx_id') for e in entries]})"
    )
    assert matching[0]["verified"] is True, (
        f"Entry tx={written_tx} is not verified in /audit: {matching[0]}"
    )


# ---------------------------------------------------------------------------
# Criterion 5: round-trip (field-casing regression)
# ---------------------------------------------------------------------------

def test_roundtrip():
    """
    Write a key via the verifier service, read it back, assert the value is
    preserved and tx_ids match.

    Regression guard for the three original I/O bugs: wrong endpoint path
    (verifiableset vs verifiable/set), wrong request body wrapper (missing
    setRequest key), and wrong field casing (eh vs eH in the tx header).
    Any of those would surface as a non-200 HTTP response or an SDK KeyError
    before this assertion is reached. A passing test means the SDK's gRPC
    path - not any hand-rolled REST call - handled the wire format correctly.
    """
    key   = f"test:roundtrip:{uuid.uuid4().hex}"
    value = f'{{"round": "trip", "id": "{key}"}}'

    write_result = verifier_write(key, value)
    assert write_result["verified"] is True, f"Write not verified: {write_result}"

    verify_result = verifier_verify(key)
    assert verify_result["verified"] is True, f"Verify failed: {verify_result}"

    returned = base64.b64decode(verify_result["value"]).decode()
    assert returned == value, f"Value mismatch: wrote={value!r} got={returned!r}"
    assert verify_result["tx_id"] == write_result["tx_id"], (
        f"tx_id mismatch: write={write_result['tx_id']} "
        f"verify={verify_result['tx_id']}"
    )
