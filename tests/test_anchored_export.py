"""
tests/test_anchored_export.py - P3b-1, P3b-2 and P3b-5, live half (D22/D23).

Requires the docker-compose.test.yml stack. The offline halves are
tests/test_writer_signing.py and tests/test_external_anchor.py; what needs a
live ledger is everything about which transaction a proof actually runs to,
because that is a property of a real ImmuDB with real transactions in it
rather than of a file.

Nothing here talks to Rekor. anchor-service is deliberately absent from
docker-compose.test.yml, so this whole file runs with external anchoring
entirely broken - which is also what makes the P3b-5 assertions at the
bottom real rather than staged.

Every `docker compose` invocation in this repository passes an explicit
-p project name; nothing in this file shells out to compose, it only talks
to the already-running services over HTTP.
"""

import base64
import hashlib
import importlib.util as _importlib_util
import inspect
import json
import os
import socket
import sys
import uuid
from pathlib import Path

import ecdsa
import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

_REAL_SOCKET_CONNECT = socket.socket.connect

CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL", "http://localhost:8002")
VERIFIER_URL = os.getenv("VERIFIER_URL", "http://localhost:8003")
READ_API_KEY = os.getenv("CONTROL_PLANE_READ_KEY", "test-read-key")
WRITE_API_KEY = os.getenv("CONTROL_PLANE_WRITE_KEY", "test-write-key")
VERIFIER_READ_KEY = os.getenv("VERIFIER_READ_KEY", "test-verifier-read-key")
VERIFIER_WRITE_KEY = os.getenv("VERIFIER_WRITE_KEY", "test-verifier-write-key")

LIVE_KEY = REPO_ROOT / "keys" / "signing.pub"
WRITER_DECISION_KEY = REPO_ROOT / "keys" / "writer-decision.key"
WRITER_DECISION_PUB = REPO_ROOT / "keys" / "writer-decision.pub"
WRITER_CONTROL_PLANE_PUB = REPO_ROOT / "keys" / "writer-control-plane.pub"

sys.path.insert(0, str(REPO_ROOT))
from provenance import record_signature as signer  # noqa: E402


def _load_module(name: str, path: Path):
    spec = _importlib_util.spec_from_file_location(name, path)
    module = _importlib_util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


checker = _load_module("ail_verify_bundle", REPO_ROOT / "tools" / "ail_verify_bundle.py")
socket.socket.connect = _REAL_SOCKET_CONNECT  # the checker's import blocks it process-wide


requires_stack = pytest.mark.needs_stack("verifier", "control_plane")


@pytest.fixture(autouse=True)
def _network_available():
    """Restore real sockets before every test here.

    tests/test_offline_verify.py and the two other Phase 3b offline files
    block them process-wide, and pytest imports every module before running
    any test, so without this these live tests would pass or fail depending
    on collection order rather than on the stack.
    """
    saved = socket.socket.connect
    socket.socket.connect = _REAL_SOCKET_CONNECT
    try:
        yield
    finally:
        socket.socket.connect = saved


# ---------------------------------------------------------------------------
# Helpers that drive the real services
# ---------------------------------------------------------------------------

def _write(key: bytes, value: bytes, view: str | None = "decision") -> dict:
    # D32 (Phase 3c-3b): a decision or intent record takes /write-ordered,
    # because it needs a commit position in the same transaction that
    # commits it and a record with no position is absent from every ordered
    # page. P3c3c-2 (Phase 3c-3c) made that a rule the route enforces rather
    # than a convention, so the plain route now refuses such a record
    # outright. `view=None` keeps the plain route for the record kinds that
    # take no position, which is what a tombstone is.
    body = {
        "key": base64.b64encode(key).decode(),
        "value": base64.b64encode(value).decode(),
    }
    route = "/write"
    if view is not None:
        route = "/write-ordered"
        body["view"] = view
    resp = httpx.post(
        f"{VERIFIER_URL}{route}",
        json=body,
        headers={"X-API-Key": VERIFIER_WRITE_KEY},
        timeout=30,
    )
    resp.raise_for_status()
    body = resp.json()
    assert body["verified"], body
    return body


def _verify(key: bytes, anchor: dict | None = None) -> dict:
    body = {"key": base64.b64encode(key).decode()}
    if anchor is not None:
        body["anchor"] = anchor
    resp = httpx.post(
        f"{VERIFIER_URL}/verify", json=body,
        headers={"X-API-Key": VERIFIER_READ_KEY}, timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def _state() -> dict:
    resp = httpx.get(
        f"{VERIFIER_URL}/state", headers={"X-API-Key": VERIFIER_READ_KEY}, timeout=15
    )
    resp.raise_for_status()
    return resp.json()


def _export(ledger_key_b64: str) -> dict:
    resp = httpx.get(
        f"{CONTROL_PLANE_URL}/audit/bundle",
        params={"key": ledger_key_b64},
        headers={"X-API-Key": READ_API_KEY},
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()


def _signed_record(extra: dict | None = None) -> bytes:
    """A record signed exactly the way the decision service signs one."""
    signing_key, verifying_key = signer.load_signing_key(WRITER_DECISION_KEY)
    record = {
        "record_type": "decision",
        "agent_id": "p3b_live",
        "timestamp": "2026-08-24T00:00:00",
        "tool_name": "provision_cloud_server",
        "call_id": uuid.uuid4().hex,
        "input_sha256": hashlib.sha256(b"p3b").hexdigest(),
        "outcome_type": "policy_allow",
        "fault_class": None,
        "policy_revision": "p3b-live",
        "reasons": [],
        "content_state": "unavailable",
        "profile": "observed",
    }
    record.update(extra or {})
    return json.dumps(signer.sign_record(record, signing_key, verifying_key),
                      separators=(",", ":")).encode()


def _new_key() -> bytes:
    return f"tool_call:p3b_live:{uuid.uuid4().hex}:provision_cloud_server".encode()


def _write_signed_record(extra: dict | None = None) -> tuple[bytes, int]:
    key = _new_key()
    tx = _write(key, _signed_record(extra))["tx_id"]
    return key, tx


def _anchor_from(state: dict) -> dict:
    return {
        "db": state["db"],
        "tx_id": state["tx_id"],
        "tx_hash": state["tx_hash"],
        "signature": state["signature"],
    }


# ---------------------------------------------------------------------------
# The seam this whole item rests on. Asserted against the installed SDK, not
# described, because an immudb-py upgrade is exactly what would move it.
# ---------------------------------------------------------------------------

def test_the_proof_source_still_comes_from_the_injected_root_service():
    """
    D23's "seam, not an API" statement, enforced.

    docs/reports/spike-consistency-proof.md probe 6 enumerated every public
    ImmudbClient method and found none that accepts a source or
    proveSinceTx argument. The capability this phase depends on exists only
    because verifiedGet.call() derives proveSinceTx from rs.get(), and rs is
    a caller-supplied object. That is private surface covered by no
    compatibility promise, so this asserts its shape rather than trusting
    it: if a future immudb-py computes proveSinceTx some other way, the
    verifier would silently anchor at the wrong transaction and every
    anchored bundle would be quietly meaningless. This is what makes that a
    failing test instead.
    """
    from immudb.client import ImmudbClient
    from immudb.handler import verifiedGet

    source = inspect.getsource(verifiedGet.call)
    assert "state = rs.get()" in source, (
        "verifiedGet.call() no longer reads its state from the injected "
        "RootService; the seam D23 depends on has moved"
    )
    assert "proveSinceTx=state.txId" in source, (
        "verifiedGet.call() no longer derives proveSinceTx from the injected "
        "state; the anchored export would anchor somewhere else"
    )

    exposed = []
    for name in dir(ImmudbClient):
        if name.startswith("_"):
            continue
        attr = getattr(ImmudbClient, name, None)
        if not callable(attr):
            continue
        try:
            params = inspect.signature(attr).parameters
        except (TypeError, ValueError):
            continue
        if {"proveSinceTx", "provenSinceTx", "sourceTx", "fromTx"} & set(params):
            exposed.append(name)
    assert exposed == [], (
        "an ImmudbClient method now takes a source transaction; the seam has "
        f"become an API and D23's maintenance note is out of date: {exposed}"
    )


@requires_stack
def test_a_dual_proof_is_rejected_when_the_source_is_newer_than_the_target():
    """
    P3b-1: "a test for the rejected direction".

    Proof direction is fixed by the ledger, not by the caller: the older
    transaction is always the source. This drives the SDK's own
    store.VerifyDualProof over a real captured proof with the two ends
    swapped, and it returns False - which is why the verifier refuses an
    anchor older than the record by name rather than letting the pair
    silently invert into a proof that says nothing about corroboration.
    """
    from immudb import schema
    from immudb.embedded import store
    from immudb.grpc import schema_pb2

    key, record_tx = _write_signed_record()
    _write_signed_record()  # advance the head so the anchor is strictly newer
    anchor = _anchor_from(_state())
    assert anchor["tx_id"] > record_tx

    material = _verify(key, anchor)["proof_material"]
    ventry = schema_pb2.VerifiableEntry()
    ventry.ParseFromString(base64.b64decode(material["verifiable_entry"]))
    dual = schema.DualProofFromProto(ventry.verifiableTx.dualProof)

    source_id = record_tx
    source_alh = dual.sourceTxHeader.Alh()
    target_id = anchor["tx_id"]
    target_alh = base64.b64decode(anchor["tx_hash"])

    assert store.VerifyDualProof(dual, source_id, target_id, source_alh, target_alh) is True
    assert store.VerifyDualProof(dual, target_id, source_id, target_alh, source_alh) is False, (
        "the SDK accepted a dual proof running from a newer transaction to an "
        "older one; the direction constraint P3b-1 relies on does not hold"
    )


# ---------------------------------------------------------------------------
# P3b-1: the export anchors at the checkpoint, not at whatever the verifier
# happened to hold.
# ---------------------------------------------------------------------------

@requires_stack
def test_the_state_endpoint_returns_a_state_immudb_actually_signed():
    """
    D23's checkpoint source. The verifier checks the signature against the
    key on its own volume before handing the state over - currentRoot's
    handler does not - so what an anchoring job submits is a state ImmuDB
    vouched for rather than one a server merely asserted.

    Verified here a second time, independently, against keys/signing.pub
    read from disk.
    """
    state = _state()
    verifying_key = ecdsa.VerifyingKey.from_pem(LIVE_KEY.read_text())

    from immudb.rootService import State

    reconstructed = State(
        db=state["db"],
        txId=int(state["tx_id"]),
        txHash=base64.b64decode(state["tx_hash"]),
        publicKey=b"",
        signature=base64.b64decode(state["signature"]),
    )
    reconstructed.Verify(verifying_key)
    assert state["signing_key_fingerprint"] == checker.key_fingerprint(verifying_key)


@requires_stack
def test_the_state_endpoint_requires_the_read_credential():
    """ADR-0011's gate, applied to the new route. An ungated /state would
    hand the ledger's current Merkle root to an unauthenticated caller for
    the same reason X5 found an ungated /verify handed out proof material."""
    resp = httpx.get(f"{VERIFIER_URL}/state", headers={"X-API-Key": "wrong"}, timeout=15)
    assert resp.status_code == 403, resp.text


@requires_stack
def test_the_proof_runs_to_the_supplied_anchor_and_not_the_verifiers_own_state():
    """
    P3b-1, the enforcing test and the mutation target.

    The mutation is: revert to anchoring at the verifier's held state. This
    test constructs the one situation that tells the two apart - a
    checkpoint strictly between the record and the verifier's current
    state - and asserts the exported material names the checkpoint.

    Phase 3a's export was anchored at whatever the verifier's volume
    happened to hold, which is meaningless to an external party: they have
    no way to learn what that state was, and nothing published it. Anchoring
    at a checkpoint that went into a public log is the whole point of D23,
    and it is invisible in a bundle unless prove_since_tx actually changes.
    """
    key, record_tx = _write_signed_record()
    _write_signed_record()
    checkpoint = _anchor_from(_state())

    # Move the verifier's own persisted state past the checkpoint, so
    # "the checkpoint" and "whatever the verifier holds" are different
    # numbers rather than coincidentally equal.
    for _ in range(2):
        later_key, _ = _write_signed_record()
    _verify(later_key)  # an unanchored read advances the persisted anchor
    held = _verify(later_key)["state_id"]
    assert held > checkpoint["tx_id"], (
        "the verifier's own state did not move past the checkpoint, so this "
        "test cannot tell the two anchors apart"
    )

    result = _verify(key, checkpoint)
    assert result["verified"] is True, result
    material = result["proof_material"]

    assert material["prove_since_tx"] == checkpoint["tx_id"], material
    assert material["source_state"]["tx_id"] == checkpoint["tx_id"], material
    assert material["source_state"]["tx_hash"] == checkpoint["tx_hash"], material
    assert material["prove_since_tx"] != held, (
        "the exported proof is anchored at the verifier's own held state, not "
        "at the checkpoint that was submitted for publication"
    )
    assert material["entry_tx_id"] == record_tx


@requires_stack
def test_a_record_at_the_anchor_itself_verifies_against_it():
    """
    P3b-1: "then the same for ... a record at the anchor itself".

    The boundary case: the checkpoint is taken immediately after the record,
    so the two transactions are the same. VerifyDualProof still has a pair
    to check because source and target are equal rather than inverted, and
    the export names that transaction on both sides.
    """
    key, record_tx = _write_signed_record()
    checkpoint = _anchor_from(_state())
    assert checkpoint["tx_id"] == record_tx

    material = _verify(key, checkpoint)["proof_material"]
    assert material["prove_since_tx"] == record_tx
    assert material["entry_tx_id"] == record_tx


@requires_stack
def test_an_anchor_older_than_the_record_is_refused_by_name():
    """
    P3b-1's rejected direction, at the endpoint rather than at the SDK.

    A checkpoint published before a record existed cannot corroborate it.
    The SDK would happily produce a proof in that direction - the pair
    simply inverts - so the refusal is this project's, made explicitly, and
    it names itself so the control plane can tell it apart from a record
    that failed to verify and fall back to an unanchored export.
    """
    old_checkpoint = _anchor_from(_state())
    key, record_tx = _write_signed_record()
    assert record_tx > old_checkpoint["tx_id"]

    result = _verify(key, old_checkpoint)
    assert result["verified"] is False
    assert result["error_class"] == "anchor_precedes_record", result
    assert result.get("proof_material") is None, (
        "material was exported for a refused request; there is no such thing "
        "as material proving a check that did not pass"
    )


@requires_stack
def test_an_anchor_immudb_never_signed_is_refused_before_any_proof_runs():
    """
    The anchor arrives from the caller, so it is checked rather than
    trusted - the same reasoning ADR-0010 gives for the offline checker
    running State.Verify on a bundle's anchor before using it. Without this,
    anyone holding the verifier's read credential could pin a proof to a
    state of their own invention.
    """
    key, _ = _write_signed_record()
    _write_signed_record()
    forged = _anchor_from(_state())
    raw = bytearray(base64.b64decode(forged["tx_hash"]))
    raw[0] ^= 0xFF
    forged["tx_hash"] = base64.b64encode(bytes(raw)).decode()

    result = _verify(key, forged)
    assert result["verified"] is False
    assert result["error_class"] == "anchor_signature_failure", result


@requires_stack
def test_verifying_against_an_anchor_does_not_move_the_verifiers_own_state():
    """
    Auditing an old record must not consume or advance the trust anchor
    every other proof is measured against. probe 7a established that the
    retained state is unchanged in this direction; _PinnedRootService makes
    that a property of the code rather than of the pair being lucky.
    """
    key, record_tx = _write_signed_record()
    _write_signed_record()
    checkpoint = _anchor_from(_state())
    later_key, _ = _write_signed_record()
    _verify(later_key)
    before = _verify(later_key)["state_id"]

    _verify(key, checkpoint)
    after = httpx.post(
        f"{VERIFIER_URL}/verify",
        json={"key": base64.b64encode(key).decode(), "anchor": checkpoint},
        headers={"X-API-Key": VERIFIER_READ_KEY}, timeout=30,
    ).json()
    assert after["state_id"] == before, (
        "an anchored verification moved the verifier's persisted state from "
        f"{before} to {after['state_id']}"
    )


# ---------------------------------------------------------------------------
# P3b-2, live: the decision service signs what it writes, and a record
# signed over the wrong bytes is refused end to end.
# ---------------------------------------------------------------------------

@requires_stack
def test_a_record_written_through_the_real_path_carries_a_verifiable_signature():
    """P3b-2, live. Written through the verifier by the same signing code
    ledger/immudb_ledger.py calls, exported through the real route, and
    checked by the real checker."""
    key, _ = _write_signed_record()
    bundle = _export(base64.b64encode(key).decode())

    result = checker.verify_bundle(
        bundle,
        checker.load_key(LIVE_KEY),
        checker.load_writer_keys([str(WRITER_DECISION_KEY.with_suffix(".pub"))]),
    )
    assert result["result_class"] == checker.VERIFIED
    assert result["writer_key_fingerprint"] == checker.key_fingerprint(
        ecdsa.VerifyingKey.from_pem(WRITER_DECISION_PUB.read_text())
    )


@requires_stack
def test_a_record_signed_over_different_bytes_is_refused_end_to_end():
    """
    P3b-2's named mutation, carried out for real rather than simulated: a
    record whose signature covers a different byte sequence than the one
    recorded.

    Everything else about it is correct - a real ECDSA signature by the real
    writer key, a well-formed fingerprint, the declared format - and it is
    committed to the real ledger, so every Phase 3a check passes on it. Only
    the D22 check catches it, which is what makes that check the thing
    holding the claim up.
    """
    signing_key, verifying_key = signer.load_signing_key(WRITER_DECISION_KEY)
    record = json.loads(_signed_record().decode())
    # Sign a different sequence: the same record with one field altered,
    # then record the untouched original alongside that signature.
    other = dict(record)
    other["outcome_type"] = "policy_deny"
    from ecdsa.util import sigencode_der
    record[signer.SIGNATURE_FIELD] = base64.b64encode(
        signing_key.sign_deterministic(
            signer.canonical_record_bytes(other),
            hashfunc=hashlib.sha256,
            sigencode=sigencode_der,
        )
    ).decode()
    del verifying_key

    key = _new_key()
    _write(key, json.dumps(record, separators=(",", ":")).encode())
    bundle = _export(base64.b64encode(key).decode())

    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        checker.verify_bundle(
            bundle,
            checker.load_key(LIVE_KEY),
            checker.load_writer_keys([str(WRITER_DECISION_PUB)]),
        )
    assert excinfo.value.result_class == checker.WRITER_SIGNATURE_FAILURE


@requires_stack
def test_an_unsigned_record_committed_to_the_ledger_is_refused_not_accepted():
    """
    P3b-2/P3b-3: "a record without a signature is rejected rather than
    treated as unsigned-and-fine", shown against a record that really is in
    the ledger and really does pass every ImmuDB proof.
    """
    key = _new_key()
    record = json.loads(_signed_record().decode())
    del record[signer.SIGNATURE_FIELD]
    del record[signer.FINGERPRINT_FIELD]
    _write(key, json.dumps(record, separators=(",", ":")).encode())
    bundle = _export(base64.b64encode(key).decode())

    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        checker.verify_bundle(
            bundle,
            checker.load_key(LIVE_KEY),
            checker.load_writer_keys([str(WRITER_DECISION_PUB)]),
        )
    assert excinfo.value.result_class == checker.WRITER_SIGNATURE_MISSING


@requires_stack
def test_the_decision_service_refuses_to_write_a_record_it_cannot_sign(monkeypatch):
    """
    D22's fail-closed half. Every dependency in this project fails closed by
    explicit rule; the single documented exception is external anchoring
    (D23), and the writer key is not that. A ledger client that quietly
    wrote unsigned records when its key went missing would fill the ledger
    with entries the checker refuses - unverifiable evidence, not weaker
    evidence.
    """
    sys.path.insert(0, str(REPO_ROOT / "ledger"))
    ledger_module = _load_module(
        "p3b_immudb_ledger", REPO_ROOT / "ledger" / "immudb_ledger.py"
    )
    monkeypatch.setattr(ledger_module, "_WRITER_SIGNING_KEY_PATH", "")
    monkeypatch.setattr(ledger_module, "_writer_keys", None)

    with pytest.raises(RuntimeError) as excinfo:
        ledger_module._sign({"record_type": "decision"})
    assert "AIL_WRITER_SIGNING_KEY" in str(excinfo.value)


# ---------------------------------------------------------------------------
# P3b-5: fail-open on the write path.
# ---------------------------------------------------------------------------

@requires_stack
def test_writes_continue_and_records_are_produced_with_anchoring_broken():
    """
    P3b-5, the enforcing test for the write path.

    External anchoring against this stack is not merely failing, it does not
    exist. That is asserted here from the compose file itself rather than
    assumed, the same way tests/test_host_port_bindings.py asserts port
    bindings from the YAML - otherwise a future edit could turn this into a
    test of nothing.

    **What is asserted changed shape in Phase 3c-3c, twice.**

    It used to be "anchor-service is absent from this file". P3c3c-4 puts
    the service in the file in `AIL_ANCHOR_MODE=reconcile-only`, because the
    sequence reconciliation lives in it and was covered by no test at all
    while it was absent. Absence by name was never the property that
    mattered; not anchoring is.

    The first replacement enumerated the three credentials an anchoring
    cycle needs and required each to be absent. **That was not equivalent to
    the absence check it replaced, and a review caught it.** A blacklist
    holds only if the enumeration is complete, and it cannot be: adding a
    fourth path to anchoring under a name the list does not carry leaves the
    test passing while anchoring is possible. Demonstrated rather than
    argued - adding `AIL_ANCHOR_SUBMISSION_TOKEN` to the service left this
    test green (`docs/reports/phase-3c3c-complete.md`).

    So it is a **whitelist**. The reconcile-only service may hold exactly
    the settings reconciliation needs and nothing else, and it may mount
    nothing but the directory it writes its verdict to. Any addition fails,
    whether or not anyone thought to name it, which is the property the
    absence check had and the blacklist did not.

    Writes succeed anyway, records are produced, and bundles export. That is
    D23's fail-open half, running on every CI job rather than staged once.
    """
    import yaml

    # Exactly what a reconcile-only pass reads. Not "the credentials we
    # thought of": anything outside this set has to be justified by editing
    # this list, which is the point.
    RECONCILE_ONLY_SETTINGS = {
        "AIL_ANCHOR_MODE",
        "IMMUDB_URL",
        "IMMUDB_USER",
        "IMMUDB_PASSWORD",
        "AIL_RESERVED_POSITIONS",
        "AIL_RECONCILE_INTERVAL_SECONDS",
        "AIL_RECONCILE_REPORT_PATH",
    }
    # And the one path it writes. A `./keys` mount would hand it signing
    # material without any environment variable naming a credential at all,
    # which is the second way a blacklist over `environment` misses.
    RECONCILE_ONLY_MOUNTS = {"./tests/.reconcile"}

    compose = yaml.safe_load(
        (REPO_ROOT / "docker-compose.test.yml").read_text(encoding="utf-8")
    )
    anchor = compose["services"].get("anchor-service")
    if anchor is not None:
        environment = anchor.get("environment") or []
        settings = dict(
            item.split("=", 1) for item in environment if "=" in item
        ) if isinstance(environment, list) else dict(environment)

        assert settings.get("AIL_ANCHOR_MODE") == "reconcile-only", (
            "anchor-service is in docker-compose.test.yml and is not in "
            "reconcile-only mode; this suite would then depend on a shared "
            "public transparency log and on CI having egress, and the "
            "fail-open demonstration would no longer be running against "
            f"genuinely broken anchoring. environment: {settings}"
        )
        unexpected = sorted(set(settings) - RECONCILE_ONLY_SETTINGS)
        assert not unexpected, (
            f"the reconcile-only anchor-service carries settings reconciliation "
            f"does not read: {unexpected}. This is a whitelist on purpose - a "
            "blacklist of the credentials an anchoring cycle needs holds only "
            "if the enumeration is complete, and a new path to anchoring under "
            "a name it does not carry would pass. If this setting is genuinely "
            "needed by reconciliation, add it to RECONCILE_ONLY_SETTINGS and "
            "say why; if it is needed by anchoring, it does not belong in this "
            "file at all."
        )
        mounts = {str(v).split(":", 1)[0] for v in (anchor.get("volumes") or [])}
        unexpected_mounts = sorted(mounts - RECONCILE_ONLY_MOUNTS)
        assert not unexpected_mounts, (
            f"the reconcile-only anchor-service mounts {unexpected_mounts}; a "
            "key mount would hand it signing material with no environment "
            "variable naming a credential at all"
        )

    key, tx = _write_signed_record()
    assert tx > 0
    bundle = _export(base64.b64encode(key).decode())
    assert bundle["record"]["tx_id"] == tx
    # And nothing anchored this record, whatever else is in the store: the
    # newest checkpoint (if any) necessarily precedes a record written after
    # it, which is the ordinary state of every record between cycles.
    latest = httpx.get(
        f"{CONTROL_PLANE_URL}/anchors/latest",
        headers={"X-API-Key": READ_API_KEY}, timeout=15,
    ).json()
    if latest["anchored"]:
        assert latest["checkpoint"]["tx_id"] < tx
    assert bundle["external_anchor"]["state"] == "not_anchored"


@requires_stack
def test_a_bundle_for_an_unanchored_record_says_so_rather_than_omitting_it():
    """
    P3b-5, the enforcing test for the claim. The fail-open write path does
    not leak into a claim of corroboration: the bundle states, in a field,
    that no checkpoint covering this record was published.
    """
    key, _ = _write_signed_record()
    bundle = _export(base64.b64encode(key).decode())

    assert "external_anchor" in bundle, (
        "the section was omitted; absence of corroboration must be stated, "
        "not inferred from a missing key"
    )
    assert bundle["external_anchor"]["state"] == "not_anchored"
    assert bundle["external_anchor"]["detail"]

    result = checker.verify_bundle(
        bundle,
        checker.load_key(LIVE_KEY),
        checker.load_writer_keys([str(WRITER_DECISION_PUB)]),
    )
    assert result["external_anchor"] == {"state": "not_anchored", "checked": False}


@requires_stack
def test_the_anchor_store_is_write_credentialled_and_the_latest_read_credentialled():
    """
    ADR-0007's split, applied to the two new routes. Neither is a new grant:
    the write key can already write an erasure tombstone the verifier treats
    as authentic, and the read key can already read every record /anchors
    would corroborate.
    """
    unauth = httpx.post(
        f"{CONTROL_PLANE_URL}/anchors", json={}, headers={"X-API-Key": READ_API_KEY}, timeout=15
    )
    assert unauth.status_code == 403, unauth.text

    unauth_read = httpx.get(
        f"{CONTROL_PLANE_URL}/anchors/latest",
        headers={"X-API-Key": "wrong"}, timeout=15,
    )
    assert unauth_read.status_code == 403, unauth_read.text


def test_the_anchor_loop_does_not_stop_on_a_failed_cycle(monkeypatch):
    """
    D23's fail-open rule, at the one place it is actually implemented: the
    loop. Needs no stack - what is under test is that an exception from a
    cycle is caught and the loop continues, which is the difference between
    a transient log outage costing one checkpoint and costing every
    checkpoint after it.

    The loop is broken out of with a sentinel raised from time.sleep, so the
    test observes exactly one caught failure and one continuation rather
    than waiting on an interval.
    """
    sys.path.insert(0, str(REPO_ROOT))
    anchor_main = _load_module("p3b_anchor_main", REPO_ROOT / "anchor_service" / "main.py")

    calls = {"n": 0}

    class _StopLoop(Exception):
        pass

    def _always_fails(*args, **kwargs):
        calls["n"] += 1
        raise RuntimeError("the transparency log is unreachable")

    def _sleep(seconds):
        if calls["n"] >= 2:
            raise _StopLoop()

    monkeypatch.setattr(anchor_main, "ANCHOR_SIGNING_KEY_PATH", str(WRITER_DECISION_KEY))
    monkeypatch.setattr(anchor_main, "anchor_once", _always_fails)
    monkeypatch.setattr(anchor_main.time, "sleep", _sleep)

    with pytest.raises(_StopLoop):
        anchor_main.run_forever()
    assert calls["n"] == 2, (
        "the loop stopped after its first failed cycle; one unreachable log "
        "would then cost every checkpoint after it, not just that one"
    )
