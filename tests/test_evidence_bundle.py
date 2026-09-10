"""
tests/test_evidence_bundle.py - P3a-1 and P3a-2 (Phase 3a, D18/D19).

P3a-1: the verifier exports the proof material it used to be able to compute
a boolean from and then throw away. What "every field the offline check
needs" means is not taken from the phase instruction: it is taken from
docs/reports/spike-offline-verify.md item 2, which enumerated exactly what
the spike's export script had to capture before offline verification would
succeed. That enumeration is transcribed into _SPIKE_REQUIRED_MATERIAL below
with the spike's own wording, and each row is checked separately.

P3a-2: a bundle can be exported for any record, through the same read
credential GET /audit already requires, for every record shape the ledger
holds.

Requires the docker-compose.test.yml stack (verifier, control plane, OPA,
ImmuDB, decision-service). tests/test_offline_verify.py is the half of this
phase that needs no stack at all.

Every `docker compose` invocation in this repository passes an explicit
-p project name; nothing in this file shells out to compose, it only talks
to the already-running services over HTTP.
"""

import asyncio
import base64
import importlib.util as _importlib_util
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

# tools/ail_verify_bundle.py kills outbound sockets for the whole process the
# moment it is imported - that is the D19 property, not a side effect to work
# around. This file is the live half of the phase and does need the network,
# so it holds the real connect() and restores it explicitly, and blocks again
# only around the offline checks it makes. Both directions are explicit here
# rather than left to whichever test module pytest happened to import first.
_REAL_SOCKET_CONNECT = socket.socket.connect

CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL", "http://localhost:8002")
VERIFIER_URL = os.getenv("VERIFIER_URL", "http://localhost:8003")
READ_API_KEY = os.getenv("CONTROL_PLANE_READ_KEY", "test-read-key")
WRITE_API_KEY = os.getenv("CONTROL_PLANE_WRITE_KEY", "test-write-key")
# D21 (Phase 3a completion): the verifier's own credential pair, independent
# of CONTROL_PLANE_READ_KEY/WRITE_KEY above - see
# docs/adr/0011-verifier-authentication.md. This file's own live helpers
# (_write, _verify) call the verifier directly and need these; _export below
# goes through the control plane, which holds these itself and needs none of
# this file's own credentials.
VERIFIER_READ_KEY = os.getenv("VERIFIER_READ_KEY", "test-verifier-read-key")
VERIFIER_WRITE_KEY = os.getenv("VERIFIER_WRITE_KEY", "test-verifier-write-key")

os.environ.setdefault("SPIRE_DISABLED", "true")

# decision_service/main.py, ledger/immudb_ledger.py and ledger/content_store.py
# each read their upstream URL from the environment at import time, defaulting
# to the compose service names (http://opa:8181, http://verifier:8003,
# http://ail-control-plane:8002). Those names resolve inside the compose
# network and nowhere else, and this file loads the decision service in-process
# on the host, so every one of them has to be pointed at the published
# loopback port instead. Setting only OPA_URL leaves the other two resolving
# to nothing, which surfaces as a fault record with fault_class
# content_store_unreachable or verifier_unreachable rather than the decision
# the test asked for: a real fail-closed response to a real outage, just not
# the outage under test. setdefault, so an operator running against a stack
# published elsewhere can still override from the shell.
os.environ.setdefault("OPA_URL", "http://localhost:8181/v1/data/ail/main/evaluation")
os.environ.setdefault("VERIFIER_URL", VERIFIER_URL)
os.environ.setdefault("CONTROL_PLANE_URL", CONTROL_PLANE_URL)
os.environ.setdefault("CONTROL_PLANE_WRITE_KEY", WRITE_API_KEY)
# D22 (Phase 3b): ledger/immudb_ledger.py refuses to write a record it
# cannot sign, so the in-process decision service loaded below needs a host
# path to the same key the decision-service container mounts at /keys.
os.environ.setdefault(
    "AIL_WRITER_SIGNING_KEY", str(REPO_ROOT / "keys" / "writer-decision.key")
)

sys.path.insert(0, str(REPO_ROOT / "decision_service"))
sys.path.insert(0, str(REPO_ROOT / "ledger"))
sys.path.insert(0, str(REPO_ROOT))


def _load_module(name: str, path: Path):
    """Explicit module names, for the reason tests/test_content_states.py
    documents: decision_service/main.py and control_plane/main.py are both
    called main.py, and a bare import clobbers whichever one another test
    file in this session loaded first."""
    spec = _importlib_util.spec_from_file_location(name, path)
    module = _importlib_util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


from provenance import record_signature as signer  # noqa: E402

decision_main = _load_module("decision_service_main", REPO_ROOT / "decision_service" / "main.py")
checker = _load_module("ail_verify_bundle", REPO_ROOT / "tools" / "ail_verify_bundle.py")
socket.socket.connect = _REAL_SOCKET_CONNECT  # see the note at the top of this file

FIXTURE_KEY = REPO_ROOT / "tests" / "fixtures" / "evidence_bundles" / "signing.pub"
LIVE_KEY = REPO_ROOT / "keys" / "signing.pub"
# D22 (Phase 3b): the two writer keys this stack's own services sign with.
# The live keys, not the fixture copies - these tests check bundles this
# stack just produced, not the committed ones.
WRITER_DECISION_PUB = REPO_ROOT / "keys" / "writer-decision.pub"
WRITER_CONTROL_PLANE_PUB = REPO_ROOT / "keys" / "writer-control-plane.pub"

_APPROVED_ARGS = {
    "instance_type": "t3.micro",
    "region": "us-east-1",
    "cost_per_hour": 5.0,
    "tags": {
        "environment": "dev",
        "data_classification": "internal",
        "cost_center": "engineering",
        "project": "webapp",
    },
}
_DENIED_ARGS = {**_APPROVED_ARGS, "instance_type": "p4d.24xlarge", "cost_per_hour": 50.0}


requires_stack = pytest.mark.needs_stack("verifier", "control_plane")
requires_decisions = pytest.mark.needs_stack("verifier", "control_plane", "opa")


@pytest.fixture(autouse=True)
def _network_available():
    """Restore real sockets before every test in this file.

    tests/test_offline_verify.py blocks them process-wide, and pytest
    imports both modules before running either, so without this the live
    tests here would fail or skip depending on collection order rather than
    on whether the stack is actually up.
    """
    saved = socket.socket.connect
    socket.socket.connect = _REAL_SOCKET_CONNECT
    try:
        yield
    finally:
        socket.socket.connect = saved


def _check_offline(bundle: dict, key_path=None):
    """Run the standalone checker with sockets dead, then hand them back.

    The block is installed here, inside this file's own live run, so the
    offline assertions below are genuinely offline even though everything
    around them is not.

    D22/D23 (Phase 3b): the checker now also needs the writer keys, because
    a record it cannot attribute is refused rather than reported as
    verified. The anchor half is deliberately NOT exercised here - this
    stack has no anchor-service, so every bundle it exports is
    not_anchored, and that path is covered by tests/test_external_anchor.py
    against a real committed log entry.
    """
    saved = socket.socket.connect
    checker.block_network()
    try:
        return checker.verify_bundle(
            bundle,
            checker.load_key(key_path or LIVE_KEY),
            checker.load_writer_keys([str(WRITER_DECISION_PUB), str(WRITER_CONTROL_PLANE_PUB)]),
        )
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
    return resp.json()


def _verify(key: bytes) -> dict:
    resp = httpx.post(
        f"{VERIFIER_URL}/verify",
        json={"key": base64.b64encode(key).decode()},
        headers={"X-API-Key": VERIFIER_READ_KEY},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def _decide(tool_name, tool_args, agent_id):
    req = decision_main.DecideRequest(
        tool_name=tool_name, tool_args=tool_args, agent_id=agent_id
    )
    return asyncio.run(decision_main.decide(req))


def _audit_entries():
    resp = httpx.get(
        f"{CONTROL_PLANE_URL}/audit",
        params={"limit": 200},
        headers={"X-API-Key": READ_API_KEY},
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()["entries"]


def _export(ledger_key_b64: str, api_key=READ_API_KEY):
    headers = {"X-API-Key": api_key} if api_key is not None else {}
    return httpx.get(
        f"{CONTROL_PLANE_URL}/audit/bundle",
        params={"key": ledger_key_b64},
        headers=headers,
        timeout=60,
    )


def _fresh_record() -> bytes:
    """One real ledger entry written through the verifier, plus a second
    write after it so the trust anchor sits ahead of the entry being proven.

    The second write is not decoration. verifiedGet.call() branches on
    state.txId <= vTx; with the anchor at the same transaction as the entry,
    the dual proof is trivial and the material would not exercise the case
    an auditor actually meets (reading a record from behind the current
    anchor). The spike made the same choice for the same reason.

    The written value carries outcome_type: policy_allow, one of the closed
    set docs/adr/0005-outcome-taxonomy.md defines, so the label the checker
    derives from the proven bytes is a real record type rather than
    "unknown". A synthetic shape here would let the record_type comparison
    in tools/ail_verify_bundle.py pass without ever exercising the
    derivation it exists to perform.

    D22 (Phase 3b): the value is signed with the decision service's own
    writer key, through provenance/record_signature.py - the same call
    ledger/immudb_ledger.py makes - rather than written raw. The offline
    check below refuses a record it cannot attribute, so a raw value here
    would fail on its writer signature and never reach the D18 material
    assertions this helper exists to feed.
    """
    key = f"p3b_material_test:{uuid.uuid4().hex}".encode()
    signing_key, verifying_key = signer.load_signing_key(
        REPO_ROOT / "keys" / "writer-decision.key"
    )
    value = json.dumps(
        signer.sign_record(
            {"outcome_type": "policy_allow", "note": "p3b proof material"},
            signing_key,
            verifying_key,
        ),
        separators=(",", ":"),
    ).encode()
    result = _write(key, value)
    assert result["verified"], result
    _write(f"p3b_material_test:{uuid.uuid4().hex}".encode(), b'{"note":"advances the anchor"}')
    return key


# ---------------------------------------------------------------------------
# P3a-1. The verifier exports proof material.
#
# The list below is transcribed from docs/reports/spike-offline-verify.md
# item 2, "What a checker needs, enumerated from what the export script
# actually had to capture to make offline verification succeed". Each entry
# is (spike's own description, where it must appear in the /verify response).
# ---------------------------------------------------------------------------

_SPIKE_REQUIRED_MATERIAL = [
    (
        "the prior trust anchor: a rootService.State with db, txId, txHash",
        ("proof_material", "source_state"),
    ),
    (
        "the raw VerifiableEntry response, serialized with SerializeToString()",
        ("proof_material", "verifiable_entry"),
    ),
    (
        "the raw key bytes being looked up, so the checker knows what it is checking",
        ("value",),  # the key is the caller's own input; the value is what came back
    ),
]

# Spike item 2.3, the ECDSA public key, is deliberately NOT in this list.
# The spike's item 4[d] found state.publicKey is never read during
# verification, so the key is configuration the checker holds separately -
# the response names it by fingerprint instead. See ADR-0010.


def _dig(mapping, path):
    node = mapping
    for step in path:
        assert isinstance(node, dict), f"expected a mapping at {path}, got {type(node).__name__}"
        assert step in node and node[step] is not None, f"missing {'.'.join(path)}"
        node = node[step]
    return node


@requires_stack
@pytest.mark.parametrize(
    "description,path",
    _SPIKE_REQUIRED_MATERIAL,
    ids=[p[-1] for _, p in _SPIKE_REQUIRED_MATERIAL],
)
def test_verify_response_carries_each_item_the_spike_enumerated(description, path):
    """P3a-1: one row per item the spike had to capture, checked on its own
    so a partial regression names the field it dropped."""
    key = _fresh_record()
    response = _verify(key)
    assert response["verified"] is True, response
    _dig(response, path)


@requires_stack
def test_proof_material_source_state_carries_the_anchor_fields_the_sdk_reads():
    """
    P3a-1: immudb-py's verifiedGet.call() reads exactly state.db,
    state.txId and state.txHash off the anchor. All three must be present,
    or the anchor cannot be reconstructed at all.
    """
    key = _fresh_record()
    src = _verify(key)["proof_material"]["source_state"]
    for field in ("db", "tx_id", "tx_hash"):
        assert field in src and src[field] is not None, f"source_state is missing {field}"
    assert isinstance(src["tx_id"], int) and src["tx_id"] > 0
    assert len(base64.b64decode(src["tx_hash"])) == 32, "txHash must be a 32-byte digest"


@requires_stack
def test_proof_material_identifies_the_transaction_and_the_request():
    """P3a-1: without prove_since_tx and the entry's own transaction id, the
    request verifiedGet.call() made cannot be reconstructed."""
    key = _fresh_record()
    material = _verify(key)["proof_material"]
    assert material["prove_since_tx"] == material["source_state"]["tx_id"]
    assert isinstance(material["entry_tx_id"], int) and material["entry_tx_id"] > 0
    # Bumped to /2 by D23 (Phase 3b): source_state was reinterpreted, from
    # "whatever this verifier held" to "the checkpoint the proof runs to".
    assert material["format"] == "ail-proof-material/2"
    assert material["sdk"] == "immudb-py==1.5.0"


@requires_stack
def test_proof_material_names_the_signing_key_and_does_not_carry_it():
    """
    P3a-1 and D18, the negative half. The material names the key by
    fingerprint; it must not contain the key.

    Checked against the actual bytes of the response, not against the shape
    of the model, so a key smuggled inside any field would be caught.
    """
    key = _fresh_record()
    response = _verify(key)
    material = response["proof_material"]

    fingerprint = material["signing_key_fingerprint"]
    assert fingerprint and fingerprint.startswith("sha256:"), fingerprint

    vk = ecdsa.VerifyingKey.from_pem(LIVE_KEY.read_text())
    assert fingerprint == checker.key_fingerprint(vk), (
        "the verifier and the offline checker must derive the same fingerprint "
        "from the same key, or a genuine bundle would be refused as key_mismatch"
    )

    blob = json.dumps(response).encode()
    assert b"BEGIN PUBLIC KEY" not in blob
    assert base64.b64encode(vk.to_der()) not in blob
    assert base64.b64encode(vk.to_string()) not in blob
    assert "public_key" not in material["source_state"]
    assert "publicKey" not in material["source_state"]


@requires_stack
def test_exported_material_actually_completes_an_offline_check():
    """
    P3a-1's real criterion: "every field the offline check needs" is only
    meaningful if the offline check completes on the exported fields alone.

    Assembles a bundle from nothing but this /verify response, and runs the
    standalone checker over it with the network blocked. A field the
    verifier quietly stopped exporting would fail here even if every
    presence assertion above still passed.
    """
    key = _fresh_record()
    response = _verify(key)
    material = response["proof_material"]

    bundle = {
        # Bumped by D22/D23 (Phase 3b) - see control_plane/main.py's
        # EVIDENCE_BUNDLE_FORMAT for why a reinterpreted field bumps it.
        "bundle_format": "ail-evidence-bundle/2",
        "exported_at": "assembled-in-test",
        "exported_by": "tests/test_evidence_bundle.py",
        "record": {
            "ledger_key": base64.b64encode(key).decode(),
            "value": response["value"],
            "tx_id": response["tx_id"],
            "timestamp": response["timestamp"],
            # The label _fresh_record's value actually supports, written out
            # literally rather than derived here. Deriving it with the
            # checker's own record_type_of would compare that function to
            # itself and prove nothing.
            "record_type": "policy_allow",
        },
        "proof": material,
        "signing_key": {"fingerprint": material["signing_key_fingerprint"]},
        # D23: stated, never omitted. This stack runs without anchor-service
        # (docker-compose.test.yml), so the honest value here is the same
        # one GET /audit/bundle would produce for this record.
        "external_anchor": {
            "state": "not_anchored",
            "detail": "assembled in a test from /verify's own material; no checkpoint was anchored",
        },
    }

    result = _check_offline(bundle)
    assert result["result_class"] == checker.VERIFIED
    assert result["tx_id"] == response["tx_id"]


@requires_stack
def test_no_proof_material_is_exported_for_a_record_that_did_not_verify():
    """
    D18: material is the input to a check that passed. A key that was never
    written produces not_found and no material - there is nothing to
    reproduce, and shipping the inputs of a failed lookup would invite
    treating them as evidence.
    """
    response = _verify(f"p3a_never_written:{uuid.uuid4().hex}".encode())
    assert response["verified"] is False
    assert response["error_class"] == "not_found"
    assert response.get("proof_material") is None


# ---------------------------------------------------------------------------
# P3a-2. A bundle can be exported for any record.
# ---------------------------------------------------------------------------

def _ledger_key_for_tx(tx_id: int) -> str:
    for entry in _audit_entries():
        if entry["tx_id"] == tx_id:
            assert entry.get("ledger_key"), (
                "/audit must report ledger_key, or a reader has no way to name "
                "the record they just read to GET /audit/bundle"
            )
            return entry["ledger_key"]
    raise AssertionError(f"tx {tx_id} not present in /audit")


@requires_decisions
def test_bundle_exported_for_a_policy_allow():
    agent_id = f"p3a_allow_{uuid.uuid4().hex[:8]}"
    decision = _decide("provision_cloud_server", _APPROVED_ARGS, agent_id)
    assert decision["outcome_type"] == "policy_allow", decision

    resp = _export(_ledger_key_for_tx(decision["ledger_tx_id"]))
    assert resp.status_code == 200, resp.text
    bundle = resp.json()
    assert bundle["record"]["record_type"] == "policy_allow"
    _assert_bundle_verifies_offline(bundle)


@requires_decisions
def test_bundle_exported_for_a_policy_deny():
    agent_id = f"p3a_deny_{uuid.uuid4().hex[:8]}"
    decision = _decide("provision_cloud_server", _DENIED_ARGS, agent_id)
    assert decision["outcome_type"] == "policy_deny", decision

    resp = _export(_ledger_key_for_tx(decision["ledger_tx_id"]))
    assert resp.status_code == 200, resp.text
    bundle = resp.json()
    assert bundle["record"]["record_type"] == "policy_deny"
    _assert_bundle_verifies_offline(bundle)


@requires_decisions
def test_bundle_exported_for_a_fault(monkeypatch):
    """A fault is a record like any other (D1) - it must be exportable as
    evidence too, or the one outcome type describing infrastructure failure
    would be the one nobody could prove."""
    agent_id = f"p3a_fault_{uuid.uuid4().hex[:8]}"
    monkeypatch.setattr(
        decision_main, "_OPA_URL", "http://localhost:1/v1/data/ail/main/evaluation"
    )
    decision = _decide("provision_cloud_server", _APPROVED_ARGS, agent_id)
    assert decision["outcome_type"] == "fault", decision
    assert decision["fault_class"] == "opa_unreachable"

    resp = _export(_ledger_key_for_tx(decision["ledger_tx_id"]))
    assert resp.status_code == 200, resp.text
    bundle = resp.json()
    assert bundle["record"]["record_type"] == "fault"
    _assert_bundle_verifies_offline(bundle)


@requires_stack
def test_bundle_exported_for_a_content_erasure_tombstone():
    """
    D11's tombstone is the record that proves an erasure happened. Exporting
    it is the case that matters most for a GDPR Article 17 audit: the
    payload is gone by design, so the tombstone is the only remaining
    evidence, and it must travel.
    """
    call_id = f"p3a-erasure-{uuid.uuid4().hex}"
    httpx.post(
        f"{CONTROL_PLANE_URL}/content",
        json={"call_id": call_id, "payload": {"note": "to be erased"}},
        headers={"X-API-Key": WRITE_API_KEY},
        timeout=30,
    ).raise_for_status()
    httpx.delete(
        f"{CONTROL_PLANE_URL}/content/{call_id}",
        headers={"X-API-Key": WRITE_API_KEY},
        timeout=30,
    ).raise_for_status()

    tombstone_key = base64.b64encode(f"content_erasure:{call_id}".encode()).decode()
    resp = _export(tombstone_key)
    assert resp.status_code == 200, resp.text
    bundle = resp.json()
    assert bundle["record"]["record_type"] == "content_erasure"

    record = json.loads(base64.b64decode(bundle["record"]["value"]))
    assert record["record_type"] == "content_erasure"
    assert record["call_id"] == call_id
    _assert_bundle_verifies_offline(bundle)


def _assert_bundle_verifies_offline(bundle: dict):
    """Every exported bundle must be checkable by the standalone tool with
    the network blocked. An export that produced something the checker
    cannot read would be a file, not evidence."""
    result = _check_offline(bundle)
    assert result["result_class"] == checker.VERIFIED
    assert result["tx_id"] == bundle["record"]["tx_id"]


# ---------------------------------------------------------------------------
# P3a-2, authorization. Same credential as GET /audit, not more permissive.
# ---------------------------------------------------------------------------

@requires_stack
def test_bundle_export_requires_the_read_credential():
    """
    P3a-2's enforcing test and the target of its mutation.

    Three refusals and one acceptance, so "gated" is not satisfied by a
    route that merely rejects nonsense. 422 for the missing header is
    FastAPI rejecting a required Header(...) before the dependency body
    runs - functionally a rejection, the same shape
    tests/test_dashboard_auth.py already accepts for the other read-gated
    routes (phase-1-1-redteam T3).
    """
    key = base64.b64encode(_fresh_record()).decode()

    no_key = _export(key, api_key=None)
    assert no_key.status_code == 422, f"expected 422 with no header, got {no_key.status_code}"

    wrong_key = _export(key, api_key="definitely-not-the-real-key")
    assert wrong_key.status_code == 403, f"expected 403 with a wrong key, got {wrong_key.status_code}"

    accepted = _export(key, api_key=READ_API_KEY)
    assert accepted.status_code == 200, f"expected 200 with the read key, got {accepted.text}"


@requires_stack
def test_bundle_export_is_not_reachable_with_the_write_credential_alone():
    """
    ADR-0007's two keys are independent secrets, not a hierarchy. Export is
    a read, so the write key must not open it - otherwise this route would
    quietly be the one place holding either credential is enough.
    """
    key = base64.b64encode(_fresh_record()).decode()
    resp = _export(key, api_key=WRITE_API_KEY)
    assert resp.status_code == 403, (
        f"the write key must not authorize a read-scoped export, got {resp.status_code}"
    )


@requires_stack
def test_bundle_export_gate_is_the_same_dependency_as_the_audit_read():
    """
    P3a-2 says "the same authorization as the audit read, not more
    permissively". Checked structurally as well as behaviourally: both
    routes must depend on the same function object, so a future change to
    one credential cannot leave the other behind.
    """
    # control_plane/main.py does `from bundle import generate_bundle`, which
    # needs its own directory on sys.path - loading a file by path does not
    # add it. tests/test_verification.py imports the same module the same
    # way, for the same reason.
    sys.path.insert(0, str(REPO_ROOT / "control_plane"))
    control_plane = _load_module("control_plane_main", REPO_ROOT / "control_plane" / "main.py")

    def _dependency_names(route_path):
        route = next(
            r for r in control_plane.app.routes
            if getattr(r, "path", None) == route_path
        )
        return {d.call for d in route.dependant.dependencies}

    audit_deps = _dependency_names("/audit")
    bundle_deps = _dependency_names("/audit/bundle")

    assert control_plane._require_read_key in audit_deps
    assert control_plane._require_read_key in bundle_deps, (
        "/audit/bundle must be gated by the same _require_read_key dependency "
        "GET /audit uses, not a separate or weaker check"
    )
    assert control_plane._require_write_key not in bundle_deps


@requires_stack
def test_no_bundle_is_exported_for_a_key_that_was_never_written():
    """A bundle asserts a record exists and verified. There is no honest
    bundle for a key with no record behind it."""
    missing = base64.b64encode(f"p3a_never_written:{uuid.uuid4().hex}".encode()).decode()
    resp = _export(missing)
    assert resp.status_code == 404, f"expected 404, got {resp.status_code}: {resp.text}"
    assert "not_found" in resp.text


@requires_stack
def test_exported_bundle_contains_no_key_material():
    """Pre-registered negative 3, checked on a freshly exported bundle
    rather than only on the committed fixtures."""
    key = base64.b64encode(_fresh_record()).decode()
    resp = _export(key)
    assert resp.status_code == 200, resp.text

    raw = resp.content
    vk = ecdsa.VerifyingKey.from_pem(LIVE_KEY.read_text())
    assert b"BEGIN PUBLIC KEY" not in raw
    assert base64.b64encode(vk.to_der()) not in raw
    assert base64.b64encode(vk.to_string()) not in raw
    assert resp.json()["signing_key"]["fingerprint"] == checker.key_fingerprint(vk)
