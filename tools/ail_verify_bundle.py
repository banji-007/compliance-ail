#!/usr/bin/env python3
"""
ail_verify_bundle.py - check an AIL evidence bundle offline.

    python tools/ail_verify_bundle.py BUNDLE.json --key signing.pub

No Docker, no ImmuDB, no control plane, no network. Two local files go in:
the bundle, and the ECDSA public key you already trust. An exit code and a
named result come out.

D19/D20, Phase 3a. docs/adr/0010-portable-evidence-bundles.md.

Zero cryptography is implemented here
-------------------------------------
Every check runs inside immudb-py's own verification code, imported from the
installed package and called unmodified:

  store.EntrySpecDigestFor  - recomputes the (key, value, metadata) leaf digest
  store.VerifyInclusion     - walks the Merkle path from that leaf to the tx's eH
  store.VerifyDualProof     - verifies the linear-hash chain anchor -> target tx
  rootService.State.Verify  - checks the server's ECDSA signature over the state

all reached through immudb.handler.verifiedGet.call(), the exact function
ImmudbClient.verifiedGet() calls. This file computes no digest, walks no
proof, and checks no signature of its own. ADR-0001 records a hand-rolled
Alh() in this project that got the field order wrong and substituted eH for
innerHash; not repeating that is the point of doing it this way.

The one hash this file computes is hashlib.sha256 over a public key's DER
encoding, to compare a fingerprint. That is an identifier, not a
verification step, and no proof result depends on it.

No network, by construction
---------------------------
socket.socket.connect is replaced with a raiser as soon as imports finish, so
a hidden fetch anywhere below raises NetworkAccessAttempted instead of
quietly succeeding. It is patched after imports rather than before because
ssl.py (pulled in transitively by grpc) subclasses socket.socket at import
time and a non-class replacement breaks that subclassing - the same ordering
constraint docs/reports/spike-offline-verify.md hit and documented.

The key is never read from the bundle
-------------------------------------
A bundle names the key it expects by fingerprint; you supply the key. The
spike found that immudb-py never reads State.publicKey during verification,
so a bundle carrying its own key would certify itself. If --key names a key
whose fingerprint is not the one the bundle expects, this refuses to check
at all (key_mismatch) - a distinct outcome from a bundle that was checked
and failed.
"""

import argparse
import base64
import binascii
import json
import socket
import sys
from pathlib import Path

# --- SDK imports. Pure computation; none of these open a connection. ------
import ecdsa                                          # noqa: E402
from ecdsa.keys import BadSignatureError              # noqa: E402
from google.protobuf.message import DecodeError       # noqa: E402
from immudb.exceptions import ErrCorruptedData        # noqa: E402
from immudb.grpc import schema_pb2                    # noqa: E402
from immudb.handler import verifiedGet                # noqa: E402
from immudb.rootService import State                  # noqa: E402


class NetworkAccessAttempted(RuntimeError):
    """Raised if anything in this process tries to open a connection."""


def _blocked_connect(self, *args, **kwargs):
    raise NetworkAccessAttempted(
        "ail_verify_bundle.py attempted a live socket connection; offline "
        "verification must not touch the network"
    )


def block_network() -> None:
    """Make 'no network' a property of this process, not an assumption.

    Exposed as a function so tests can install the same block in their own
    process and prove the checker never needed it lifted.
    """
    socket.socket.connect = _blocked_connect


block_network()


# --- Formats this checker understands -------------------------------------

BUNDLE_FORMAT = "ail-evidence-bundle/1"
PROOF_MATERIAL_FORMAT = "ail-proof-material/1"


# --- The closed set of outcomes -------------------------------------------
#
# The first three line up exactly with what the live verifier already
# reports (verifier/main.py's error_class, docs/adr/0006-verification-
# states.md): a proof rejection and a signature rejection are never
# collapsed into each other, and a pass is a pass.
#
# The last three name failures that can only exist because a bundle is a
# file that travelled - there is no bundle in the live read path, so the
# live verifier has no equivalent. They are additions to the vocabulary,
# never substitutes: nothing that used to report consistency_failure now
# reports one of these.

VERIFIED            = "verified"
CONSISTENCY_FAILURE = "consistency_failure"   # ErrCorruptedData: a proof was rejected
SIGNATURE_FAILURE   = "signature_failure"     # BadSignatureError: an ECDSA signature was rejected
RECORD_MISMATCH     = "record_mismatch"       # the bundle's own copy of the record is not the record proven
KEY_MISMATCH        = "key_mismatch"          # the supplied key is not the key the bundle expects
MALFORMED_BUNDLE    = "malformed_bundle"      # the file is not a bundle this checker can read

RESULT_CLASSES = frozenset({
    VERIFIED,
    CONSISTENCY_FAILURE,
    SIGNATURE_FAILURE,
    RECORD_MISMATCH,
    KEY_MISMATCH,
    MALFORMED_BUNDLE,
})


class BundleCheckFailed(Exception):
    """A bundle did not verify. `result_class` names which check failed."""

    def __init__(self, result_class: str, detail: str):
        assert result_class in RESULT_CLASSES, f"unknown result class {result_class!r}"
        self.result_class = result_class
        self.detail = detail
        super().__init__(f"{result_class}: {detail}")


# --- The SDK shims --------------------------------------------------------
#
# immudb.handler.verifiedGet.call() takes a gRPC stub and a RootService only
# to (a) make one RPC and (b) read and then replace the trust anchor.
# Everything between those is pure computation over the response. These two
# objects supply the pre-captured answers, so the SDK's real verification
# code runs against material from a file instead of a server.
#
# verifier/main.py holds its own copy of the stub shim. Deliberately not
# shared: this file has to stay runnable with nothing installed but
# immudb-py, and importing from the verifier service would tie an auditor's
# offline check to this project's Docker image.

class _BundleStub:
    """Stands in for the gRPC ImmuServiceStub. Returns the bundle's captured
    VerifiableEntry instead of making an RPC."""

    def __init__(self, ventry):
        self._ventry = ventry

    def VerifiableGet(self, req):
        return self._ventry


class _BundleRootService:
    """Stands in for immudb.rootService.RootService. get() hands back the
    bundle's trust anchor; set() records the anchor the SDK derived rather
    than persisting it (nothing to persist when checking a file)."""

    def __init__(self, state):
        self._state = state
        self.new_state = None

    def get(self):
        return self._state

    def set(self, new_state):
        self.new_state = new_state


# --- Loading --------------------------------------------------------------

def key_fingerprint(verifying_key: "ecdsa.VerifyingKey") -> str:
    """SHA-256 over the key's DER SubjectPublicKeyInfo encoding.

    Over the DER rather than the PEM text so the fingerprint survives the
    line-ending and whitespace differences a PEM file picks up crossing
    operating systems, which a bundle is expected to do. Matches
    verifier/main.py::signing_key_fingerprint exactly; the round-trip is
    asserted in tests/test_evidence_bundle.py rather than assumed.
    """
    import hashlib
    return "sha256:" + hashlib.sha256(verifying_key.to_der()).hexdigest()


def load_key(key_path) -> "ecdsa.VerifyingKey":
    """Load the trusted ECDSA public key from a PEM file on disk.

    This is the only place a key enters the process, and its path comes from
    the command line, never from the bundle.
    """
    try:
        return ecdsa.VerifyingKey.from_pem(Path(key_path).read_text())
    except Exception as exc:
        raise BundleCheckFailed(
            MALFORMED_BUNDLE,
            f"could not load a PEM ECDSA public key from {key_path}: {exc}",
        )


def record_type_of(raw_value: bytes) -> str:
    """Name the shape of a proven record, from its own fields.

    Deliberately a copy of control_plane/main.py::_record_type_of rather
    than an import: this tool has to run with nothing but immudb-py
    installed, and an auditor checking a bundle from a system they do not
    operate cannot be asked to obtain that system's source. The two are
    held in agreement by tests/test_offline_verify.py, which checks a
    control-plane-exported fixture's label against this function's answer.

    Discriminates on fields inside the record, never on the key prefix, and
    returns "unknown" for anything it does not recognise so a foreign
    record cannot be described as an outcome type it never claimed.
    """
    try:
        value = json.loads(raw_value.decode())
    except Exception:
        return "unknown"
    if not isinstance(value, dict):
        return "unknown"
    record_type = value.get("record_type")
    if record_type in ("content_erasure", "decision_intent"):
        return record_type
    outcome_type = value.get("outcome_type")
    if outcome_type in ("policy_allow", "policy_deny", "schema_deny", "fault"):
        return outcome_type
    return "unknown"


def _require(mapping, field, where):
    if not isinstance(mapping, dict) or field not in mapping:
        raise BundleCheckFailed(
            MALFORMED_BUNDLE, f"bundle is missing required field {where}.{field}"
        )
    return mapping[field]


def _b64(value, where):
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, TypeError, ValueError) as exc:
        raise BundleCheckFailed(MALFORMED_BUNDLE, f"{where} is not valid base64: {exc}")


def load_bundle(bundle_path) -> dict:
    try:
        raw = Path(bundle_path).read_text(encoding="utf-8")
    except OSError as exc:
        raise BundleCheckFailed(MALFORMED_BUNDLE, f"could not read {bundle_path}: {exc}")
    try:
        bundle = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BundleCheckFailed(MALFORMED_BUNDLE, f"{bundle_path} is not valid JSON: {exc}")
    if not isinstance(bundle, dict):
        raise BundleCheckFailed(MALFORMED_BUNDLE, "bundle must be a JSON object")

    declared = bundle.get("bundle_format")
    if declared != BUNDLE_FORMAT:
        raise BundleCheckFailed(
            MALFORMED_BUNDLE,
            f"unsupported bundle_format {declared!r}; this checker reads {BUNDLE_FORMAT!r}",
        )
    proof_format = bundle.get("proof", {}).get("format") if isinstance(bundle.get("proof"), dict) else None
    if proof_format != PROOF_MATERIAL_FORMAT:
        raise BundleCheckFailed(
            MALFORMED_BUNDLE,
            f"unsupported proof.format {proof_format!r}; this checker reads {PROOF_MATERIAL_FORMAT!r}",
        )
    return bundle


# --- The check ------------------------------------------------------------

def verify_bundle(bundle: dict, verifying_key: "ecdsa.VerifyingKey") -> dict:
    """
    Check one bundle against one independently supplied key.

    Returns a dict on success. Raises BundleCheckFailed, carrying the
    result_class that names which check failed, on every failure. It never
    raises a bare exception for a tamper case - which check rejected the
    bundle is the whole answer, so "something went wrong" would not be one.
    """
    record = _require(bundle, "record", "bundle")
    proof = _require(bundle, "proof", "bundle")

    # 1. Key identity. Refused before any proof runs: checking a bundle
    #    against a key it never claimed produces a signature failure that
    #    looks exactly like tampering, and those are different situations
    #    for whoever has to act on the result.
    expected_fp = _require(bundle, "signing_key", "bundle").get("fingerprint")
    if not expected_fp:
        raise BundleCheckFailed(
            KEY_MISMATCH,
            "bundle names no signing key fingerprint, so no key can be shown to be the right one",
        )
    actual_fp = key_fingerprint(verifying_key)
    if actual_fp != expected_fp:
        raise BundleCheckFailed(
            KEY_MISMATCH,
            f"bundle expects key {expected_fp}, the supplied key is {actual_fp}; "
            "this bundle was not exported against the key you hold",
        )
    # The proof material names the same key, and the two copies must agree.
    # Found by tools/bundle_byte_sweep.py: without this, every byte of
    # proof.signing_key_fingerprint was inert, because only the outer copy
    # was ever read. A field nothing reads is not evidence, it is clutter
    # that looks like evidence.
    proof_fp = _require(proof, "signing_key_fingerprint", "proof")
    if proof_fp != expected_fp:
        raise BundleCheckFailed(
            KEY_MISMATCH,
            f"the bundle names key {expected_fp} but its proof material names "
            f"{proof_fp}; the two copies disagree about which key signed this",
        )

    # 2. Rebuild the trust anchor the exporting verifier held going in.
    #
    #    publicKey is set to b"" on purpose. The bundle carries no key, and
    #    verifiedGet.call() never reads this field (spike item 4[d]); the
    #    only key that decides anything is the PEM loaded from disk above.
    src = _require(proof, "source_state", "proof")
    anchor = State(
        db=_require(src, "db", "proof.source_state"),
        txId=int(_require(src, "tx_id", "proof.source_state")),
        txHash=_b64(_require(src, "tx_hash", "proof.source_state"), "proof.source_state.tx_hash"),
        publicKey=b"",
        signature=_b64(src.get("signature") or "", "proof.source_state.signature"),
    )

    # 3. Verify the anchor itself, with the SDK's own State.Verify.
    #
    #    verifiedGet.call() does not do this - it verifies the state it
    #    derives, against the anchor it was handed, and trusts the anchor
    #    because online it came from the verifier's own protected volume. A
    #    bundle's anchor arrived in the same file as everything else, so it
    #    is checked here rather than trusted. Strictly additional: nothing
    #    that verified before stops verifying, because every anchor a real
    #    verifier persists is a state the server signed (it is the newstate
    #    of a previous verifiedGet/verifiedSet, or the signed CurrentState).
    #
    #    This is also what catches a substituted anchor at txId 0, which
    #    would otherwise skip VerifyDualProof entirely (see verifiedGet.call:
    #    the dual proof runs only when state.txId > 0) and downgrade the
    #    check to inclusion-only without saying so.
    try:
        anchor.Verify(verifying_key)
    except BadSignatureError as exc:
        raise BundleCheckFailed(
            SIGNATURE_FAILURE,
            f"the bundle's trust anchor (tx {anchor.txId}) is not signed by the supplied key: {exc}",
        )
    except Exception as exc:
        raise BundleCheckFailed(
            SIGNATURE_FAILURE,
            f"the bundle's trust anchor (tx {anchor.txId}) carries no usable signature: "
            f"{type(exc).__name__}: {exc}",
        )

    # 4. Parse the captured server response.
    ventry = schema_pb2.VerifiableEntry()
    try:
        ventry.ParseFromString(_b64(_require(proof, "verifiable_entry", "proof"), "proof.verifiable_entry"))
    except DecodeError as exc:
        raise BundleCheckFailed(
            MALFORMED_BUNDLE, f"proof.verifiable_entry is not a decodable VerifiableEntry: {exc}"
        )

    ledger_key = _b64(_require(record, "ledger_key", "bundle.record"), "bundle.record.ledger_key")

    # 5. The SDK's verification, unmodified. Everything cryptographic in
    #    this whole tool happens inside this one call.
    try:
        result = verifiedGet.call(
            _BundleStub(ventry),
            _BundleRootService(anchor),
            ledger_key,
            verifying_key=verifying_key,
        )
    except ErrCorruptedData:
        raise BundleCheckFailed(
            CONSISTENCY_FAILURE,
            "immudb-py rejected a proof: the inclusion proof or the dual "
            "consistency proof did not check out against the trust anchor",
        )
    except BadSignatureError as exc:
        raise BundleCheckFailed(
            SIGNATURE_FAILURE,
            f"immudb-py rejected the server's ECDSA state signature: {exc}",
        )
    except SystemExit as exc:
        # Not defensive padding for a case that cannot happen: found by
        # tools/bundle_byte_sweep.py. immudb-py's own
        # embedded/store/tx.py::Alh() calls sys.exit() when a transaction
        # header carries a version it does not know, and immudb-py's
        # EntrySpecDigestFor raises ErrUnsupportedTxVersion for the same
        # reason. Corrupting one byte of the captured header is enough to
        # reach it. sys.exit raises SystemExit, which is a BaseException, so
        # without this the checker would terminate rather than report - a
        # file under examination must never be able to end the process
        # examining it.
        raise BundleCheckFailed(
            MALFORMED_BUNDLE,
            f"the captured transaction header names a format immudb-py cannot "
            f"process, so no proof could be evaluated: {exc}",
        )
    except Exception as exc:
        if type(exc).__name__ == "ErrUnsupportedTxVersion":
            raise BundleCheckFailed(
                MALFORMED_BUNDLE,
                "the captured transaction header names an unsupported entry "
                "version, so no leaf digest could be computed",
            )
        raise

    if not result.verified:
        raise BundleCheckFailed(
            CONSISTENCY_FAILURE, "immudb-py returned verified=False for this entry"
        )

    # 6. Bind the bundle's own readable copy of the record to the record the
    #    proof actually covers.
    #
    #    The SDK verifies the entry inside the protobuf; it has never seen
    #    bundle.record.value, which exists so a person can read the bundle.
    #    Without this comparison, editing that copy would leave a bundle that
    #    still verifies while displaying something the ledger never held.
    claimed_value = _b64(_require(record, "value", "bundle.record"), "bundle.record.value")
    if claimed_value != result.value:
        raise BundleCheckFailed(
            RECORD_MISMATCH,
            "bundle.record.value is not the value the proof covers: the bundle "
            f"claims {len(claimed_value)} bytes, the proven entry is {len(result.value)} bytes"
            if len(claimed_value) != len(result.value) else
            "bundle.record.value differs from the proven entry at the byte level",
        )
    if result.key != ledger_key:
        raise BundleCheckFailed(
            RECORD_MISMATCH,
            "bundle.record.ledger_key is not the key of the proven entry",
        )

    # tx_id, timestamp and record_type below are read with _require, not
    # .get(). Treating them as optional was a bypass, found by
    # tools/bundle_byte_sweep.py: corrupting a byte of the field *name*
    # ("record_type" -> "secord_type") makes the value unreachable, and a
    # check that skips an absent claim then passes a bundle whose label says
    # whatever the editor left behind. Every field this format defines is
    # required, so deleting one is a refusal rather than a way out of a
    # comparison.
    claimed_tx = _require(record, "tx_id", "bundle.record")
    if int(claimed_tx) != int(result.id):
        raise BundleCheckFailed(
            RECORD_MISMATCH,
            f"bundle.record.tx_id claims tx {claimed_tx}, the proof covers tx {result.id}",
        )

    claimed_ts = _require(record, "timestamp", "bundle.record")
    if int(claimed_ts) != int(result.timestamp):
        raise BundleCheckFailed(
            RECORD_MISMATCH,
            f"bundle.record.timestamp claims {claimed_ts}, the proven transaction is "
            f"stamped {result.timestamp}",
        )

    # 7. The bundle's human-readable label for the record must be the label
    #    the proven bytes actually support.
    #
    #    Found by tools/bundle_byte_sweep.py: before this check, relabelling
    #    record_type from "policy_allow" to "policy_deny" left a bundle that
    #    still verified, because the label is not an input to any proof. The
    #    label is derivable from the proven value, so it is derived here and
    #    compared rather than believed.
    claimed_type = _require(record, "record_type", "bundle.record")
    actual_type = record_type_of(result.value)
    if claimed_type != actual_type:
        raise BundleCheckFailed(
            RECORD_MISMATCH,
            f"bundle.record.record_type claims {claimed_type!r}, the proven record is "
            f"{actual_type!r}",
        )

    # 8. The proof's own transaction identifiers must describe this proof.
    if int(_require(proof, "entry_tx_id", "proof")) != int(result.id):
        raise BundleCheckFailed(
            RECORD_MISMATCH,
            f"proof.entry_tx_id claims tx {proof['entry_tx_id']}, the proof covers tx {result.id}",
        )
    if int(_require(proof, "prove_since_tx", "proof")) != int(anchor.txId):
        raise BundleCheckFailed(
            RECORD_MISMATCH,
            f"proof.prove_since_tx claims {proof['prove_since_tx']}, the trust anchor is "
            f"at tx {anchor.txId}",
        )

    return {
        "result_class": VERIFIED,
        "tx_id": result.id,
        "ledger_key": result.key.decode("utf-8", errors="replace"),
        "value": result.value,
        "timestamp": result.timestamp,
        # The derived label, not the bundle's claim about it.
        "record_type": actual_type,
        "key_fingerprint": actual_fp,
        "anchor_tx_id": anchor.txId,
    }


def check(bundle_path, key_path) -> dict:
    """Load and check, from two paths. The library entry point."""
    verifying_key = load_key(key_path)
    bundle = load_bundle(bundle_path)
    return verify_bundle(bundle, verifying_key)


# --- CLI ------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify an AIL evidence bundle offline (no Docker, no ImmuDB, no network).",
    )
    parser.add_argument("bundle", help="path to the .json evidence bundle")
    parser.add_argument(
        "--key",
        required=True,
        help="path to the trusted ECDSA public key (PEM). Never read from the bundle.",
    )
    args = parser.parse_args(argv)

    try:
        result = check(args.bundle, args.key)
    except BundleCheckFailed as exc:
        print(f"FAILED [{exc.result_class}] {exc.detail}")
        return 1

    print(f"OK [{result['result_class']}]")
    print(f"  ledger key   : {result['ledger_key']}")
    print(f"  record type  : {result['record_type']}")
    print(f"  transaction  : {result['tx_id']} (proven against trust anchor at tx {result['anchor_tx_id']})")
    print(f"  signing key  : {result['key_fingerprint']}")
    print(f"  record bytes : {result['value']!r}")
    print()
    print("This bundle proves the record above was committed to the ledger and has")
    print("not been altered since. It does not prove the policy that produced the")
    print("record was correct, nor that the writer was honest. See readME.md 3.4.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
