#!/usr/bin/env python3
"""
ail_verify_bundle.py - check an AIL evidence bundle offline.

    python tools/ail_verify_bundle.py BUNDLE.json --key signing.pub \
        --writer-key writer-decision.pub --writer-key writer-control-plane.pub \
        --trusted-root trusted_root.json --anchor-key anchor-signing.pub

No Docker, no ImmuDB, no control plane, no network. Local files go in: the
bundle, and the public keys you already trust. An exit code and a named
result come out.

D19/D20, Phase 3a. D22/D23, Phase 3b.
docs/adr/0010-portable-evidence-bundles.md,
docs/adr/0012-writer-signing-and-external-anchoring.md.

What this checks, in order
--------------------------
1. That the bundle names the ImmuDB signing key you supplied (D19).
2. That the trust anchor the proof runs to is a state ImmuDB signed (D19).
3. That the record was committed and is unaltered, via immudb-py's own
   inclusion and dual consistency proofs (D20).
4. That the bundle's readable copy of the record is the record proven (D19).
5. That the record was signed by a writer key you hold, over its own
   canonical bytes, and that the key is not on your deny-list (D22).
6. That the anchor the proof runs to is in a public transparency log, bound
   to that same anchor by its digest, and that the log's inclusion proof and
   witnessed checkpoint verify against a trust root you supply (D23) - or,
   if the bundle says no checkpoint covers this record, that it says so.

Zero cryptography is implemented here
-------------------------------------
Every check runs inside somebody else's verification code, imported from an
installed package and called unmodified:

  store.EntrySpecDigestFor  - recomputes the (key, value, metadata) leaf digest
  store.VerifyInclusion     - walks the Merkle path from that leaf to the tx's eH
  store.VerifyDualProof     - verifies the linear-hash chain anchor -> target tx
  rootService.State.Verify  - checks the server's ECDSA signature over the state
  VerifyingKey.verify       - checks the writer and anchoring ECDSA signatures
  sigstore ... verify_merkle_inclusion / verify_checkpoint
                            - reached through TransparencyLogEntry._verify,
                              the same functions sigstore-python's own client
                              uses, and the ones
                              docs/reports/spike-signing-anchor.md B3 drove

The first four are reached through immudb.handler.verifiedGet.call(), the
exact function ImmudbClient.verifiedGet() calls. This file computes no
digest as part of any construction, walks no proof, and checks no signature
of its own. ADR-0001 records a hand-rolled Alh() in this project that got the
field order wrong and substituted eH for innerHash; not repeating that is the
point of doing it this way.

hashlib appears in exactly three functions and nowhere else, which
tests/test_offline_verify.py enforces against this source:
  key_fingerprint       - derives an identifier for comparison
  anchor_payload_digest - recomputes the preimage digest a log entry claims,
                          so the entry is bound to this bundle's own anchor
                          rather than to an unrelated one
  _ecdsa_verify         - passes hashlib.sha256 to ecdsa as its hashfunc,
                          because ecdsa's default is SHA-1
None of the three assembles a construction of this project's own.

No network, by construction
---------------------------
socket.socket.connect is replaced with a raiser as soon as imports finish, so
a hidden fetch anywhere below raises NetworkAccessAttempted instead of
quietly succeeding. It is patched after imports rather than before because
ssl.py (pulled in transitively by grpc) subclasses socket.socket at import
time and a non-class replacement breaks that subclassing - the same ordering
constraint docs/reports/spike-offline-verify.md hit and documented. The
sigstore import in step 6 is deliberately made after the block is already
installed, so the anchor check has to prove it needs no network rather than
being trusted not to use one.

No key is ever read from the bundle
-----------------------------------
A bundle names every key it expects by fingerprint; you supply the keys. The
spike found that immudb-py never reads State.publicKey during verification,
so a bundle carrying its own key would certify itself. The same rule extends
to the two Phase 3b keys: the writer key that signed the record, and the key
that signed the anchoring submission. If a bundle names a key you did not
supply, this refuses to check it at all (key_mismatch, writer_key_unknown,
anchor_key_unknown) - each distinct from a bundle that was checked and
failed, because "you are holding the wrong key" and "this evidence was
altered" call for different responses from whoever reads the result.
"""

import argparse
import base64
import binascii
import hashlib
import json
import socket
import sys
from pathlib import Path

# --- SDK imports. Pure computation; none of these open a connection. ------
import ecdsa                                          # noqa: E402
from ecdsa.keys import BadSignatureError              # noqa: E402
from ecdsa.util import sigdecode_der                  # noqa: E402
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

BUNDLE_FORMAT = "ail-evidence-bundle/2"
PROOF_MATERIAL_FORMAT = "ail-proof-material/2"

# D22: the canonicalization rule and field names a signed record uses. Held
# here as this tool's own copy rather than imported from provenance/, for
# the same reason the stub shim and the record_type rule are copies (see
# ADR-0010): an auditor checking a bundle from a system they do not operate
# cannot be asked to obtain that system's source. tests/test_writer_signing.py
# holds the two copies in agreement by signing through one and verifying
# through the other.
RECORD_SIGNATURE_FORMAT = "ail-record-signature/1"
SIGNATURE_FIELD = "writer_signature"
FINGERPRINT_FIELD = "writer_key_fingerprint"
SIGNATURE_FORMAT_FIELD = "writer_signature_format"

# D23: the anchor payload's own canonicalization rule, same reasoning.
ANCHOR_PAYLOAD_FORMAT = "ail-immudb-state-anchor/1"
ANCHOR_STATE_ANCHORED = "anchored"
ANCHOR_STATE_NOT_ANCHORED = "not_anchored"


# --- The closed set of outcomes -------------------------------------------
#
# The first three line up exactly with what the live verifier already
# reports (verifier/main.py's error_class, docs/adr/0006-verification-
# states.md): a proof rejection and a signature rejection are never
# collapsed into each other, and a pass is a pass.
#
# The rest name failures that can only exist because a bundle is a file that
# travelled - there is no bundle in the live read path, so the live verifier
# has no equivalent. They are additions to the vocabulary, never
# substitutes: nothing that used to report consistency_failure now reports
# one of these.

VERIFIED                  = "verified"
CONSISTENCY_FAILURE       = "consistency_failure"   # ErrCorruptedData: a proof was rejected
SIGNATURE_FAILURE         = "signature_failure"     # BadSignatureError: an ECDSA signature was rejected
RECORD_MISMATCH           = "record_mismatch"       # the bundle's own copy of the record is not the record proven
KEY_MISMATCH              = "key_mismatch"          # the supplied key is not the key the bundle expects
MALFORMED_BUNDLE          = "malformed_bundle"      # the file is not a bundle this checker can read
# D22 (Phase 3b)
WRITER_SIGNATURE_MISSING  = "writer_signature_missing"   # the record carries no writer signature at all
WRITER_SIGNATURE_FAILURE  = "writer_signature_failure"   # the writer signature did not verify
WRITER_KEY_UNKNOWN        = "writer_key_unknown"         # the record names a writer key this checker was not given
WRITER_KEY_REVOKED        = "writer_key_revoked"         # the record names a writer key on the deny-list
# D23 (Phase 3b)
ANCHOR_FAILURE            = "anchor_failure"        # the bundle claims corroboration the log does not support
ANCHOR_KEY_UNKNOWN        = "anchor_key_unknown"    # the anchor names a key this checker was not given
ANCHOR_UNCHECKED          = "anchor_unchecked"      # the bundle claims corroboration and nothing was supplied to check it with

RESULT_CLASSES = frozenset({
    VERIFIED,
    CONSISTENCY_FAILURE,
    SIGNATURE_FAILURE,
    RECORD_MISMATCH,
    KEY_MISMATCH,
    MALFORMED_BUNDLE,
    WRITER_SIGNATURE_MISSING,
    WRITER_SIGNATURE_FAILURE,
    WRITER_KEY_UNKNOWN,
    WRITER_KEY_REVOKED,
    ANCHOR_FAILURE,
    ANCHOR_KEY_UNKNOWN,
    ANCHOR_UNCHECKED,
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
    verifier/main.py::signing_key_fingerprint and
    provenance/record_signature.py::key_fingerprint exactly; the round-trip
    is asserted in tests rather than assumed.
    """
    return "sha256:" + hashlib.sha256(verifying_key.to_der()).hexdigest()


def load_key(key_path) -> "ecdsa.VerifyingKey":
    """Load a trusted ECDSA public key from a PEM file on disk.

    The only place a key enters the process, for all four kinds this tool
    holds - the ImmuDB state-signing key, each writer key, and the anchoring
    key. Every path comes from the command line, never from the bundle.
    tests/test_offline_verify.py asserts against this source that no other
    function constructs a verifying key.
    """
    try:
        return ecdsa.VerifyingKey.from_pem(Path(key_path).read_text())
    except Exception as exc:
        raise BundleCheckFailed(
            MALFORMED_BUNDLE,
            f"could not load a PEM ECDSA public key from {key_path}: {exc}",
        )


def load_writer_keys(key_paths) -> dict:
    """Fingerprint -> verifying key, for every writer key supplied.

    A map rather than a single key because this project has more than one
    writer: decision-service signs decision and intent records, the control
    plane signs erasure tombstones, and they hold separate long-lived pairs
    so a bundle names which service wrote the record (D22). A checker holds
    whichever it has been given; a record naming one it was not given is
    writer_key_unknown, not a failure of the evidence.
    """
    keys = {}
    for path in key_paths:
        verifying_key = load_key(path)
        keys[key_fingerprint(verifying_key)] = verifying_key
    return keys


def load_deny_list(path) -> dict:
    """Fingerprint -> reason, for writer keys this checker must refuse.

    D22 requires a revocation path, because long-lived does not mean no
    lifecycle. The deny-list is held by the checker, out of band, exactly
    like the keys: a bundle that carried its own revocation status would be
    asserting its own writer had not been compromised.

    Shape: {"revoked": [{"fingerprint": "sha256:...", "reason": "..."}]}.
    """
    if not path:
        return {}
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise BundleCheckFailed(
            MALFORMED_BUNDLE, f"could not read a writer deny-list from {path}: {exc}"
        )
    entries = data.get("revoked") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise BundleCheckFailed(
            MALFORMED_BUNDLE,
            f"{path} is not a deny-list: expected an object with a 'revoked' list",
        )
    denied = {}
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("fingerprint"):
            raise BundleCheckFailed(
                MALFORMED_BUNDLE,
                f"{path} has a revoked entry with no fingerprint; a deny-list that "
                "silently skips a malformed row is a deny-list with a hole in it",
            )
        denied[entry["fingerprint"]] = entry.get("reason") or "no reason recorded"
    return denied


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


# --- D22: the writer signature --------------------------------------------

def canonical_record_bytes(record: dict) -> bytes:
    """The bytes the writer signed, re-derived from the proven record.

    This tool's own copy of provenance/record_signature.py's rule, for the
    reason given at RECORD_SIGNATURE_FORMAT above. Everything in the record
    except the signature itself; sorted keys, no whitespace, ASCII escapes,
    so the bytes do not depend on the order the ledger happened to store
    them in or on the encoding a reader chose.
    """
    payload = {k: v for k, v in record.items() if k != SIGNATURE_FIELD}
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _ecdsa_verify(verifying_key, signature: bytes, message: bytes) -> None:
    """ecdsa's own verify, with SHA-256 named explicitly.

    Named explicitly because ecdsa's default hashfunc is SHA-1, and a
    signature check that silently ran under a hash nobody chose would be a
    check in name only. Raises BadSignatureError, which every caller here
    maps to a specific named result rather than letting it escape.
    """
    verifying_key.verify(
        signature, message, hashfunc=hashlib.sha256, sigdecode=sigdecode_der
    )


def verify_writer_signature(record: dict, writer_keys: dict, deny_list: dict) -> dict:
    """D22/P3b-3. Returns what was established; raises with a named class.

    Runs against the record the proof actually covers, not the bundle's
    readable copy of it - by the time this is called those two have already
    been shown to be the same bytes, and using the proven one means the
    signature is checked over something the ledger is known to hold.

    Four distinct refusals, because they call for four different responses:
      no signature at all  -> the record is unattributable
      key on the deny-list -> the writer is known compromised
      key not held         -> you cannot answer this question yet
      signature bad        -> the record or the signature was altered
    """
    if not isinstance(record, dict):
        raise BundleCheckFailed(
            WRITER_SIGNATURE_MISSING,
            "the proven record is not a JSON object, so it carries no writer "
            "signature and cannot be attributed to any writer",
        )

    signature_b64 = record.get(SIGNATURE_FIELD)
    fingerprint = record.get(FINGERPRINT_FIELD)
    declared_format = record.get(SIGNATURE_FORMAT_FIELD)

    if not signature_b64 or not fingerprint:
        # Not treated as unsigned-and-fine. A record with no writer
        # signature is a record no one can be shown to have written, and
        # this tool's whole output is an attribution.
        raise BundleCheckFailed(
            WRITER_SIGNATURE_MISSING,
            "the proven record carries no writer signature "
            f"({SIGNATURE_FIELD}/{FINGERPRINT_FIELD}); it cannot be attributed to "
            "any writer, so it is refused rather than reported as verified",
        )
    if declared_format != RECORD_SIGNATURE_FORMAT:
        raise BundleCheckFailed(
            MALFORMED_BUNDLE,
            f"the record declares {SIGNATURE_FORMAT_FIELD}={declared_format!r}; this "
            f"checker verifies {RECORD_SIGNATURE_FORMAT!r} and will not guess at "
            "another rule for which bytes were signed",
        )

    if fingerprint in deny_list:
        raise BundleCheckFailed(
            WRITER_KEY_REVOKED,
            f"the record was signed by {fingerprint}, which your deny-list revokes "
            f"({deny_list[fingerprint]}); nothing this key signed is accepted, "
            "whether or not the signature itself checks out",
        )

    verifying_key = writer_keys.get(fingerprint)
    if verifying_key is None:
        raise BundleCheckFailed(
            WRITER_KEY_UNKNOWN,
            f"the record was signed by writer key {fingerprint}, which you did not "
            "supply with --writer-key; this is not a statement that the record is "
            "bad, it is that you cannot yet say who wrote it",
        )

    signed_bytes = canonical_record_bytes(record)
    try:
        _ecdsa_verify(verifying_key, _b64(signature_b64, "record.writer_signature"), signed_bytes)
    except BadSignatureError as exc:
        raise BundleCheckFailed(
            WRITER_SIGNATURE_FAILURE,
            f"the writer signature does not verify against {fingerprint}: {exc}",
        )
    except BundleCheckFailed:
        raise
    except Exception as exc:
        raise BundleCheckFailed(
            WRITER_SIGNATURE_FAILURE,
            f"the writer signature could not be checked against {fingerprint}: "
            f"{type(exc).__name__}: {exc}",
        )

    return {"writer_key_fingerprint": fingerprint, "signed_bytes": len(signed_bytes)}


# --- D23: the external anchor ---------------------------------------------

def canonical_anchor_bytes(db: str, tx_id: int, tx_hash_b64: str, signature_b64: str) -> bytes:
    """The preimage whose digest was submitted to the transparency log.

    This tool's own copy of provenance/anchor.py's rule, same reasoning as
    canonical_record_bytes above. Rebuilt from proof.source_state - the
    checkpoint the dual proof actually runs to - rather than from a second
    copy carried alongside it, so there is no pair of fields that could
    disagree about which state was anchored.
    """
    return json.dumps(
        {
            "anchor_payload_format": ANCHOR_PAYLOAD_FORMAT,
            "db": db,
            "tx_id": int(tx_id),
            "tx_hash": tx_hash_b64,
            "signature": signature_b64,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def anchor_payload_digest(payload: bytes) -> bytes:
    """sha256 of the canonical anchor payload - the hashedrekord digest.

    A recomputation for comparison, not a step in any proof: what it
    establishes is that the log entry in this bundle is about this bundle's
    anchor and not some other state.
    """
    return hashlib.sha256(payload).digest()


def _hashedrekord_body(entry: dict) -> dict:
    """Decode the entry's canonicalizedBody, which is what the log holds.

    Read from canonicalizedBody rather than from any convenience field,
    because canonicalizedBody is the preimage of the Merkle leaf that
    sigstore's inclusion proof recomputes. A digest or signature taken from
    anywhere else in the response would not be the bytes the log committed
    to. CLIENTS.md's own warning is the same one in a different place: do
    not use unverified copies of values the checkpoint covers.
    """
    body_b64 = entry.get("canonicalizedBody")
    if not body_b64:
        raise BundleCheckFailed(
            ANCHOR_FAILURE,
            "the transparency log entry carries no canonicalizedBody, so there is "
            "nothing the log's own Merkle leaf could be recomputed from",
        )
    try:
        body = json.loads(base64.b64decode(body_b64))
    except Exception as exc:
        raise BundleCheckFailed(
            ANCHOR_FAILURE, f"the entry's canonicalizedBody is not decodable JSON: {exc}"
        )
    spec = ((body.get("spec") or {}).get("hashedRekordV002")) if isinstance(body, dict) else None
    if not isinstance(spec, dict):
        raise BundleCheckFailed(
            ANCHOR_FAILURE,
            f"the entry is not a hashedrekord v0.0.2 body: kind={body.get('kind')!r} "
            f"apiVersion={body.get('apiVersion')!r}",
        )
    return spec


def verify_external_anchor(bundle: dict, source_state: dict, trusted_root_path, anchor_keys: dict,
                           skip: bool = False) -> dict:
    """D23/P3b-4. Returns what was established; raises with a named class.

    The section is required, always, in both states. A bundle that simply
    omitted it when nothing anchored the record would make "not
    corroborated" and "exported by a build that predates anchoring" the same
    bytes.
    """
    section = _require(bundle, "external_anchor", "bundle")
    state = _require(section, "state", "bundle.external_anchor")

    if state == ANCHOR_STATE_NOT_ANCHORED:
        # Fail-closed on the claim: an unanchored bundle claims nothing, and
        # is not a failure. It must still say so out loud, which it just did.
        _require(section, "detail", "bundle.external_anchor")
        return {"state": ANCHOR_STATE_NOT_ANCHORED, "checked": False}

    if state != ANCHOR_STATE_ANCHORED:
        raise BundleCheckFailed(
            MALFORMED_BUNDLE,
            f"bundle.external_anchor.state is {state!r}; this checker knows only "
            f"{ANCHOR_STATE_ANCHORED!r} and {ANCHOR_STATE_NOT_ANCHORED!r}",
        )

    declared_payload_format = _require(section, "anchor_payload_format", "bundle.external_anchor")
    if declared_payload_format != ANCHOR_PAYLOAD_FORMAT:
        raise BundleCheckFailed(
            MALFORMED_BUNDLE,
            f"the anchor declares anchor_payload_format={declared_payload_format!r}; "
            f"this checker recomputes {ANCHOR_PAYLOAD_FORMAT!r} and will not guess at "
            "another rule for which bytes were anchored",
        )
    anchor_fp = _require(section, "anchor_key_fingerprint", "bundle.external_anchor")
    entry = _require(section, "transparency_log_entry", "bundle.external_anchor")

    if skip:
        # Explicit, never a default. A bundle that claims corroboration and
        # is checked without the means to test that claim has not been fully
        # checked, and the result says which parts were skipped rather than
        # printing the same "verified" a full check prints.
        return {"state": ANCHOR_STATE_ANCHORED, "checked": False,
                "detail": "anchor check skipped at the caller's explicit request"}

    if not trusted_root_path or not anchor_keys:
        raise BundleCheckFailed(
            ANCHOR_UNCHECKED,
            "this bundle claims external corroboration, but no --trusted-root and "
            "--anchor-key were supplied to test that claim against. Supply them, or "
            "pass --skip-anchor-check to say deliberately that you are not checking it",
        )

    # 1. The log entry has to be about this bundle's own anchor. Recompute
    #    the anchored payload from proof.source_state - the state the dual
    #    proof runs to - and compare its digest with the one in the body the
    #    log committed to.
    payload = canonical_anchor_bytes(
        _require(source_state, "db", "proof.source_state"),
        int(_require(source_state, "tx_id", "proof.source_state")),
        _require(source_state, "tx_hash", "proof.source_state"),
        _require(source_state, "signature", "proof.source_state") or "",
    )
    spec = _hashedrekord_body(entry)
    logged_digest_b64 = ((spec.get("data") or {}).get("digest"))
    if not logged_digest_b64:
        raise BundleCheckFailed(ANCHOR_FAILURE, "the log entry's body carries no digest")
    if _b64(logged_digest_b64, "transparency_log_entry.digest") != anchor_payload_digest(payload):
        raise BundleCheckFailed(
            ANCHOR_FAILURE,
            "the transparency log entry is not about this bundle's trust anchor: the "
            "digest the log holds is not the digest of the checkpoint this proof runs "
            "to. Corroboration of some other state is not corroboration of this one",
        )

    # 2. The anchoring key. Held out of band, named by fingerprint, exactly
    #    like the ImmuDB key and the writer keys.
    anchor_key = anchor_keys.get(anchor_fp)
    if anchor_key is None:
        raise BundleCheckFailed(
            ANCHOR_KEY_UNKNOWN,
            f"the anchor was submitted under key {anchor_fp}, which you did not supply "
            "with --anchor-key",
        )
    logged_key_b64 = (((spec.get("signature") or {}).get("verifier") or {}).get("publicKey") or {}).get("rawBytes")
    if not logged_key_b64 or _b64(logged_key_b64, "transparency_log_entry.publicKey") != anchor_key.to_der():
        raise BundleCheckFailed(
            ANCHOR_FAILURE,
            "the public key inside the log entry is not the key the bundle names; the "
            "entry was submitted by someone else",
        )
    logged_signature_b64 = (spec.get("signature") or {}).get("content")
    if not logged_signature_b64:
        raise BundleCheckFailed(ANCHOR_FAILURE, "the log entry's body carries no signature")
    try:
        _ecdsa_verify(
            anchor_key, _b64(logged_signature_b64, "transparency_log_entry.signature"), payload
        )
    except BadSignatureError as exc:
        raise BundleCheckFailed(
            ANCHOR_FAILURE,
            f"the signature in the log entry does not cover this bundle's anchor: {exc}",
        )

    # 3. The bundle's own readable description of where the entry lives must
    #    be the entry's. Found by tools/bundle_byte_sweep.py, exactly the way
    #    Phase 3a found record_type: before this, every byte of log_index and
    #    log_url was inert, so a bundle could point a reader at the wrong
    #    index in the wrong log and still verify. Those two fields are what
    #    a person acts on when they go and look the entry up.
    claimed_index = str(_require(section, "log_index", "bundle.external_anchor"))
    if str(entry.get("logIndex")) != claimed_index:
        raise BundleCheckFailed(
            ANCHOR_FAILURE,
            f"bundle.external_anchor.log_index claims {claimed_index}, the entry is at "
            f"index {entry.get('logIndex')}",
        )

    claimed_url = _require(section, "log_url", "bundle.external_anchor")
    key_id = (entry.get("logId") or {}).get("keyId")
    if not key_id:
        raise BundleCheckFailed(
            ANCHOR_FAILURE, "the log entry names no logId.keyId, so which log holds it is unstated"
        )
    try:
        trusted_root_doc = json.loads(Path(trusted_root_path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise BundleCheckFailed(
            MALFORMED_BUNDLE, f"could not read a TrustedRoot from {trusted_root_path}: {exc}"
        )
    #    The URL is checked against the trust root you hold, not against the
    #    bundle: the entry says which log signed it (logId.keyId), the trust
    #    root says what that log's base URL is, and the bundle's claim has to
    #    agree with both. Step 4 then verifies the checkpoint signature under
    #    that same key, so the keyId is not taken on the entry's word either.
    matching = [
        tlog for tlog in (trusted_root_doc.get("tlogs") or [])
        if (tlog.get("logId") or {}).get("keyId") == key_id
    ]
    if not matching:
        raise BundleCheckFailed(
            ANCHOR_FAILURE,
            f"the entry names log key id {key_id}, which is not a log your TrustedRoot "
            "knows about",
        )
    known_urls = {(tlog.get("baseUrl") or "").rstrip("/") for tlog in matching}
    if claimed_url.rstrip("/") not in known_urls:
        raise BundleCheckFailed(
            ANCHOR_FAILURE,
            f"bundle.external_anchor.log_url claims {claimed_url}, but the log that signed "
            f"this entry is {sorted(known_urls)} according to your TrustedRoot",
        )

    # 4. The log's own proof, verified by the log's own client code. Imported
    #    here, after the socket block is already installed, so this has to
    #    prove it needs no network rather than be trusted not to use one.
    try:
        from sigstore._internal.trust import KeyringPurpose
        from sigstore.errors import VerificationError
        from sigstore.models import TransparencyLogEntry, TrustedRoot
        from sigstore_models.rekor.v1 import TransparencyLogEntry as _RawEntry
    except ImportError as exc:
        raise BundleCheckFailed(
            ANCHOR_UNCHECKED,
            "checking an anchored bundle needs sigstore-python installed "
            f"(pip install sigstore==4.5.0): {exc}",
        )

    try:
        trusted_root = TrustedRoot.from_file(str(trusted_root_path))
        keyring = trusted_root.rekor_keyring(KeyringPurpose.VERIFY)
        raw_entry = _RawEntry.from_dict(entry)
        TransparencyLogEntry(raw_entry)._verify(keyring)
    except VerificationError as exc:
        raise BundleCheckFailed(
            ANCHOR_FAILURE,
            f"the transparency log's inclusion proof or signed checkpoint was "
            f"rejected by sigstore-python's own verification: {exc}",
        )
    except NetworkAccessAttempted:
        raise
    except BundleCheckFailed:
        raise
    except Exception as exc:
        raise BundleCheckFailed(
            ANCHOR_FAILURE,
            f"the transparency log entry could not be verified: {type(exc).__name__}: {exc}",
        )

    return {
        "state": ANCHOR_STATE_ANCHORED,
        "checked": True,
        "log_url": section.get("log_url"),
        "log_index": section.get("log_index"),
        "anchor_key_fingerprint": anchor_fp,
        "anchored_tx_id": int(_require(source_state, "tx_id", "proof.source_state")),
    }


# --- The check ------------------------------------------------------------

def verify_bundle(bundle: dict, verifying_key: "ecdsa.VerifyingKey", writer_keys: dict,
                  deny_list: dict | None = None, trusted_root_path=None,
                  anchor_keys: dict | None = None, skip_anchor_check: bool = False) -> dict:
    """
    Check one bundle against keys the caller independently supplied.

    Returns a dict on success. Raises BundleCheckFailed, carrying the
    result_class that names which check failed, on every failure. It never
    raises a bare exception for a tamper case - which check rejected the
    bundle is the whole answer, so "something went wrong" would not be one.
    """
    deny_list = deny_list or {}
    anchor_keys = anchor_keys or {}

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

    # 2. Rebuild the trust anchor the proof runs to.
    #
    #    Since D23 this is normally the externally anchored checkpoint, not
    #    an internal state of the exporting deployment - which is what makes
    #    the proof mean anything to a party who has no way to learn what
    #    that deployment held.
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
    #    this whole tool happens inside this call and the two ecdsa/sigstore
    #    calls further down.
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

    # 9. D22: who wrote it. Checked against the record the proof covers, not
    #    the bundle's readable copy - by now those are known to be the same
    #    bytes, and using the proven one means the attribution is over
    #    something the ledger is known to hold.
    try:
        proven_record = json.loads(result.value.decode())
    except Exception:
        proven_record = None
    writer = verify_writer_signature(proven_record, writer_keys, deny_list)

    # 10. D23: whether anything outside this deployment corroborates the
    #     state the proof runs to, and if the bundle says nothing does, that
    #     it says so rather than leaving a field out.
    anchor_result = verify_external_anchor(
        bundle, src, trusted_root_path, anchor_keys, skip=skip_anchor_check
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
        "writer_key_fingerprint": writer["writer_key_fingerprint"],
        "external_anchor": anchor_result,
    }


def check(bundle_path, key_path, writer_key_paths, deny_list_path=None,
          trusted_root_path=None, anchor_key_paths=(), skip_anchor_check=False) -> dict:
    """Load and check, from paths. The library entry point."""
    verifying_key = load_key(key_path)
    writer_keys = load_writer_keys(writer_key_paths)
    anchor_keys = load_writer_keys(anchor_key_paths)
    deny_list = load_deny_list(deny_list_path)
    bundle = load_bundle(bundle_path)
    return verify_bundle(
        bundle, verifying_key, writer_keys,
        deny_list=deny_list,
        trusted_root_path=trusted_root_path,
        anchor_keys=anchor_keys,
        skip_anchor_check=skip_anchor_check,
    )


# --- CLI ------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify an AIL evidence bundle offline (no Docker, no ImmuDB, no network).",
    )
    parser.add_argument("bundle", help="path to the .json evidence bundle")
    parser.add_argument(
        "--key",
        required=True,
        help="path to the trusted ImmuDB state-signing public key (PEM). Never read from the bundle.",
    )
    parser.add_argument(
        "--writer-key",
        required=True,
        action="append",
        default=[],
        metavar="PEM",
        help="path to a trusted writer public key (PEM). Repeatable: this project has "
             "one writer key per writing service. Never read from the bundle.",
    )
    parser.add_argument(
        "--writer-deny-list",
        metavar="JSON",
        help="path to a JSON deny-list of revoked writer key fingerprints. Anything a "
             "listed key signed is refused, whether or not its signature checks out.",
    )
    parser.add_argument(
        "--trusted-root",
        metavar="JSON",
        help="path to Sigstore's TrustedRoot, fetched via TUF and held out of band. "
             "Required to check a bundle that claims external corroboration.",
    )
    parser.add_argument(
        "--anchor-key",
        action="append",
        default=[],
        metavar="PEM",
        help="path to a trusted anchoring public key (PEM). Never read from the bundle.",
    )
    parser.add_argument(
        "--skip-anchor-check",
        action="store_true",
        help="deliberately do not check an anchored bundle's transparency log entry. "
             "The result says which checks were skipped; it is never the default.",
    )
    args = parser.parse_args(argv)

    try:
        result = check(
            args.bundle, args.key, args.writer_key,
            deny_list_path=args.writer_deny_list,
            trusted_root_path=args.trusted_root,
            anchor_key_paths=args.anchor_key,
            skip_anchor_check=args.skip_anchor_check,
        )
    except BundleCheckFailed as exc:
        print(f"FAILED [{exc.result_class}] {exc.detail}")
        return 1

    external = result["external_anchor"]
    if external["state"] == ANCHOR_STATE_ANCHORED and external["checked"]:
        anchor_line = (
            f"anchored in {external['log_url']} at index {external['log_index']}, "
            f"inclusion proof and checkpoint verified"
        )
    elif external["state"] == ANCHOR_STATE_ANCHORED:
        anchor_line = "anchored, NOT CHECKED (--skip-anchor-check)"
    else:
        anchor_line = "none claimed (no checkpoint covering this record was anchored)"

    print(f"OK [{result['result_class']}]")
    print(f"  ledger key   : {result['ledger_key']}")
    print(f"  record type  : {result['record_type']}")
    print(f"  transaction  : {result['tx_id']} (proven against trust anchor at tx {result['anchor_tx_id']})")
    print(f"  signing key  : {result['key_fingerprint']}")
    print(f"  written by   : {result['writer_key_fingerprint']}")
    print(f"  corroboration: {anchor_line}")
    print(f"  record bytes : {result['value']!r}")
    print()
    print("This bundle proves the record above was committed to the ledger, has not")
    print("been altered since, and was signed by the writer key named. It does not")
    print("prove the policy that produced the record was correct, and it does not")
    print("prove that writer was honest - only which key signed. See readME.md 3.4.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
