"""
D22: the decision service signs the canonical record bytes before the write.

The signature is a field in the record, not metadata beside it, so it is
covered by the inclusion proof like every other byte of the record. That is
the whole reason it goes in before the ledger write rather than into the
bundle at export time: a signature the exporter attaches is a claim the
exporter makes, and docs/adr/0010-portable-evidence-bundles.md already
records that a bundle's export-time metadata is covered by nothing.

Why a dedicated long-lived key and not the SVID
-----------------------------------------------
docs/reports/spike-signing-anchor.md Question A returned NO-GO, from direct
observation in both directions: a rotated-away SVID keeps verifying, but
only until its own not_after, which is 24 hours at this project's own
default_x509_svid_ttl. SPIFFE answers who is connecting right now, with a
credential designed to expire; durable evidence answers who wrote this,
checkable years later. See
docs/adr/0012-writer-signing-and-external-anchoring.md.

Canonicalization
----------------
The signed bytes are a deterministic JSON serialization of the record with
the signature field itself removed - sorted keys, no whitespace, ASCII
escapes. Deterministic so a checker can recompute exactly the bytes that
were signed from the parsed record, without depending on the byte order the
ledger happened to store them in. The fingerprint of the signing key is
inside the signed bytes: the record states which key signed it, and that
statement is covered.

Signatures are RFC 6979 deterministic ECDSA (sign_deterministic), so signing
the same record twice produces identical bytes. That is asserted rather than
assumed - see tests/test_writer_signing.py.
"""

import base64
import hashlib
import json

# The wire format of a signed record. Bumped when the canonicalization rule,
# the field names, or the signature algorithm change, so a checker refuses a
# record it would otherwise verify under the wrong rule.
RECORD_SIGNATURE_FORMAT = "ail-record-signature/1"

# The one field a record carries that is not itself covered by the
# signature - it cannot be, it is the signature. Everything else in the
# record is, including the fingerprint field and the format field below.
SIGNATURE_FIELD = "writer_signature"

# Named as constants so the writer and the checker agree by definition
# rather than by two string literals in two files that can drift apart.
FINGERPRINT_FIELD = "writer_key_fingerprint"
FORMAT_FIELD = "writer_signature_format"


def key_fingerprint(verifying_key) -> str:
    """SHA-256 over the key's DER SubjectPublicKeyInfo encoding.

    Identical rule to verifier/main.py::signing_key_fingerprint and
    tools/ail_verify_bundle.py::key_fingerprint, and for the same reason:
    over the DER rather than the PEM text, so the fingerprint survives the
    line-ending differences a PEM file picks up crossing operating systems.
    An identifier, not a check - no verification result depends on it.
    """
    return "sha256:" + hashlib.sha256(verifying_key.to_der()).hexdigest()


def canonical_record_bytes(record: dict) -> bytes:
    """The exact bytes a writer signs and a checker re-derives.

    Everything in the record except the signature itself. Sorted keys and no
    whitespace so the same record always produces the same bytes; ASCII
    escaping so a non-ASCII value cannot make the bytes depend on the
    encoding a reader chose.
    """
    payload = {k: v for k, v in record.items() if k != SIGNATURE_FIELD}
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def sign_record(record: dict, signing_key, verifying_key) -> dict:
    """Return the record with its writer signature fields filled in.

    The fingerprint and the format string are written into the record BEFORE
    the canonical bytes are computed, so both are covered by the signature.
    A record whose fingerprint could be rewritten without breaking the
    signature would let a forger point a checker at a key of their choosing.
    """
    from ecdsa.util import sigencode_der

    signed = dict(record)
    signed[FORMAT_FIELD] = RECORD_SIGNATURE_FORMAT
    signed[FINGERPRINT_FIELD] = key_fingerprint(verifying_key)
    signature = signing_key.sign_deterministic(
        canonical_record_bytes(signed),
        hashfunc=hashlib.sha256,
        sigencode=sigencode_der,
    )
    signed[SIGNATURE_FIELD] = base64.b64encode(signature).decode()
    return signed


def load_signing_key(path):
    """Load a writer's private key from a PEM file on disk.

    The only place a private key enters a writer process, and its path comes
    from that process's own environment, never from anything a caller sent.
    """
    import ecdsa

    with open(path, "r", encoding="utf-8") as f:
        sk = ecdsa.SigningKey.from_pem(f.read())
    return sk, sk.get_verifying_key()


def load_verifying_key(path):
    """Load a writer's public key from a PEM file on disk.

    The read-path counterpart of load_signing_key, and the only place a
    checker in this package constructs a verifying key.
    """
    import ecdsa

    with open(path, "r", encoding="utf-8") as f:
        return ecdsa.VerifyingKey.from_pem(f.read())


def verify_record(record: dict, verifying_key) -> bool:
    """Does this record carry a writer signature that checks out under this key.

    D41 (Phase 3c-3d). The checker half of sign_record, here rather than in
    the reader, so the writer and the checker agree by definition rather than
    by two implementations of one canonicalization rule in two files. Same
    reason FINGERPRINT_FIELD and FORMAT_FIELD are constants.

    Four conditions, all of them refusing:

    - the signature field is present and is a string. A record with none is
      refused rather than treated as unsigned-and-fine, the same rule
      tools/ail_verify_bundle.py applies (`writer_signature_missing`).
    - the format field is exactly RECORD_SIGNATURE_FORMAT, so a record signed
      under a future canonicalization rule is refused rather than checked
      under this one and reported as a forgery.
    - the fingerprint field names this key. It is inside the signed bytes, so
      it cannot be rewritten without breaking the signature; checking it here
      is what makes "signed by this writer" the question rather than "signed
      by somebody".
    - the ECDSA verification itself, over the canonical bytes, with SHA-256
      named explicitly rather than left to a library default.

    Returns a boolean rather than raising: every caller's next move is the
    same either way, which is to not present the record as authoritative.
    """
    from ecdsa.util import sigdecode_der

    signature_b64 = record.get(SIGNATURE_FIELD)
    if not isinstance(signature_b64, str) or not signature_b64:
        return False
    if record.get(FORMAT_FIELD) != RECORD_SIGNATURE_FORMAT:
        return False
    if record.get(FINGERPRINT_FIELD) != key_fingerprint(verifying_key):
        return False
    try:
        signature = base64.b64decode(signature_b64)
    except Exception:
        return False
    try:
        verifying_key.verify(
            signature, canonical_record_bytes(record),
            hashfunc=hashlib.sha256, sigdecode=sigdecode_der,
        )
    except Exception:
        return False
    return True
