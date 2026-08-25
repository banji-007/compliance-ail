"""
D23: anchoring uses Rekor v2 over ImmuDB's own signed states.

ImmuDB's transaction hash is already a Merkle root, and probe 7d in
docs/reports/spike-consistency-proof.md established that the server signs
the state at an arbitrary transaction, not only at the head. So what gets
submitted to a public transparency log is one of those signed states, not a
second tree this project would have to build and get right.

This module defines the one thing the submitter and every checker have to
agree on byte for byte: what a state's canonical anchor payload is, and
therefore what digest goes into the hashedrekord entry.

Nothing content-bearing reaches the log. The payload is a database name, a
transaction id, a Merkle root, and the server's own signature over them -
and even that payload is not transmitted: only sha256 of it, the anchoring
signature over it, and the anchoring public key.
docs/reports/spike-signing-anchor.md B5 measured exactly what a live
submission puts on the public record.
"""

import hashlib
import json

# The wire format of an anchor payload. Bumped when the field list or the
# canonicalization rule changes: this digest is the entire binding between a
# log entry and a ledger state, so a checker computing it under a different
# rule would silently fail to bind anything.
ANCHOR_PAYLOAD_FORMAT = "ail-immudb-state-anchor/1"


def canonical_anchor_bytes(db: str, tx_id: int, tx_hash_b64: str, signature_b64: str) -> bytes:
    """The exact preimage whose sha256 is submitted to Rekor.

    Identical canonicalization rule to provenance/record_signature.py -
    sorted keys, no whitespace, ASCII escapes - for the same reason: a
    checker has to reproduce these bytes from the state fields a bundle
    carries, with nothing but parsed JSON to work from.

    The state's own ECDSA signature is part of the payload, not stripped
    from it. Anchoring an unsigned (db, tx_id, tx_hash) triple would anchor
    a claim about the ledger rather than the ledger's own attestation of it.
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


def anchor_payload_digest(db: str, tx_id: int, tx_hash_b64: str, signature_b64: str) -> bytes:
    """sha256 of the canonical anchor payload - the hashedrekord digest."""
    return hashlib.sha256(
        canonical_anchor_bytes(db, tx_id, tx_hash_b64, signature_b64)
    ).digest()
