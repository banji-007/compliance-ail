"""
spikes/signing-anchor/submit_dsse_checkpoint.py

B2: submit a DSSE checkpoint over a synthetic Merkle root, signed with a
self-generated key, to the live public Rekor v2 log.

Rekor v2 dropped DSSE as a native entry type (confirmed from
sigstore/rekor-tiles CLIENTS.md, read from source this session). The
documented client path is: build a real DSSE envelope, compute its PAE
(Pre-Authentication Encoding) per the DSSE spec, sign the PAE, then submit
sha256(PAE) as the hashedrekord digest and the DSSE signature as the
hashedrekord signature. That is what this script does - a real DSSE
envelope is constructed, not skipped.

No reimplemented crypto: PAE encoding is a string format (not a
cryptographic primitive - it is the same class of operation as
JSON-canonicalizing a body before hashing, which the ledger already does
elsewhere in this project). Hashing and ECDSA signing are both
cryptography.hazmat calls.
"""

import base64
import hashlib
import json
import sys

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

REKOR_V2_URL = "https://log2025-1.rekor.sigstore.dev/api/v2/log/entries"

PAYLOAD_TYPE = "application/vnd.ail.spike.merkle-root+json"


def dsse_pae(payload_type: bytes, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding, per the DSSE spec
    (https://github.com/secure-systems-lab/dsse/blob/master/protocol.md#signature-definition).
    This is a length-prefixed concatenation format, not a crypto primitive."""
    return (
        b"DSSEv1"
        + b" "
        + str(len(payload_type)).encode()
        + b" "
        + payload_type
        + b" "
        + str(len(payload)).encode()
        + b" "
        + payload
    )


def main():
    # A synthetic Merkle root - not derived from any real tree, this is a
    # go/no-go spike, not a claim that this root means anything.
    synthetic_root_hex = hashlib.sha256(b"ail-spike-signing-anchor-synthetic-merkle-root").hexdigest()
    payload_obj = {
        "merkle_root": synthetic_root_hex,
        "tree_size": 1,
        "note": "synthetic root for spike-signing-anchor B2, not a real AIL ledger checkpoint",
    }
    payload_bytes = json.dumps(payload_obj, sort_keys=True, separators=(",", ":")).encode()

    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    pub_der = pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    pae = dsse_pae(PAYLOAD_TYPE.encode(), payload_bytes)
    dsse_signature = priv.sign(pae, ec.ECDSA(hashes.SHA256()))

    envelope = {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload_bytes).decode(),
        "signatures": [{"sig": base64.b64encode(dsse_signature).decode()}],
    }
    print("=== DSSE envelope constructed ===")
    print(json.dumps(envelope, indent=2))

    pae_digest = hashlib.sha256(pae).digest()

    request_body = {
        "hashedRekordRequestV002": {
            "digest": base64.b64encode(pae_digest).decode(),
            "signature": {
                "content": base64.b64encode(dsse_signature).decode(),
                "verifier": {
                    "publicKey": {"rawBytes": base64.b64encode(pub_der).decode()},
                    "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                },
            },
        }
    }
    print()
    print("=== hashedrekord request body (digest = sha256(PAE), signature = DSSE sig) ===")
    print(json.dumps(request_body, indent=2))

    print()
    print(f"=== POST {REKOR_V2_URL} ===")
    resp = httpx.post(REKOR_V2_URL, json=request_body, timeout=30.0)
    print("status:", resp.status_code)
    print("body:", resp.text[:4000])

    with open("submit_response.json", "w") as f:
        f.write(resp.text)
    with open("submit_request.json", "w") as f:
        json.dump(request_body, f, indent=2)
    with open("dsse_envelope.json", "w") as f:
        json.dump(envelope, f, indent=2)
    with open("signing_key_priv.pem", "wb") as f:
        f.write(priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    with open("signing_key_pub.pem", "wb") as f:
        f.write(pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    with open("pae_bytes.bin", "wb") as f:
        f.write(pae)

    sys.exit(0 if resp.status_code == 200 else 1)


if __name__ == "__main__":
    main()
