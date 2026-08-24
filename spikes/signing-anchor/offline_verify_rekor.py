"""
spikes/signing-anchor/offline_verify_rekor.py

B3: persist what the Rekor v2 upload returned and verify the inclusion
proof offline, with no network.

Reuses the official sigstore-python client's own verification functions
(sigstore._internal.merkle.verify_merkle_inclusion,
sigstore._internal.rekor.checkpoint.verify_checkpoint) rather than
reimplementing Merkle tree or checkpoint-signature verification - the same
rule the offline-verify spike applied to immudb-py.

Inputs, both local files, nothing else at verification time:
  1. submit_response.json - exactly what POST /api/v2/log/entries returned
  2. trusted_root.json - Sigstore's public TrustedRoot, fetched once via TUF
     ahead of time (the same role signing.pub plays for the checker in
     tools/ail_verify_bundle.py: an independently obtained trust anchor,
     not something the entry itself supplies)

Network is blocked at import, after the trust root has already been read
from disk - the same "block after imports finish" reasoning
tools/ail_verify_bundle.py's own docstring gives (ssl.py subclasses
socket.socket at import time in some paths, so blocking too early breaks
imports that never touch the network).
"""

import json
import socket
import sys


def main():
    trusted_root_path, response_path = sys.argv[1], sys.argv[2]

    # Read local files BEFORE blocking the network - this mirrors
    # tools/ail_verify_bundle.py's own ordering.
    trusted_root_bytes = open(trusted_root_path, "rb").read()
    response_dict = json.load(open(response_path))

    _real_connect = socket.socket.connect

    class NetworkAccessAttempted(Exception):
        pass

    def _blocked_connect(self, *a, **kw):
        raise NetworkAccessAttempted(f"socket.connect attempted: {a!r}")

    socket.socket.connect = _blocked_connect

    from sigstore._internal.trust import KeyringPurpose
    from sigstore.models import TrustedRoot
    from sigstore_models.rekor.v1 import TransparencyLogEntry as _TransparencyLogEntry
    from sigstore.models import TransparencyLogEntry
    from sigstore.errors import VerificationError

    # TrustedRoot.from_file() reads a path with open(), not a network call -
    # confirm this really does not touch the network despite the file having
    # been fetched over the network earlier in a separate, already-completed
    # process (mirrors tools/ail_verify_bundle.py's key_fingerprint pattern:
    # verification-time and acquisition-time are different steps).
    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        tf.write(trusted_root_bytes)
        tmp_path = tf.name
    try:
        trusted_root = TrustedRoot.from_file(tmp_path)
    finally:
        os.unlink(tmp_path)

    keyring = trusted_root.rekor_keyring(KeyringPurpose.VERIFY)

    inner = _TransparencyLogEntry.from_dict(response_dict)
    entry = TransparencyLogEntry(inner)

    try:
        entry._verify(keyring)
    except VerificationError as exc:
        print("FAILED:", exc)
        sys.exit(1)
    except NetworkAccessAttempted as exc:
        print("FAILED (network attempted during verification):", exc)
        sys.exit(1)

    print("OK: Merkle inclusion proof and checkpoint signature both verified, offline")
    print("log_index:", inner.log_index)
    print("tree_size (from inclusion proof, cross-checked against signed checkpoint):",
          inner.inclusion_proof.tree_size)
    print("root_hash:", inner.inclusion_proof.root_hash.hex())
    sys.exit(0)


if __name__ == "__main__":
    main()
