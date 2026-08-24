"""
spikes/signing-anchor/offline_check.py

A3: what a checker needs to verify an SVID-signed record with no network.

Inputs, all local files, nothing else:
  1. the record bytes that were signed
  2. the signature bytes (DER-encoded ECDSA)
  3. the leaf certificate (the SVID that signed it) as PEM
  4. the trust bundle (the trust domain's CA root cert(s)) as PEM
  5. the expected SPIFFE ID of the signer (a string, not a file - this is
     policy, the same way the offline-verify spike's checker takes the
     expected key path as a CLI argument rather than trusting the bundle)

Blocks network at import, the same pattern tools/ail_verify_bundle.py and
spikes/offline-verify/verify_offline.py use, to make "no network" a property
of the process rather than a claim about it.

No cryptography reimplemented: certificate parsing, path validation, and
signature verification are all cryptography.x509 / cryptography.x509.verification
calls (that module wraps rustls-webpki, not a reimplementation written for this
project).
"""

import datetime
import socket
import sys

_real_connect = socket.socket.connect


class NetworkAccessAttempted(Exception):
    pass


def _blocked_connect(self, *a, **kw):
    raise NetworkAccessAttempted(f"socket.connect attempted: {a!r}")


socket.socket.connect = _blocked_connect

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError


def check(record_path, signature_path, leaf_cert_path, trust_bundle_path, expected_spiffe_id):
    record_bytes = open(record_path, "rb").read()
    signature = open(signature_path, "rb").read()
    leaf = x509.load_pem_x509_certificate(open(leaf_cert_path, "rb").read())
    bundle_pem = open(trust_bundle_path, "rb").read()
    authorities = x509.load_pem_x509_certificates(bundle_pem)

    # Step 1: the leaf cert carries a SPIFFE ID (URI SAN). Confirm it is the
    # identity the caller expects, before trusting anything else about it -
    # chain validation alone only proves "issued by our CA", not "issued to
    # the specific workload we mean by 'the signer'".
    san = leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    if expected_spiffe_id not in uris:
        return False, f"leaf SPIFFE ID mismatch: expected {expected_spiffe_id!r}, found {uris!r}"

    # Step 2: path-validate the leaf against the trust bundle. This is
    # cryptography.x509.verification's own webpki-backed validator, not a
    # hand-rolled chain walk - the same rule the offline-verify spike and
    # ADR-0001 both apply (do not reimplement crypto).
    store = Store(authorities)
    builder = PolicyBuilder().store(store)
    # SPIFFE leaf certs carry no DNS SAN, only a URI SAN. build_server_verifier
    # requires a DNS name to check the leaf against; SPIFFE has none, so the
    # client verifier form is used instead - it validates the chain (issuer,
    # validity window, path length, key usage) without requiring a DNS
    # subject. Identity (which SPIFFE ID) is checked separately in step 1.
    verifier = builder.build_client_verifier()
    try:
        verified_client = verifier.verify(leaf, [])
        chain = verified_client.chain
    except VerificationError as exc:
        return False, f"chain validation failed: {exc}"

    # Step 3: the signature itself, over the exact record bytes, using the
    # leaf's own public key. ECDSA/SHA-256 because that is what the SVID's
    # key type is (secp256r1) - not a preference, a fact about the key.
    pub = leaf.public_key()
    try:
        pub.verify(signature, record_bytes, ec.ECDSA(hashes.SHA256()))
    except Exception as exc:
        return False, f"signature verification failed: {exc}"

    return True, {
        "signer_spiffe_id": expected_spiffe_id,
        "leaf_not_before": leaf.not_valid_before_utc.isoformat(),
        "leaf_not_after": leaf.not_valid_after_utc.isoformat(),
        "chain_length": len(chain),
        "verified_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


if __name__ == "__main__":
    record_path, signature_path, leaf_cert_path, trust_bundle_path, expected_spiffe_id = sys.argv[1:6]
    ok, detail = check(record_path, signature_path, leaf_cert_path, trust_bundle_path, expected_spiffe_id)
    print("OK" if ok else "FAILED", detail)
    sys.exit(0 if ok else 1)
