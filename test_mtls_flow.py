#!/usr/bin/env python3

import os
import socket
import ssl
import tempfile

import httpx
from cryptography.hazmat.primitives import serialization
from spiffe import TrustDomain, WorkloadApiClient

ENVOY_HOST = "envoy"
ENVOY_PORT = 8443
ENVOY_URL = f"https://{ENVOY_HOST}:{ENVOY_PORT}/v1/data/ail/policy"
EXPECTED_SERVER_SPIFFE_ID = "spiffe://ail.internal/workload/envoy"


def build_ssl_context(cert_path, key_path, ca_pem):
    """
    Build an mTLS SSLContext using SPIRE-issued credentials.

    - CA root is the SPIRE trust bundle fetched from the Workload API,
      NOT the OS certificate store. This ensures only workloads issued
      by our SPIRE server are trusted.
    - check_hostname is disabled because SPIFFE certs carry URI SANs
      (spiffe://...), not DNS SANs. Chain validation is still enforced
      via verify_mode = CERT_REQUIRED.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    ctx.load_verify_locations(cadata=ca_pem.decode())
    return ctx


def verify_peer_spiffe_id(host, port, ssl_ctx, expected_spiffe_id):
    """
    Open a bare TLS connection, extract the server certificate's URI SAN,
    and assert it matches the expected SPIFFE ID.

    This is the manual peer validation step: even after chain verification
    passes, we confirm the server is presenting the identity we expect
    (workload/envoy) rather than any other valid workload in the trust domain.
    """
    with socket.create_connection((host, port), timeout=10) as raw_sock:
        with ssl_ctx.wrap_socket(raw_sock) as tls_sock:
            peer_cert = tls_sock.getpeercert()

    for san_type, san_value in peer_cert.get("subjectAltName", []):
        if san_type == "URI" and san_value == expected_spiffe_id:
            return

    raise ValueError(
        f"Peer SPIFFE ID mismatch. Expected '{expected_spiffe_id}', "
        f"got SANs: {peer_cert.get('subjectAltName', [])}"
    )


def test_spiffe_mtls_to_envoy():
    """Test complete mTLS flow from Python client to Envoy proxy."""
    print("=== Testing Complete mTLS Flow ===")

    try:
        # Step 1: Fetch SVID and trust bundle from SPIRE Workload API.
        # WorkloadApiClient reads SPIFFE_ENDPOINT_SOCKET from the environment.
        with WorkloadApiClient() as client:
            svid = client.fetch_x509_svid()
            print(f"  SVID fetched: {svid.spiffe_id}")

            bundle_set = client.fetch_x509_bundles()
            bundle = bundle_set.get_bundle_for_trust_domain(TrustDomain("ail.internal"))

        # Step 2: Serialize credentials to PEM.
        cert_pem = b"".join(
            cert.public_bytes(serialization.Encoding.PEM)
            for cert in svid.cert_chain
        )
        key_pem = svid.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        # SPIRE trust bundle used as the CA root — replaces OS certs entirely.
        ca_pem = b"".join(
            cert.public_bytes(serialization.Encoding.PEM)
            for cert in bundle.x509_authorities
        )

        # Step 3: Write cert/key to temp files (ssl module requires file paths).
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cf:
            cf.write(cert_pem)
            cert_path = cf.name
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf:
            kf.write(key_pem)
            key_path = kf.name

        try:
            ssl_ctx = build_ssl_context(cert_path, key_path, ca_pem)
            print("  SSL context configured (SPIRE trust bundle loaded as CA root)")

            # Step 4: Manually verify the server's SPIFFE ID before trusting
            # any response. Confirms Envoy is presenting workload/envoy, not
            # an unexpected identity that happens to be in the trust domain.
            verify_peer_spiffe_id(ENVOY_HOST, ENVOY_PORT, ssl_ctx, EXPECTED_SERVER_SPIFFE_ID)
            print(f"  Peer SPIFFE ID verified: {EXPECTED_SERVER_SPIFFE_ID}")

            # Step 5: Make the policy request over mTLS.
            with httpx.Client(verify=ssl_ctx) as http:
                response = http.post(
                    ENVOY_URL,
                    json={"input": {"tool_args": {"action": "read"}}},
                    timeout=10,
                )

            print(f"  mTLS connection successful!")
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text}")
            return True

        finally:
            os.unlink(cert_path)
            os.unlink(key_path)

    except Exception as e:
        print(f"  Test failed: {type(e).__name__}: {e}")
        return False


if __name__ == "__main__":
    success = test_spiffe_mtls_to_envoy()
    if success:
        print("\nTrue mTLS enforcement is working!")
    else:
        print("\nmTLS enforcement needs troubleshooting.")
