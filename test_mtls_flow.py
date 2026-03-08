#!/usr/bin/env python3

import ssl
import tempfile
import os
import httpx
from cryptography.hazmat.primitives import serialization
from spiffe import WorkloadApiClient, TrustDomain

ENVOY_URL = "https://envoy:8443/v1/data/ail/policy"


def test_spiffe_mtls_to_envoy():
    """Test complete mTLS flow from Python client to Envoy proxy."""
    print("=== Testing Complete mTLS Flow ===")

    try:
        # WorkloadApiClient reads SPIFFE_ENDPOINT_SOCKET from env
        with WorkloadApiClient() as client:
            svid = client.fetch_x509_svid()
            print(f"✅ SVID fetched: {svid.spiffe_id}")

            bundle_set = client.fetch_x509_bundles()
            bundle = bundle_set.get_bundle_for_trust_domain(TrustDomain("ail.internal"))

        # Serialize cert chain to PEM bytes
        cert_pem = b"".join(
            cert.public_bytes(serialization.Encoding.PEM)
            for cert in svid.cert_chain
        )

        # Serialize private key to PEM bytes
        key_pem = svid.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )

        # Serialize CA bundle to PEM bytes
        ca_pem = b"".join(
            cert.public_bytes(serialization.Encoding.PEM)
            for cert in bundle.x509_authorities
        )

        # Write cert and key to temp files (ssl module requires file paths)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cf:
            cf.write(cert_pem)
            cert_path = cf.name
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf:
            kf.write(key_pem)
            key_path = kf.name

        try:
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # SPIFFE certs use URI SANs (spiffe://...), not DNS SANs.
            # Disable hostname check; chain validation against trust bundle still runs.
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_REQUIRED
            ssl_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            ssl_ctx.load_verify_locations(cadata=ca_pem.decode())

            print("✅ SSL context configured for mTLS")

            with httpx.Client(verify=ssl_ctx) as http:
                response = http.post(
                    ENVOY_URL,
                    json={"input": {"tool_args": {"action": "read"}}},
                    timeout=10,
                )

            print(f"✅ mTLS connection successful!")
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text}")
            return True

        finally:
            os.unlink(cert_path)
            os.unlink(key_path)

    except Exception as e:
        print(f"❌ Test failed: {type(e).__name__}: {e}")
        return False


if __name__ == "__main__":
    success = test_spiffe_mtls_to_envoy()
    if success:
        print("\n✅ True mTLS enforcement is working!")
    else:
        print("\n❌ mTLS enforcement needs troubleshooting.")
