#!/usr/bin/env python3

import os
import sys
import ssl
from spiffe.workloadapi.x509_source import X509Source
from spiffe.workloadapi.errors import X509SourceError

def test_spiffe_svid():
    """Test SPIFFE SVID fetching from Workload API."""
    print("=== Testing SPIFFE SVID Fetch ===")
    
    # Set SPIFFE endpoint socket
    os.environ['SPIFFE_ENDPOINT_SOCKET'] = 'unix:///tmp/spire-sockets/workload_api.sock'
    
    try:
        # Initialize X509Source to fetch SVID from SPIRE Workload API
        x509_source = X509Source()
        
        # Fetch the default SVID (X.509 certificate and private key)
        svid = x509_source.fetch_default_svid()
        
        print(f"✅ SVID fetched successfully!")
        print(f"   SPIFFE ID: {svid.spiffe_id}")
        print(f"   Certificate expires: {svid.expires_at}")
        print(f"   Trust domain: {svid.spiffe_id.trust_domain}")
        
        # Create SSL context for client authentication
        ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        
        # Load client certificate and private key
        ssl_context.load_cert_chain(
            certfile=svid.cert_chain_bytes,
            keyfile=svid.private_key_bytes
        )
        
        # Load SPIRE trust bundle for server certificate validation
        x509_bundle = x509_source.fetch_x509_bundle_for_trust_domain('ail.internal')
        ssl_context.load_verify_locations(cafile=x509_bundle.pem_bytes)
        
        # Require client certificate (mutual TLS)
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        
        print(f"✅ SSL context configured for mTLS!")
        print(f"   Trust bundle loaded for: ail.internal")
        print(f"   Client certificate loaded")
        print(f"   Mutual TLS required: {ssl_context.verify_mode == ssl.CERT_REQUIRED}")
        
        return ssl_context
        
    except X509SourceError as e:
        print(f"❌ SPIFFE Workload API error: {e}")
        return None
    except Exception as e:
        print(f"❌ Failed to fetch SPIFFE SVID: {e}")
        return None

if __name__ == "__main__":
    test_spiffe_svid()
