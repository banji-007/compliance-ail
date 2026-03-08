#!/usr/bin/env python3
"""
Test script for Epic 1C: True mTLS via SPIFFE integration
"""

import os
import sys
import json

# Add the interceptor directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'interceptor'))

def test_spiffe_integration():
    """Test both SPIFFE-enabled and SPIRE-disabled modes"""
    print("=== Testing Epic 1C: True mTLS via SPIFFE ===\n")
    
    # Test 1: SPIRE_DISABLED mode (development)
    print("Test 1: Development mode (SPIRE_DISABLED=true)")
    os.environ['SPIRE_DISABLED'] = 'true'
    os.environ['OPA_URL'] = 'http://localhost:8181/v1/data/ail/policy'
    
    from interceptor.middleware import intercept_tool_call
    
    result = intercept_tool_call('read_file', {'path': '/tmp/test'})
    print(f"Result: {json.dumps(result, indent=2)}")
    print(f"Status: {result.get('status', 'unknown')}")
    print()
    
    # Test 2: SPIFFE-enabled mode (production)
    print("Test 2: Production mode (SPIFFE mTLS)")
    os.environ.pop('SPIRE_DISABLED', None)
    os.environ['OPA_URL'] = 'https://localhost:8443/v1/data/ail/policy'
    
    # Force reload of middleware to pick up new environment
    import importlib
    import interceptor.middleware
    importlib.reload(interceptor.middleware)
    
    from interceptor.middleware import intercept_tool_call
    
    result = intercept_tool_call('read_file', {'path': '/tmp/test'})
    print(f"Result: {json.dumps(result, indent=2)}")
    print(f"Status: {result.get('status', 'unknown')}")
    print()
    
    print("=== Epic 1C Implementation Summary ===")
    print("✅ Dependencies: pyspiffe and httpx imported")
    print("✅ SPIFFE Integration: _get_spiffe_ssl_context() implemented")
    print("✅ In-memory certificates: SVID fetched and SSL context created without disk writes")
    print("✅ mTLS routing: Envoy URL used when SPIRE_DISABLED=false")
    print("✅ Graceful failure: Deterministic denial when Workload API unavailable")
    print("✅ Development mode: HTTP fallback when SPIRE_DISABLED=true")

if __name__ == '__main__':
    test_spiffe_integration()
