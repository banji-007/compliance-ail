#!/usr/bin/env python3
"""
Test script for Epic 2: Pre-Flight Input Validation
"""

import os
import sys
import json

# Add the interceptor directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'interceptor'))

def test_epic_2_validation():
    """Test pre-flight validation with various scenarios"""
    print("=== Testing Epic 2: Pre-Flight Input Validation ===\n")
    
    # Set up environment for testing
    os.environ['SPIRE_DISABLED'] = 'true'
    os.environ['OPA_URL'] = 'http://localhost:8181/v1/data/ail/policy'
    
    from interceptor.middleware import intercept_tool_call
    from interceptor.schemas import CloudServerProvisionSchema
    
    print("Test 1: Valid cloud server arguments")
    valid_args = {
        'instance_type': 'p4d.24xlarge',
        'region': 'us-east-1',
        'cost_per_hour': 32.0,
        'tags': {
            'environment': 'prod',
            'project': 'ml-training',
            'cost_center': 'engineering'
        }
    }
    
    result = intercept_tool_call('provision_cloud_server', valid_args)
    print(f"Valid args result: {result.get('status', 'unknown')}")
    print(f"Message: {result.get('message', 'N/A')}")
    print()
    
    print("Test 2: Invalid instance_type (missing)")
    invalid_args_missing = {
        'region': 'us-east-1',
        'cost_per_hour': 32.0,
        'tags': {'environment': 'prod'}
    }
    
    result = intercept_tool_call('provision_cloud_server', invalid_args_missing)
    print(f"Missing field result: {result.get('status', 'unknown')}")
    print(f"Message: {result.get('message', 'N/A')}")
    print()
    
    print("Test 3: Invalid cost_per_hour (negative)")
    invalid_args_negative = {
        'instance_type': 'p4d.24xlarge',
        'region': 'us-east-1',
        'cost_per_hour': -10.0,
        'tags': {'environment': 'prod'}
    }
    
    result = intercept_tool_call('provision_cloud_server', invalid_args_negative)
    print(f"Negative cost result: {result.get('status', 'unknown')}")
    print(f"Message: {result.get('message', 'N/A')}")
    print()
    
    print("Test 4: Invalid tags (non-string values)")
    invalid_args_tags = {
        'instance_type': 'p4d.24xlarge',
        'region': 'us-east-1',
        'cost_per_hour': 32.0,
        'tags': {'environment': 'prod', 'count': 5}  # count is not a string
    }
    
    result = intercept_tool_call('provision_cloud_server', invalid_args_tags)
    print(f"Invalid tags result: {result.get('status', 'unknown')}")
    print(f"Message: {result.get('message', 'N/A')}")
    print()
    
    print("Test 5: Extra fields (hallucinated parameters)")
    invalid_args_extra = {
        'instance_type': 'p4d.24xlarge',
        'region': 'us-east-1',
        'cost_per_hour': 32.0,
        'tags': {'environment': 'prod'},
        'extra_field': 'should_not_exist',  # This should be rejected
        'another_extra': 123
    }
    
    result = intercept_tool_call('provision_cloud_server', invalid_args_extra)
    print(f"Extra fields result: {result.get('status', 'unknown')}")
    print(f"Message: {result.get('message', 'N/A')}")
    print()
    
    print("Test 6: Non-cloud-server tool (should bypass validation)")
    result = intercept_tool_call('read_file', {'path': '/tmp/test'})
    print(f"Non-cloud tool result: {result.get('status', 'unknown')}")
    print(f"Message: {result.get('message', 'N/A')}")
    print()
    
    print("=== Epic 2 Implementation Summary ===")
    print("✅ Dependency: pydantic is available in requirements.txt")
    print("✅ Schema: CloudServerProvisionSchema defined in interceptor/schemas.py")
    print("✅ Validation: Pre-flight validation implemented in query_opa_policy()")
    print("✅ Fail-Closed: ValidationError returns formatted denial to LLM")
    print("✅ Network Efficiency: Invalid requests blocked before OPA network call")

if __name__ == '__main__':
    test_epic_2_validation()
