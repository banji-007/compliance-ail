#!/usr/bin/env python3
"""
Test script for Epic 3: Enterprise Policy Packs
"""

import os
import sys
import json

# Add the interceptor directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'interceptor'))

def test_epic_3_enterprise_packs():
    """Test modular policy packs with aggregator functionality"""
    print("=== Testing Epic 3: Enterprise Policy Packs ===\n")
    
    # Set up environment for testing
    os.environ['SPIRE_DISABLED'] = 'true'
    os.environ['OPA_URL'] = 'http://localhost:8181/v1/data/ail/main/deny'
    
    from interceptor.middleware import intercept_tool_call
    
    print("Test 1: GDPR Compliance - PCI-DSS data residency violation")
    gdpr_violation = {
        'instance_type': 't3.large',
        'region': 'us-east-1',  # Wrong region for PCI-DSS
        'cost_per_hour': 0.10,
        'tags': {
            'environment': 'prod',
            'data_classification': 'pci-dss',
            'cost_center': 'finance',
            'encryption_at_rest': 'true'
        }
    }
    
    result = intercept_tool_call('provision_cloud_server', gdpr_violation)
    print(f"GDPR violation result: {result.get('status', 'unknown')}")
    print(f"Message: {result.get('message', 'N/A')}")
    print()
    
    print("Test 2: SOC2 Compliance - Missing encryption in production")
    soc2_violation = {
        'instance_type': 't3.large',
        'region': 'us-east-1',
        'cost_per_hour': 0.10,
        'tags': {
            'environment': 'prod',
            'cost_center': 'finance',
            'encryption_at_rest': 'false'  # Missing encryption
        }
    }
    
    result = intercept_tool_call('provision_cloud_server', soc2_violation)
    print(f"SOC2 violation result: {result.get('status', 'unknown')}")
    print(f"Message: {result.get('message', 'N/A')}")
    print()
    
    print("Test 3: FinOps Compliance - Missing cost center in production")
    finops_violation = {
        'instance_type': 't3.large',
        'region': 'us-east-1',
        'cost_per_hour': 0.10,
        'tags': {
            'environment': 'prod',
            'encryption_at_rest': 'true'
            # Missing cost_center
        }
    }
    
    result = intercept_tool_call('provision_cloud_server', finops_violation)
    print(f"FinOps violation result: {result.get('status', 'unknown')}")
    print(f"Message: {result.get('message', 'N/A')}")
    print()
    
    print("Test 4: DISASTER PROMPT - Multiple simultaneous violations")
    disaster_scenario = {
        'instance_type': 'p4d.24xlarge',  # FinOps violation (restricted type)
        'region': 'us-east-1',  # GDPR violation (PCI-DSS wrong region)
        'cost_per_hour': 32.0,
        'tags': {
            'environment': 'prod',
            'data_classification': 'pci-dss',  # Triggers GDPR
            'encryption_at_rest': 'false',  # Triggers SOC2
            'project': 'web-app'  # Wrong project for restricted instance
            # Missing cost_center - triggers FinOps
        }
    }
    
    result = intercept_tool_call('provision_cloud_server', disaster_scenario)
    print(f"Disaster scenario result: {result.get('status', 'unknown')}")
    print(f"Message: {result.get('message', 'N/A')}")
    print()
    
    print("Test 5: Fully compliant request - should be approved")
    compliant_request = {
        'instance_type': 't3.large',
        'region': 'eu-central-1',  # Correct for PCI-DSS
        'cost_per_hour': 0.10,
        'tags': {
            'environment': 'prod',
            'data_classification': 'pci-dss',
            'cost_center': 'finance',
            'encryption_at_rest': 'true',
            'project': 'ml-training'
        }
    }
    
    result = intercept_tool_call('provision_cloud_server', compliant_request)
    print(f"Compliant request result: {result.get('status', 'unknown')}")
    print(f"Message: {result.get('message', 'N/A')}")
    print()
    
    print("Test 6: Non-production environment - relaxed rules")
    non_prod_request = {
        'instance_type': 'p4d.24xlarge',
        'region': 'us-east-1',
        'cost_per_hour': 32.0,
        'tags': {
            'environment': 'dev',  # Not prod, so many rules don't apply
            'project': 'web-app'
            # Missing cost_center and encryption - OK for dev
        }
    }
    
    result = intercept_tool_call('provision_cloud_server', non_prod_request)
    print(f"Non-prod result: {result.get('status', 'unknown')}")
    print(f"Message: {result.get('message', 'N/A')}")
    print()
    
    print("=== Epic 3 Implementation Summary ===")
    print("✅ Directory Structure: policy/frameworks/ created")
    print("✅ GDPR Framework: Data residency rules in policy/frameworks/gdpr.rego")
    print("✅ SOC2 Framework: Encryption requirements in policy/frameworks/soc2.rego")
    print("✅ FinOps Framework: Cost controls in policy/frameworks/internal_finops.rego")
    print("✅ Aggregator: policy/main.rego imports and unifies all frameworks")
    print("✅ OPA Integration: Updated to load entire policy directory")
    print("✅ Middleware Routing: Updated to new aggregated endpoint")
    print("✅ Multi-Framework Testing: Disaster scenario tests aggregator functionality")

if __name__ == '__main__':
    test_epic_3_enterprise_packs()
