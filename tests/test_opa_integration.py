import os
import json
import sys

# Add paths
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'interceptor'))

from middleware import intercept_tool_call, query_opa_policy

def test_opa_policy():
    """Test OPA policy decisions directly"""
    print("Testing OPA Policy Directly")
    print("=" * 50)

    # Test 1: Small instance without restricted tags (likely approved)
    print("\n1. Testing small instance (t3.micro):")
    args1 = {
        "instance_type": "t3.micro",
        "region": "us-east-1",
        "cost_per_hour": 5
    }
    decision1 = query_opa_policy("provision_cloud_server", args1)
    print(f"Input: {args1}")
    print(f"Decision: {decision1}")

    # Test 2: Large restricted instance without proper project tag (denied)
    print("\n2. Testing restricted instance without project tag:")
    args2 = {
        "instance_type": "p4d.24xlarge",
        "region": "us-east-1",
        "cost_per_hour": 50
    }
    decision2 = query_opa_policy("provision_cloud_server", args2)
    print(f"Input: {args2}")
    print(f"Decision: {decision2}")

    # Test 3: Small instance in different region (approved - no region restriction)
    print("\n3. Testing small instance in different region:")
    args3 = {
        "instance_type": "t3.micro",
        "region": "us-west-2",
        "cost_per_hour": 5
    }
    decision3 = query_opa_policy("provision_cloud_server", args3)
    print(f"Input: {args3}")
    print(f"Decision: {decision3}")

    # Test 4: Large instance with wrong project tag (denied)
    print("\n4. Testing restricted instance with wrong project tag:")
    args4 = {
        "instance_type": "p4d.24xlarge",
        "region": "eu-west-1",
        "cost_per_hour": 25,
        "tags": {"project": "webapp"}
    }
    decision4 = query_opa_policy("provision_cloud_server", args4)
    print(f"Input: {args4}")
    print(f"Decision: {decision4}")

def test_interceptor_with_opa():
    """Test the full interceptor with OPA integration"""
    print("\n\nTesting Full Interceptor with OPA")
    print("=" * 50)

    # Test approved case
    print("\n1. Testing interceptor with APPROVED request:")
    approved_args = {
        "instance_type": "t3.micro",
        "region": "us-east-1",
        "cost_per_hour": 5
    }

    response1 = intercept_tool_call("provision_cloud_server", approved_args, "test_opa_agent")
    print(f"Interceptor response: {response1}")

    # Test denied case
    print("\n2. Testing interceptor with DENIED request:")
    denied_args = {
        "instance_type": "p4d.24xlarge",
        "region": "us-east-1",
        "cost_per_hour": 50
    }

    response2 = intercept_tool_call("provision_cloud_server", denied_args, "test_opa_agent")
    print(f"Interceptor response: {response2}")

def test_ledger_after_opa():
    """Show ledger state after OPA tests"""
    print("\n\nLedger State After OPA Tests")
    print("=" * 50)
    
    print("All test records logged to ImmuDB cryptographic ledger.")
    print("SQLite ledger is not used in production flow.")
    print("Use ImmuDB client tools to view the actual audit trail.")

if __name__ == "__main__":
    print("OPA Integration Test Suite")
    print("Make sure OPA is running on localhost:8181")
    print("And the policy is loaded: docker run -p 8181:8181 -v $(pwd)/policy:/policy openpolicyagent/opa:latest run --server --addr=0.0.0.0:8181 /policy")

    try:
        test_opa_policy()
        test_interceptor_with_opa()
        test_ledger_after_opa()
    except Exception as e:
        print(f"Test failed: {e}")
        print("Make sure OPA is running and the policy is loaded correctly!")
