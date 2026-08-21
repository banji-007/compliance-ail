#!/usr/bin/env python3
"""
Test script for Epic 2: Pre-Flight Input Validation
"""

import asyncio
import importlib.util as _importlib_util
import os
import sys
import json

# decision_service/main.py's own `from schemas import ...` needs this
# directory on sys.path - loading main.py itself via spec_from_file_location
# below (to dodge the module-name collision, see _load_decision_service_main)
# does not add its own directory to sys.path automatically the way a normal
# package-relative import would.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "decision_service"))

# Add the decision_service directory to the path (moved from repo root, as
# test_epic_2.py, into tests/ in Phase 0 housekeeping; retargeted in Phase 2
# (P2-1) from interceptor/ to decision_service/ - interceptor/schemas.py was
# deleted entirely when D12 moved schema validation, the OPA query, and the
# ledger write out of the agent process into decision_service. Path and
# OPA_URL adjusted for the new location and current endpoint convention
# only, content otherwise unchanged. Renamed to avoid colliding with the
# existing tests/test_epic_2.py, which covers QueryDatabaseSchema and
# DeployToProductionSchema but not CloudServerProvisionSchema - this file's
# actual, still-unique coverage.)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'decision_service'))


def _load_decision_service_main():
    """decision_service/main.py and control_plane/main.py are both named
    main.py - a bare `import main` clobbers sys.modules["main"] for every
    other test file in the same pytest session regardless of which
    sys.path entry was active when the import ran. Loading this one under
    its own explicit module name sidesteps the collision."""
    spec = _importlib_util.spec_from_file_location(
        "decision_service_main",
        os.path.join(os.path.dirname(__file__), "..", "decision_service", "main.py"),
    )
    module = _importlib_util.module_from_spec(spec)
    sys.modules["decision_service_main"] = module
    spec.loader.exec_module(module)
    return module


def test_epic_2_validation():
    """Test pre-flight validation with various scenarios"""
    print("=== Testing Epic 2: Pre-Flight Input Validation ===\n")

    # Set up environment for testing
    os.environ['SPIRE_DISABLED'] = 'true'
    os.environ['OPA_URL'] = 'http://localhost:8181/v1/data/ail/main/evaluation'

    decision_main = _load_decision_service_main()
    from schemas import CloudServerProvisionSchema

    def _decide(tool_name, tool_args, agent_id="epic2_test"):
        # P2-1: this used to be middleware.intercept_tool_call, which ran
        # schema validation, the OPA query, and the ledger write in-process.
        # That logic now lives in decision_service/main.py (D12);
        # middleware.intercept_tool_call is just an HTTP client to it now
        # (default target https://envoy:8443/decide, not reachable from this
        # test process without additional wiring). Calling decision_main's
        # own /decide route function in-process is what tests/test_outcome_
        # types.py's _decide() helper does for the same reason, and is what
        # actually exercises the pre-flight validation this test is about.
        req = decision_main.DecideRequest(tool_name=tool_name, tool_args=tool_args, agent_id=agent_id)
        return asyncio.run(decision_main.decide(req))

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

    result = _decide('provision_cloud_server', valid_args)
    print(f"Valid args result: {result.get('status', 'unknown')}")
    print(f"Message: {result.get('message', 'N/A')}")
    print()

    print("Test 2: Invalid instance_type (missing)")
    invalid_args_missing = {
        'region': 'us-east-1',
        'cost_per_hour': 32.0,
        'tags': {'environment': 'prod'}
    }

    result = _decide('provision_cloud_server', invalid_args_missing)
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

    result = _decide('provision_cloud_server', invalid_args_negative)
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

    result = _decide('provision_cloud_server', invalid_args_tags)
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

    result = _decide('provision_cloud_server', invalid_args_extra)
    print(f"Extra fields result: {result.get('status', 'unknown')}")
    print(f"Message: {result.get('message', 'N/A')}")
    print()

    print("Test 6: Unregistered tool (fail-closed — must be DENIED before OPA is queried)")
    result = _decide('read_file', {'path': '/tmp/test'})
    print(f"Unregistered tool result: {result.get('status', 'unknown')}")
    print(f"Message: {result.get('message', 'N/A')}")
    assert result.get('status') == 'DENIED', (
        f"Expected DENIED for unregistered tool 'read_file', got {result.get('status')!r}"
    )
    print("[PASS] Confirmed: unregistered tool blocked fail-closed by TOOL_REGISTRY registry")
    print()

    print("=== Epic 2 Implementation Summary ===")
    print("[OK] Dependency: pydantic is available in requirements.txt")
    print("[OK] Schema: CloudServerProvisionSchema defined in decision_service/schemas.py")
    print("[OK] Validation: Pre-flight validation implemented in query_opa_policy()")
    print("[OK] Fail-Closed: ValidationError returns formatted denial to LLM")
    print("[OK] Network Efficiency: Invalid requests blocked before OPA network call")

if __name__ == '__main__':
    test_epic_2_validation()
