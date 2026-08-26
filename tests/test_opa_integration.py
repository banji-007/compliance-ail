"""
tests/test_opa_integration.py — OPA + decision-service integration tests for provision_cloud_server.

All payloads conform to CloudServerProvisionSchema (instance_type, region,
cost_per_hour, tags: Dict[str, str]).  The original file had no tags field,
causing every test to fail at pre-flight schema validation before reaching OPA.

Skip guards:
  requires_opa               — query_opa_policy tests (no ImmuDB dependency)
  requires_opa_and_immudb    — full-decision tests (ledger required)

Migrated in Phase 2 (P2-1): query_opa_policy moved from
interceptor/middleware.py to decision_service/main.py (D12). Part 2's full
pipeline test (schema -> OPA -> ledger) moved from
middleware.intercept_tool_call (now just an HTTP client to decision_service)
to decision_main.decide(), called in-process via the same `_decide()`
pattern tests/test_outcome_types.py established - this exercises exactly
the same decision/schema/OPA/ledger internals the original test intended,
just from the module that now actually holds them.
"""

import asyncio
import os
import sys

import httpx
import pytest


import importlib.util as _importlib_util

# decision_service/main.py's own `from schemas import ...` needs this
# directory on sys.path - loading main.py itself via spec_from_file_location
# below (to dodge the module-name collision, see _load_decision_service_main)
# does not add its own directory to sys.path automatically the way a normal
# package-relative import would.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "decision_service"))


def _load_decision_service_main():
    """decision_service/main.py and control_plane/main.py are both named
    main.py - a bare `import main` in one test file clobbers whichever
    module sys.modules["main"] already held for every other test file in
    the same pytest session (Python caches by module name, not by which
    sys.path entry was active when the import statement ran - confirmed
    live: test_verification.py's control-plane tests got decision_service's
    module back instead, AttributeError on a function that only exists in
    control_plane/main.py). Loading this one under its own explicit module
    name sidesteps the collision instead of depending on import order."""
    spec = _importlib_util.spec_from_file_location(
        "decision_service_main",
        os.path.join(os.path.dirname(__file__), "..", "decision_service", "main.py"),
    )
    module = _importlib_util.module_from_spec(spec)
    sys.modules["decision_service_main"] = module
    spec.loader.exec_module(module)
    return module


os.environ.setdefault("SPIRE_DISABLED", "true")
os.environ.setdefault("OPA_URL", "http://localhost:8181/v1/data/ail/main/evaluation")

decision_main = _load_decision_service_main()

query_opa_policy = decision_main.query_opa_policy


def _decide(tool_name, tool_args, agent_id="test_opa_agent") -> dict:
    req = decision_main.DecideRequest(tool_name=tool_name, tool_args=tool_args, agent_id=agent_id)
    return asyncio.run(decision_main.decide(req))


# ---------------------------------------------------------------------------
# Infrastructure availability helpers
# ---------------------------------------------------------------------------

requires_opa = pytest.mark.needs_stack("opa")

requires_opa_and_immudb = pytest.mark.needs_stack("opa", "immudb")


# ---------------------------------------------------------------------------
# Shared payload fixtures — all conform to CloudServerProvisionSchema
# ---------------------------------------------------------------------------

# Approved: small instance, approved region, internal data, valid cost center.
_APPROVED_ARGS = {
    "instance_type": "t3.micro",
    "region": "us-east-1",
    "cost_per_hour": 5.0,
    "tags": {
        "environment": "dev",
        "data_classification": "internal",
        "cost_center": "engineering",
        "project": "webapp",
    },
}

# Denied by FinOps: p4d.24xlarge requires tags.project == "ml-training".
_DENIED_RESTRICTED_INSTANCE = {
    "instance_type": "p4d.24xlarge",
    "region": "us-east-1",
    "cost_per_hour": 50.0,
    "tags": {
        "environment": "dev",
        "data_classification": "internal",
        "cost_center": "engineering",
        "project": "webapp",        # not "ml-training" → FinOps denial
    },
}

# Approved: non-approved region but data_classification="internal" so neither
# GDPR pci-dss rule nor unclassified-data rule fires.
_APPROVED_NON_DEFAULT_REGION = {
    "instance_type": "t3.micro",
    "region": "us-west-2",
    "cost_per_hour": 5.0,
    "tags": {
        "environment": "dev",
        "data_classification": "internal",
        "cost_center": "engineering",
        "project": "webapp",
    },
}

# Denied by FinOps (wrong project tag on restricted instance).
_DENIED_WRONG_PROJECT = {
    "instance_type": "p4d.24xlarge",
    "region": "eu-west-1",
    "cost_per_hour": 25.0,
    "tags": {
        "environment": "dev",
        "data_classification": "internal",
        "cost_center": "engineering",
        "project": "webapp",        # not "ml-training" → FinOps denial
    },
}


# ---------------------------------------------------------------------------
# Part 1: query_opa_policy — no ImmuDB dependency
# ---------------------------------------------------------------------------

@requires_opa
class TestOpaPolicy:
    """Direct OPA policy evaluation tests for provision_cloud_server."""

    def test_small_instance_approved(self):
        """t3.micro in an approved region with valid tags must be allowed."""
        result = query_opa_policy("provision_cloud_server", _APPROVED_ARGS)
        assert result["outcome_type"] == "policy_allow", (
            f"Expected policy_allow for t3.micro/us-east-1, got: {result}"
        )
        assert result["policy_revision"], f"Expected a policy_revision, got: {result}"

    def test_restricted_instance_without_ml_training_denied(self):
        """p4d.24xlarge without project=ml-training must be denied by FinOps."""
        result = query_opa_policy("provision_cloud_server", _DENIED_RESTRICTED_INSTANCE)
        assert result["outcome_type"] == "policy_deny", (
            f"Expected policy_deny for p4d.24xlarge/webapp, got: {result}"
        )
        denial_text = " ".join(result.get("reasons", []))
        assert any(kw in denial_text for kw in ("ml-training", "FinOps", "restricted", "Instance")), (
            f"Expected FinOps denial text, got: {denial_text!r}"
        )

    def test_small_instance_non_approved_region_with_internal_data_approved(self):
        """t3.micro in us-west-2 with data_classification=internal must be allowed.

        GDPR residency rules only fire for pci-dss or unclassified data.
        'internal' classification is neither, so no rule denies this request.
        """
        result = query_opa_policy("provision_cloud_server", _APPROVED_NON_DEFAULT_REGION)
        assert result["outcome_type"] == "policy_allow", (
            f"Expected policy_allow for t3.micro/us-west-2/internal, got: {result}"
        )

    def test_restricted_instance_wrong_project_denied(self):
        """p4d.24xlarge with project=webapp (not ml-training) must be denied."""
        result = query_opa_policy("provision_cloud_server", _DENIED_WRONG_PROJECT)
        assert result["outcome_type"] == "policy_deny", (
            f"Expected policy_deny for p4d.24xlarge/webapp/eu-west-1, got: {result}"
        )


# ---------------------------------------------------------------------------
# Part 2: the full decision (schema -> OPA -> ledger) — requires OPA + ImmuDB
# ---------------------------------------------------------------------------

@requires_opa_and_immudb
class TestInterceptorWithOpa:
    """Full decision pipeline tests. Requires both OPA and ImmuDB."""

    def test_approved_request_returns_approved_status(self):
        """A schema-valid, policy-compliant request must reach APPROVED status."""
        response = _decide(
            "provision_cloud_server", _APPROVED_ARGS, "test_opa_agent"
        )
        assert "status" in response
        assert response["status"] == "APPROVED", (
            f"Expected APPROVED, got: {response}"
        )

    def test_denied_request_returns_denied_status(self):
        """A restricted instance without ml-training tag must reach DENIED status."""
        response = _decide(
            "provision_cloud_server", _DENIED_RESTRICTED_INSTANCE, "test_opa_agent"
        )
        assert "status" in response
        assert response["status"] == "DENIED", (
            f"Expected DENIED, got: {response}"
        )
