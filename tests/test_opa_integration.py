"""
tests/test_opa_integration.py — OPA + interceptor integration tests for provision_cloud_server.

All payloads conform to CloudServerProvisionSchema (instance_type, region,
cost_per_hour, tags: Dict[str, str]).  The original file had no tags field,
causing every test to fail at pre-flight schema validation before reaching OPA.

Skip guards:
  requires_opa               — query_opa_policy tests (no ImmuDB dependency)
  requires_opa_and_immudb    — intercept_tool_call tests (ledger required)
"""

import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "interceptor"))

os.environ.setdefault("SPIRE_DISABLED", "true")
os.environ.setdefault("OPA_URL", "http://localhost:8181/v1/data/ail/main/allow")

from middleware import intercept_tool_call, query_opa_policy  # noqa: E402


# ---------------------------------------------------------------------------
# Infrastructure availability helpers
# ---------------------------------------------------------------------------

def _opa_reachable() -> bool:
    try:
        httpx.get("http://localhost:8181/health", timeout=2)
        return True
    except Exception:
        return False


def _immudb_reachable() -> bool:
    immudb_url = os.getenv("IMMUDB_URL", "http://localhost:8080")
    try:
        # Any HTTP response (even 401) means the REST API is up.
        httpx.get(immudb_url, timeout=2)
        return True
    except Exception:
        return False


requires_opa = pytest.mark.skipif(
    not _opa_reachable(),
    reason="OPA not reachable at localhost:8181",
)

requires_opa_and_immudb = pytest.mark.skipif(
    not (_opa_reachable() and _immudb_reachable()),
    reason="OPA (localhost:8181) and/or ImmuDB (IMMUDB_URL) not reachable",
)


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
        assert result["allowed"] is True, (
            f"Expected APPROVED for t3.micro/us-east-1, got: {result}"
        )

    def test_restricted_instance_without_ml_training_denied(self):
        """p4d.24xlarge without project=ml-training must be denied by FinOps."""
        result = query_opa_policy("provision_cloud_server", _DENIED_RESTRICTED_INSTANCE)
        assert result["allowed"] is False, (
            f"Expected DENIED for p4d.24xlarge/webapp, got: {result}"
        )
        denial_text = " ".join(result.get("deny", [])) + " " + result.get("reason", "")
        assert any(kw in denial_text for kw in ("ml-training", "FinOps", "restricted", "Instance")), (
            f"Expected FinOps denial text, got: {denial_text!r}"
        )

    def test_small_instance_non_approved_region_with_internal_data_approved(self):
        """t3.micro in us-west-2 with data_classification=internal must be allowed.

        GDPR residency rules only fire for pci-dss or unclassified data.
        'internal' classification is neither, so no rule denies this request.
        """
        result = query_opa_policy("provision_cloud_server", _APPROVED_NON_DEFAULT_REGION)
        assert result["allowed"] is True, (
            f"Expected APPROVED for t3.micro/us-west-2/internal, got: {result}"
        )

    def test_restricted_instance_wrong_project_denied(self):
        """p4d.24xlarge with project=webapp (not ml-training) must be denied."""
        result = query_opa_policy("provision_cloud_server", _DENIED_WRONG_PROJECT)
        assert result["allowed"] is False, (
            f"Expected DENIED for p4d.24xlarge/webapp/eu-west-1, got: {result}"
        )


# ---------------------------------------------------------------------------
# Part 2: intercept_tool_call — requires OPA + ImmuDB
# ---------------------------------------------------------------------------

@requires_opa_and_immudb
class TestInterceptorWithOpa:
    """Full interceptor pipeline tests. Requires both OPA and ImmuDB."""

    def test_approved_request_returns_approved_status(self):
        """A schema-valid, policy-compliant request must reach APPROVED status."""
        response = intercept_tool_call(
            "provision_cloud_server", _APPROVED_ARGS, "test_opa_agent"
        )
        assert "status" in response
        assert response["status"] == "APPROVED", (
            f"Expected APPROVED, got: {response}"
        )

    def test_denied_request_returns_denied_status(self):
        """A restricted instance without ml-training tag must reach DENIED status."""
        response = intercept_tool_call(
            "provision_cloud_server", _DENIED_RESTRICTED_INSTANCE, "test_opa_agent"
        )
        assert "status" in response
        assert response["status"] == "DENIED", (
            f"Expected DENIED, got: {response}"
        )


# ---------------------------------------------------------------------------
# Part 3: ledger notice (documentation — no assertions required)
# ---------------------------------------------------------------------------

def test_ledger_after_opa():
    """Reminder: ImmuDB is the source of truth for audit records."""
    print("\nAll intercepts are logged to ImmuDB cryptographic ledger.")
    print("ImmuDB is the source of truth for audit records.")
    print("Use ImmuDB client tools to query the audit trail.")
