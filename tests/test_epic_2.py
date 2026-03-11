"""
tests/test_epic_2.py — Pytest test suite for Phase 4 pre-flight validation.

Part A — Pure schema unit tests      (no I/O, always run)
Part B — Middleware routing tests    (no OPA / ImmuDB — returns before network)
Part C — OPA integration tests       (skipped if OPA unreachable at localhost:8181)
"""

import os
import sys

import httpx
import pytest

# Make the interceptor package importable from within the tests/ directory.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "interceptor"))

# ---------------------------------------------------------------------------
# Environment must be set BEFORE middleware is imported so that Prometheus
# and SPIRE init code picks up dev-mode settings on first import.
# ---------------------------------------------------------------------------
os.environ.setdefault("SPIRE_DISABLED", "true")
os.environ.setdefault("OPA_URL", "http://localhost:8181/v1/data/ail/main/allow")


# ===========================================================================
# Part A: Pure Schema Unit Tests
# ===========================================================================

from pydantic import ValidationError  # noqa: E402 — after sys.path patch
from schemas import TOOL_VALIDATORS, QueryDatabaseSchema, DeployToProductionSchema  # noqa: E402


class TestQueryDatabaseSchema:
    """Unit tests for QueryDatabaseSchema. No I/O; always run."""

    def test_valid_payload_parses_correctly(self):
        """Positive case: all required fields present with correct types."""
        schema = QueryDatabaseSchema(
            target_table="pii_records",
            query="SELECT id, name FROM pii_records WHERE id = 42",
            processing_purpose="customer_support",
            masking_enabled=True,
        )
        assert schema.target_table == "pii_records"
        assert schema.processing_purpose == "customer_support"
        assert schema.masking_enabled is True

    def test_missing_required_field_raises(self):
        """Negative case 1: omitting processing_purpose must raise ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            QueryDatabaseSchema(
                target_table="pii_records",
                query="SELECT *",
                # processing_purpose intentionally omitted
                masking_enabled=True,
            )
        field_names = [e["loc"][0] for e in exc_info.value.errors()]
        assert "processing_purpose" in field_names

    def test_type_mismatch_masking_enabled_raises(self):
        """Negative case 2: masking_enabled as a non-coercible string raises ValidationError.

        Pydantic v2 lax mode accepts 'yes'/'no'/'true'/'false' etc. as valid
        bool strings. 'not_a_bool' is outside that set and must fail.
        """
        with pytest.raises(ValidationError) as exc_info:
            QueryDatabaseSchema(
                target_table="pii_records",
                query="SELECT *",
                processing_purpose="customer_support",
                masking_enabled="not_a_bool",
            )
        field_names = [e["loc"][0] for e in exc_info.value.errors()]
        assert "masking_enabled" in field_names


class TestDeployToProductionSchema:
    """Unit tests for DeployToProductionSchema. No I/O; always run."""

    def test_valid_payload_parses_correctly(self):
        """Positive case: all required fields present with correct types."""
        schema = DeployToProductionSchema(
            repository_name="auth-service",
            commit_hash="abc123def456",
            environment="production",
            approval_ticket="PROJ-999",
            bypass_ci=False,
        )
        assert schema.repository_name == "auth-service"
        assert schema.environment == "production"
        assert schema.bypass_ci is False

    def test_missing_required_field_raises(self):
        """Negative case 1: omitting commit_hash must raise ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            DeployToProductionSchema(
                repository_name="auth-service",
                # commit_hash intentionally omitted
                environment="production",
                approval_ticket="PROJ-999",
                bypass_ci=False,
            )
        field_names = [e["loc"][0] for e in exc_info.value.errors()]
        assert "commit_hash" in field_names

    def test_type_mismatch_bypass_ci_raises(self):
        """Negative case 2: bypass_ci as a non-coercible string raises ValidationError.

        Pydantic v2 lax mode accepts 'yes'/'no'/'true'/'false' etc. as valid
        bool strings. 'not_a_bool' is outside that set and must fail.
        """
        with pytest.raises(ValidationError) as exc_info:
            DeployToProductionSchema(
                repository_name="auth-service",
                commit_hash="abc123def456",
                environment="production",
                approval_ticket="PROJ-999",
                bypass_ci="not_a_bool",
            )
        field_names = [e["loc"][0] for e in exc_info.value.errors()]
        assert "bypass_ci" in field_names


class TestToolValidatorsRegistry:
    """Assert the TOOL_VALIDATORS registry contains the expected tool entries."""

    def test_provision_cloud_server_registered(self):
        assert "provision_cloud_server" in TOOL_VALIDATORS

    def test_query_database_registered(self):
        assert "query_database" in TOOL_VALIDATORS

    def test_deploy_to_production_registered(self):
        assert "deploy_to_production" in TOOL_VALIDATORS


# ===========================================================================
# Part B: Middleware Routing Tests (no OPA / no ImmuDB)
# ===========================================================================

from middleware import query_opa_policy  # noqa: E402


class TestMiddlewareRoutingFailClosed:
    """Tests for the TOOL_VALIDATORS routing stage inside query_opa_policy.

    query_opa_policy returns a fail-closed denial at the registry lookup
    (middleware.py lines 202-210) before any network call to OPA is made
    and before intercept_tool_call's ImmuDB block is reached.
    No mocking is required.
    """

    def test_hallucinated_tool_is_denied(self):
        """An unregistered tool name must produce allowed=False."""
        result = query_opa_policy("hallucinated_tool", {"arbitrary": "payload"})
        assert result["allowed"] is False

    def test_hallucinated_tool_denial_names_the_tool(self):
        """The denial reason must reference the unknown tool name, not a generic OPA error.

        This distinguishes a pre-flight registry miss from an OPA network failure.
        """
        result = query_opa_policy("hallucinated_tool", {"arbitrary": "payload"})
        assert "hallucinated_tool" in result["reason"]

    def test_hallucinated_tool_returns_populated_deny_list(self):
        """deny must be a non-empty list so downstream Prometheus labeling never KeyErrors."""
        result = query_opa_policy("hallucinated_tool", {"arbitrary": "payload"})
        assert isinstance(result.get("deny"), list)
        assert len(result["deny"]) > 0


# ===========================================================================
# Part C: OPA Integration Tests
# ===========================================================================


def _opa_reachable() -> bool:
    """Return True if OPA is responding at localhost:8181."""
    try:
        httpx.get("http://localhost:8181/health", timeout=2)
        return True
    except Exception:
        return False


requires_opa = pytest.mark.skipif(
    not _opa_reachable(),
    reason="OPA not reachable at localhost:8181 — skipping OPA integration tests",
)


@requires_opa
class TestQueryDatabaseOpaIntegration:
    """OPA Rego evaluation tests for the query_database tool.

    These tests verify that the Rego rules in policy/packs/soc2/soc2.rego and
    policy/packs/gdpr/gdpr.rego fire correctly for query_database inputs.

    Requires OPA running with the full policy bundle loaded:
        policy/core/main.rego + policy/packs/*/

    The base payload is schema-valid so inputs always pass Pydantic pre-flight
    validation and reach OPA. Individual tests mutate only the field under test.
    """

    # A fully valid base payload — passes QueryDatabaseSchema without errors.
    _BASE = {
        "target_table": "pii_records",
        "query": "SELECT id, name FROM pii_records WHERE id = 42",
        "processing_purpose": "customer_support",  # approved default in gdpr.rego
        "masking_enabled": True,
    }

    def test_soc2_denies_unmasked_pii_query(self):
        """SOC2 CC6.1: masking_enabled=False on a table containing 'pii' must be denied.

        Expected denial text: 'DENIED: SOC2 Violation. Unmasked queries on PII tables...'
        """
        args = {**self._BASE, "masking_enabled": False}
        result = query_opa_policy("query_database", args)

        assert result["allowed"] is False
        denial_text = " ".join(result.get("deny", [])) + " " + result.get("reason", "")
        assert "SOC2" in denial_text, (
            f"Expected SOC2 in denial text, got: {denial_text!r}"
        )

    def test_gdpr_denies_unapproved_processing_purpose(self):
        """GDPR Art.5(1)(b): an unapproved processing_purpose on a 'pii' table must be denied.

        masking_enabled=True satisfies SOC2 so only the GDPR rule fires.
        Expected denial text: 'DENIED: GDPR Violation. Unauthorized processing purpose...'
        """
        args = {**self._BASE, "processing_purpose": "marketing_profiling"}
        result = query_opa_policy("query_database", args)

        assert result["allowed"] is False
        denial_text = " ".join(result.get("deny", [])) + " " + result.get("reason", "")
        assert "GDPR" in denial_text, (
            f"Expected GDPR in denial text, got: {denial_text!r}"
        )


@requires_opa
class TestDeployToProductionOpaIntegration:
    """OPA Rego evaluation tests for the deploy_to_production tool.

    Verifies SOC2 CC8.1 rules (soc2.rego) and the FinOps experimental
    guardrail (finops.rego) fire correctly.

    The base payload is schema-valid and targets 'staging' with a valid ticket
    and bypass_ci=False. Individual tests mutate only the field under test.
    """

    _BASE = {
        "repository_name": "auth-service",
        "commit_hash": "abc123def456",
        "environment": "staging",
        "approval_ticket": "PROJ-999",
        "bypass_ci": False,
    }

    def test_soc2_denies_production_deploy_without_approval_ticket(self):
        """SOC2 CC8.1: environment='production' with an empty approval_ticket must be denied.

        Expected denial text: 'SOC2 CC8.1 Violation: Production deployments require...'
        """
        args = {**self._BASE, "environment": "production", "approval_ticket": ""}
        result = query_opa_policy("deploy_to_production", args)

        assert result["allowed"] is False
        denial_text = " ".join(result.get("deny", [])) + " " + result.get("reason", "")
        assert "SOC2" in denial_text, (
            f"Expected SOC2 in denial text, got: {denial_text!r}"
        )

    def test_soc2_denies_bypass_ci(self):
        """SOC2 CC8.1: bypass_ci=True must be denied regardless of environment.

        Expected denial text: 'SOC2 CC8.1 Violation: Bypassing CI/CD pipeline...'
        """
        args = {**self._BASE, "bypass_ci": True}
        result = query_opa_policy("deploy_to_production", args)

        assert result["allowed"] is False
        denial_text = " ".join(result.get("deny", [])) + " " + result.get("reason", "")
        assert "SOC2" in denial_text, (
            f"Expected SOC2 in denial text, got: {denial_text!r}"
        )

    def test_finops_denies_experimental_repo_in_production(self):
        """FinOps: repository_name containing 'experimental' targeting 'production' must be denied.

        bypass_ci=False and a valid ticket satisfy SOC2, so only the FinOps rule fires.
        Expected denial text: 'FinOps Violation: Experimental repositories...'
        """
        args = {
            **self._BASE,
            "repository_name": "experimental-ml-pipeline",
            "environment": "production",
            "approval_ticket": "PROJ-999",
        }
        result = query_opa_policy("deploy_to_production", args)

        assert result["allowed"] is False
        denial_text = " ".join(result.get("deny", [])) + " " + result.get("reason", "")
        assert "FinOps" in denial_text, (
            f"Expected FinOps in denial text, got: {denial_text!r}"
        )
