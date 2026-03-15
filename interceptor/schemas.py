"""
Pydantic schemas for pre-flight input validation (Stage 2 of the AIL pipeline).

Every registered tool must have a schema here. The middleware routes incoming
tool calls to the appropriate validator via TOOL_VALIDATORS. An unregistered
tool name is treated as fail-closed: execution is blocked before OPA is queried.
"""

from typing import Callable, Dict, Optional
from pydantic import BaseModel, Field, ValidationError


# ---------------------------------------------------------------------------
# Per-tool schemas
# ---------------------------------------------------------------------------

class CloudServerProvisionSchema(BaseModel):
    """
    Strict schema for cloud server provisioning tool arguments.
    Catches LLM hallucinations before they reach OPA.
    """
    # e.g. "t3.micro", "p4d.24xlarge" — alphanumeric with dots/dashes only
    instance_type: str = Field(
        ...,
        pattern=r'^[a-z][a-z0-9\-]*\.[a-z0-9]+$',
        max_length=32,
        description="EC2 instance type (e.g., 'p4d.24xlarge')",
    )
    # e.g. "us-east-1", "eu-central-1"
    region: str = Field(
        ...,
        pattern=r'^[a-z]{2}-[a-z]+-\d+$',
        max_length=24,
        description="AWS region (e.g., 'us-east-1')",
    )
    cost_per_hour: float = Field(..., gt=0, description="Hourly cost in USD (must be positive)")
    tags: Dict[str, str] = Field(..., description="Dictionary of tags with string keys and values")

    model_config = {"extra": "forbid"}


class QueryDatabaseSchema(BaseModel):
    """
    Strict schema for database query tool arguments.
    Ensures target_table, query, processing_purpose, and masking_enabled are
    all present and correctly typed before the call reaches OPA.
    """
    # Table names: letters, digits, underscores only — no SQL metacharacters
    target_table: str = Field(
        ...,
        pattern=r'^[a-zA-Z_][a-zA-Z0-9_]*$',
        max_length=128,
        description="Database table to query (e.g., 'users', 'pii_records')",
    )
    query: str = Field(..., max_length=4096, description="SQL query or query description to execute")
    processing_purpose: str = Field(
        ...,
        pattern=r'^[a-zA-Z0-9_\-]+$',
        max_length=64,
        description="Declared business purpose for accessing this data",
    )
    masking_enabled: bool = Field(..., description="Whether PII field masking is enabled")

    model_config = {"extra": "forbid"}


class DeployToProductionSchema(BaseModel):
    """
    Strict schema for production deployment tool arguments.
    Ensures change-management fields are present and correctly typed
    before the call reaches OPA (SOC2 CC8.1 / FinOps guardrails).
    """
    # Repo names: alphanumeric, dash, underscore, dot — no path traversal
    repository_name: str = Field(
        ...,
        pattern=r'^[a-zA-Z0-9][a-zA-Z0-9_\-\.]*$',
        max_length=255,
        description="Name of the code repository being deployed",
    )
    # Git SHA: hex chars only, 7–64 characters
    commit_hash: str = Field(
        ...,
        pattern=r'^[0-9a-f]{7,64}$',
        description="Git commit SHA being deployed",
    )
    # Environment: lowercase alphanumeric with dashes
    environment: str = Field(
        ...,
        pattern=r'^[a-z][a-z0-9\-]*$',
        max_length=32,
        description="Target environment (e.g., 'staging', 'production')",
    )
    approval_ticket: str = Field(
        ...,
        max_length=64,
        description="Jira/ServiceNow ticket reference; empty string if absent (policy will deny)",
    )
    bypass_ci: bool = Field(..., description="Whether automated CI/CD checks are being skipped")

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# Shared validation helper
# ---------------------------------------------------------------------------

def _validate(schema_cls: type[BaseModel], tool_args: dict) -> tuple[bool, Optional[str]]:
    try:
        schema_cls(**tool_args)
        return True, None
    except ValidationError as e:
        parts = [
            f"{' -> '.join(str(x) for x in err['loc'])}: {err['msg']}"
            for err in e.errors()
        ]
        return False, "; ".join(parts)


# ---------------------------------------------------------------------------
# Public API — one entry point per tool, plus registry for middleware routing
# ---------------------------------------------------------------------------

def validate_cloud_server_args(tool_args: dict) -> tuple[bool, Optional[str]]:
    return _validate(CloudServerProvisionSchema, tool_args)


def validate_query_database_args(tool_args: dict) -> tuple[bool, Optional[str]]:
    return _validate(QueryDatabaseSchema, tool_args)


def validate_deploy_to_production_args(tool_args: dict) -> tuple[bool, Optional[str]]:
    return _validate(DeployToProductionSchema, tool_args)


# Registry used by middleware for dict-based routing.
# Adding a new tool: (1) define a schema above, (2) add an entry here.
TOOL_VALIDATORS: Dict[str, Callable[[dict], tuple[bool, Optional[str]]]] = {
    "provision_cloud_server": validate_cloud_server_args,
    "query_database": validate_query_database_args,
    "deploy_to_production": validate_deploy_to_production_args,
}
