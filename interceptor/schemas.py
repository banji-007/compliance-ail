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
    instance_type: str = Field(..., description="EC2 instance type (e.g., 'p4d.24xlarge')")
    region: str = Field(..., description="AWS region (e.g., 'us-east-1')")
    cost_per_hour: float = Field(..., gt=0, description="Hourly cost in USD (must be positive)")
    tags: Dict[str, str] = Field(..., description="Dictionary of tags with string keys and values")

    model_config = {"extra": "forbid"}


class QueryDatabaseSchema(BaseModel):
    """
    Strict schema for database query tool arguments.
    Ensures target_table, query, processing_purpose, and masking_enabled are
    all present and correctly typed before the call reaches OPA.
    """
    target_table: str = Field(..., description="Database table to query (e.g., 'users', 'pii_records')")
    query: str = Field(..., description="SQL query or query description to execute")
    processing_purpose: str = Field(..., description="Declared business purpose for accessing this data")
    masking_enabled: bool = Field(..., description="Whether PII field masking is enabled")

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


# Registry used by middleware for dict-based routing.
# Adding a new tool: (1) define a schema above, (2) add an entry here.
TOOL_VALIDATORS: Dict[str, Callable[[dict], tuple[bool, Optional[str]]]] = {
    "provision_cloud_server": validate_cloud_server_args,
    "query_database": validate_query_database_args,
}
