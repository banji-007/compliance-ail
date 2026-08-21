"""
Pydantic schemas and the tool registry (Stage 2 of the AIL pipeline), moved
here from interceptor/schemas.py (Phase 2, D12): the agent process no longer
ships any of this.

D13 extends the registry beyond a bare validator: every entry also declares
who holds the tool's real authority, by what mechanism, and whether that
mechanism is a kind the gateway can independently verify ("demonstrated") or
only assert ("declared"). The distinction is never taken from config as-is -
see resolve_exclusivity_for below, which is the only function allowed to
produce the value a ledger record actually carries.
"""

import logging
from dataclasses import dataclass
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
    instance_type: str = Field(
        ...,
        pattern=r'^[a-z][a-z0-9\-]*\.[a-z0-9]+$',
        max_length=32,
        description="EC2 instance type (e.g., 'p4d.24xlarge')",
    )
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
    """
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
    """
    repository_name: str = Field(
        ...,
        pattern=r'^[a-zA-Z0-9][a-zA-Z0-9_\-\.]*$',
        max_length=255,
        description="Name of the code repository being deployed",
    )
    commit_hash: str = Field(
        ...,
        pattern=r'^[0-9a-f]{7,64}$',
        description="Git commit SHA being deployed",
    )
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


class ReadVaultSecretSchema(BaseModel):
    """
    Strict schema for the D14 demonstration tool. secret_name is a lookup
    key into vault_server.py's in-memory vault, never the secret value
    itself - the value never appears in a tool call's arguments, so it
    never reaches the schema layer, the ledger's input_sha256, or the
    erasable content store.
    """
    secret_name: str = Field(
        ...,
        pattern=r'^[a-z][a-z0-9_]*$',
        max_length=64,
        description="Name of the vault secret to read (e.g., 'db_master_password')",
    )

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


def validate_cloud_server_args(tool_args: dict) -> tuple[bool, Optional[str]]:
    return _validate(CloudServerProvisionSchema, tool_args)


def validate_query_database_args(tool_args: dict) -> tuple[bool, Optional[str]]:
    return _validate(QueryDatabaseSchema, tool_args)


def validate_deploy_to_production_args(tool_args: dict) -> tuple[bool, Optional[str]]:
    return _validate(DeployToProductionSchema, tool_args)


def validate_read_vault_secret_args(tool_args: dict) -> tuple[bool, Optional[str]]:
    return _validate(ReadVaultSecretSchema, tool_args)


# ---------------------------------------------------------------------------
# D13: the registry - authority holder, mechanism, and a claimed exclusivity
# kind per tool. The claim is never trusted verbatim; see below.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ToolRegistration:
    validator: Callable[[dict], tuple[bool, Optional[str]]]
    authority_holder: str
    mechanism: str
    profile: str  # "observed" | "mediated" (ADR-0005's closed set)
    # What this tool's config claims about its own exclusivity. None for
    # tools that make no such claim at all (the three observed tools - D15
    # labels them, it does not ask them to pretend to be something else).
    claimed_exclusivity: Optional[str] = None


# Mechanisms this gateway actually knows how to check, not just name. A
# mechanism string appearing here is necessary but not sufficient for
# "demonstrated" - see _TOOL_VERIFIED below, populated only by
# run_verification_pass() actually running that mechanism's own check,
# once per tool that claims it.
_VERIFIABLE_MECHANISMS = frozenset({"mcp_stdio_secret_mount"})

# D17 (Phase 2 completion pass): mechanism name -> the callable that checks
# it, registered by main.py at import time (registration is cheap; running
# the check is not, and stays confined to run_verification_pass()).
_MECHANISM_VERIFIERS: Dict[str, Callable[[], bool]] = {}

# D17: keyed by TOOL NAME, not by mechanism string. Before this, a single
# mechanism-keyed cache meant a second tool declaring the identical
# mechanism string as an already-verified tool would inherit that result
# without the check ever running again in that tool's own name - config
# alone would then be enough to make it "demonstrated" for a tool the
# gateway never actually checked, which is exactly what D13 forbids.
# Populated only by run_verification_pass(); never set from config, and
# never assumed for a tool absent from this dict (see the late-registration
# note below).
_TOOL_VERIFIED: Dict[str, bool] = {}

# Set to True only once run_verification_pass() has iterated every tool
# present in TOOL_REGISTRY at that moment. A tool appended to TOOL_REGISTRY
# after that point (there is no runtime registration API today, but nothing
# stops one being added later) is never a key in _TOOL_VERIFIED, and
# resolve_exclusivity_for's dict lookup already treats an absent key as
# unverified - so such a tool is refused "demonstrated" unconditionally,
# structurally, not by an extra check that could itself be forgotten.
_VERIFICATION_PASS_COMPLETE = False


def register_mechanism_verifier(mechanism: str, verify_fn: Callable[[], bool]) -> None:
    _MECHANISM_VERIFIERS[mechanism] = verify_fn


def run_verification_pass() -> None:
    """
    D17: called once, at decision-service startup, before the app accepts
    traffic. For every tool currently in TOOL_REGISTRY whose mechanism is
    verifiable, this independently invokes that mechanism's own check and
    stores the result under the TOOL's name - even if two tools name the
    identical mechanism string, each one triggers its own call, so neither
    can inherit the other's result.

    Mutation (D17's named mutation): cache the check's result per mechanism
    and skip re-invoking it for a second tool sharing that mechanism string
    (the old behavior). tests/test_exclusivity_verification.py asserts the
    verifier callable is invoked once per verifiable tool, not once total -
    this mutation drops that count and fails the test directly.
    """
    global _VERIFICATION_PASS_COMPLETE
    for tool_name, reg in TOOL_REGISTRY.items():
        if reg.mechanism not in _VERIFIABLE_MECHANISMS:
            continue
        verify_fn = _MECHANISM_VERIFIERS.get(reg.mechanism)
        result = bool(verify_fn()) if verify_fn is not None else False
        _TOOL_VERIFIED[tool_name] = result
        logging.info("Verification pass: tool=%s mechanism=%s verified=%s", tool_name, reg.mechanism, result)
    _VERIFICATION_PASS_COMPLETE = True


def get_verified_tools() -> Dict[str, bool]:
    return dict(_TOOL_VERIFIED)


def resolve_exclusivity_for(tool_name: str, reg: ToolRegistration) -> Optional[str]:
    """
    D13's own rule, as code: a record's exclusivity kind is never read off
    a tool's config. It is "demonstrated" only if this specific tool's own
    name is present in _TOOL_VERIFIED with a True result - never inferred
    from another tool, never from the mechanism string alone. This is what
    catches the spike's A5b case (a tool whose real authority is an ambient
    shared resource, mechanism outside _VERIFIABLE_MECHANISMS, cannot be
    recorded "demonstrated" no matter what its own config says) and D17's
    own case (a tool sharing a verified tool's mechanism string is not
    itself verified merely by that coincidence, and a tool added after
    run_verification_pass() already ran is never verified at all).

    Returns None for a tool with no exclusivity claim at all (the three
    observed, Python-function tools - profile is "observed" for these, and
    no exclusivity key is ever written to their records at all).
    """
    if reg.claimed_exclusivity is None:
        return None
    if _TOOL_VERIFIED.get(tool_name) is True:
        return "demonstrated"
    return "declared"


def resolve_exclusivity(tool_name: str) -> Optional[str]:
    reg = TOOL_REGISTRY.get(tool_name)
    if reg is None:
        return None
    return resolve_exclusivity_for(tool_name, reg)


# Registry used by main.py for dict-based routing.
# Adding a new tool: (1) define a schema above, (2) add an entry here.
TOOL_REGISTRY: Dict[str, ToolRegistration] = {
    "provision_cloud_server": ToolRegistration(
        validate_cloud_server_args, "agent (ambient)", "in_process_function", "observed",
    ),
    "query_database": ToolRegistration(
        validate_query_database_args, "agent (ambient)", "in_process_function", "observed",
    ),
    "deploy_to_production": ToolRegistration(
        validate_deploy_to_production_args, "agent (ambient)", "in_process_function", "observed",
    ),
    "read_vault_secret": ToolRegistration(
        validate_read_vault_secret_args,
        "decision-service (vault_server.py subprocess, secret-mounted)",
        "mcp_stdio_secret_mount",
        "mediated",
        claimed_exclusivity="demonstrated",
    ),
}
