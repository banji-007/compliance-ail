"""
tests/test_exclusivity_verification.py - P2-2 (Phase 2, D13).

The registry declares an authority holder, a mechanism, and a claimed
exclusivity kind per tool - but the gateway never records "demonstrated" on
the strength of that claim alone. decision_service/schemas.py::
resolve_exclusivity_for is the one function that decides what actually gets
written to a ledger record, and it answers only from two things it can
itself check: whether the tool's mechanism is one this gateway knows how to
verify at all (schemas._VERIFIABLE_MECHANISMS, a closed set with exactly
one member today), and whether that mechanism's own startup check actually
ran and passed (schemas._MECHANISM_VERIFIED, populated only by
decision_service/main.py actually running the check - never by config).

The planted case below is the spike's A5b shape (docs/reports/
spike-mcp-mediation.md): a tool whose real authority is an ambient shared
resource, configured to claim "demonstrated" anyway. No live stack needed -
this is a pure-function test against the registry logic itself.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "decision_service"))

import schemas  # noqa: E402


def _dummy_validator(tool_args):
    return True, None


def test_ambient_resource_claiming_demonstrated_is_recorded_declared():
    """
    The spike's A5b case, restated as config: a tool whose mechanism is an
    ambient shared resource (never in _VERIFIABLE_MECHANISMS) but whose
    config claims exclusivity_kind "demonstrated" anyway - the gateway must
    still record "declared", because it has no way to check this
    mechanism's exclusivity at all.

    Mutation (P2-2's named mutation): change resolve_exclusivity_for to
    `return reg.claimed_exclusivity` directly, skipping the mechanism/
    verification check. This test must fail against that mutation (it would
    then return "demonstrated").
    """
    ambient_resource_tool = schemas.ToolRegistration(
        validator=_dummy_validator,
        authority_holder="agent (ambient, shared volume)",
        mechanism="shared_volume",
        profile="mediated",
        claimed_exclusivity="demonstrated",
    )
    assert schemas.resolve_exclusivity_for(ambient_resource_tool) == "declared"


def test_verifiable_mechanism_not_yet_verified_is_also_declared():
    """
    Naming the right mechanism string is necessary but not sufficient - the
    gateway must have actually run and passed that mechanism's own check
    this boot. Before decision_service/main.py's startup check runs (or if
    it ran and failed), even the one real verifiable mechanism records
    "declared", not "demonstrated".
    """
    schemas.mark_mechanism_verified("mcp_stdio_secret_mount", False)
    try:
        real_tool = schemas.ToolRegistration(
            validator=_dummy_validator,
            authority_holder="decision-service (vault_server.py subprocess, secret-mounted)",
            mechanism="mcp_stdio_secret_mount",
            profile="mediated",
            claimed_exclusivity="demonstrated",
        )
        assert schemas.resolve_exclusivity_for(real_tool) == "declared"

        schemas.mark_mechanism_verified("mcp_stdio_secret_mount", True)
        assert schemas.resolve_exclusivity_for(real_tool) == "demonstrated"
    finally:
        # Leave global verification state as this module's own startup
        # would set it, so other tests in the same process aren't affected
        # by whichever branch ran last.
        schemas.mark_mechanism_verified("mcp_stdio_secret_mount", False)


def test_tool_with_no_exclusivity_claim_resolves_to_none():
    """
    The three observed, Python-function tools (D15) make no exclusivity
    claim at all - not "declared", not "demonstrated", nothing. A record
    for one of these must never carry an exclusivity key (see
    tests/test_record_profile.py).
    """
    observed_tool = schemas.ToolRegistration(
        validator=_dummy_validator,
        authority_holder="agent (ambient)",
        mechanism="in_process_function",
        profile="observed",
    )
    assert schemas.resolve_exclusivity_for(observed_tool) is None


def test_the_three_python_function_tools_are_registered_observed_with_no_claim():
    for tool_name in ("provision_cloud_server", "query_database", "deploy_to_production"):
        reg = schemas.TOOL_REGISTRY[tool_name]
        assert reg.profile == "observed"
        assert reg.claimed_exclusivity is None
        assert schemas.resolve_exclusivity(tool_name) is None


def test_read_vault_secret_is_registered_mediated_with_the_verifiable_mechanism():
    reg = schemas.TOOL_REGISTRY["read_vault_secret"]
    assert reg.profile == "mediated"
    assert reg.mechanism in schemas._VERIFIABLE_MECHANISMS
    assert reg.claimed_exclusivity == "demonstrated"
