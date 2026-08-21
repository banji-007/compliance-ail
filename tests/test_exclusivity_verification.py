"""
tests/test_exclusivity_verification.py - P2-2 (Phase 2, D13) and D17 (Phase 2
completion pass).

The registry declares an authority holder, a mechanism, and a claimed
exclusivity kind per tool - but the gateway never records "demonstrated" on
the strength of that claim alone. decision_service/schemas.py::
resolve_exclusivity_for is the one function that decides what actually gets
written to a ledger record, and it answers only from two things it can
itself check: whether the tool's mechanism is one this gateway knows how to
verify at all (schemas._VERIFIABLE_MECHANISMS, a closed set with exactly
one member today), and whether THAT SPECIFIC TOOL's own name is present in
schemas._TOOL_VERIFIED with a True result - populated only by
run_verification_pass() actually invoking the mechanism's check once per
tool that claims it, never by config, and never inherited from another
tool sharing the same mechanism string (D17).

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


def _reset_verification_state():
    schemas._TOOL_VERIFIED.clear()
    schemas._MECHANISM_VERIFIERS.clear()
    schemas._VERIFICATION_PASS_COMPLETE = False


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
    assert schemas.resolve_exclusivity_for("ambient_resource_tool", ambient_resource_tool) == "declared"


def test_verifiable_mechanism_not_yet_verified_is_also_declared():
    """
    Naming the right mechanism string is necessary but not sufficient - the
    gateway must have actually run and passed that mechanism's own check,
    for THIS tool, this boot. Before decision_service/main.py's startup
    check runs (or if it ran and failed for this tool), even the one real
    verifiable mechanism records "declared", not "demonstrated".
    """
    saved = dict(schemas._TOOL_VERIFIED)
    try:
        real_tool = schemas.ToolRegistration(
            validator=_dummy_validator,
            authority_holder="decision-service (vault_server.py subprocess, secret-mounted)",
            mechanism="mcp_stdio_secret_mount",
            profile="mediated",
            claimed_exclusivity="demonstrated",
        )
        schemas._TOOL_VERIFIED["real_tool"] = False
        assert schemas.resolve_exclusivity_for("real_tool", real_tool) == "declared"

        schemas._TOOL_VERIFIED["real_tool"] = True
        assert schemas.resolve_exclusivity_for("real_tool", real_tool) == "demonstrated"
    finally:
        schemas._TOOL_VERIFIED.clear()
        schemas._TOOL_VERIFIED.update(saved)


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
    assert schemas.resolve_exclusivity_for("observed_tool", observed_tool) is None


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


# ---------------------------------------------------------------------------
# D17 (Phase 2 completion pass): verification is keyed by tool, not by
# mechanism string.
# ---------------------------------------------------------------------------

def test_two_tools_sharing_a_mechanism_are_each_independently_verified():
    """
    Before D17, _MECHANISM_VERIFIED was a boolean keyed on the mechanism
    string - a check run for one tool populated a value a second tool
    naming the same mechanism would read directly, without its own
    verification ever running. run_verification_pass() must invoke the
    mechanism's check once per tool that claims it, not once per mechanism
    - proven here by call count, since the check itself has no per-tool
    parameter and so can't be distinguished by differing return values
    alone.

    Mutation (D17's named mutation): cache the check's result the first
    time a mechanism is seen and reuse it for subsequent tools naming the
    same mechanism, instead of invoking it again. This drops the call count
    from 2 to 1 and fails this test directly.
    """
    saved_registry = dict(schemas.TOOL_REGISTRY)
    saved_verified = dict(schemas._TOOL_VERIFIED)
    saved_verifiers = dict(schemas._MECHANISM_VERIFIERS)
    saved_complete = schemas._VERIFICATION_PASS_COMPLETE
    call_count = {"n": 0}

    def _fake_check():
        call_count["n"] += 1
        return True

    try:
        schemas._TOOL_VERIFIED.clear()
        schemas._MECHANISM_VERIFIERS.clear()
        schemas.register_mechanism_verifier("mcp_stdio_secret_mount", _fake_check)

        schemas.TOOL_REGISTRY.clear()
        schemas.TOOL_REGISTRY["tool_a"] = schemas.ToolRegistration(
            validator=_dummy_validator,
            authority_holder="decision-service (vault_server.py subprocess, secret-mounted)",
            mechanism="mcp_stdio_secret_mount",
            profile="mediated",
            claimed_exclusivity="demonstrated",
        )
        schemas.TOOL_REGISTRY["tool_b"] = schemas.ToolRegistration(
            validator=_dummy_validator,
            authority_holder="decision-service (a second, unrelated subprocess)",
            mechanism="mcp_stdio_secret_mount",
            profile="mediated",
            claimed_exclusivity="demonstrated",
        )

        schemas.run_verification_pass()

        assert call_count["n"] == 2, (
            f"expected the check to run once per tool (2 tools sharing the "
            f"mechanism), ran {call_count['n']} times - a shared cache is "
            f"letting one tool's verification stand in for the other's"
        )
        assert schemas._TOOL_VERIFIED["tool_a"] is True
        assert schemas._TOOL_VERIFIED["tool_b"] is True
    finally:
        schemas.TOOL_REGISTRY.clear()
        schemas.TOOL_REGISTRY.update(saved_registry)
        schemas._TOOL_VERIFIED.clear()
        schemas._TOOL_VERIFIED.update(saved_verified)
        schemas._MECHANISM_VERIFIERS.clear()
        schemas._MECHANISM_VERIFIERS.update(saved_verifiers)
        schemas._VERIFICATION_PASS_COMPLETE = saved_complete


def test_tool_registered_after_the_verification_pass_never_gets_demonstrated():
    """
    D17's second half: a tool added to TOOL_REGISTRY after
    run_verification_pass() has already completed must never resolve to
    "demonstrated", even if it declares a mechanism that verified True for
    every tool checked during that pass. There is no dynamic registration
    API in this codebase today, but the refusal must hold structurally -
    from an absent dict key defaulting to "not verified" - not from a
    special case that a future registration path could omit.

    Mutation: have resolve_exclusivity_for fall back to True whenever ANY
    tool sharing the mechanism has been verified (e.g. checking
    `mechanism in _VERIFIABLE_MECHANISMS and any(_TOOL_VERIFIED.values())`
    instead of the specific tool's own key). This test must fail against
    that mutation.
    """
    saved_verified = dict(schemas._TOOL_VERIFIED)
    try:
        schemas._TOOL_VERIFIED.clear()
        schemas._TOOL_VERIFIED["some_other_tool"] = True

        late_tool = schemas.ToolRegistration(
            validator=_dummy_validator,
            authority_holder="decision-service (registered after boot)",
            mechanism="mcp_stdio_secret_mount",
            profile="mediated",
            claimed_exclusivity="demonstrated",
        )
        assert schemas.resolve_exclusivity_for("late_tool", late_tool) == "declared"
    finally:
        schemas._TOOL_VERIFIED.clear()
        schemas._TOOL_VERIFIED.update(saved_verified)
