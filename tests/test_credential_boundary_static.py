"""
tests/test_credential_boundary_static.py - P2-4 (Phase 2, D14).

The direct assertion D14's Enforce section names: "the credential must not
be readable from the agent's principal; assert that directly." Static
checks, no running stack required - complements the live bypass attempts in
tests/test_vault_tool_bypass.py by checking the two things that would make
those bypasses succeed even before anything is booted: the secret's Compose
attachment, and how decision_service spawns vault_server.py.

Mutation (P2-4's named mutation): "deliver the credential by environment
variable" - change decision_service/main.py's StdioServerParameters call to
pass env={"VAULT_API_TOKEN": ...} (or similar) to the spawned child, or add
the vault_api_token secret to langgraph-demo's service definition. Both
tests below must fail against either mutation - proving they test the
boundary (how the credential is actually delivered) rather than the
configuration (whether a config value happens to claim isolation).
"""

import os
import re

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")


def _read(*parts: str) -> str:
    with open(os.path.join(REPO_ROOT, *parts), "r", encoding="utf-8") as f:
        return f.read()


def test_vault_secret_is_attached_only_to_decision_service():
    import yaml

    with open(os.path.join(REPO_ROOT, "docker-compose.yml"), "r", encoding="utf-8") as f:
        compose = yaml.safe_load(f)

    assert "vault_api_token" in compose.get("secrets", {}), (
        "docker-compose.yml must declare the vault_api_token secret at the top level"
    )

    def _secret_names(service_def: dict) -> set[str]:
        names = set()
        for entry in service_def.get("secrets", []):
            if isinstance(entry, str):
                names.add(entry)
            elif isinstance(entry, dict):
                names.add(entry.get("source"))
        return names

    decision_service_secrets = _secret_names(compose["services"]["decision-service"])
    assert "vault_api_token" in decision_service_secrets, (
        "decision-service must have the vault_api_token secret attached"
    )

    agent_secrets = _secret_names(compose["services"]["langgraph-demo"])
    assert "vault_api_token" not in agent_secrets, (
        "langgraph-demo (the agent) must never have the vault_api_token secret attached - "
        "this is the primary D14 boundary. Found it attached."
    )
    assert not agent_secrets, (
        f"langgraph-demo must have no secrets at all attached, found: {sorted(agent_secrets)}"
    )


def test_vault_server_spawn_carries_no_env_override():
    """
    decision_service/main.py::_execute_vault_tool spawns vault_server.py via
    StdioServerParameters. The credential must never be assigned to an
    environment variable anywhere in that spawn call - vault_server.py
    reads it itself, from the mounted secret file, at its own startup (see
    decision_service/mcp_tools/vault_server.py::_load_token).
    """
    source = _read("decision_service", "main.py")

    match = re.search(r"StdioServerParameters\((.*?)\)", source, re.DOTALL)
    assert match, "Could not find the StdioServerParameters(...) spawn call in decision_service/main.py"
    call_body = match.group(1)

    assert "env=" not in call_body, (
        f"StdioServerParameters call must not pass env= (the credential-by-environment-"
        f"variable delivery D14 explicitly rules out - see docs/reports/"
        f"spike-mcp-mediation.md's M4 finding). Call body: {call_body!r}"
    )
    # decision_service/main.py may hold the *path* to the secret file
    # (VAULT_TOKEN_PATH) but must never hold or forward the token's value -
    # any TOKEN-named env var read here must also be PATH-named.
    env_lookups = re.findall(r'os\.environ(?:\.get)?\(["\']([A-Z_]+)["\']', source)
    for name in env_lookups:
        if "TOKEN" in name:
            assert "PATH" in name, (
                f"decision_service/main.py reads env var {name!r} - a TOKEN-named var that "
                f"is not PATH-named looks like the credential's value being read from the "
                f"environment, which D14 rules out"
            )


def test_vault_server_reads_its_own_token_from_a_file_not_an_env_var():
    """
    The other half of the boundary: vault_server.py itself must read the
    credential from a file path, never from an environment variable set to
    the credential's value. VAULT_TOKEN_PATH (a path, not a secret) is fine;
    an env var carrying the token value itself is exactly what this test
    rules out.
    """
    source = _read("decision_service", "mcp_tools", "vault_server.py")
    assert "open(_TOKEN_PATH" in source or "open(_token_path" in source.lower(), (
        "vault_server.py must load its token via open() on a file path"
    )
    # No environ lookup should carry the literal token value - only the path.
    env_lookups = re.findall(r'os\.environ(?:\.get)?\(["\']([A-Z_]+)["\']', source)
    for name in env_lookups:
        assert "PATH" in name, (
            f"vault_server.py reads env var {name!r}, which does not look like a path variable - "
            f"the token itself must never be read from the environment"
        )
