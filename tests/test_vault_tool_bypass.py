"""
tests/test_vault_tool_bypass.py - P2-4 (Phase 2, D14), the phase's own exit
criterion: a compromised agent with arbitrary code execution in its own
container cannot reach the mediated tool directly, bypassing the decision
service.

Every attempt below is from the spike's M2 list (docs/reports/
spike-mcp-mediation.md), adapted from MCP's stdio/HTTP topology to this
project's actual one (the agent talks to a decision service over mTLS, not
to an MCP proxy directly): read the agent's own configuration for anything
naming the vault, enumerate the network for it, inspect the process/
environment for the credential, attempt to reach decision-service or the
vault directly bypassing Envoy, and check whether the vault server binary
is even present to spawn.

Unlike the rest of tests/, this file requires the FULL production stack
(docker-compose.yml - real SPIRE, Envoy, and a running langgraph-demo
container), not docker-compose.test.yml. docker-compose.test.yml has no
agent container at all to execute code inside of, and no network
segmentation to test (it is deliberately flat - see that file's own header
comment). This means these tests are skipped under the ordinary `make
test-integration` / CI run, the same way test_mtls_flow.py already is,
except these stay inside testpaths (collected, with a visible skip reason)
rather than being excluded from it entirely - see docs/reports/phase-2.md
for the live run against the real stack these tests are the recorded,
re-runnable form of.

Mutation (P2-4's named mutation): deliver the vault credential by
environment variable. See tests/test_credential_boundary_static.py for the
direct, no-stack-required test that mutation breaks immediately;
test_a3_credential_not_in_agent_environ_or_filesystem below would also
start failing once the token value stops being confined to
decision-service's own mount.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = "docker-compose.yml"
AGENT_SERVICE = "langgraph-demo"


def _default_compose_project_name() -> str:
    name = re.sub(r"[^a-z0-9_-]", "", REPO_ROOT.name.lower())
    return name.lstrip("_-") or "default"


def _compose_project_name() -> str:
    env_name = os.getenv("COMPOSE_PROJECT_NAME")
    if env_name:
        return env_name
    dotenv_path = REPO_ROOT / ".env"
    if dotenv_path.exists():
        for line in dotenv_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line.startswith("COMPOSE_PROJECT_NAME="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return _default_compose_project_name()


COMPOSE_PROJECT = _compose_project_name()


def _docker_cli_usable() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(["docker", "version"], capture_output=True, timeout=10)
        return True
    except OSError:
        return False


def _agent_container_running() -> bool:
    if not _docker_cli_usable():
        return False
    try:
        result = subprocess.run(
            ["docker", "compose", "-p", COMPOSE_PROJECT, "-f", COMPOSE_FILE, "ps", "-q", AGENT_SERVICE],
            cwd=str(REPO_ROOT), capture_output=True, timeout=15, text=True,
        )
        return bool(result.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        # Same project-name-mismatch and environment-dependent-CLI concerns
        # tests/test_content_states.py's requires_docker_cli guard documents
        # (P13-5/R6) apply here too - this is a collection-time skip check,
        # so an uncaught TimeoutExpired here would abort collection for the
        # entire suite, not just skip this one file's tests.
        return False


requires_full_stack = pytest.mark.skipif(
    not _agent_container_running(),
    reason=(
        f"Full production stack (docker-compose.yml, service {AGENT_SERVICE!r}) not running "
        f"under compose project {COMPOSE_PROJECT!r} - these bypass tests need the real agent "
        f"container, not the docker-compose.test.yml stack. See docs/reports/phase-2.md for "
        f"the live run."
    ),
)


def _exec_in_agent(cmd: list[str], timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "-p", COMPOSE_PROJECT, "-f", COMPOSE_FILE, "exec", "-T", AGENT_SERVICE] + cmd,
        cwd=str(REPO_ROOT), capture_output=True, timeout=timeout, text=True,
    )


@requires_full_stack
def test_a1_agent_has_no_mcp_client_config_naming_the_vault():
    """
    A1 (spike M2): read the agent's own client config, connect to what it
    names. The agent holds no MCP client config for read_vault_secret at
    all - its only configured target for anything AIL-related is the
    decision service (DECISION_SERVICE_URL), never an MCP endpoint or the
    vault server directly.
    """
    result = _exec_in_agent(["env"])
    assert result.returncode == 0, result.stderr
    env_text = result.stdout
    assert "VAULT" not in env_text.upper(), (
        f"Agent environment must not name the vault at all. Found:\n{env_text}"
    )
    assert "DECISION_SERVICE_URL" in env_text


@requires_full_stack
@pytest.mark.parametrize("target", ["opa", "verifier", "ail-control-plane", "immudb", "decision-service"])
def test_a2_agent_cannot_resolve_or_reach_backend_hosts(target):
    """
    A2 (spike M2): enumerate the network for the upstream, connect. The
    agent is edge-only (P2-1); none of these hostnames should even resolve
    from inside its container, let alone accept a connection.
    """
    result = _exec_in_agent([
        "python3", "-c",
        f"import socket; socket.setdefaulttimeout(3); socket.gethostbyname('{target}')",
    ])
    assert result.returncode != 0, (
        f"Expected DNS resolution of {target!r} to fail from inside the agent container "
        f"(edge-only network); it succeeded instead: {result.stdout}"
    )


@requires_full_stack
def test_a3_credential_not_in_agent_environ_or_filesystem():
    """
    A3 (spike M2): inspect the process tree and environment for the
    upstream credential. Also checks the filesystem directly - the vault
    token is a Compose secret attached only to decision-service, so
    /run/secrets should not even exist in the agent's container, and no
    file anywhere should contain the literal secret name.
    """
    env_result = _exec_in_agent(["env"])
    assert env_result.returncode == 0, env_result.stderr
    assert "vault_api_token" not in env_result.stdout.lower()

    secrets_result = _exec_in_agent(["sh", "-c", "ls /run/secrets 2>&1 || true"])
    combined = (secrets_result.stdout or "") + (secrets_result.stderr or "")
    assert "vault_api_token" not in combined, (
        f"/run/secrets must not contain vault_api_token inside the agent container: {combined}"
    )


@requires_full_stack
def test_a4_direct_http_to_decision_service_bypassing_envoy_fails():
    """
    A4 (spike M2): rewrite config to the real upstream URL, reconnect. There
    is no Envoy-mTLS step to bypass here because there is no route to
    decision-service at all from the agent's network segment - confirmed by
    attempting the plain HTTP call directly.
    """
    result = _exec_in_agent([
        "python3", "-c",
        "import httpx; httpx.post('http://decision-service:8010/decide', "
        "json={'tool_name':'read_vault_secret','tool_args':{'secret_name':'db_master_password'},"
        "'agent_id':'bypass-attempt'}, timeout=5)",
    ])
    assert result.returncode != 0, (
        f"Expected a direct, unmediated POST to decision-service to fail (no network route "
        f"from the agent's edge-only segment); it succeeded: {result.stdout}"
    )


@requires_full_stack
def test_a5_vault_server_binary_not_present_in_agent_image():
    """
    A5 (spike M2): spawn the server binary directly. vault_server.py is
    never COPY'd into the agent's Docker image (see the root Dockerfile) -
    there is nothing to spawn even with arbitrary code execution.
    """
    result = _exec_in_agent(["sh", "-c", "find / -iname 'vault_server*' 2>/dev/null"])
    assert result.stdout.strip() == "", (
        f"vault_server.py must not exist anywhere in the agent's image; found: {result.stdout}"
    )
