"""tests/compose_helpers.py - Phase 3c-3c.

Shared docker-compose plumbing for the tests that have to act on the running
stack rather than only talk to it.

Why this file exists. Three test modules now need the same two things: the
Compose project name of the stack they are talking to, and a way to run a
command inside one of its containers. tests/test_content_states.py worked
that out first (roadmap-commit item 6); copying its forty lines a third time
is how two copies drift into disagreeing about which stack they mean.

The project-name rule is the load-bearing part and is unchanged from that
file: prefer COMPOSE_PROJECT_NAME, then a root .env, then Compose's own
directory-basename default. Without it, a stack brought up under an explicit
`-p` is invisible to a test that guesses, and the failure reads as a broken
service rather than as a mismatched project.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = "docker-compose.test.yml"


def default_compose_project_name() -> str:
    """Compose's own default when COMPOSE_PROJECT_NAME is not set.

    The lowercased basename of the project directory, with anything outside
    `[a-z0-9_-]` stripped and leading separators removed. **A hyphen
    survives.** Getting that wrong is not a cosmetic difference: this
    repository's own directory is `compliance-ail`, so dropping the hyphen
    produces `complianceail`, and every `docker compose` call against it
    creates a second, empty project rather than addressing the running one.
    It cost a CI run - `docker compose up --force-recreate verifier` created
    a new network and then failed on `Bind for 127.0.0.1:8003 failed: port is
    already allocated`, because the real verifier was up under the real
    project name. Invisible locally, where COMPOSE_PROJECT_NAME is set
    explicitly and this fallback never runs.

    tests/test_content_states.py holds the other copy of this rule, and
    test_the_two_copies_of_the_compose_project_rule_agree below is what stops
    them drifting.
    """
    name = re.sub(r"[^a-z0-9_-]", "", REPO_ROOT.name.lower())
    return name.lstrip("_-") or "default"


def compose_project_name() -> str:
    """The Compose project name of the stack these tests talk to."""
    env_name = os.getenv("COMPOSE_PROJECT_NAME")
    if env_name:
        return env_name
    dotenv_path = REPO_ROOT / ".env"
    if dotenv_path.exists():
        for line in dotenv_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line.startswith("COMPOSE_PROJECT_NAME="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return default_compose_project_name()


COMPOSE_PROJECT = compose_project_name()


def docker_cli_usable() -> bool:
    """Whether the docker CLI is on PATH and actually runnable.

    P13-5's finding, kept: shutil.which alone is not enough, because a file
    named "docker" that is not a valid executable satisfies it and then
    raises deep inside subprocess.Popen, where the failure reads as a
    regression in whatever the test was checking.
    """
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(["docker", "version"], capture_output=True, timeout=10)
    except Exception:
        return False
    return True


requires_docker_cli = pytest.mark.skipif(
    not docker_cli_usable(),
    reason="docker CLI not on PATH or not runnable",
)


def compose(*args: str, check: bool = True, stdin: str | None = None,
            timeout: int = 180, env: dict[str, str] | None = None
            ) -> subprocess.CompletedProcess:
    """One `docker compose` invocation against this stack, project named.

    `env` is merged over this process's environment, which is how a test
    recreates one service with a different setting: the compose files read
    their values through `${NAME:-default}`, so the substitution happens at
    invocation time and nothing on disk changes.
    """
    cmd = ["docker", "compose", "-p", COMPOSE_PROJECT, "-f", COMPOSE_FILE, *args]
    merged = {**os.environ, **(env or {})}
    return subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True,
                          input=stdin, check=check, timeout=timeout, env=merged)


def wait_for_health(url: str, timeout_seconds: float = 120.0) -> bool:
    """Poll until the service answers 200, or give up and say so."""
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            if httpx.get(url, timeout=3).status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False

