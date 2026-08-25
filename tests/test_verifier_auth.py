"""
tests/test_verifier_auth.py - D21, P3a-7 (Phase 3a completion pass).

Red-team X5 (docs/reports/phase-3a-redteam.md): GET /audit/bundle's own
authorization (Depends(_require_read_key), control_plane/main.py) computes
nothing about the endpoint its own material actually comes from -
verifier/main.py's POST /verify had no Depends(...) at all, so an anonymous
caller who could not pass the bundle route's own gate could reach the
verifier directly and assemble an equivalent bundle by hand. D21
(docs/adr/0011-verifier-authentication.md) closes this: /verify requires
VERIFIER_READ_KEY, /write requires VERIFIER_WRITE_KEY - independent secrets
from CONTROL_PLANE_READ_KEY/WRITE_KEY, the same two-tier split
docs/adr/0007-two-tier-authorization.md already established for the control
plane, applied a third time.

Live tests below require the docker-compose.test.yml stack (verifier only).
The missing-env-var 503 tests need no stack at all - they import
verifier/main.py directly and monkeypatch its module-level key constants,
the same in-process pattern tests/test_verification.py already uses for
control_plane/main.py's pure functions.
"""

import base64
import importlib.util
import os
import sys
import uuid
from pathlib import Path

import httpx
import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]

VERIFIER_URL = os.getenv("VERIFIER_URL", "http://localhost:8003")
VERIFIER_READ_KEY = os.getenv("VERIFIER_READ_KEY", "test-verifier-read-key")
VERIFIER_WRITE_KEY = os.getenv("VERIFIER_WRITE_KEY", "test-verifier-write-key")

_WRONG_KEY = "definitely-not-a-real-verifier-key"


requires_stack = pytest.mark.needs_stack("verifier")


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _verify(api_key):
    """A key that was never written - error_class not_found on a 200, so a
    200 here is unambiguous proof the request got past the dependency."""
    headers = {"X-API-Key": api_key} if api_key is not None else {}
    return httpx.post(
        f"{VERIFIER_URL}/verify",
        json={"key": _b64(f"p3a7_never_written:{uuid.uuid4().hex}")},
        headers=headers,
        timeout=15,
    )


def _write(api_key):
    headers = {"X-API-Key": api_key} if api_key is not None else {}
    return httpx.post(
        f"{VERIFIER_URL}/write",
        json={"key": _b64(f"p3a7_probe:{uuid.uuid4().hex}"), "value": _b64("probe")},
        headers=headers,
        timeout=15,
    )


# ---------------------------------------------------------------------------
# Demonstrate: the red-team's X5 attack, verbatim - now refused.
# ---------------------------------------------------------------------------

@requires_stack
def test_x5_unauthenticated_verify_now_refused():
    """
    The exact call X5 REFUTED this phase's own claim with: POST /verify,
    zero credentials, used to return 200 with proof_material attached
    regardless of whether the caller could pass GET /audit/bundle's own
    gate. Refused before the request body is even read.
    """
    resp = _verify(api_key=None)
    assert resp.status_code == 422, f"expected 422 with no header, got {resp.status_code}: {resp.text}"


@requires_stack
def test_x5_read_credentialed_verify_still_succeeds():
    """The fix is a credential check, not a blanket refusal - the
    credentialed path (what control_plane/main.py itself uses) must still
    return a real result, not merely a non-422 status."""
    resp = _verify(api_key=VERIFIER_READ_KEY)
    assert resp.status_code == 200, f"expected 200 with the read key, got {resp.status_code}: {resp.text}"
    assert resp.json()["verified"] is False
    assert resp.json()["error_class"] == "not_found"  # the probe key was never written


@requires_stack
def test_x5_write_credentialed_verify_refused():
    """Cross-tier: the write key must not open /verify either - ADR-0007's
    two independent keys, not a hierarchy, applied to the verifier."""
    resp = _verify(api_key=VERIFIER_WRITE_KEY)
    assert resp.status_code == 403, f"expected 403 with the write key, got {resp.status_code}: {resp.text}"


# ---------------------------------------------------------------------------
# Enforce: unauthenticated refusal on both endpoints.
# ---------------------------------------------------------------------------

@requires_stack
def test_verify_rejected_with_no_key():
    resp = _verify(api_key=None)
    assert resp.status_code == 422, f"expected 422, got {resp.status_code}: {resp.text}"


@requires_stack
def test_verify_rejected_with_wrong_key():
    resp = _verify(api_key=_WRONG_KEY)
    assert resp.status_code == 403, f"expected 403, got {resp.status_code}: {resp.text}"


@requires_stack
def test_write_rejected_with_no_key():
    resp = _write(api_key=None)
    assert resp.status_code == 422, f"expected 422, got {resp.status_code}: {resp.text}"


@requires_stack
def test_write_rejected_with_wrong_key():
    resp = _write(api_key=_WRONG_KEY)
    assert resp.status_code == 403, f"expected 403, got {resp.status_code}: {resp.text}"


@requires_stack
def test_write_accepted_with_write_key():
    resp = _write(api_key=VERIFIER_WRITE_KEY)
    assert resp.status_code == 200, f"expected 200 with the write key, got {resp.status_code}: {resp.text}"
    assert resp.json()["verified"] is True, resp.json()


# ---------------------------------------------------------------------------
# Enforce: cross-tier refusal, both directions.
# ---------------------------------------------------------------------------

@requires_stack
def test_write_rejected_with_read_key():
    """The read key must not open /write - the converse of
    test_x5_write_credentialed_verify_refused above."""
    resp = _write(api_key=VERIFIER_READ_KEY)
    assert resp.status_code == 403, f"expected 403 with the read key, got {resp.status_code}: {resp.text}"


# (test_x5_write_credentialed_verify_refused above is this test's converse:
# the write key rejected on /verify.)


# ---------------------------------------------------------------------------
# Enforce: missing env var yields 503, not open. No stack required - this
# imports verifier/main.py directly and calls its dependency functions as
# plain callables, monkeypatching the module-level key constants the same
# way _require_read_key/_require_write_key read them at request time.
# ---------------------------------------------------------------------------

def _load_verifier_module():
    """Explicit module name: control_plane/main.py, decision_service/main.py
    and verifier/main.py are all named main.py - tests/test_evidence_bundle.py
    documents why a bare import would clobber whichever one loaded first."""
    spec = importlib.util.spec_from_file_location("verifier_main", REPO_ROOT / "verifier" / "main.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["verifier_main"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def verifier_main():
    return _load_verifier_module()


def test_missing_read_key_env_var_yields_503(verifier_main, monkeypatch):
    """
    D21's own fail-closed requirement: an unset VERIFIER_READ_KEY must
    refuse every caller, correct key included, rather than the dependency
    silently no-opping. Mirrors control_plane/main.py::_require_read_key's
    already-established behavior for the same condition.
    """
    monkeypatch.setattr(verifier_main, "_VERIFIER_READ_KEY", "")
    with pytest.raises(verifier_main.HTTPException) as exc_info:
        verifier_main._require_read_key(x_api_key=VERIFIER_READ_KEY)
    assert exc_info.value.status_code == 503


def test_missing_write_key_env_var_yields_503(verifier_main, monkeypatch):
    monkeypatch.setattr(verifier_main, "_VERIFIER_WRITE_KEY", "")
    with pytest.raises(verifier_main.HTTPException) as exc_info:
        verifier_main._require_write_key(x_api_key=VERIFIER_WRITE_KEY)
    assert exc_info.value.status_code == 503


def test_configured_read_key_rejects_wrong_value_not_503(verifier_main, monkeypatch):
    """Negative control for the two tests above: a *configured* key must
    still discriminate right from wrong (403), not fail open or fail closed
    indiscriminately - the 503 path above is specifically the unset case."""
    monkeypatch.setattr(verifier_main, "_VERIFIER_READ_KEY", "the-real-key")
    with pytest.raises(verifier_main.HTTPException) as exc_info:
        verifier_main._require_read_key(x_api_key="not-the-real-key")
    assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# Enforce: the agent is provisioned with neither verifier key.
# ---------------------------------------------------------------------------

def _load_compose(filename: str) -> dict:
    with open(REPO_ROOT / filename, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _env_names(compose: dict, service: str) -> set[str]:
    """docker-compose.yml's environment: entries are "KEY=value" strings, not
    a mapping - same list form tests/test_decision_service_network_isolation.py
    already reads for this file's networks: blocks."""
    entries = compose["services"][service].get("environment", [])
    return {entry.split("=", 1)[0] for entry in entries}


def test_agent_container_provisioned_with_neither_verifier_key():
    """
    P3a-7's own provisioning claim, checked statically against
    docker-compose.yml rather than assumed from langgraph-demo never having
    held VERIFIER_URL: the agent must not name VERIFIER_READ_KEY or
    VERIFIER_WRITE_KEY in its environment at all, credential value aside.

    Mutation: add "- VERIFIER_READ_KEY=${VERIFIER_READ_KEY}" (or the write
    key) to langgraph-demo's environment: block. This test must fail against
    that mutation.
    """
    compose = _load_compose("docker-compose.yml")
    agent_env = _env_names(compose, "langgraph-demo")
    assert "VERIFIER_READ_KEY" not in agent_env, (
        "langgraph-demo must never be provisioned with VERIFIER_READ_KEY - "
        "it has no code path that would use it and no network route to the "
        "verifier at all (backend-only vs. its own edge-only membership)."
    )
    assert "VERIFIER_WRITE_KEY" not in agent_env, (
        "langgraph-demo must never be provisioned with VERIFIER_WRITE_KEY - "
        "D12 (Phase 2) moved every ledger write to decision-service."
    )


@pytest.mark.parametrize("service,expected", [
    ("ail-control-plane", {"VERIFIER_READ_KEY", "VERIFIER_WRITE_KEY"}),
    ("decision-service", {"VERIFIER_WRITE_KEY"}),
])
def test_backend_services_hold_exactly_the_verifier_keys_their_code_uses(service, expected):
    """
    The converse of the agent check above, checked per service rather than
    assumed: ail-control-plane calls both /verify and /write (get_audit,
    get_audit_bundle, _has_tombstone, _write_tombstone), so it holds both
    keys; decision-service's ledger client only ever writes, so it holds
    VERIFIER_WRITE_KEY and must not additionally hold VERIFIER_READ_KEY it
    has no use for.
    """
    compose = _load_compose("docker-compose.yml")
    env = _env_names(compose, service)
    verifier_keys_present = env & {"VERIFIER_READ_KEY", "VERIFIER_WRITE_KEY"}
    assert verifier_keys_present == expected, (
        f"{service}: expected exactly {sorted(expected)}, found {sorted(verifier_keys_present)}"
    )
