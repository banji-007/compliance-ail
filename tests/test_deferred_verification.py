"""
tests/test_deferred_verification.py - Phase 3c-2 (D29).

`GET /audit` no longer verifies per record by default. Every row comes back
`asserted`, the response carries `verifier_reachable`, and a caller who
wants a specific record checked calls `GET /audit/verify?key=` for that one
record.

What each group of tests here holds in place:

  The default page defers.        No per-record POST /verify reaches the
                                  verifier while a default page is served.
  Verification stays reachable.   `?verify=true` restores the old per-record
                                  behaviour, so the existing assertions that
                                  read a real state off /audit still read one
                                  (tests/test_verification.py::
                                  test_cross_process, tests/
                                  test_content_states.py's erasure test).
  Reachability is probed, never   `verifier_reachable` comes from a live GET
  inferred.                       /health on every path, so a deferred page
                                  that checked nothing still reports an
                                  outage instead of looking normal.
  `asserted` has both producers.  Deferral, and the pre-existing circuit
                                  breaker on the ?verify=true path.

Counting requests. The verifier's own Docker healthcheck calls GET /health
every 5s from inside its container, so its uvicorn access log always carries
loopback-sourced /health lines. Every count below therefore filters on the
client address: the control plane reaches the verifier across the compose
network (a 172.x address), the healthcheck reaches it from 127.0.0.1. POST
/verify needs no such filter - nothing else posts to it.
"""

import base64
import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path

import httpx
import pytest

CONTROL_PLANE_URL  = os.getenv("CONTROL_PLANE_URL",      "http://localhost:8002")
READ_API_KEY       = os.getenv("CONTROL_PLANE_READ_KEY", "test-read-key")
VERIFIER_URL       = os.getenv("VERIFIER_URL",           "http://localhost:8003")
VERIFIER_READ_KEY  = os.getenv("VERIFIER_READ_KEY",      "test-verifier-read-key")
VERIFIER_WRITE_KEY = os.getenv("VERIFIER_WRITE_KEY",     "test-verifier-write-key")

REPO_ROOT    = Path(__file__).resolve().parents[1]
COMPOSE_FILE = "docker-compose.test.yml"

requires_stack = pytest.mark.needs_stack("immudb", "verifier", "control_plane")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _default_compose_project_name() -> str:
    """Compose's own default: the lowercased basename of the project
    directory, with anything outside [a-z0-9_-] stripped. Same derivation
    tests/test_content_states.py uses, and for the same reason - a stack
    brought up under an explicit -p must be targeted by that name, not by
    one this process guesses."""
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
    """Resolving the binary is not enough (R6, Phase 1.3 completion pass): a
    file named "docker" that is not a valid executable satisfies
    shutil.which and then raises OSError inside subprocess.run, which pytest
    reports as ERROR rather than a clean skip."""
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(["docker", "version"], capture_output=True, timeout=10)
        return True
    except OSError:
        return False


requires_docker_cli = pytest.mark.skipif(
    not _docker_cli_usable(),
    reason="docker CLI not on PATH or not runnable",
)


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def verifier_write(key_raw: str, value_raw: str, view: str | None = "decision") -> dict:
    # D32 (Phase 3c-3b): /write-ordered, because a decision or intent
    # record now takes a commit position in the same transaction that
    # commits it, and a record with no position is absent from every
    # ordered page. `view` picks which view index it lands in; a
    # tombstone is neither and keeps the plain /write route.
    body = {"key": b64(key_raw), "value": b64(value_raw)}
    route = "/write"
    if view is not None:
        route = "/write-ordered"
        body["view"] = view
    resp = httpx.post(
        f"{VERIFIER_URL}{route}",
        json=body,
        headers={"X-API-Key": VERIFIER_WRITE_KEY},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def audit(verify: bool | None = None, limit: int = 200) -> dict:
    params: dict = {"limit": limit}
    if verify is not None:
        params["verify"] = str(verify).lower()
    resp = httpx.get(
        f"{CONTROL_PLANE_URL}/audit",
        params=params,
        headers={"X-API-Key": READ_API_KEY},
        # Deferred by default, so this is cheap - but ?verify=true is still
        # O(min(limit, ledger)) round trips and this suite accumulates
        # entries, so the headroom stays for the calls that ask for it.
        timeout=90,
    )
    resp.raise_for_status()
    return resp.json()


def verifier_log() -> str:
    """The verifier container's stdout so far. uvicorn's access log is the
    only record of who called it and how often; nothing in the verifier
    counts its own requests."""
    result = subprocess.run(
        ["docker", "compose", "-p", COMPOSE_PROJECT, "-f", COMPOSE_FILE, "logs", "--no-log-prefix", "verifier"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, f"docker compose logs failed: {result.stdout}\n{result.stderr}"
    return result.stdout


# uvicorn access-log line:
#   172.18.0.7:41234 - "POST /verify HTTP/1.1" 200
_ACCESS_RE = re.compile(
    r'\s(?P<client>[0-9a-fA-F:.]+):\d+ - "(?P<method>[A-Z]+) (?P<path>\S+) [^"]*"'
)


def _count_calls(log: str, method: str, path: str, exclude_loopback: bool = False) -> int:
    total = 0
    for match in _ACCESS_RE.finditer(log):
        if match.group("method") != method or match.group("path") != path:
            continue
        if exclude_loopback and match.group("client") in ("127.0.0.1", "::1", "localhost"):
            continue
        total += 1
    return total


# ---------------------------------------------------------------------------
# P3c2-1. A record can be verified on demand
# ---------------------------------------------------------------------------

@requires_stack
def test_per_record_route_verifies_a_written_record():
    """
    GET /audit/verify?key= returns the same verification object /audit
    produces per row, for a record that was actually written.

    Mutation (P3c2-1): remove the credential check on the route - caught by
    test_per_record_route_requires_the_read_credential below, not by this
    one. This test's own failure mode is the route not verifying at all.
    """
    key_raw = f"tool_call:test-agent:{uuid.uuid4().hex}:p3c2_ondemand"
    write = verifier_write(key_raw, '{"phase": "3c-2", "criterion": "on-demand verify"}')
    assert write["verified"] is True, write

    resp = httpx.get(
        f"{CONTROL_PLANE_URL}/audit/verify",
        params={"key": b64(key_raw)},
        headers={"X-API-Key": READ_API_KEY},
        timeout=30,
    )
    assert resp.status_code == 200, f"HTTP {resp.status_code}: {resp.text[:300]}"
    body = resp.json()
    assert body["key"] == b64(key_raw), body
    verification = body["verification"]
    assert verification["state"] == "verified", verification
    # Same object shape /audit puts on every row - not a different one that
    # happens to carry a state.
    assert set(verification) == {"state", "state_id", "detail", "error_class"}, verification
    assert verification["state_id"] is not None, verification


@requires_stack
def test_per_record_route_reports_not_found_for_an_unwritten_key():
    """
    D8's not_found, live and end to end, for the first time.

    ADR-0006 recorded that not_found was reachable only against the verifier
    directly, never through the control plane, because /audit's own scan
    lists keys ImmuDB confirms exist - a key that is simultaneously scanned
    and never written is not constructible. This route takes a key from the
    caller instead of from a scan, so the case it could not reach is the
    ordinary one here.

    not_found is a 200 carrying state "not_found", not an HTTP 404. The
    route reports a verification result; it does not model the record as a
    missing resource. GET /audit/bundle does 404, and differently on
    purpose: a bundle is evidence, and there is no honest bundle for a key
    that was never written.
    """
    never_written = f"tool_call:test-agent:{uuid.uuid4().hex}:never_written"
    resp = httpx.get(
        f"{CONTROL_PLANE_URL}/audit/verify",
        params={"key": b64(never_written)},
        headers={"X-API-Key": READ_API_KEY},
        timeout=30,
    )
    assert resp.status_code == 200, f"HTTP {resp.status_code}: {resp.text[:300]}"
    verification = resp.json()["verification"]
    assert verification["state"] == "not_found", verification
    assert verification["error_class"] == "not_found", verification


@requires_stack
def test_per_record_route_requires_the_read_credential():
    """
    The named test for P3c2-1's mutation: remove Depends(_require_read_key)
    from the route.

    Both halves matter. A missing header is a 422 from FastAPI's own
    required-header handling; a present but wrong one is the 403 the
    dependency itself raises. Asserting only the first would pass against a
    route that accepts any key at all.
    """
    key_raw = f"tool_call:test-agent:{uuid.uuid4().hex}:p3c2_auth"
    verifier_write(key_raw, '{"phase": "3c-2", "criterion": "auth"}')

    no_key = httpx.get(
        f"{CONTROL_PLANE_URL}/audit/verify",
        params={"key": b64(key_raw)},
        timeout=30,
    )
    assert no_key.status_code == 422, (
        f"Route answered without any X-API-Key at all: HTTP {no_key.status_code} {no_key.text[:200]}"
    )

    wrong_key = httpx.get(
        f"{CONTROL_PLANE_URL}/audit/verify",
        params={"key": b64(key_raw)},
        headers={"X-API-Key": "not-the-read-key"},
        timeout=30,
    )
    assert wrong_key.status_code == 403, (
        f"Route accepted a wrong X-API-Key: HTTP {wrong_key.status_code} {wrong_key.text[:200]}"
    )


@requires_stack
def test_per_record_route_rejects_a_key_that_is_not_base64():
    """A malformed key is a 400 from the route's own decode check, the same
    validation GET /audit/bundle applies to the identical parameter - not a
    500 out of the verifier, and not a fabricated verification state."""
    resp = httpx.get(
        f"{CONTROL_PLANE_URL}/audit/verify",
        params={"key": "not!base64!at!all"},
        headers={"X-API-Key": READ_API_KEY},
        timeout=30,
    )
    assert resp.status_code == 400, f"HTTP {resp.status_code}: {resp.text[:300]}"


def test_the_failed_state_maps_from_a_fabricated_verifier_body():
    """
    P3c2-1's third case, and the one this project cannot demonstrate live.

    A live "failed" needs the verifier's own persisted state corrupted and
    the service restarted, which leaves the stack inconsistent for every
    test after it. The two existing tamper tests
    (tests/test_verification.py::test_tamper_state, ::test_tamper_pubkey)
    corrupt a client-side PersistentRootService in this process instead, and
    neither goes through the verifier service at all.

    So the enforcing test for "failed" is a mapping unit test against a
    fabricated verifier body, which is the same treatment not_found already
    gets in tests/test_verification.py::
    test_control_plane_maps_not_found_state_not_failed and the same reason
    _verification_from_200 was extracted as a pure function in the first
    place. What this establishes is the mapping, not a live tamper. Said
    again in the phase report's mapping table and in Residual Limits, so the
    Claim is not read as more than it is.
    """
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "control_plane"))
    import main as control_plane_main  # noqa: E402

    for error_class in ("consistency_failure", "signature_failure"):
        vdata = {"verified": False, "detail": f"{error_class} detail", "error_class": error_class}
        verification = control_plane_main._verification_from_200(vdata)
        assert verification["state"] == "failed", verification
        assert verification["error_class"] == error_class, verification


# ---------------------------------------------------------------------------
# P3c2-2. The default page defers
# ---------------------------------------------------------------------------

@requires_stack
def test_default_audit_page_returns_every_row_asserted():
    """
    Mutation (P3c2-2): restore per-record verification on the default path,
    by making `verify`'s default True or by dropping the branch that honours
    it. This test must fail.
    """
    key_raw = f"tool_call:test-agent:{uuid.uuid4().hex}:p3c2_deferred"
    written = verifier_write(key_raw, '{"phase": "3c-2", "criterion": "deferred page"}')["tx_id"]

    body = audit()
    entries = body["entries"]
    assert entries, "Audit returned no entries"
    assert any(e["tx_id"] == written for e in entries), (
        f"Written tx={written} not in the default page"
    )

    states = {e["verification"]["state"] for e in entries}
    assert states == {"asserted"}, (
        f"Default page verified something: states present were {sorted(states)}"
    )


@requires_stack
@requires_docker_cli
def test_default_audit_page_issues_no_per_record_verify_call():
    """
    The count, not the states. A page could report every row `asserted` and
    still have called the verifier for each of them and thrown the answers
    away; the states alone do not distinguish those.

    Counted from the verifier's own uvicorn access log, which is the only
    place the calls are recorded. POST /verify needs no client filter -
    nothing but the control plane posts to it.
    """
    before = _count_calls(verifier_log(), "POST", "/verify")
    audit()
    after = _count_calls(verifier_log(), "POST", "/verify")
    assert after == before, (
        f"Default /audit made {after - before} per-record POST /verify call(s); expected 0"
    )


@requires_stack
@requires_docker_cli
def test_default_audit_page_issues_exactly_one_health_call():
    """
    P3c2-3's probe, counted rather than assumed: one GET /health per
    request, not one per row and not zero.

    The verifier's Docker healthcheck also calls GET /health, every 5s, from
    inside the container - so loopback-sourced lines are excluded. The
    control plane reaches the verifier across the compose network and never
    appears as 127.0.0.1.
    """
    before = _count_calls(verifier_log(), "GET", "/health", exclude_loopback=True)
    audit()
    after = _count_calls(verifier_log(), "GET", "/health", exclude_loopback=True)
    assert after - before == 1, (
        f"Default /audit made {after - before} GET /health call(s) from off-loopback; expected exactly 1"
    )


@requires_stack
def test_verify_true_restores_per_record_verification():
    """
    Deferral is the default, not the only behaviour. Without this, the two
    existing assertions that read a real state off /audit
    (tests/test_verification.py::test_cross_process and
    tests/test_content_states.py's erasure test) would have nothing to read:
    one would fail outright, and the other - which compares the state before
    an erasure to the state after it - would compare "asserted" to
    "asserted" and pass while proving nothing.
    """
    key_raw = f"tool_call:test-agent:{uuid.uuid4().hex}:p3c2_verify_true"
    written = verifier_write(key_raw, '{"phase": "3c-2", "criterion": "verify=true"}')["tx_id"]

    entries = audit(verify=True)["entries"]
    matching = [e for e in entries if e["tx_id"] == written]
    assert matching, f"Written tx={written} not in the verified page"
    assert matching[0]["verification"]["state"] == "verified", matching[0]


# ---------------------------------------------------------------------------
# P3c2-3 and P3c2-4. An outage is visible on a page that verified nothing
# ---------------------------------------------------------------------------

def _compose(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "-p", COMPOSE_PROJECT, "-f", COMPOSE_FILE, *args],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
    )


def _verifier_healthy(timeout_s: int = 60) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            if httpx.get(f"{VERIFIER_URL}/health", timeout=3).status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


@pytest.fixture
def verifier_stopped():
    """
    Stop the verifier for the duration of one test, then restart it and wait
    for health.

    Function-scoped, deliberately, after a module-scoped version of this
    fixture was wrong in a way worth recording: a module-scoped stop is not
    released until the last test in the file finishes, so it took the
    verifier down for every test defined after its first user - including
    test_asserted_comes_from_deferral, which needs the verifier up for its
    assertion to mean anything and failed with a connection error instead.
    Sharing one restart across two tests saved about thirty seconds and
    coupled every later test in the file to the order they happen to be
    written in.

    Restoration is not left to the assertions. A failure inside a test must
    not also leave the verifier down: tests/conftest.py's
    pytest_sessionfinish fails the whole run when a service healthy at the
    start is not healthy at the end, which is the right behaviour and
    exactly what a leaked stop would trigger. The restore problem is
    collected and raised after the yield rather than asserted inside a
    finally, so it cannot replace a primary failure with itself.
    """
    stop = _compose("stop", "verifier")
    assert stop.returncode == 0, f"Failed to stop verifier: {stop.stdout}\n{stop.stderr}"
    restore_problem = None
    try:
        yield
    finally:
        start = _compose("start", "verifier")
        if start.returncode != 0:
            restore_problem = f"Failed to restart verifier: {start.stdout}\n{start.stderr}"
        elif not _verifier_healthy():
            restore_problem = "Verifier did not come back healthy after restart"
    if restore_problem:
        raise AssertionError(restore_problem)


@requires_stack
def test_verifier_reachable_is_true_on_a_healthy_stack():
    body = audit()
    assert body["verifier_reachable"] is True, body.get("verifier_reachable")


@requires_stack
@requires_docker_cli
def test_verifier_reachable_is_false_on_a_deferred_page_when_the_verifier_is_down(verifier_stopped):
    """
    The whole reason the field exists.

    Before deferral, an unreachable verifier left a fingerprint on the page:
    the first row came back `unverifiable` because the first attempt failed.
    A deferred page attempts nothing, so there is no first attempt to fail,
    no row is `unverifiable`, and without this field an outage renders
    identically to a healthy stack that simply did not look.

    Mutation (P3c2-3): return a static value instead of probing - hardcode
    True, or derive the field from whether any verification ran. This test
    must fail.
    """
    body = audit()
    assert body["verifier_reachable"] is False, (
        f"Deferred page reported the verifier reachable while it was stopped: {body.get('verifier_reachable')}"
    )
    # And the page is still a page. Deferral means the outage costs the
    # reader the checks, not the records.
    assert body["entries"], "Deferred page returned no entries with the verifier down"
    assert {e["verification"]["state"] for e in body["entries"]} == {"asserted"}


@requires_stack
@requires_docker_cli
def test_asserted_comes_from_the_circuit_breaker_too(verifier_stopped):
    """
    P3c2-4's second producer.

    On the ?verify=true path with the verifier down, the first entry's
    attempt fails and becomes `unverifiable`; verifier_up flips and every
    entry after it becomes `asserted` without an attempt. That branch
    (control_plane/main.py, the `if not verifier_up` arm) is untouched by
    this phase, and it stays reachable only because verification stayed
    reachable - under unconditional deferral it would be dead code and this
    test could not exist.

    Two producers of one state is the situation ADR-0006 already describes;
    what changes in Phase 3c-2 is that the second one is now the ordinary
    case rather than an outage artifact.

    Scoped to the scan-loop entries on purpose, and the reason is a finding.
    get_audit builds its response in two passes: the tool_call: scan, which
    the circuit breaker governs, and a second pass that synthesizes an entry
    for every intent record with no matching completion (D16). That second
    pass never consults verifier_up, so with the verifier down it attempts a
    verify for each orphaned intent and each one comes back "unverifiable" -
    the response therefore carries one "unverifiable" per orphaned intent
    *after* the run of "asserted", and the breaker's own stop-hammering
    property does not reach them. That is pre-existing behaviour on the
    verify=true path, unchanged by Phase 3c-2 and outside its items; it is
    reported in docs/reports/phase-3c2.md rather than widened into this
    phase. Synthesized entries are exactly the ones carrying
    execution_state "unknown", which is how they are excluded here.
    """
    body = audit(verify=True)
    scanned = [e for e in body["entries"] if e["execution_state"] != "unknown"]
    assert len(scanned) >= 2, (
        f"Need at least two scan-loop entries to see the breaker flip; got {len(scanned)}"
    )
    states = [e["verification"]["state"] for e in scanned]
    assert states[0] == "unverifiable", (
        f"First entry on a verify=true page with the verifier down should be unverifiable, got {states[0]}"
    )
    assert set(states[1:]) == {"asserted"}, (
        f"Scan entries after the breaker flipped should all be asserted, got {sorted(set(states[1:]))}"
    )


@requires_stack
def test_asserted_comes_from_deferral():
    """
    P3c2-4's first producer, stated on its own rather than inferred from the
    default-page test above. `asserted` carried zero assertions anywhere in
    tests/ before this phase, while being produced by one hard-to-reach
    branch and rendered as a muted badge. This phase makes it the normal
    case for most rows, so it gets a test that names it.
    """
    key_raw = f"tool_call:test-agent:{uuid.uuid4().hex}:p3c2_asserted"
    written = verifier_write(key_raw, '{"phase": "3c-2", "criterion": "asserted by deferral"}')["tx_id"]

    body = audit()
    assert body["verifier_reachable"] is True, (
        "This test is about deferral, not an outage - the verifier must be up for it to mean anything"
    )
    matching = [e for e in body["entries"] if e["tx_id"] == written]
    assert matching, f"Written tx={written} not in the default page"
    verification = matching[0]["verification"]
    assert verification["state"] == "asserted", verification
    # Deferral produces a bare state, not a state carrying an error the
    # reader could mistake for a diagnosis.
    assert verification["detail"] is None, verification
    assert verification["error_class"] is None, verification
    assert verification["state_id"] is None, verification


# ---------------------------------------------------------------------------
# Dashboard. Static source parse, and what that does and does not establish
# ---------------------------------------------------------------------------
#
# The dashboard has no JavaScript test harness: dashboard/package.json
# declares dev, build, start and lint and no runner, and CI runs pytest
# only. The project's existing precedent for asserting anything about the
# dashboard is a static parse of its own source
# (tests/test_dashboard_state_rendering.py, P2-10), and these follow it.
#
# What a static parse establishes is exactly this: the source names what it
# should name and does not name what it should not. It does not establish
# that clicking the control fires the request. Adding a JS runner and a CI
# job to close that gap is its own phase; it is stated here and in the phase
# report's mapping table rather than glossed.

DASHBOARD      = REPO_ROOT / "dashboard"
AUDIT_TABLE    = DASHBOARD / "components" / "audit-table.tsx"
AUDIT_PAGE     = DASHBOARD / "app" / "audit" / "page.tsx"
API_LIB        = DASHBOARD / "lib" / "api.ts"
CONSTANTS      = DASHBOARD / "lib" / "constants.ts"
AUDIT_ROUTE    = DASHBOARD / "app" / "api" / "audit" / "route.ts"
VERIFY_ROUTE   = DASHBOARD / "app" / "api" / "audit" / "verify" / "route.ts"


def test_the_expand_handler_names_the_per_record_route_and_names_no_other():
    """
    P3c2-2's dashboard half, claimed at exactly its strength: the expand
    handler names the per-record verify route and names no other API path.

    Mutation: point the expand handler at /api/audit (re-fetching the whole
    page instead of the one record), or drop the handler. This test must
    fail.
    """
    table = AUDIT_TABLE.read_text(encoding="utf-8")
    api = API_LIB.read_text(encoding="utf-8")

    assert "fetchRecordVerification" in table, (
        "audit-table.tsx has no call to the per-record verification helper - "
        "there is no expand affordance, or it calls something else"
    )
    assert "onClick" in table, "audit-table.tsx has no click handler to expand a row with"
    assert "ledger_key" in table, (
        "the expand handler does not name ledger_key, which is the only identifier "
        "the per-record route takes"
    )

    # The helper, and only it, names the route.
    assert re.search(r"export function fetchRecordVerification\b", api), api[:200]
    helper = api[api.index("export function fetchRecordVerification"):]
    helper = helper[:helper.index("\n}")]
    assert "/audit/verify" in helper, helper

    # And the component reaches the API through that helper alone: no
    # fetch() of its own, no second path.
    assert "fetch(" not in table, (
        "audit-table.tsx calls fetch() directly - the expand path must go through "
        "lib/api.ts so there is one place the route is named"
    )
    other_paths = set(re.findall(r'"(/api/[^"]*)"', table))
    assert not other_paths, f"audit-table.tsx names API paths of its own: {sorted(other_paths)}"


def test_the_verify_proxy_route_exists_and_holds_the_key_server_side():
    """D4: the browser never learns the control plane's address or its
    credential. The new proxy route is the same shape as the existing
    /api/audit one, and the same test that would catch it leaking is
    tests/test_credential_boundary_static.py - this only checks the route is
    there and reads the key from the server environment."""
    assert VERIFY_ROUTE.exists(), f"{VERIFY_ROUTE} does not exist"
    source = VERIFY_ROUTE.read_text(encoding="utf-8")
    assert "process.env.CONTROL_PLANE_READ_KEY" in source, source[:300]
    # The property is what the code reads, not what the comments mention: the
    # route's own comment says the words "NEXT_PUBLIC_ prefix", and a bare
    # substring check failed on its own documentation.
    assert "process.env.NEXT_PUBLIC" not in source, (
        "the read key must never be read from a NEXT_PUBLIC_ variable - that prefix "
        "is what ships a value to the browser"
    )
    assert "/audit/verify" in source, source[:300]


def test_asserted_renders_distinctly_from_verified():
    """
    P3c2-4's mutation: render `asserted` identically to `verified`. This
    test must fail.

    `asserted` is now the state most rows carry, so "quiet" must not become
    "invisible" or, worse, "looks checked". The two must not share a badge
    label, and the asserted branch must not claim verification.
    """
    table = AUDIT_TABLE.read_text(encoding="utf-8")
    cell_start = table.index("function VerificationCell")
    cell = table[cell_start:]
    cell = cell[:cell.index("\n// ---")] if "\n// ---" in cell else cell

    assert "NOT CHECKED" in cell, (
        "the asserted branch no longer renders its own NOT CHECKED badge"
    )
    verified_branch = cell[cell.index('=== "verified"'):]
    verified_branch = verified_branch[:verified_branch.index('=== "failed"')]
    assert "NOT CHECKED" not in verified_branch, (
        "verified and asserted render the same badge text"
    )
    assert "Verified" in verified_branch, verified_branch[:200]

    # Anchored on the branch's own marker comment rather than on a character
    # offset back from the badge, so reordering the branches cannot quietly
    # turn this into an assertion about a different one.
    marker = "// asserted -"
    assert marker in cell, (
        "the asserted branch's marker comment is gone - this test can no "
        "longer tell which branch it is looking at"
    )
    asserted_branch = cell[cell.index(marker):]
    assert "NOT CHECKED" in asserted_branch, asserted_branch[:300]
    assert "Verified" not in asserted_branch, (
        "the asserted branch claims verification"
    )
    assert "emerald" not in asserted_branch, (
        "the asserted branch uses the verified branch's colour"
    )


def test_the_dashboard_renders_an_unreachable_verifier():
    """
    P3c2-3's dashboard half. A page of `asserted` rows means one of two very
    different things, and the reader cannot tell them apart from the rows.
    The page must render the difference.
    """
    page = AUDIT_PAGE.read_text(encoding="utf-8")
    assert "verifier_reachable" in page, (
        "app/audit/page.tsx never reads verifier_reachable - an outage renders "
        "identically to a healthy stack that deferred"
    )
    banner = page[page.index("verifier_reachable"):]
    assert "===" in banner or "!" in banner, banner[:200]


def test_the_audit_page_size_has_exactly_one_definition():
    """
    P3c2-5's mutation: reintroduce a second literal. This test must fail.

    Three files carried the number before this phase, not the two the
    instruction names: app/api/audit/route.ts, lib/api.ts's default
    parameter, and app/audit/page.tsx's fetchAudit(200) call site. All three
    must now take it from one place, and none of them may spell it.
    """
    assert CONSTANTS.exists(), f"{CONSTANTS} does not exist"
    constants = CONSTANTS.read_text(encoding="utf-8")
    definitions = re.findall(r"export const AUDIT_PAGE_SIZE\s*=\s*(\d+)", constants)
    assert len(definitions) == 1, f"AUDIT_PAGE_SIZE is defined {len(definitions)} times"

    # The two files that need the value take it from that one definition.
    for path in (AUDIT_ROUTE, API_LIB):
        source = path.read_text(encoding="utf-8")
        assert "AUDIT_PAGE_SIZE" in source, f"{path.name} does not use AUDIT_PAGE_SIZE"

    # And none of the three spells it, comments included. A comment carrying
    # the number is how the next literal gets copied back in.
    for path in (AUDIT_ROUTE, API_LIB, AUDIT_PAGE):
        source = path.read_text(encoding="utf-8")
        stray = re.findall(r"\b200\b", source)
        assert not stray, (
            f"{path.name} spells the page size literally ({len(stray)} occurrence(s)) "
            f"instead of taking it from lib/constants.ts"
        )
