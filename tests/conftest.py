"""
tests/conftest.py

Phase 3c-1 completion pass, item 5. A test that breaks the stack must not be
able to hide every test that runs after it.

What happened. `tests/test_content_states.py::test_erasure_refused_when_
tombstone_write_fails` stops the verifier on purpose, then restarts it and
waits for health. On one CI attempt that wait timed out. The verifier stayed
down for the rest of the session and 66 later tests failed against a dead
service, each one reporting an ordinary assertion failure on a response body.
Nothing in the output said the environment was broken, so the run looked like
a 66-test regression.

Why the existing guards did not catch it. Every stack-dependent test file
carried its own module-level `requires_stack = pytest.mark.skipif(...)`. Two
independent problems:

  Import time. A module-level skipif predicate is evaluated once, when the
  module is imported during collection. A stack that breaks mid-session is
  never re-examined.

  The wrong services. Nine of the twelve definitions asked only whether OPA
  and ImmuDB were reachable. Neither is the verifier. The test that stops the
  verifier was itself gated by a predicate that does not look at it.

What this file does instead. `@pytest.mark.needs_stack("verifier", "immudb")`
declares which services a test actually needs. The probe runs per file, not
per test, and not at import: `pytest_runtest_setup` checks the module's
declared services the first time a test from that module runs, so a service
that dies mid-session is caught at the next file boundary and its dependants
skip with a reason that names the service.

Skipping alone would be a worse bug than the one it fixes. A genuine crash in
a service, caused by a real defect, would then produce a run of quiet skips
instead of a run of failures: the same hiding, wearing a different coat. So
the skip is paired with a session-scoped check. Every service healthy when the
session started must be healthy when it ends, and `pytest_sessionfinish` fails
the run if one is not. A crash is therefore one loud failure naming the
service, and the tests that could not run are skips naming the same service,
which is the distinction the CI log did not have.

Probe results are cached per file so a 306-test session does not make 1200
health requests; the cache is cleared at each file boundary, which is what
makes a mid-session death visible at all.
"""

from __future__ import annotations

import os

import httpx
import pytest

# Where each service answers, and what counts as an answer. Read from the same
# environment variables the tests themselves use, so a probe cannot succeed
# against a different endpoint than the test then talks to.
SERVICES = {
    "opa": lambda: ("http://localhost:8181/health", None),
    "immudb": lambda: (os.getenv("IMMUDB_URL", "http://localhost:8080"), None),
    "verifier": lambda: (
        os.getenv("VERIFIER_URL", "http://localhost:8003") + "/health",
        200,
    ),
    "control_plane": lambda: (
        os.getenv("CONTROL_PLANE_URL", "http://localhost:8002") + "/health",
        200,
    ),
    "decision_service": lambda: (
        os.getenv("DECISION_SERVICE_URL", "http://localhost:8010/decide").replace(
            "/decide", "/health"
        ),
        200,
    ),
    "dashboard": lambda: (os.getenv("DASHBOARD_URL", "http://localhost:3001"), None),
}

_PROBE_CACHE: dict[str, bool] = {}
_CURRENT_FILE: list[str] = []
_HEALTHY_AT_START: dict[str, bool] = {}


def probe(service: str) -> bool:
    """Is this service answering right now? Uncached."""
    url, expected = SERVICES[service]()
    try:
        response = httpx.get(url, timeout=2)
    except Exception:
        return False
    return True if expected is None else response.status_code == expected


def _probe_cached(service: str) -> bool:
    if service not in _PROBE_CACHE:
        _PROBE_CACHE[service] = probe(service)
    return _PROBE_CACHE[service]


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "needs_stack(*services): skip unless the named services answer. Probed "
        "per file rather than at import, so a service that dies mid-session is "
        "caught at the next file boundary.",
    )


def pytest_sessionstart(session):
    """Record which services were up before any test ran.

    This is the reference the end-of-session check compares against. A service
    that was never up is an environment the suite was not run against, which is
    not a regression; a service that was up and is now down is.
    """
    for service in SERVICES:
        _HEALTHY_AT_START[service] = probe(service)


def pytest_runtest_setup(item):
    marker = item.get_closest_marker("needs_stack")
    if marker is None:
        return

    path = str(item.fspath)
    if not _CURRENT_FILE or _CURRENT_FILE[0] != path:
        _CURRENT_FILE[:] = [path]
        _PROBE_CACHE.clear()

    missing = [s for s in marker.args if not _probe_cached(s)]
    if missing:
        pytest.skip(
            "stack service(s) not answering: %s. This is an environment "
            "condition, not an assertion failure." % ", ".join(sorted(missing))
        )


def pytest_sessionfinish(session, exitstatus):
    """Fail the run if a service that was up at the start is down at the end.

    Without this, item 5's per-file skip would convert a real service crash
    into a quiet run of skips. The skip says which tests could not run; this
    says the environment changed underneath them, and makes the run fail so
    nobody reads the skips as a pass.
    """
    died = [
        service
        for service, was_up in _HEALTHY_AT_START.items()
        if was_up and not probe(service)
    ]
    if not died:
        return
    session.exitstatus = 1
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    message = (
        "service(s) healthy at session start and down at session end: %s. "
        "Tests after the failure point were skipped, not passed; something in "
        "this run left the stack broken." % ", ".join(sorted(died))
    )
    if reporter is not None:
        reporter.write_sep("=", "STACK DIED DURING THIS RUN", red=True)
        reporter.write_line(message)
