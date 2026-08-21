"""
tests/test_spire_absent_guard.py - P2-5 (Phase 2).

Before this phase, the SPIRE-absent exit existed only as a side effect of
verify_bundle_at_startup's own control flow - nothing separated "SPIRE
identity unavailable" from "the thing being checked afterward is
unavailable". Reordering that function's internals could silently drop the
documented security property (process refuses to run without a verified
SPIRE identity) with no test catching it.

interceptor/middleware.py::_spire_absent_exit is now a standalone function
with its own call site inside verify_bundle_at_startup, checked first,
unconditionally. This file asserts both: the guard itself exits and names
SPIRE, and verify_bundle_at_startup actually calls it before anything else -
independent of whether the decision service is reachable at all.

No live stack required - both tests fail before any network call is made.
"""

import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "interceptor"))

os.environ.setdefault("SPIRE_DISABLED", "true")

import middleware  # noqa: E402


def test_spire_absent_exit_names_spire(monkeypatch, caplog):
    """
    Direct test of the guard function itself. Mutation: remove this
    function's body (or make it a no-op). This test must fail against
    that mutation.
    """
    monkeypatch.setattr(middleware, "_SPIRE_DISABLED", False)
    monkeypatch.setattr(middleware, "_get_spiffe_ssl_context", lambda: None)

    with caplog.at_level(logging.ERROR):
        with pytest.raises(SystemExit) as exc_info:
            middleware._spire_absent_exit("https://envoy:8443/decide")

    assert exc_info.value.code == 1
    assert any("SPIRE" in record.message for record in caplog.records), (
        "SPIRE-absent exit must name SPIRE specifically in its message, so it is never "
        "mistaken for a decision-service or policy-engine problem."
    )


def test_verify_bundle_at_startup_exits_on_spire_absence_before_any_network_call(monkeypatch, caplog):
    """
    P2-5's actual named mutation target: verify_bundle_at_startup must call
    the SPIRE-absent guard, unconditionally, before its own decision-service
    reachability polling. Proven two ways, because exit code alone does not
    distinguish the two failure paths (a first version of this test asserted
    only `exc_info.value.code == 1` and passed identically whether the guard
    ran or not - both paths exit 1, one immediately via the guard, one after
    the full poll timeout via unreachable-service):

    (1) Timing: with an unroutable decision-service URL and a real 30s
        timeout_seconds budget, the guard must fire in well under a second -
        if it takes anywhere near the full budget, the polling loop ran
        instead, meaning the guard was skipped.
    (2) Log content: the message must name SPIRE specifically, not decision-
        service reachability - the two paths log different text.

    Mutation: delete the `_spire_absent_exit(...)` call from
    verify_bundle_at_startup (leaving _spire_absent_exit itself intact).
    This test must fail against that mutation - it exits at close to the
    full 30s timeout instead of immediately, with the wrong message.
    """
    import time as _time

    monkeypatch.setattr(middleware, "_SPIRE_DISABLED", False)
    monkeypatch.setattr(middleware, "_get_spiffe_ssl_context", lambda: None)
    monkeypatch.setattr(middleware, "_DECISION_SERVICE_URL", "http://localhost:1/decide")
    monkeypatch.setattr(middleware, "_DECISION_SERVICE_HEALTH_URL", "http://localhost:1/health")

    start = _time.monotonic()
    with caplog.at_level(logging.ERROR):
        with pytest.raises(SystemExit) as exc_info:
            middleware.verify_bundle_at_startup(timeout_seconds=30, poll_interval=2)
    elapsed = _time.monotonic() - start

    assert exc_info.value.code == 1
    assert elapsed < 5, (
        f"Exited after {elapsed:.1f}s against a 30s timeout budget - too slow to have been "
        f"the SPIRE guard (which never touches the network); the reachability polling loop "
        f"must have run instead, meaning the guard was skipped or ran after it."
    )
    assert any("SPIRE" in record.message for record in caplog.records), (
        f"Expected a log message naming SPIRE; got: {[r.message for r in caplog.records]}"
    )


def test_verify_bundle_at_startup_skips_guard_when_spire_disabled(monkeypatch):
    """
    Sanity check on the other branch: SPIRE_DISABLED=true (dev mode) must
    not trip this guard at all - only the reachability check applies. Uses
    a reachable decision-service health endpoint stand-in via monkeypatch
    on httpx so no live stack is needed.
    """
    import httpx

    monkeypatch.setattr(middleware, "_SPIRE_DISABLED", True)
    monkeypatch.setattr(middleware, "_DECISION_SERVICE_HEALTH_URL", "http://fake/health")

    class _FakeResponse:
        status_code = 200

    class _FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, *a, **kw):
            return _FakeResponse()

    monkeypatch.setattr(httpx, "Client", lambda *a, **kw: _FakeClient())

    # Must not raise SystemExit at all.
    middleware.verify_bundle_at_startup(timeout_seconds=5, poll_interval=1)
