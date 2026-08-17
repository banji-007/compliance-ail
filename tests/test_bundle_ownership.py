"""
tests/test_bundle_ownership.py - P11-7, Phase 1.1.

Exactly one loaded OPA bundle may claim the `ail` root, and its name must
match AIL_BUNDLE_NAME. Red-team S2: a decoy bundle claiming a disjoint root
("decoy") loaded alongside the real "ail-policies" bundle produced no error -
nothing checked that only one bundle claimed "ail". This extends
verify_bundle_at_startup's existing revision-polling check
(middleware.py::_check_bundle_root_ownership) rather than adding a second
independent gate.

Pure unit tests - no live stack. sys.exit is replaced with a function that
raises a catchable sentinel exception instead of actually exiting the test
process; the two OPA fetch helpers are monkeypatched directly so no real
network calls happen.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "interceptor"))

os.environ.setdefault("SPIRE_DISABLED", "true")
os.environ.setdefault("OPA_URL", "http://localhost:8181/v1/data/ail/main/allow")

import pytest

import middleware  # noqa: E402


class _StartupExit(Exception):
    """Raised by the mocked sys.exit in place of actually exiting."""


def _raise_startup_exit(code=1):
    raise _StartupExit(f"sys.exit({code})")


def _bundles_map(*claimants_and_roots: tuple[str, list[str]]) -> dict:
    return {
        name: {"manifest": {"revision": f"rev-{name}", "roots": roots}}
        for name, roots in claimants_and_roots
    }


def _run_check(monkeypatch, bundles_map: dict | None, bundle_name: str = "ail-policies"):
    monkeypatch.setattr(middleware, "_BUNDLE_NAME", bundle_name)
    monkeypatch.setattr(middleware, "_fetch_opa_bundles_map", lambda ssl_context: bundles_map)
    monkeypatch.setattr(middleware.sys, "exit", _raise_startup_exit)
    middleware._check_bundle_root_ownership(ssl_context=True)


def test_single_correct_claimant_does_not_exit(monkeypatch):
    bundles = _bundles_map(("ail-policies", ["ail"]))
    _run_check(monkeypatch, bundles)  # must not raise


def test_two_claimants_of_ail_root_exits(monkeypatch):
    """Red-team S2's exact repro: a decoy bundle also claiming 'ail'."""
    bundles = _bundles_map(("ail-policies", ["ail"]), ("decoy-bundle", ["ail"]))
    with pytest.raises(_StartupExit):
        _run_check(monkeypatch, bundles)


def test_single_claimant_name_mismatch_exits(monkeypatch):
    """The bundle claiming 'ail' exists, but under a different name than
    AIL_BUNDLE_NAME - the revision this agent would read back would name a
    bundle other than the one actually serving policy."""
    bundles = _bundles_map(("some-other-bundle-name", ["ail"]))
    with pytest.raises(_StartupExit):
        _run_check(monkeypatch, bundles, bundle_name="ail-policies")


def test_zero_claimants_exits(monkeypatch):
    bundles = _bundles_map(("decoy-bundle", ["decoy"]))
    with pytest.raises(_StartupExit):
        _run_check(monkeypatch, bundles)


def test_unreachable_bundles_map_exits(monkeypatch):
    """A failed fetch of /v1/data/system/bundles is itself fatal - fail
    closed, matching the rest of the startup check."""
    with pytest.raises(_StartupExit):
        _run_check(monkeypatch, None)


def test_disjoint_roots_do_not_count_as_claiming_ail(monkeypatch):
    """A bundle claiming an unrelated root ('decoy') alongside the real
    'ail-policies' bundle is not itself a claimant - only 'ail' membership
    in `roots` counts."""
    bundles = _bundles_map(("ail-policies", ["ail"]), ("decoy-bundle", ["decoy"]))
    _run_check(monkeypatch, bundles)  # must not raise
