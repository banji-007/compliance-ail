"""
tests/test_opa_request_count.py - P11-8, Phase 1.1.

Exactly one OPA request per intercepted call that reaches evaluation.
Red-team S1 mutation #7: a second OPA round trip reintroduced for deny
reasons (a real extra httpx POST after the combined /evaluation call already
decided policy_deny) left the 42-item suite fully green - nothing counted
OPA requests. P1-1's "exactly one OPA request" claim was demonstrated live,
by hand, via a container log diff, never gated by anything that runs in CI.

Requires the docker-compose.test.yml stack. SPIRE_DISABLED=true bypasses
mTLS, matching Makefile:45-53. httpx.Client.post is spy-wrapped (real calls
still go through - this counts, it does not mock) so content-store and
ledger writes still happen normally; only requests to _OPA_EVAL_URL count.
"""

import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "interceptor"))

os.environ.setdefault("SPIRE_DISABLED", "true")
os.environ.setdefault("OPA_URL", "http://localhost:8181/v1/data/ail/main/allow")

import middleware  # noqa: E402

_APPROVED_ARGS = {
    "instance_type": "t3.micro",
    "region": "us-east-1",
    "cost_per_hour": 5.0,
    "tags": {"environment": "dev", "data_classification": "internal", "cost_center": "engineering", "project": "webapp"},
}

_DENIED_ARGS = {
    "instance_type": "p4d.24xlarge",
    "region": "us-east-1",
    "cost_per_hour": 50.0,
    "tags": {"environment": "dev", "data_classification": "internal", "cost_center": "engineering", "project": "webapp"},
}


def _opa_reachable() -> bool:
    try:
        httpx.get("http://localhost:8181/health", timeout=2)
        return True
    except Exception:
        return False


def _immudb_reachable() -> bool:
    immudb_url = os.getenv("IMMUDB_URL", "http://localhost:8080")
    try:
        httpx.get(immudb_url, timeout=2)
        return True
    except Exception:
        return False


requires_stack = pytest.mark.skipif(
    not (_opa_reachable() and _immudb_reachable()),
    reason="OPA and/or ImmuDB not reachable",
)

_REAL_POST = httpx.Client.post


def _make_counting_post(counter: list, url_prefix: str):
    """Spy wrapper - delegates to the real implementation so this counts
    real requests rather than mocking them away."""

    def _counting_post(self, url, *args, **kwargs):
        if str(url).startswith(url_prefix):
            counter[0] += 1
        return _REAL_POST(self, url, *args, **kwargs)

    return _counting_post


@requires_stack
def test_exactly_one_opa_request_for_an_approved_call(monkeypatch):
    counter = [0]
    monkeypatch.setattr(httpx.Client, "post", _make_counting_post(counter, middleware._OPA_EVAL_URL))
    r = middleware.intercept_tool_call("provision_cloud_server", _APPROVED_ARGS, "opa_count_test")
    assert r["outcome_type"] == "policy_allow", f"Expected policy_allow, got: {r}"
    assert counter[0] == 1, f"Expected exactly 1 OPA request, got {counter[0]}"


@requires_stack
def test_exactly_one_opa_request_for_a_denied_call(monkeypatch):
    """The specific case red-team mutation #7 targeted: a second round trip
    for deny reasons after the combined /evaluation call already decided
    policy_deny."""
    counter = [0]
    monkeypatch.setattr(httpx.Client, "post", _make_counting_post(counter, middleware._OPA_EVAL_URL))
    r = middleware.intercept_tool_call("provision_cloud_server", _DENIED_ARGS, "opa_count_test")
    assert r["outcome_type"] == "policy_deny", f"Expected policy_deny, got: {r}"
    assert counter[0] == 1, f"Expected exactly 1 OPA request, got {counter[0]}"
