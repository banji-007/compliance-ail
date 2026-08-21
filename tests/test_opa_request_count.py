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
ledger writes still happen normally; only requests to _OPA_URL count.

Migrated in Phase 2 (P2-1): the OPA query moved from
interceptor/middleware.py to decision_service/main.py (D12), and there is
no longer a separate _OPA_EVAL_URL - decision_service/main.py's _OPA_URL is
itself the /evaluation endpoint. The full-pipeline call under test moved
from middleware.intercept_tool_call (now just an HTTP client to
decision_service) to decision_main.decide(), called in-process the same way
tests/test_outcome_types.py does - this is what actually reaches
query_opa_policy in this process, where the spy can see it.
"""

import asyncio
import os
import sys

import httpx
import pytest


import importlib.util as _importlib_util

# decision_service/main.py's own `from schemas import ...` needs this
# directory on sys.path - loading main.py itself via spec_from_file_location
# below (to dodge the module-name collision, see _load_decision_service_main)
# does not add its own directory to sys.path automatically the way a normal
# package-relative import would.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "decision_service"))


def _load_decision_service_main():
    """decision_service/main.py and control_plane/main.py are both named
    main.py - a bare `import main` in one test file clobbers whichever
    module sys.modules["main"] already held for every other test file in
    the same pytest session (Python caches by module name, not by which
    sys.path entry was active when the import statement ran - confirmed
    live: test_verification.py's control-plane tests got decision_service's
    module back instead, AttributeError on a function that only exists in
    control_plane/main.py). Loading this one under its own explicit module
    name sidesteps the collision instead of depending on import order."""
    spec = _importlib_util.spec_from_file_location(
        "decision_service_main",
        os.path.join(os.path.dirname(__file__), "..", "decision_service", "main.py"),
    )
    module = _importlib_util.module_from_spec(spec)
    sys.modules["decision_service_main"] = module
    spec.loader.exec_module(module)
    return module


os.environ.setdefault("SPIRE_DISABLED", "true")
os.environ.setdefault("OPA_URL", "http://localhost:8181/v1/data/ail/main/evaluation")

decision_main = _load_decision_service_main()

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


def _decide(tool_name, tool_args, agent_id="opa_count_test") -> dict:
    req = decision_main.DecideRequest(tool_name=tool_name, tool_args=tool_args, agent_id=agent_id)
    return asyncio.run(decision_main.decide(req))


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
    monkeypatch.setattr(httpx.Client, "post", _make_counting_post(counter, decision_main._OPA_URL))
    r = _decide("provision_cloud_server", _APPROVED_ARGS)
    assert r["outcome_type"] == "policy_allow", f"Expected policy_allow, got: {r}"
    assert counter[0] == 1, f"Expected exactly 1 OPA request, got {counter[0]}"


@requires_stack
def test_exactly_one_opa_request_for_a_denied_call(monkeypatch):
    """The specific case red-team mutation #7 targeted: a second round trip
    for deny reasons after the combined /evaluation call already decided
    policy_deny."""
    counter = [0]
    monkeypatch.setattr(httpx.Client, "post", _make_counting_post(counter, decision_main._OPA_URL))
    r = _decide("provision_cloud_server", _DENIED_ARGS)
    assert r["outcome_type"] == "policy_deny", f"Expected policy_deny, got: {r}"
    assert counter[0] == 1, f"Expected exactly 1 OPA request, got {counter[0]}"
