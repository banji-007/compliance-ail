"""
tests/test_bundle_revision_attribution.py - P12-1, Phase 1.2 (D9).

Attack to reproduce (docs/reports/phase-1-1-redteam.md, T7, verbatim): a
decoy bundle served to a running OPA, then an evaluation naming it, let a
real FinOps deny reason from ail-policies get attributed to the decoy's
revision. The original mechanism was `input.bundle_name`: a caller-supplied
key with no relationship to whichever bundle actually populated
data.ail.*.

D9 removes input.bundle_name from the request entirely and replaces the
lookup with a rule that finds whichever loaded bundle's manifest.roots
claims "ail". This is exercised here directly against the live OPA
instance (docker-compose.test.yml) using OPA's generic Data API to write a
second bundle's manifest into data.system.bundles - the exact shape the
new rule reads, and the exact shape a real second bundle-serving container
would produce via the Bundle API. Cleaned up after each test.

Migrated in Phase 2 (P2-1): query_opa_policy moved from
interceptor/middleware.py to decision_service/main.py (D12). The two live
decoy-bundle tests below talk to OPA directly over its own Data/eval API
and are unaffected by that move - only the capturing-client test at the
bottom (which exercises query_opa_policy's own request-building code, not
OPA itself) needed to retarget its monkeypatch and call site.
"""

import os
import sys
import uuid

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

OPA_BASE = os.environ["OPA_URL"].replace("/v1/data/ail/main/evaluation", "")

_APPROVED_ARGS = {
    "instance_type": "t3.micro",
    "region": "us-east-1",
    "cost_per_hour": 5.0,
    "tags": {"environment": "dev", "data_classification": "internal", "cost_center": "engineering", "project": "webapp"},
}


requires_opa = pytest.mark.needs_stack("opa")


def _real_revision() -> str:
    resp = httpx.get(f"{OPA_BASE}/v1/data/system/bundles/ail-policies/manifest/revision", timeout=5)
    resp.raise_for_status()
    revision = resp.json().get("result")
    assert revision, f"OPA has no ail-policies revision loaded: {resp.json()}"
    return revision


def _put_decoy_bundle(name: str, roots: list, revision: str) -> None:
    resp = httpx.put(
        f"{OPA_BASE}/v1/data/system/bundles/{name}",
        json={"manifest": {"revision": revision, "roots": roots}},
        timeout=5,
    )
    resp.raise_for_status()


def _delete_decoy_bundle(name: str) -> None:
    httpx.delete(f"{OPA_BASE}/v1/data/system/bundles/{name}", timeout=5)


def _query_evaluation() -> dict:
    resp = httpx.post(
        f"{OPA_BASE}/v1/data/ail/main/evaluation",
        json={"input": {"tool_name": "provision_cloud_server", "tool_args": _APPROVED_ARGS}},
        timeout=5,
    )
    resp.raise_for_status()
    return resp.json()


@requires_opa
def test_decoy_bundle_with_disjoint_root_does_not_get_attributed():
    """T7's exact repro: a decoy bundle claiming an unrelated root
    ("decoy"), alongside the real ail-policies bundle. Even though the
    decoy exists in data.system.bundles, it never claims "ail" - the
    single real claimant still resolves, and its own real revision is
    what gets attributed, never the decoy's."""
    real_revision = _real_revision()
    decoy_name = f"decoy-bundle-{uuid.uuid4().hex}"
    decoy_revision = f"DECOY-REVISION-{uuid.uuid4().hex}-NOT-AIL-POLICIES"
    _put_decoy_bundle(decoy_name, ["decoy"], decoy_revision)
    try:
        body = _query_evaluation()
        result = body.get("result")
        assert result is not None, f"Expected a defined result with one real claimant, got: {body}"
        assert result["revision"] == real_revision, (
            f"Expected the real ail-policies revision {real_revision!r}, got {result['revision']!r} "
            f"(decoy revision was {decoy_revision!r})"
        )
        assert result["revision"] != decoy_revision
    finally:
        _delete_decoy_bundle(decoy_name)


@requires_opa
def test_two_claimants_of_ail_root_is_undefined():
    """A second bundle also claiming the `ail` root (not a disjoint root)
    must make the whole evaluation undefined - there is no longer a
    single answer for "the" ail-policies revision, and the rule must not
    guess. The interceptor treats this as FAULT_REVISION_UNAVAILABLE
    (see tests/test_outcome_types.py::test_fault_revision_unavailable for
    the fault-mapping side of this contract)."""
    decoy_name = f"decoy-bundle-{uuid.uuid4().hex}"
    decoy_revision = f"DECOY-REVISION-{uuid.uuid4().hex}"
    _put_decoy_bundle(decoy_name, ["ail"], decoy_revision)
    try:
        body = _query_evaluation()
        assert body.get("result") is None, (
            f"Expected an undefined result with two claimants of 'ail', got: {body}"
        )
    finally:
        _delete_decoy_bundle(decoy_name)


# ---------------------------------------------------------------------------
# input.bundle_name is gone from the request entirely (P12-1's own required
# result, distinct from the live decoy tests above)
# ---------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, body: dict):
        self._body = body
        self.status_code = 200
        self.text = "{}"

    def json(self):
        return self._body


class _CapturingClient:
    """Stands in for httpx.Client(verify=...) - captures the input document
    query_opa_policy actually sends, without a live OPA."""

    captured_input: dict = {}

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def post(self, url, json=None, timeout=None):
        _CapturingClient.captured_input = json["input"]
        return _FakeResponse({"result": {"allow": True, "reasons": [], "revision": "x"}})


def test_bundle_name_not_sent_in_evaluation_request(monkeypatch):
    monkeypatch.setattr(decision_main.httpx, "Client", _CapturingClient)
    decision_main.query_opa_policy("provision_cloud_server", _APPROVED_ARGS)
    assert "bundle_name" not in _CapturingClient.captured_input, (
        f"input.bundle_name must not exist - a caller must not be able to name "
        f"the bundle whose revision gets recorded (D9). Sent: {_CapturingClient.captured_input}"
    )
    assert set(_CapturingClient.captured_input.keys()) == {"tool_name", "tool_args"}, (
        f"Unexpected keys in the OPA input document: {_CapturingClient.captured_input}"
    )
