"""
tests/test_policy_response_shape.py - P11-3, Phase 1.1.

A malformed OPA /evaluation response must be a fault, not an implicit
approval. Red-team S3 attack 2: {"result": {"allow": true}} with no
`reasons`/`revision` produced outcome_type: policy_allow, policy_revision:
None - contradicting ADR-0005's own table (policy_allow always carries a set
revision).

Pure unit tests - no live stack. httpx.Client is mocked entirely, matching
the red-team's own repro style, and query_opa_policy is called directly
(not intercept_tool_call), so no ledger/content infra is needed either.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "interceptor"))

os.environ.setdefault("SPIRE_DISABLED", "true")
os.environ.setdefault("OPA_URL", "http://localhost:8181/v1/data/ail/main/allow")

import middleware  # noqa: E402

_VALID_ARGS = {
    "instance_type": "t3.micro",
    "region": "us-east-1",
    "cost_per_hour": 5.0,
    "tags": {"environment": "dev", "data_classification": "internal", "cost_center": "engineering", "project": "webapp"},
}


class _FakeResponse:
    def __init__(self, body: dict, status_code: int = 200):
        self._body = body
        self.status_code = status_code
        self.text = json.dumps(body)

    def json(self):
        return self._body


class _FakeClient:
    """Stands in for httpx.Client(verify=...) - only .post is exercised by
    query_opa_policy's /evaluation call."""

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def post(self, *args, **kwargs):
        return _FakeResponse(_RESPONSE_BODY)


_RESPONSE_BODY: dict = {}


def _query_with_mocked_response(monkeypatch, body: dict) -> dict:
    global _RESPONSE_BODY
    _RESPONSE_BODY = body
    monkeypatch.setattr(middleware.httpx, "Client", _FakeClient)
    return middleware.query_opa_policy("provision_cloud_server", _VALID_ARGS)


def test_missing_reasons_and_revision_is_a_fault(monkeypatch):
    result = _query_with_mocked_response(monkeypatch, {"result": {"allow": True}})
    assert result["outcome_type"] == "fault", f"Expected fault, got: {result}"
    assert result["fault_class"] == "malformed_policy_response", f"Expected malformed_policy_response, got: {result}"
    assert result["policy_revision"] is None


def test_missing_reasons_only_is_a_fault(monkeypatch):
    result = _query_with_mocked_response(
        monkeypatch, {"result": {"allow": True, "revision": "some-real-revision"}}
    )
    assert result["outcome_type"] == "fault", f"Expected fault, got: {result}"
    assert result["fault_class"] == "malformed_policy_response", f"Expected malformed_policy_response, got: {result}"
    assert result["policy_revision"] is None


def test_missing_revision_only_is_a_fault(monkeypatch):
    result = _query_with_mocked_response(
        monkeypatch, {"result": {"allow": False, "reasons": ["some reason"]}}
    )
    assert result["outcome_type"] == "fault", f"Expected fault, got: {result}"
    assert result["fault_class"] == "malformed_policy_response", f"Expected malformed_policy_response, got: {result}"
    assert result["policy_revision"] is None


def test_wrong_typed_allow_is_a_fault(monkeypatch):
    """allow present but not a bool (e.g. a truthy string) must not be
    treated as an implicit True."""
    result = _query_with_mocked_response(
        monkeypatch, {"result": {"allow": "true", "reasons": [], "revision": "x"}}
    )
    assert result["outcome_type"] == "fault", f"Expected fault, got: {result}"
    assert result["fault_class"] == "malformed_policy_response", f"Expected malformed_policy_response, got: {result}"


def test_well_formed_response_still_produces_policy_allow(monkeypatch):
    """Sanity check: the shape guard does not reject a valid response."""
    result = _query_with_mocked_response(
        monkeypatch, {"result": {"allow": True, "reasons": [], "revision": "a-real-revision"}}
    )
    assert result["outcome_type"] == "policy_allow", f"Expected policy_allow, got: {result}"
    assert result["fault_class"] is None
    assert result["policy_revision"] == "a-real-revision"
