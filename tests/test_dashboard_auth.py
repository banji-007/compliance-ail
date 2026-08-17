"""
tests/test_dashboard_auth.py - P11-1, Phase 1.1 (D6).

Red-team S6: an anonymous curl with zero headers read the full audit log
(including other agents' raw payloads) and mutated tenant policy through the
dashboard's own /api/* routes - the control-plane credential was never
reachable from the browser, but nothing else protected those routes either.

D6 splits authorization at both layers:
  - dashboard/middleware.ts: the caller (browser/curl) must present one of
    two independent HTTP Basic Auth credential pairs (read, write) before
    any route handler runs. Read never authorizes a write route.
  - control_plane/main.py: CONTROL_PLANE_API_KEY splits into
    CONTROL_PLANE_READ_KEY (GET /audit only) and CONTROL_PLANE_WRITE_KEY
    (PUT/POST /tenants, POST/DELETE /content) - tested here directly against
    the control plane, bypassing the dashboard entirely, so a dashboard-layer
    regression can't be mistaken for control-plane enforcement.

Requires the docker-compose.test.yml stack, including the dashboard service
(only this test file needs it).
"""

import os
import uuid

import httpx
import pytest

DASHBOARD_URL = os.getenv("DASHBOARD_URL", "http://localhost:3001")
CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL", "http://localhost:8002")

DASHBOARD_READ_USER = os.getenv("DASHBOARD_READ_USER", "test-dashboard-reader")
DASHBOARD_READ_PASSWORD = os.getenv("DASHBOARD_READ_PASSWORD", "test-dashboard-read-pw")
DASHBOARD_WRITE_USER = os.getenv("DASHBOARD_WRITE_USER", "test-dashboard-writer")
DASHBOARD_WRITE_PASSWORD = os.getenv("DASHBOARD_WRITE_PASSWORD", "test-dashboard-write-pw")

CONTROL_PLANE_READ_KEY = os.getenv("CONTROL_PLANE_READ_KEY", "test-read-key")
CONTROL_PLANE_WRITE_KEY = os.getenv("CONTROL_PLANE_WRITE_KEY", "test-write-key")

READ_AUTH = (DASHBOARD_READ_USER, DASHBOARD_READ_PASSWORD)
WRITE_AUTH = (DASHBOARD_WRITE_USER, DASHBOARD_WRITE_PASSWORD)

_TENANT_ID = "tenant_default"
_NOOP_UPDATE = {"name": "Default Tenant"}  # matches the seeded value - idempotent even if wrongly authorized


def _dashboard_reachable() -> bool:
    try:
        httpx.get(f"{DASHBOARD_URL}/audit", timeout=3)
        return True
    except Exception:
        return False


def _control_plane_reachable() -> bool:
    try:
        httpx.get(f"{CONTROL_PLANE_URL}/health", timeout=3)
        return True
    except Exception:
        return False


requires_dashboard = pytest.mark.skipif(
    not (_dashboard_reachable() and _control_plane_reachable()),
    reason="dashboard and/or control plane not reachable",
)


# ---------------------------------------------------------------------------
# Dashboard layer (middleware.ts) - anonymous and cross-scope rejection
# ---------------------------------------------------------------------------

@requires_dashboard
def test_anonymous_get_audit_rejected():
    resp = httpx.get(f"{DASHBOARD_URL}/api/audit", timeout=10)
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"


@requires_dashboard
def test_anonymous_get_tenant_rejected():
    resp = httpx.get(f"{DASHBOARD_URL}/api/tenants/{_TENANT_ID}", timeout=10)
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"


@requires_dashboard
def test_anonymous_put_tenant_rejected():
    resp = httpx.put(f"{DASHBOARD_URL}/api/tenants/{_TENANT_ID}", json=_NOOP_UPDATE, timeout=10)
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"


@requires_dashboard
def test_read_credentialed_get_audit_succeeds():
    resp = httpx.get(f"{DASHBOARD_URL}/api/audit", auth=READ_AUTH, timeout=10)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"


@requires_dashboard
def test_read_credentialed_put_tenant_rejected():
    """The named cross-scope case: valid read credentials do not authorize
    the write route."""
    resp = httpx.put(f"{DASHBOARD_URL}/api/tenants/{_TENANT_ID}", json=_NOOP_UPDATE, auth=READ_AUTH, timeout=10)
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"


@requires_dashboard
def test_write_credentialed_put_tenant_succeeds():
    resp = httpx.put(f"{DASHBOARD_URL}/api/tenants/{_TENANT_ID}", json=_NOOP_UPDATE, auth=WRITE_AUTH, timeout=10)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"


# ---------------------------------------------------------------------------
# Control-plane layer, direct - bypasses the dashboard entirely
# ---------------------------------------------------------------------------

@requires_dashboard
def test_control_plane_read_key_rejected_on_put_tenants():
    resp = httpx.put(
        f"{CONTROL_PLANE_URL}/tenants/{_TENANT_ID}",
        json=_NOOP_UPDATE,
        headers={"X-API-Key": CONTROL_PLANE_READ_KEY},
        timeout=10,
    )
    assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.text}"


@requires_dashboard
def test_control_plane_read_key_rejected_on_post_content():
    resp = httpx.post(
        f"{CONTROL_PLANE_URL}/content",
        json={"call_id": f"test-auth-probe-{uuid.uuid4().hex}", "payload": {"probe": True}},
        headers={"X-API-Key": CONTROL_PLANE_READ_KEY},
        timeout=10,
    )
    assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.text}"


@requires_dashboard
def test_control_plane_read_key_rejected_on_delete_content():
    resp = httpx.delete(
        f"{CONTROL_PLANE_URL}/content/test-auth-probe-nonexistent",
        headers={"X-API-Key": CONTROL_PLANE_READ_KEY},
        timeout=10,
    )
    assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.text}"


@requires_dashboard
def test_control_plane_write_key_succeeds_on_mutating_routes():
    call_id = f"test-auth-probe-{uuid.uuid4().hex}"

    put_resp = httpx.put(
        f"{CONTROL_PLANE_URL}/tenants/{_TENANT_ID}",
        json=_NOOP_UPDATE,
        headers={"X-API-Key": CONTROL_PLANE_WRITE_KEY},
        timeout=10,
    )
    assert put_resp.status_code == 200, f"Expected 200, got {put_resp.status_code}: {put_resp.text}"

    post_resp = httpx.post(
        f"{CONTROL_PLANE_URL}/content",
        json={"call_id": call_id, "payload": {"probe": True}},
        headers={"X-API-Key": CONTROL_PLANE_WRITE_KEY},
        timeout=10,
    )
    assert post_resp.status_code == 204, f"Expected 204, got {post_resp.status_code}: {post_resp.text}"

    delete_resp = httpx.delete(
        f"{CONTROL_PLANE_URL}/content/{call_id}",
        headers={"X-API-Key": CONTROL_PLANE_WRITE_KEY},
        timeout=10,
    )
    assert delete_resp.status_code == 204, f"Expected 204, got {delete_resp.status_code}: {delete_resp.text}"
