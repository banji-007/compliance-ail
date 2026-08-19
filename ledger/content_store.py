"""
AIL Content Store Client
=========================
Thin HTTP client for the control plane's erasable content store (D5).

The immutable ledger (immudb_ledger.py) holds only input_sha256 - never the
raw tool arguments. The full arguments are stored here, keyed by call_id
(D7, Phase 1.1 - minted at intercept, independent of ImmuDB's own tx
numbering), so an erasure request can delete them without touching the
ledger.

Phase 1.1 (D7) changes the ordering: this write now happens *before* the
ledger write, and a failure here is no longer best-effort - the caller
(interceptor/middleware.py::intercept_tool_call) treats it as fail-closed,
denying the call as a fault rather than recording a ledger entry whose
content_state it cannot yet know.
"""

import logging
import os

import httpx

_CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL", "http://ail-control-plane:8002")
# POST /content is a mutating route (D6, Phase 1.1) - gated by the
# control plane's write-scoped key, never the read key.
_CONTROL_PLANE_WRITE_KEY = os.getenv("CONTROL_PLANE_WRITE_KEY", "")


def store_content(call_id: str, payload: dict) -> None:
    """
    Upsert the raw tool arguments for a call_id. Raises on any failure -
    the caller now treats this as fail-closed (D7), not best-effort.
    """
    with httpx.Client(timeout=10) as client:
        resp = client.post(
            f"{_CONTROL_PLANE_URL}/content",
            json={"call_id": call_id, "payload": payload},
            headers={"X-API-Key": _CONTROL_PLANE_WRITE_KEY},
        )
        resp.raise_for_status()
