"""
AIL Content Store Client
=========================
Thin HTTP client for the control plane's erasable content store (D5).

The immutable ledger (immudb_ledger.py) holds only input_sha256 - never the
raw tool arguments. The full arguments are stored here, keyed by ImmuDB
transaction id, so an erasure request can delete them without touching the
ledger. This is a best-effort join convenience, not part of the integrity
chain: the decision is already durably recorded with its hash by the time
this is called, so a failure here is logged, not fail-closed (see
docs/adr/0005-outcome-taxonomy.md).
"""

import logging
import os

import httpx

_CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL", "http://ail-control-plane:8002")
_CONTROL_PLANE_API_KEY = os.getenv("CONTROL_PLANE_API_KEY", "")


def store_content(tx_id: int, payload: dict) -> None:
    """
    Upsert the raw tool arguments for a ledger transaction. Raises on any
    failure - callers treat this as best-effort and catch, matching the
    documented boundary that content-store failures do not deny execution
    (the decision this content would join to has already been recorded).
    """
    with httpx.Client(timeout=10) as client:
        resp = client.post(
            f"{_CONTROL_PLANE_URL}/content",
            json={"tx_id": tx_id, "payload": payload},
            headers={"X-API-Key": _CONTROL_PLANE_API_KEY},
        )
        resp.raise_for_status()
