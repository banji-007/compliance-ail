"""
AIL Ledger Client
=================
Thin HTTP client that routes all ImmuDB writes through the isolated verifier
service. The verifier holds immudb-py (gRPC SDK), keeping protobuf out of the
interceptor process and preserving the SPIFFE mTLS posture (ADR-0001).

Fail-closed: if the verifier is unreachable or returns verified: false, this
module raises, causing the middleware to return DENY rather than allowing
execution without a durable, verified audit record.
"""

import base64
import json
import logging
import os
import uuid
from datetime import datetime

import httpx
from dotenv import load_dotenv

load_dotenv()

_VERIFIER_URL = os.getenv("VERIFIER_URL", "http://verifier:8003")


class ImmuDBLedger:
    def __init__(self, verifier_url: str | None = None):
        self.verifier_url = verifier_url or _VERIFIER_URL
        self._check_health()

    def _check_health(self) -> None:
        try:
            with httpx.Client(timeout=5) as client:
                resp = client.get(f"{self.verifier_url}/health")
                resp.raise_for_status()
            logging.info("Verifier service reachable at %s", self.verifier_url)
        except Exception as exc:
            logging.error("Verifier service unreachable at %s: %s", self.verifier_url, exc)
            raise

    def log_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        call_id: str,
        input_sha256: str,
        outcome_type: str,
        fault_class: str | None,
        policy_revision: str | None,
        reasons: list,
        content_state: str,
    ) -> int:
        """
        Write an outcome record to ImmuDB via the verifier's verifiedSet.

        The record carries a hash of the tool arguments, not the arguments
        themselves (D5) - the immutable ledger proves what was decided and
        that the input hashed to this value; the arguments live in the
        control plane's erasable content store, joined by call_id (D7,
        Phase 1.1 - minted at intercept, independent of ImmuDB's own tx
        numbering). content_state records whether that content write landed
        ("present") or was never attempted because tool_args wasn't
        dict-shaped ("unavailable") - "erased" is never written here, it is
        inferred at read time from content_state plus whether the
        content-store row still exists (control_plane/main.py::get_audit).

        The verifier performs inclusion-proof and consistency-proof verification
        on every write. A response with verified: false or any transport error
        raises so the middleware returns DENY rather than recording an entry
        that cannot be cryptographically confirmed.

        Returns the ImmuDB transaction ID on success.
        """
        timestamp = datetime.utcnow().isoformat()
        log_entry = {
            "agent_id": agent_id,
            "timestamp": timestamp,
            "tool_name": tool_name,
            "call_id": call_id,
            "input_sha256": input_sha256,
            "outcome_type": outcome_type,
            "fault_class": fault_class,
            "policy_revision": policy_revision,
            "reasons": reasons,
            "content_state": content_state,
        }
        serialized  = json.dumps(log_entry, separators=(",", ":"))
        key         = f"tool_call:{agent_id}:{uuid.uuid4().hex}:{tool_name}"
        encoded_key = base64.b64encode(key.encode()).decode()
        encoded_val = base64.b64encode(serialized.encode()).decode()

        try:
            with httpx.Client(timeout=15) as client:
                resp = client.post(
                    f"{self.verifier_url}/write",
                    json={"key": encoded_key, "value": encoded_val},
                )
                resp.raise_for_status()

            result = resp.json()
            if not result.get("verified"):
                detail = result.get("detail", "no detail")
                raise RuntimeError(f"Ledger write not verified by SDK: {detail}")

            tx_id = result["tx_id"]
            logging.info("Ledger write verified: tx=%d", tx_id)
            return tx_id

        except Exception as exc:
            logging.error("Verifier write failed for agent=%s tool=%s: %s", agent_id, tool_name, exc)
            raise


_ledger_instance = None


def get_ledger() -> ImmuDBLedger:
    global _ledger_instance
    if _ledger_instance is None:
        _ledger_instance = ImmuDBLedger()
    return _ledger_instance
