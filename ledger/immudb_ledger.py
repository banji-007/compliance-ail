import json
import logging
import os
import base64
import uuid
import pathlib
import httpx
from datetime import datetime
from dotenv import load_dotenv
from proof_verifier import compute_alh, verify_alh

load_dotenv()

_TRUSTED_STATE_PATH = pathlib.Path(__file__).parent / ".trusted_state.json"


class ImmuDBLedger:
    def __init__(self, url=None, user=None, password=None, database="defaultdb"):
        self.url = url or os.getenv("IMMUDB_URL", "http://localhost:8080")
        self.user = user or os.getenv("IMMUDB_USER")
        self.password = password or os.getenv("IMMUDB_PASSWORD")
        self.database = database
        self.auth_token = None

        if self.user is None or self.password is None:
            raise ValueError("Critical: ImmuDB credentials missing from environment.")

        self._trusted: dict = self._load_trusted_state()
        self._connect()

    # ------------------------------------------------------------------
    # Trusted state: maps str(tx_id) -> base64 ALH recorded at write time
    # ------------------------------------------------------------------

    def _load_trusted_state(self) -> dict:
        if _TRUSTED_STATE_PATH.exists():
            try:
                return json.loads(_TRUSTED_STATE_PATH.read_text())
            except Exception as exc:
                logging.warning("Could not load trusted state: %s — starting fresh", exc)
        return {}

    def _save_trusted_state(self) -> None:
        try:
            _TRUSTED_STATE_PATH.write_text(json.dumps(self._trusted, indent=2))
        except Exception as exc:
            logging.error("Failed to persist trusted state: %s", exc)

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def _connect(self):
        try:
            login_data = {
                "user": base64.b64encode(self.user.encode()).decode(),
                "password": base64.b64encode(self.password.encode()).decode(),
                "database": base64.b64encode(self.database.encode()).decode(),
            }
            with httpx.Client() as client:
                response = client.post(f"{self.url}/api/v2/login", json=login_data)
                response.raise_for_status()
                self.auth_token = response.json().get("token")
                if not self.auth_token:
                    raise ValueError("No authentication token received from ImmuDB")
                logging.info("Connected to ImmuDB at %s", self.url)
        except Exception as exc:
            logging.error("ImmuDB REST connection failed: %s", exc)
            raise

    # ------------------------------------------------------------------
    # Write — verifiableSet
    # ------------------------------------------------------------------

    def log_tool_call(self, agent_id, tool_name, payload, decision) -> int:
        """
        Write a policy decision to ImmuDB via verifiableSet.

        Returns the ImmuDB transaction ID. The ALH of that transaction is
        computed and persisted in the local trusted state so future reads
        can verify the entry has not been tampered with.
        """
        timestamp = datetime.utcnow().isoformat()
        log_entry = {
            "agent_id": agent_id,
            "timestamp": timestamp,
            "tool_name": tool_name,
            "payload": payload,
            "decision": decision,
        }

        serialized = json.dumps(log_entry, separators=(",", ":"))
        key = f"tool_call:{agent_id}:{uuid.uuid4().hex}:{tool_name}"
        encoded_key = base64.b64encode(key.encode()).decode()
        encoded_value = base64.b64encode(serialized.encode()).decode()

        headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json",
        }
        body = {"KVs": [{"key": encoded_key, "value": encoded_value}]}

        try:
            with httpx.Client() as client:
                response = client.post(
                    f"{self.url}/api/v2/db/verifiableset",
                    json=body,
                    headers=headers,
                )
                if response.status_code == 401:
                    self._connect()
                    headers["Authorization"] = f"Bearer {self.auth_token}"
                    response = client.post(
                        f"{self.url}/api/v2/db/verifiableset",
                        json=body,
                        headers=headers,
                    )
                response.raise_for_status()

            result = response.json()
            tx_header = result["tx"]["header"]
            tx_id = int(tx_header["id"])

            alh = compute_alh(tx_header["prevAlh"], tx_id, tx_header["eh"])
            self._trusted[str(tx_id)] = alh
            self._save_trusted_state()

            logging.info("Logged to ImmuDB tx=%d alh=%.16s...", tx_id, alh)
            return tx_id

        except Exception as exc:
            logging.error("Failed to write verifiable ledger entry: %s", exc)
            raise

    # ------------------------------------------------------------------
    # Verify — compare a verifiableGet source header against trusted state
    # ------------------------------------------------------------------

    def verify_entry(self, tx_id: int, source_tx_header: dict) -> bool:
        """
        Verify that the ALH in a verifiableGet source header matches
        the ALH stored locally at write time for tx_id.
        """
        stored = self._trusted.get(str(tx_id))
        if stored is None:
            logging.warning("No trusted ALH for tx %d — entry predates state tracking", tx_id)
            return False
        return verify_alh(source_tx_header, stored)


# Strict enforcement: fails closed if credentials are missing.

_ledger_instance = None


def get_ledger():
    global _ledger_instance
    if _ledger_instance is None:
        _ledger_instance = ImmuDBLedger()
    return _ledger_instance
