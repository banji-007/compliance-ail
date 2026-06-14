import base64
import hashlib
import logging
import struct

logger = logging.getLogger(__name__)


def compute_alh(prev_alh_b64: str, tx_id: int, entries_hash_b64: str) -> str:
    """
    Compute ImmuDB's Accumulated Ledger Hash (ALH) for a transaction.

    Formula: SHA256(prevAlh || BigEndian8(txID) || entriesHash)
    Matches TxHeader.Alh() in immudb/pkg/store/tx.go.
    """
    prev_alh = base64.b64decode(prev_alh_b64)
    tx_id_bytes = struct.pack(">Q", tx_id)
    entries_hash = base64.b64decode(entries_hash_b64)
    digest = hashlib.sha256(prev_alh + tx_id_bytes + entries_hash).digest()
    return base64.b64encode(digest).decode()


def verify_alh(tx_header: dict, stored_alh: str) -> bool:
    """
    Recompute the ALH from a verifiableGet source tx header and compare it
    to the ALH stored at write time.

    A mismatch means the entry or its transaction was modified after the write.
    tx_header must contain: id (str or int), prevAlh (base64), eh (base64).
    """
    try:
        tx_id = int(tx_header["id"])
        recomputed = compute_alh(tx_header["prevAlh"], tx_id, tx_header["eh"])
        if recomputed == stored_alh:
            return True
        logger.warning(
            "ALH mismatch for tx %d — possible tampering. "
            "stored=%.16s... recomputed=%.16s...",
            tx_id,
            stored_alh,
            recomputed,
        )
        return False
    except (KeyError, ValueError) as exc:
        logger.error("ALH verification error for tx %s: %s", tx_header.get("id"), exc)
        return False
