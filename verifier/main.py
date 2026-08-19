"""
AIL Verifier Service
====================
Isolated FastAPI service wrapping immudb-py (gRPC SDK) for verified writes
and reads. Running this in a separate process keeps protobuf out of the
interceptor process and preserves the SPIFFE mTLS posture described in
ADR-0001.

Every write uses verifiedSet: the SDK checks the inclusion proof (leaf->eH)
and the dual consistency proof from the persisted signed state to the new tx.
Every read uses verifiedGet: same proof chain in reverse.

ErrCorruptedData or BadSignatureError is mapped to {verified: false}. Callers
must treat unverified as a hard failure; the interceptor returns DENY and the
audit dashboard flags the entry.

State is persisted in VERIFIER_STATE_FILE via PersistentRootService (pickle).
Mount this path on a volume that is not writable by the ledger-writing
identity (the interceptor/langgraph-demo service).
"""

import base64
import logging
import os
import pathlib
from contextlib import asynccontextmanager

import grpc
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

IMMUDB_ADDR    = os.getenv("IMMUDB_ADDR", "immudb:3322")
IMMUDB_USER    = os.getenv("IMMUDB_USER", "immudb")
IMMUDB_PASSWORD = os.getenv("IMMUDB_PASSWORD", "immudb")
IMMUDB_DB      = os.getenv("IMMUDB_DB", "defaultdb")
STATE_FILE     = os.getenv("VERIFIER_STATE_FILE", "/data/verifier-state/immudb.state")
PUBKEY_FILE    = os.getenv("IMMUDB_SIGNING_PUBKEY", "")

_client = None


def _get_client():
    global _client
    if _client is not None:
        return _client

    from immudb import ImmudbClient
    from immudb.rootService import PersistentRootService

    pathlib.Path(STATE_FILE).parent.mkdir(parents=True, exist_ok=True)

    rs = PersistentRootService(STATE_FILE)
    pubkey = PUBKEY_FILE if PUBKEY_FILE and pathlib.Path(PUBKEY_FILE).exists() else None

    _client = ImmudbClient(IMMUDB_ADDR, rs=rs, publicKeyFile=pubkey)
    _client.login(
        IMMUDB_USER.encode(),
        IMMUDB_PASSWORD.encode(),
        database=IMMUDB_DB.encode(),
    )
    logger.info(
        "Connected to ImmuDB at %s (state=%s signing=%s)",
        IMMUDB_ADDR,
        STATE_FILE,
        "enabled" if pubkey else "disabled - run 'make keygen' and restart to enable",
    )
    return _client


@asynccontextmanager
async def lifespan(app: FastAPI):
    _get_client()
    yield


app = FastAPI(title="AIL Verifier", version="1.0.0", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class WriteRequest(BaseModel):
    key: str    # base64-encoded raw key bytes
    value: str  # base64-encoded raw value bytes


class WriteResponse(BaseModel):
    tx_id: int | None
    verified: bool
    detail: str | None = None


class VerifyRequest(BaseModel):
    key: str    # base64-encoded raw key bytes


class VerifyResponse(BaseModel):
    verified: bool
    tx_id: int | None = None
    value: str | None = None   # base64-encoded
    timestamp: int | None = None
    state_id: int | None = None  # latest verified state tx_id
    detail: str | None = None
    # Closed set distinguishing which proof failed (D2): "consistency_failure"
    # (ErrCorruptedData - the linear-hash chain diverged), "signature_failure"
    # (BadSignatureError - the server's ECDSA state signature didn't verify),
    # "not_found" (D8, Phase 1.1 - no entry was ever written for this key, so
    # no proof was ever rejected; detected from the RPC error's message text,
    # not its gRPC status code - see the except grpc.RpcError branch below
    # for why), or "unknown" for anything else. Only meaningful when verified
    # is False.
    error_class: str | None = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/write", response_model=WriteResponse)
def write(payload: WriteRequest):
    """
    Write a key-value pair via verifiedSet.

    The SDK verifies the inclusion proof and the consistency proof from the
    persisted state to the new transaction before updating its local state.
    Returns verified: false (never raises HTTP 500) so callers can fail closed
    without catching exceptions.
    """
    from immudb.exceptions import ErrCorruptedData

    key   = base64.b64decode(payload.key)
    value = base64.b64decode(payload.value)
    try:
        client = _get_client()
        resp   = client.verifiedSet(key, value)
        state  = client.currentState()
        logger.info("Verified write: tx=%d state_id=%d", resp.id, state.txId)
        return WriteResponse(tx_id=resp.id, verified=True)
    except ErrCorruptedData:
        logger.error("verifiedSet: inclusion or consistency proof failed")
        return WriteResponse(tx_id=None, verified=False, detail="proof verification failed")
    except Exception as exc:
        logger.error("verifiedSet error: %s", exc)
        return WriteResponse(tx_id=None, verified=False, detail=str(exc))


@app.post("/verify", response_model=VerifyResponse)
def verify(payload: VerifyRequest):
    """
    Retrieve and verify a key via verifiedGet.

    The SDK walks the inclusion proof from the (key, value) leaf to eH, then
    verifies a dual consistency proof from the persisted state to this tx.
    If signing is configured, the returned state is verified against the
    server's ECDSA signature before updating local state.
    """
    from ecdsa.keys import BadSignatureError
    from immudb.exceptions import ErrCorruptedData

    key = base64.b64decode(payload.key)
    try:
        client = _get_client()
        resp   = client.verifiedGet(key)
        state  = client.currentState()
        logger.info(
            "Verified read: tx=%d state_id=%d verified=%s",
            resp.id,
            state.txId,
            resp.verified,
        )
        return VerifyResponse(
            verified=True,
            tx_id=resp.id,
            value=base64.b64encode(resp.value).decode(),
            timestamp=resp.timestamp,
            state_id=state.txId,
        )
    except ErrCorruptedData:
        logger.warning("verifiedGet: proof failed for key %.32s...", payload.key)
        return VerifyResponse(
            verified=False,
            detail="consistency proof failed - the linear-hash chain diverged",
            error_class="consistency_failure",
        )
    except BadSignatureError:
        logger.warning("verifiedGet: state signature failed for key %.32s...", payload.key)
        return VerifyResponse(
            verified=False,
            detail="state signature verification failed",
            error_class="signature_failure",
        )
    except grpc.RpcError as exc:
        # D8 (Phase 1.1): a key that was never written is not tampering - no
        # proof was ever rejected, because there was never a proof to check.
        #
        # The original design called for detecting this via a dedicated gRPC
        # status code rather than matching message text. Live testing against
        # immudb 1.9.5 disproved that premise: VerifiableGet on a missing key
        # returns StatusCode.UNKNOWN, not NOT_FOUND - the server gives no
        # status-code-level signal to distinguish this from any other
        # failure. immudb-py's own plain-Get handler
        # (immudb/handler/get.py::call) makes exactly this distinction the
        # same way, out of the same necessity:
        # `e.details().endswith('key not found')`. This mirrors that
        # established precedent rather than inventing a different strategy
        # for VerifiableGet specifically. Still a real fragility - pin
        # immudb-py's version (see verifier/requirements.txt) and re-check
        # this string on any upgrade.
        details = exc.details() or ""
        if details.endswith("key not found"):
            logger.info("verifiedGet: key not found (no prior write) for key %.32s...", payload.key)
            return VerifyResponse(
                verified=False,
                detail="key not found: no entry was ever written for this key",
                error_class="not_found",
            )
        logger.error("verifiedGet grpc error: %s", exc)
        return VerifyResponse(verified=False, detail=str(exc), error_class="unknown")
    except Exception as exc:
        logger.error("verifiedGet error: %s", exc)
        return VerifyResponse(verified=False, detail=str(exc), error_class="unknown")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8003, workers=1)
