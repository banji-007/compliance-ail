"""
AIL Control Plane — FastAPI
===========================
Serves OPA policy bundles over the OPA Bundle API.
Tenant configurations are persisted in SQLite (/data/control_plane.db).

Endpoints:
  GET  /health                  — liveness probe
  GET  /tenants/{tenant_id}     — fetch tenant config
  POST /tenants                 — create a tenant
  PUT  /tenants/{tenant_id}     — update tenant config (triggers new bundle ETag)
  GET  /bundles/{tenant_id}     — OPA Bundle API (ETag-aware)
  GET  /audit                   — proxy to ImmuDB; returns decoded ledger entries
"""

import base64
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

from bundle import generate_bundle
from database import Base, engine, get_db
from models import CallContent, Tenant

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

DEFAULT_TENANT_ID = "tenant_default"

# P13-8 (Phase 1.3): see ledger/immudb_ledger.py's RECORD_PROFILE - same
# value, same reason, defined independently here because the control plane
# writes its own record (the erasure tombstone) rather than importing the
# interceptor's ledger module.
RECORD_PROFILE = "observed"

# Two scoped keys, not one shared key (D6, Phase 1.1). CONTROL_PLANE_READ_KEY
# authorizes GET /audit only; CONTROL_PLANE_WRITE_KEY authorizes every
# mutating route (PUT/POST /tenants, POST /content, DELETE /content). A
# regression that drops the caller check on one route no longer risks
# granting writes through a credential that was only ever meant to read -
# the two credentials are independent secrets, not a hierarchy.
# Set both in the environment (docker-compose .env). If either is unset,
# the routes it gates return 503 rather than operating unauthenticated.
_CONTROL_PLANE_READ_KEY = os.getenv("CONTROL_PLANE_READ_KEY", "")
_CONTROL_PLANE_WRITE_KEY = os.getenv("CONTROL_PLANE_WRITE_KEY", "")


def _require_read_key(x_api_key: str = Header(..., alias="X-API-Key")) -> None:
    """FastAPI dependency: enforces X-API-Key (read-scoped) on GET /audit."""
    if not _CONTROL_PLANE_READ_KEY:
        raise HTTPException(
            status_code=503,
            detail="Read-key authentication not configured (CONTROL_PLANE_READ_KEY missing)",
        )
    if x_api_key != _CONTROL_PLANE_READ_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")


def _require_write_key(x_api_key: str = Header(..., alias="X-API-Key")) -> None:
    """FastAPI dependency: enforces X-API-Key (write-scoped) on mutating routes."""
    if not _CONTROL_PLANE_WRITE_KEY:
        raise HTTPException(
            status_code=503,
            detail="Write-key authentication not configured (CONTROL_PLANE_WRITE_KEY missing)",
        )
    if x_api_key != _CONTROL_PLANE_WRITE_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")


# Internal Docker service names; overridable via env for local dev.
IMMUDB_URL   = os.getenv("IMMUDB_URL", "http://immudb:8080")
IMMUDB_USER  = os.getenv("IMMUDB_USER")
IMMUDB_PASSWORD = os.getenv("IMMUDB_PASSWORD")
VERIFIER_URL = os.getenv("VERIFIER_URL", "http://verifier:8003")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create schema and seed the default tenant on first boot
    Base.metadata.create_all(bind=engine)
    db = next(get_db())
    try:
        if not db.query(Tenant).filter_by(id=DEFAULT_TENANT_ID).first():
            db.add(Tenant(
                id=DEFAULT_TENANT_ID,
                name="Default Tenant",
                enable_gdpr=True,
                enable_soc2=True,
                enable_finops=True,
                enable_hipaa=True,
                allowed_cost_centers="engineering,marketing,finance,operations",
                approved_regions="eu-central-1,us-east-1",
                approved_purposes="customer_support,billing",
            ))
            db.commit()
            logger.info("Seeded default tenant: %s", DEFAULT_TENANT_ID)

        if not db.query(Tenant).filter_by(id="tenant_finance").first():
            db.add(Tenant(
                id="tenant_finance",
                name="Finance Tenant",
                enable_gdpr=True,
                enable_soc2=True,
                enable_finops=True,
                enable_hipaa=True,
                # Strict spend controls — only finance and executive cost centers approved.
                allowed_cost_centers="finance,executive",
                approved_regions="eu-central-1,us-east-1",
                approved_purposes="customer_support,billing",
            ))
            db.commit()
            logger.info("Seeded finance tenant: tenant_finance")
    finally:
        db.close()
    yield


app = FastAPI(title="AIL Control Plane", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    # Allow the CISO dashboard origin; extend this list for staging/prod hosts.
    allow_origins=["http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "OPTIONS"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class TenantCreate(BaseModel):
    id: str
    name: str
    enable_gdpr: bool = True
    enable_soc2: bool = True
    enable_finops: bool = True
    enable_hipaa: bool = False
    allowed_cost_centers: str = "engineering,marketing,finance,operations"
    approved_regions: str = "eu-central-1,us-east-1"
    approved_purposes: str = "customer_support,billing"


class TenantUpdate(BaseModel):
    """All fields optional — PATCH semantics over PUT for ergonomic UI saves."""
    name: Optional[str] = None
    enable_gdpr: Optional[bool] = None
    enable_soc2: Optional[bool] = None
    enable_finops: Optional[bool] = None
    enable_hipaa: Optional[bool] = None
    allowed_cost_centers: Optional[str] = None
    approved_regions: Optional[str] = None
    approved_purposes: Optional[str] = None


class TenantRead(BaseModel):
    id: str
    name: str
    enable_gdpr: bool
    enable_soc2: bool
    enable_finops: bool
    enable_hipaa: bool
    allowed_cost_centers: str
    approved_regions: str
    approved_purposes: str

    model_config = {"from_attributes": True}


class ContentWrite(BaseModel):
    """D5: raw tool arguments for a call, stored separately from the
    immutable ledger so they remain erasable. Keyed by call_id (D7,
    Phase 1.1), minted by the interceptor at intercept time - independent
    of ImmuDB's own transaction numbering."""
    call_id: str
    payload: dict


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/tenants/{tenant_id}", response_model=TenantRead)
def get_tenant(
    tenant_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(_require_read_key),
):
    """
    P13-3: named by Phase 1.1's red-team (finding #2) and reconfirmed
    unfixed by Phase 1.2's red-team - this route had no auth dependency at
    all, so full tenant configuration (enabled frameworks, cost-center and
    region allowlists) was readable with zero credentials. Read-scoped, not
    write-scoped: this is a GET, same tier as /audit.
    """
    tenant = db.query(Tenant).filter_by(id=tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")
    return tenant


@app.post("/tenants", response_model=TenantRead, status_code=201)
def create_tenant(
    payload: TenantCreate,
    db: Session = Depends(get_db),
    _: None = Depends(_require_write_key),
):
    if db.query(Tenant).filter_by(id=payload.id).first():
        raise HTTPException(status_code=409, detail=f"Tenant '{payload.id}' already exists")
    tenant = Tenant(**payload.model_dump())
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    logger.info("Created tenant: %s", tenant.id)
    return tenant


@app.put("/tenants/{tenant_id}", response_model=TenantRead)
def update_tenant(
    tenant_id: str,
    payload: TenantUpdate,
    db: Session = Depends(get_db),
    _: None = Depends(_require_write_key),
):
    """
    Update a tenant's compliance pack settings and/or allowed cost centers.
    OPA will receive a new bundle on its next poll (the ETag changes because
    generate_bundle re-hashes the active policy files + data.json).
    """
    tenant = db.query(Tenant).filter_by(id=tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(tenant, field, value)
    db.commit()
    db.refresh(tenant)
    logger.info("Updated tenant %s: %s", tenant_id, payload.model_dump(exclude_unset=True))
    return tenant


@app.get("/bundles/{tenant_id}")
def get_bundle(tenant_id: str, request: Request, db: Session = Depends(get_db)):
    """
    OPA Bundle API endpoint. OPA polls this on the configured interval,
    sending If-None-Match with the last known ETag. Return 304 if unchanged.
    """
    tenant = db.query(Tenant).filter_by(id=tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")

    bundle_bytes, etag = generate_bundle(tenant)

    if request.headers.get("If-None-Match") == etag:
        logger.debug("Bundle unchanged for tenant %s (ETag: %s…)", tenant_id, etag[:12])
        return Response(status_code=304)

    logger.info("Serving bundle for tenant %s (ETag: %s…)", tenant_id, etag[:12])
    return Response(
        content=bundle_bytes,
        media_type="application/gzip",
        headers={"ETag": etag, "Cache-Control": "max-age=300, must-revalidate"},
    )


def _has_tombstone(call_id: str) -> bool:
    """
    P13-4: check the verifier directly (the same source of truth /audit
    reads) for a content_erasure tombstone before allowing a write to
    call_id. Checking the verifier rather than local SQL means a tombstone
    written directly to the verifier - bypassing this control plane
    entirely - still blocks a resurrection attempt through this route.

    Fails closed: only a clean, positively-identified error_class ==
    "not_found" is treated as "no tombstone exists". Any other outcome
    (verifier unreachable, a malformed response, any other error_class)
    is treated as "tombstone present" - an erasure must never be undoable
    merely because the check that would have caught it could not run.
    """
    key = f"content_erasure:{call_id}"
    encoded_key = base64.b64encode(key.encode()).decode()
    try:
        with httpx.Client(timeout=15) as client:
            resp = client.post(f"{VERIFIER_URL}/verify", json={"key": encoded_key})
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.error("Tombstone check failed for call_id=%s: %s", call_id, exc)
        return True
    if data.get("verified"):
        return True
    return data.get("error_class") != "not_found"


@app.post("/content", status_code=204)
def write_content(
    payload: ContentWrite,
    db: Session = Depends(get_db),
    _: None = Depends(_require_write_key),
):
    """
    Upsert the raw tool arguments for a call_id (D5, D7). Called by the
    interceptor *before* the ledger write for that call (D7, Phase 1.1) -
    the ledger entry then records whether this landed (content_state). A
    failure here is fail-closed at the caller: the interceptor denies the
    call as a fault rather than writing a ledger entry it cannot yet
    describe.

    P13-4: refuses the write outright if call_id already carries a
    content_erasure tombstone. Before this check, the ordinary write key -
    no escalation, the same credential used for any normal content write -
    could resurrect an erased call_id with arbitrary attacker-chosen
    content and /audit would show no trace an erasure had ever happened
    (red-team U4, combination 2).
    """
    if _has_tombstone(payload.call_id):
        raise HTTPException(
            status_code=409,
            detail=f"call_id '{payload.call_id}' has been erased; content writes are refused",
        )
    existing = db.query(CallContent).filter_by(call_id=payload.call_id).first()
    payload_json = json.dumps(payload.payload)
    if existing:
        existing.payload_json = payload_json
    else:
        db.add(CallContent(call_id=payload.call_id, payload_json=payload_json))
    db.commit()


def _write_tombstone(call_id: str) -> None:
    """
    D11 (Phase 1.2): append a content_erasure tombstone to the ledger, via
    the same verifier the interceptor's own ledger writes use, before the
    row is deleted - same ordering discipline as D7 (the durable record of
    an event is written before the action it describes becomes
    irreversible). No personal data: call_id, timestamp, actor only - never
    the erased payload itself.

    "actor" names the authorization boundary the caller crossed, not an
    individual - control-plane write access is a single shared
    write-scoped API key (ADR-0007), not a per-caller credential, so no
    finer-grained identity exists at this layer to record.

    Raises on any failure (non-2xx, transport error, or verified: false) -
    the caller (erase_content) treats this as fail-closed: the erasure is
    refused and the row survives.
    """
    tombstone = {
        "record_type": "content_erasure",
        "call_id": call_id,
        "timestamp": datetime.utcnow().isoformat(),
        "actor": "control-plane-write-key",
        "profile": RECORD_PROFILE,
    }
    serialized = json.dumps(tombstone, separators=(",", ":"))
    key = f"content_erasure:{call_id}"
    encoded_key = base64.b64encode(key.encode()).decode()
    encoded_val = base64.b64encode(serialized.encode()).decode()

    with httpx.Client(timeout=15) as client:
        resp = client.post(
            f"{VERIFIER_URL}/write",
            json={"key": encoded_key, "value": encoded_val},
        )
        resp.raise_for_status()

    result = resp.json()
    if not result.get("verified"):
        raise RuntimeError(f"Tombstone write not verified: {result.get('detail', 'no detail')}")


@app.delete("/content/{call_id}", status_code=204)
def erase_content(
    call_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(_require_write_key),
):
    """
    GDPR Article 17 erasure: delete the raw-argument row for a call_id. The
    ledger entry that recorded content_state="present" for the same call_id
    is untouched - it still proves what was decided and that the input
    hashed to input_sha256; only the erasable content this hash could be
    checked against is gone. /audit infers "erased" at read time from the
    ledger's content_state, the absence of this row, and the presence of a
    content_erasure tombstone (D7, D11).

    D11 (Phase 1.2): the tombstone is written first. If it fails, the
    erasure is refused (503) and the row survives - there is no path that
    deletes a row without a durable record of having done so. A call_id
    with no row (already erased, or never had one) is a no-op: nothing to
    erase, so no tombstone is written for it.
    """
    existing = db.query(CallContent).filter_by(call_id=call_id).first()
    if existing is None:
        return

    try:
        _write_tombstone(call_id)
    except Exception as exc:
        logger.error("Tombstone write failed for call_id=%s: %s", call_id, exc)
        raise HTTPException(
            status_code=503,
            detail=f"Tombstone write failed; erasure refused: {exc}",
        )

    db.delete(existing)
    db.commit()


_TAMPER_ERROR_CLASSES = frozenset({"consistency_failure", "signature_failure"})


def _verification_from_200(vdata: dict) -> dict:
    """
    Map a verifier /verify HTTP-200 body to one of the read-time verification
    states (D2, D8, D10). Extracted as a pure function - independent of the
    ImmuDB scan/join in get_audit - so the not_found branch (D8, Phase 1.1)
    is directly unit-testable with a fabricated vdata, without needing a key
    that is both scanned by ImmuDB and simultaneously never written (get_audit's
    own scan only ever lists keys that do exist, so this branch is not
    reachable end-to-end through /audit alone - see tests/test_verification.py).

    D10 (Phase 1.2): "failed" is a positive claim of tamper evidence and
    requires positive identification - error_class must be exactly
    "consistency_failure" or "signature_failure" (verifier/main.py's own two
    exception-derived classes). Everything else that isn't verified and
    isn't not_found, including "unknown" and any future error_class this
    function has never seen, maps to "unverifiable" with the detail
    preserved. Red-team T1: the old default sent any unrecognized
    error_class to "failed", so a change in the ImmuDB server's own message
    wording (verifier/main.py's error_class="unknown" fallback) turned a
    never-written key into a tamper alarm - with no source diff and no build
    to fail.
    """
    if vdata.get("verified"):
        return {
            "state": "verified",
            "state_id": vdata.get("state_id"),
            "detail": None,
            "error_class": None,
        }
    error_class = vdata.get("error_class")
    if error_class == "not_found":
        # A key with no prior write is not a tamper signal - no proof was
        # ever rejected, because there was never a proof to check. Kept
        # distinct from "failed" so a CISO reading this doesn't see the same
        # badge for "someone tampered with this entry" and "this key
        # reference doesn't point at anything".
        return {
            "state": "not_found",
            "state_id": vdata.get("state_id"),
            "detail": vdata.get("detail"),
            "error_class": error_class,
        }
    if error_class in _TAMPER_ERROR_CLASSES:
        return {
            "state": "failed",
            "state_id": vdata.get("state_id"),
            "detail": vdata.get("detail"),
            "error_class": error_class,
        }
    return {
        "state": "unverifiable",
        "state_id": vdata.get("state_id"),
        "detail": vdata.get("detail"),
        "error_class": error_class,
    }


def _payload_state(content_state: str | None, content_row, has_tombstone: bool) -> tuple[str, dict | None]:
    """
    Map a ledger entry's content_state (D7), whether its CallContent row
    still exists, and whether a content_erasure tombstone exists for its
    call_id, to the read-time payload_state (D7, D11, P13-4): present |
    unavailable | erased | lost | erasure_conflict. Pure function,
    unit-testable independent of the ImmuDB/SQL join.

    content_state == "unavailable" always wins - it was never attempted, so
    there is nothing to erase or lose.

    A tombstone now wins over a present row (P13-4, red-team U4 combination
    1): before this, a content_erasure tombstone coexisting with a row that
    was never actually deleted rendered as plain "present", discarding the
    tombstone silently - a durable record nobody read. write_content's own
    tombstone check (see _has_tombstone) means this combination should not
    arise through this control plane's own routes going forward; it can
    still arise from a tombstone forged directly against the verifier (P13-2's
    residual: any party with the agent's network position can write ledger
    records the verifier will treat as authentic) or from an operational
    failure between a real tombstone write and the row delete that should
    follow it. Either way the payload is never returned once a tombstone
    exists - erasure_conflict, not "present", flags that this call_id needs
    investigation: the ledger says the content was erased and the row that
    should have been deleted still exists.

    Otherwise, a present row is "present"; an absent row is "erased" only if
    the real erasure endpoint's tombstone exists for this call_id
    (erase_content always writes it before deleting), and "lost" otherwise -
    the row disappeared some other way (red-team T5: a direct SQL delete
    bypassing the endpoint entirely). "lost" and "erased" must never render
    identically: one is a GDPR Article 17 request honored through the real
    endpoint, the other is an operational incident with no erasure
    semantics behind it at all.
    """
    if content_state == "unavailable":
        return "unavailable", None
    if has_tombstone:
        if content_row is not None:
            return "erasure_conflict", None
        return "erased", None
    if content_row is not None:
        return "present", json.loads(content_row.payload_json)
    return "lost", None


@app.get("/audit")
def get_audit(limit: int = 100, _: None = Depends(_require_read_key), db: Session = Depends(get_db)):
    """
    Return audit entries: the structured outcome record from ImmuDB, the
    read-time verification state (D2 - never self-certified by the entry),
    and the raw arguments joined from the erasable content store (D5, D7).

    Scans for all tool_call: keys via REST (no SDK needed for a key listing),
    then calls the verifier service for each key to compute verification
    state. See docs/adr/0006-verification-states.md for why this is computed
    here, at read time, rather than stored in the entry. payload_state is
    computed the same way, from the entry's own content_state (D7).

    Returns:
        {"entries": [...], "total": <int>}

    Each entry:
        tx_id, call_id, agent_id, timestamp, tool_name  - as recorded; call_id
                          is the key erasure targets (DELETE /content/{call_id})
        outcome_type   - policy_allow | policy_deny | schema_deny | fault
        fault_class    - null, or the closed-set fault reason
        policy_revision - the bundle revision that produced the decision, or null
        reasons        - deny messages, empty for an allow
        input_sha256   - hash of the original tool arguments
        payload        - joined from the content store by call_id; null unless
                          payload_state is "present"
        payload_state  - present | unavailable | erased | lost | erasure_conflict
                          (D7, D11, P13-4): "unavailable" means content_state
                          was already "unavailable" at write time (nothing
                          dict-shaped to store) and always wins over the
                          rest; a content_erasure tombstone for this call_id
                          then wins over everything except "unavailable" -
                          "erased" if the row is also gone (the normal case:
                          the real DELETE /content/{call_id} endpoint always
                          writes the tombstone before deleting the row), or
                          "erasure_conflict" if the row still exists despite
                          the tombstone (P13-4: a tombstone must never be
                          silently discarded just because a row outlived it -
                          this needs investigation, and payload is withheld
                          either way); with no tombstone, a present row is
                          "present" and an absent one is "lost" - some other
                          way the row disappeared (e.g. a direct SQL delete
                          bypassing the endpoint)
        verification   - {state, state_id, detail, error_class}; state is one
                          of verified | failed | unverifiable | asserted | not_found
        profile        - conformance profile this record was produced under
                          (P13-8); "observed" is the only value that exists
                          today. See docs/adr/0005-outcome-taxonomy.md.
    """
    if not IMMUDB_USER or not IMMUDB_PASSWORD:
        raise HTTPException(
            status_code=503,
            detail="ImmuDB credentials not configured (IMMUDB_USER / IMMUDB_PASSWORD missing)",
        )

    # --- Scan ImmuDB for all tool_call: keys (REST; scan needs no proof) ---
    try:
        with httpx.Client(timeout=30.0) as client:
            login_resp = client.post(
                f"{IMMUDB_URL}/api/v2/login",
                json={
                    "user": base64.b64encode(IMMUDB_USER.encode()).decode(),
                    "password": base64.b64encode(IMMUDB_PASSWORD.encode()).decode(),
                    "database": base64.b64encode(b"defaultdb").decode(),
                },
            )
            login_resp.raise_for_status()
            token = login_resp.json().get("token")
            if not token:
                raise ValueError("No auth token in ImmuDB login response")

            scan_resp = client.post(
                f"{IMMUDB_URL}/api/v2/db/scan",
                json={
                    "prefix": base64.b64encode(b"tool_call:").decode(),
                    "desc": True,
                    "limit": limit,
                },
                headers={"Authorization": f"Bearer {token}"},
            )
            scan_resp.raise_for_status()
            raw_entries = scan_resp.json().get("entries", [])

            # D11 (Phase 1.2): a second scan, over content_erasure: keys,
            # never tool_call: - this is what keeps a tombstone structurally
            # out of the decision entries built below, rather than relying
            # on a filter that could be gotten wrong. Classification of what
            # counts as a tombstone still goes through record_type, not the
            # key prefix alone (D11's own "discriminate on a field" point).
            tombstone_scan_resp = client.post(
                f"{IMMUDB_URL}/api/v2/db/scan",
                json={
                    "prefix": base64.b64encode(b"content_erasure:").decode(),
                    "desc": True,
                    "limit": limit,
                },
                headers={"Authorization": f"Bearer {token}"},
            )
            tombstone_scan_resp.raise_for_status()
            raw_tombstones = tombstone_scan_resp.json().get("entries", [])

    except httpx.HTTPStatusError as exc:
        logger.error("ImmuDB HTTP error during audit scan: %s", exc)
        raise HTTPException(status_code=502, detail=f"ImmuDB returned {exc.response.status_code}")
    except Exception as exc:
        logger.error("ImmuDB unavailable for audit scan: %s", exc)
        raise HTTPException(status_code=503, detail=f"ImmuDB unavailable: {exc}")

    tombstoned_call_ids: set[str] = set()
    for raw in raw_tombstones:
        try:
            value = json.loads(base64.b64decode(raw["value"]).decode())
            if value.get("record_type") == "content_erasure" and value.get("call_id"):
                tombstoned_call_ids.add(value["call_id"])
        except Exception as exc:
            logger.warning("Skipping malformed tombstone entry: %s", exc)
            continue

    # --- Verify each entry via the verifier service; join content by call_id ---
    verifier_up = True
    entries = []
    for raw in raw_entries:
        try:
            encoded_key: str       = raw.get("key", "")
            serialized_entry: str  = base64.b64decode(raw["value"]).decode()
            log_entry: dict        = json.loads(serialized_entry)
            tx_id: int             = int(raw.get("tx", 0))

            if not verifier_up:
                # A prior entry in this same scan already failed to reach the
                # verifier - this entry was never attempted at all.
                verification = {"state": "asserted", "state_id": None, "detail": None, "error_class": None}
            else:
                try:
                    with httpx.Client(timeout=10.0) as vc:
                        vr = vc.post(f"{VERIFIER_URL}/verify", json={"key": encoded_key})
                    if vr.status_code == 200:
                        verification = _verification_from_200(vr.json())
                        if verification["state"] == "failed":
                            logger.warning(
                                "Audit: entry tx=%d failed verification: %s", tx_id, verification["detail"]
                            )
                        elif verification["state"] == "not_found":
                            logger.info(
                                "Audit: entry tx=%d has no corresponding ImmuDB write (not_found)", tx_id
                            )
                    else:
                        logger.warning("Verifier returned HTTP %d for tx=%d", vr.status_code, tx_id)
                        verification = {
                            "state": "unverifiable",
                            "state_id": None,
                            "detail": f"verifier returned HTTP {vr.status_code}",
                            "error_class": None,
                        }
                except Exception as vexc:
                    logger.error("Verifier unreachable during audit: %s", vexc)
                    verifier_up = False  # stop hammering; remaining entries become "asserted"
                    verification = {
                        "state": "unverifiable",
                        "state_id": None,
                        "detail": str(vexc),
                        "error_class": None,
                    }

            call_id = log_entry.get("call_id")
            content_row = db.query(CallContent).filter_by(call_id=call_id).first() if call_id else None
            has_tombstone = call_id in tombstoned_call_ids if call_id else False
            payload_state, payload = _payload_state(log_entry.get("content_state"), content_row, has_tombstone)

            entries.append({
                "tx_id":           tx_id,
                "call_id":         call_id,
                "agent_id":        log_entry.get("agent_id"),
                "timestamp":       log_entry.get("timestamp"),
                "tool_name":       log_entry.get("tool_name"),
                "outcome_type":    log_entry.get("outcome_type"),
                "fault_class":     log_entry.get("fault_class"),
                "policy_revision": log_entry.get("policy_revision"),
                "reasons":         log_entry.get("reasons", []),
                "input_sha256":    log_entry.get("input_sha256"),
                "payload":         payload,
                "payload_state":   payload_state,
                "verification":    verification,
                # P13-8: every record ever written by this codebase carries
                # this same value (RECORD_PROFILE) - defaulted here, not
                # trusted from a caller-suppliable field, for the rare
                # pre-P13-8 entry that predates the key existing at all.
                "profile":         log_entry.get("profile", RECORD_PROFILE),
            })
        except Exception as exc:
            logger.warning("Skipping malformed ledger entry (tx=%s): %s", raw.get("tx"), exc)
            continue

    logger.info(
        "Audit: %d entries; verifier_up=%s by state: verified=%d failed=%d unverifiable=%d asserted=%d not_found=%d",
        len(entries),
        verifier_up,
        sum(1 for e in entries if e["verification"]["state"] == "verified"),
        sum(1 for e in entries if e["verification"]["state"] == "failed"),
        sum(1 for e in entries if e["verification"]["state"] == "unverifiable"),
        sum(1 for e in entries if e["verification"]["state"] == "asserted"),
        sum(1 for e in entries if e["verification"]["state"] == "not_found"),
    )
    return {"entries": entries, "total": len(entries)}
