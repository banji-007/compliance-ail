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
import hashlib
import json
import logging
import os
import struct
from contextlib import asynccontextmanager
from typing import Optional

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

from bundle import generate_bundle
from database import Base, engine, get_db
from models import Tenant

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

DEFAULT_TENANT_ID = "tenant_default"

# Static API key for mutating control-plane endpoints.
# Set CONTROL_PLANE_API_KEY in the environment (docker-compose .env).
# If unset, mutating endpoints return 503 rather than operating unauthenticated.
_CONTROL_PLANE_API_KEY = os.getenv("CONTROL_PLANE_API_KEY", "")


def _require_api_key(x_api_key: str = Header(..., alias="X-API-Key")) -> None:
    """FastAPI dependency: enforces X-API-Key on mutating endpoints."""
    if not _CONTROL_PLANE_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="API key authentication not configured (CONTROL_PLANE_API_KEY missing)",
        )
    if x_api_key != _CONTROL_PLANE_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")


# Internal Docker service name; overridable via env for local dev.
IMMUDB_URL = os.getenv("IMMUDB_URL", "http://immudb:8080")
IMMUDB_USER = os.getenv("IMMUDB_USER")
IMMUDB_PASSWORD = os.getenv("IMMUDB_PASSWORD")


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


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/tenants/{tenant_id}", response_model=TenantRead)
def get_tenant(tenant_id: str, db: Session = Depends(get_db)):
    tenant = db.query(Tenant).filter_by(id=tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")
    return tenant


@app.post("/tenants", response_model=TenantRead, status_code=201)
def create_tenant(
    payload: TenantCreate,
    db: Session = Depends(get_db),
    _: None = Depends(_require_api_key),
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
    _: None = Depends(_require_api_key),
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


@app.head("/bundles/{tenant_id}")
def head_bundle(tenant_id: str, db: Session = Depends(get_db)):
    """
    HEAD /bundles/{tenant_id} — returns the current ETag without streaming bundle bytes.
    Used by the interceptor's _compute_policy_hash() to record the live bundle version
    in ledger entries without the overhead of a full tar.gz transfer.
    """
    tenant = db.query(Tenant).filter_by(id=tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")

    _, etag = generate_bundle(tenant)
    logger.debug("HEAD /bundles/%s → ETag %s…", tenant_id, etag[:12])
    return Response(headers={"ETag": etag, "Cache-Control": "max-age=300, must-revalidate"})


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


def _compute_alh(prev_alh_b64: str, tx_id: int, entries_hash_b64: str) -> str:
    """ALH = SHA256(prevAlh || BigEndian8(txID) || entriesHash). Matches TxHeader.Alh() in ImmuDB."""
    prev_alh = base64.b64decode(prev_alh_b64)
    tx_id_bytes = struct.pack(">Q", tx_id)
    entries_hash = base64.b64decode(entries_hash_b64)
    digest = hashlib.sha256(prev_alh + tx_id_bytes + entries_hash).digest()
    return base64.b64encode(digest).decode()


@app.get("/audit")
def get_audit(limit: int = 100, _: None = Depends(_require_api_key)):
    """
    Proxy to ImmuDB REST API using verifiable reads.

    Scans for all tool_call: keys, then calls verifiableGet for each entry to
    retrieve the inclusion proof and source transaction header. The ALH is
    computed from the source tx header fields so an auditor can compare it
    against the ALH persisted by the interceptor at write time (stored in
    ledger/.trusted_state.json). Full Merkle proof walking is handled
    separately by the interceptor's verify_entry() or offline via immuclient.

    Returns:
        {"entries": [...], "total": <int>}

    Each entry:
        tx_id           — ImmuDB transaction ID
        agent_id        — SPIFFE workload identity
        timestamp       — ISO-8601 UTC string
        tool_name       — tool that was intercepted
        payload         — original tool arguments
        decision        — OPA verdict
        entry_alh       — ALH recomputed from verifiableGet source tx header
        inclusion_proof — {leaf, width, terms} from ImmuDB for offline verification
    """
    if not IMMUDB_USER or not IMMUDB_PASSWORD:
        raise HTTPException(
            status_code=503,
            detail="ImmuDB credentials not configured (IMMUDB_USER / IMMUDB_PASSWORD missing)",
        )

    try:
        with httpx.Client(timeout=30.0) as client:
            # --- Authenticate ---
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

            auth_headers = {"Authorization": f"Bearer {token}"}

            # --- Scan for all tool_call: keys (newest first) ---
            scan_resp = client.post(
                f"{IMMUDB_URL}/api/v2/db/scan",
                json={
                    "prefix": base64.b64encode(b"tool_call:").decode(),
                    "desc": True,
                    "limit": limit,
                },
                headers=auth_headers,
            )
            scan_resp.raise_for_status()
            raw_entries = scan_resp.json().get("entries", [])

            # --- verifiableGet per key to retrieve inclusion proof ---
            verified_entries = []
            for raw in raw_entries:
                encoded_key = raw.get("key", "")
                vget_resp = client.post(
                    f"{IMMUDB_URL}/api/v2/db/verifiableget",
                    json={"keyRequest": {"key": encoded_key}, "proveSinceTx": "0"},
                    headers=auth_headers,
                )
                if vget_resp.status_code != 200:
                    logger.warning(
                        "verifiableGet failed for key (tx=%s): HTTP %d",
                        raw.get("tx"),
                        vget_resp.status_code,
                    )
                    verified_entries.append((raw, None))
                    continue
                verified_entries.append((raw, vget_resp.json()))

    except httpx.HTTPStatusError as exc:
        logger.error("ImmuDB HTTP error during audit fetch: %s", exc)
        raise HTTPException(status_code=502, detail=f"ImmuDB returned {exc.response.status_code}")
    except Exception as exc:
        logger.error("ImmuDB unavailable for audit fetch: %s", exc)
        raise HTTPException(status_code=503, detail=f"ImmuDB unavailable: {exc}")

    entries = []
    for raw, vget in verified_entries:
        try:
            key: str = base64.b64decode(raw["key"]).decode()
            serialized_entry: str = base64.b64decode(raw["value"]).decode()
            log_entry: dict = json.loads(serialized_entry)
            tx_id: int = int(raw.get("tx", 0))

            entry_alh = None
            inclusion_proof = None

            if vget is not None:
                try:
                    # dualProof.sourceTxHeader is the tx that wrote this entry
                    src_hdr = vget["verifiableTx"]["dualProof"]["sourceTxHeader"]
                    entry_alh = _compute_alh(
                        src_hdr["prevAlh"], int(src_hdr["id"]), src_hdr["eh"]
                    )
                    inclusion_proof = vget.get("inclusionProof")
                except (KeyError, TypeError, ValueError) as exc:
                    logger.warning("Could not extract proof fields for tx %d: %s", tx_id, exc)

            entries.append({
                "tx_id": tx_id,
                "agent_id": log_entry.get("agent_id"),
                "timestamp": log_entry.get("timestamp"),
                "tool_name": log_entry.get("tool_name"),
                "payload": log_entry.get("payload"),
                "decision": log_entry.get("decision"),
                "entry_alh": entry_alh,
                "inclusion_proof": inclusion_proof,
            })
        except Exception as exc:
            logger.warning("Skipping malformed ledger entry (tx=%s): %s", raw.get("tx"), exc)
            continue

    logger.info("Audit: returned %d ledger entries with inclusion proofs", len(entries))
    return {"entries": entries, "total": len(entries)}
