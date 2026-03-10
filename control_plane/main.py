"""
AIL Control Plane — FastAPI
===========================
Serves OPA policy bundles over the OPA Bundle API.
Tenant configurations are persisted in SQLite (/data/control_plane.db).

Endpoints:
  GET  /health                  — liveness probe
  GET  /tenants/{tenant_id}     — fetch tenant config
  POST /tenants                 — create a tenant
  GET  /bundles/{tenant_id}     — OPA Bundle API (ETag-aware)
"""

import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from bundle import generate_bundle
from database import Base, engine, get_db
from models import Tenant

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

DEFAULT_TENANT_ID = "tenant_default"


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
                enable_hipaa=False,
                allowed_cost_centers="engineering,marketing,finance,operations",
            ))
            db.commit()
            logger.info("Seeded default tenant: %s", DEFAULT_TENANT_ID)
    finally:
        db.close()
    yield


app = FastAPI(title="AIL Control Plane", version="2.0.0", lifespan=lifespan)


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


class TenantRead(BaseModel):
    id: str
    name: str
    enable_gdpr: bool
    enable_soc2: bool
    enable_finops: bool
    enable_hipaa: bool
    allowed_cost_centers: str

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
def create_tenant(payload: TenantCreate, db: Session = Depends(get_db)):
    if db.query(Tenant).filter_by(id=payload.id).first():
        raise HTTPException(status_code=409, detail=f"Tenant '{payload.id}' already exists")
    tenant = Tenant(**payload.model_dump())
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    logger.info("Created tenant: %s", tenant.id)
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
        headers={"ETag": etag},
    )
