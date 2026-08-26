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
  GET  /audit/verify            - one record's verification, on demand (D29)
  GET  /audit/bundle            - one record's portable evidence bundle (D19)
  POST /anchors                 - record an externally anchored checkpoint (D23)
  GET  /anchors/latest          - the newest anchored checkpoint, if any (D23)
"""

import base64
import json
import logging
import os
import sys
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
from models import CallContent, StateAnchor, Tenant

# provenance/ is copied into this service's image alongside its own source
# (control_plane/Dockerfile builds from the repo root for this reason) and
# sits at the repo root in a checkout. Both are tried, the same way
# ledger/immudb_ledger.py resolves it, so this module imports identically
# in the container and under pytest.
for _provenance_parent in (
    os.path.dirname(os.path.abspath(__file__)),
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
):
    if os.path.isdir(os.path.join(_provenance_parent, "provenance")):
        if _provenance_parent not in sys.path:
            sys.path.insert(0, _provenance_parent)
        break

from provenance.record_signature import load_signing_key, sign_record  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

DEFAULT_TENANT_ID = "tenant_default"

# P13-8 (Phase 1.3): see ledger/immudb_ledger.py's RECORD_PROFILE - same
# value, same reason, defined independently here because the control plane
# writes its own record (the erasure tombstone) rather than importing the
# interceptor's ledger module.
RECORD_PROFILE = "observed"

# D19 (Phase 3a): the wire format of an evidence bundle. One file, per
# record, self-describing, verifiable with no network. Bumped only when a
# field is added, removed, or reinterpreted, so tools/ail_verify_bundle.py
# can refuse a bundle it does not understand instead of guessing.
# docs/adr/0010-portable-evidence-bundles.md.
# Bumped to /2 by D22/D23 (Phase 3b): a bundle now carries an
# external_anchor section, its record carries a writer signature, and its
# proof material is anchored at a published checkpoint rather than at
# whatever this deployment's verifier held. A /1 checker reading a /2 bundle
# would skip all three, which is exactly what this string exists to refuse.
EVIDENCE_BUNDLE_FORMAT = "ail-evidence-bundle/2"

# D22 (Phase 3b): this service writes exactly one kind of ledger record, the
# erasure tombstone, and it signs that record with its OWN writer key - not
# the decision service's. The two are separate long-lived pairs so a bundle's
# writer_key_fingerprint names which service wrote the record, and so one
# writer can be put on a checker's deny-list without revoking the other.
# See docs/adr/0012-writer-signing-and-external-anchoring.md.
_WRITER_SIGNING_KEY_PATH = os.getenv("AIL_WRITER_SIGNING_KEY", "")

_writer_keys = None


def get_writer_keys():
    """Load (signing key, verifying key) once, or raise.

    Fail-closed, like every write path in this project except the one D23
    names. An unsigned tombstone is not a weaker tombstone: it is one
    tools/ail_verify_bundle.py refuses, so the erasure it records would have
    no verifiable evidence behind it.
    """
    global _writer_keys
    if _writer_keys is None:
        if not _WRITER_SIGNING_KEY_PATH or not os.path.exists(_WRITER_SIGNING_KEY_PATH):
            raise RuntimeError(
                "AIL_WRITER_SIGNING_KEY is unset or points at a missing file; this "
                "service cannot sign the tombstone it is about to write (D22)."
            )
        _writer_keys = load_signing_key(_WRITER_SIGNING_KEY_PATH)
        logger.info("Writer signing key loaded from %s", _WRITER_SIGNING_KEY_PATH)
    return _writer_keys

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

# D21 (Phase 3a completion): the verifier's own credential pair
# (docs/adr/0011-verifier-authentication.md), independent of
# CONTROL_PLANE_READ_KEY/WRITE_KEY - the control plane is a caller of the
# verifier, not the verifier itself, so it holds both: READ for every
# /verify call below (get_audit, get_audit_bundle, _has_tombstone), WRITE
# for the one /write call (_write_tombstone).
_VERIFIER_READ_KEY  = os.getenv("VERIFIER_READ_KEY", "")
_VERIFIER_WRITE_KEY = os.getenv("VERIFIER_WRITE_KEY", "")


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
def get_bundle(
    tenant_id: str,
    request: Request,
    db: Session = Depends(get_db),
    _: None = Depends(_require_read_key),
):
    """
    OPA Bundle API endpoint. OPA polls this on the configured interval,
    sending If-None-Match with the last known ETag. Return 304 if unchanged.

    R4 (Phase 1.3 completion pass, red-team V6): this returned the same
    tenant configuration GET /tenants/{id} is gated to protect, with zero
    authentication. Read-scoped, not write-scoped - OPA only ever reads
    this route. See opa-config.yaml, which attaches the read key as
    X-API-Key on every poll.
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
            resp = client.post(
                f"{VERIFIER_URL}/verify",
                json={"key": encoded_key},
                headers={"X-API-Key": _VERIFIER_READ_KEY},
            )
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
    # D22: signed before serialization, so the signature is a field in the
    # record and the inclusion proof covers it like every other byte.
    signing_key, verifying_key = get_writer_keys()
    serialized = json.dumps(
        sign_record(tombstone, signing_key, verifying_key), separators=(",", ":")
    )
    key = f"content_erasure:{call_id}"
    encoded_key = base64.b64encode(key.encode()).decode()
    encoded_val = base64.b64encode(serialized.encode()).decode()

    with httpx.Client(timeout=15) as client:
        resp = client.post(
            f"{VERIFIER_URL}/write",
            json={"key": encoded_key, "value": encoded_val},
            headers={"X-API-Key": _VERIFIER_WRITE_KEY},
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


# D29 (Phase 3c-2). Three helpers the deferred-verification path is built
# from: how long one /verify is given, one round trip mapped to a state, the
# state a deferred row carries, and the health probe behind
# verifier_reachable.
_VERIFIER_VERIFY_TIMEOUT = 10.0
_VERIFIER_HEALTH_TIMEOUT = 5.0


def _verify_one_key(encoded_key: str) -> tuple[dict, bool]:
    """
    One /verify round trip against the verifier, mapped to a verification
    object.

    Returns (verification, transport_ok). transport_ok is False only when the
    call itself could not be made - the condition get_audit's circuit breaker
    trips on, so that a scan whose verifier has died stops attempting the
    rest. A non-200 from a verifier that answered is "unverifiable" with
    transport_ok True: it answered, it just did not answer with a proof, and
    the next entry deserves its own attempt.

    Extracted so get_audit's scan loop, its intent-record loop, and
    GET /audit/verify all make the same call and map it the same way, rather
    than three copies that can drift - the same reasoning that extracted
    _verification_from_200 out of the first of them (D2).
    """
    try:
        with httpx.Client(timeout=_VERIFIER_VERIFY_TIMEOUT) as vc:
            vr = vc.post(
                f"{VERIFIER_URL}/verify",
                json={"key": encoded_key},
                headers={"X-API-Key": _VERIFIER_READ_KEY},
            )
    except Exception as vexc:
        logger.error("Verifier unreachable during verification: %s", vexc)
        return {
            "state": "unverifiable",
            "state_id": None,
            "detail": str(vexc),
            "error_class": None,
        }, False

    if vr.status_code == 200:
        return _verification_from_200(vr.json()), True

    logger.warning("Verifier returned HTTP %d", vr.status_code)
    return {
        "state": "unverifiable",
        "state_id": None,
        "detail": f"verifier returned HTTP {vr.status_code}",
        "error_class": None,
    }, True


def _deferred_verification() -> dict:
    """
    The verification object a deferred row carries.

    A fresh dict per row, never one shared object every entry in the response
    aliases. `asserted` with nothing else set is the honest shape: no
    verifiedGet was attempted, so there is no state_id to report, no detail to
    explain, and no error_class - a deferred row must not carry anything a
    reader could mistake for a diagnosis.
    """
    return {"state": "asserted", "state_id": None, "detail": None, "error_class": None}


def _probe_verifier_reachable() -> bool:
    """
    Whether the verifier answered a health check, right now.

    Why the probe exists at all. Before D29 an unreachable verifier left a
    fingerprint on an /audit page: the first entry's attempt failed and
    rendered "unverifiable", and the circuit breaker then produced a run of
    "asserted" rows behind it. A deferred page attempts nothing, so there is
    no first attempt to fail, nothing is "unverifiable", and an outage renders
    exactly like a healthy stack that simply did not look. This is the field
    that keeps those two apart.

    Why it runs on every path, including ?verify=true where the per-record
    calls would also answer the question: one field, established one way, so
    it cannot mean two things depending on which path produced it. The cost is
    one round trip against the up-to-`limit` D29 removed.

    What it establishes, exactly: the verifier answered GET /health at the
    moment this response was produced. It does not mean these rows would
    verify. A probe that succeeds can be followed by an expand that fails -
    they are separate calls at separate times, and no field closes that gap.
    Stated here, in docs/adr/0006-verification-states.md, and in the README's
    Residual Limits, because a boolean named for reachability invites being
    read as a claim about the records.

    Failure is False, never an exception: this is a field on a response, and a
    page that cannot reach the verifier is exactly the page that most needs to
    say so.
    """
    try:
        with httpx.Client(timeout=_VERIFIER_HEALTH_TIMEOUT) as vc:
            resp = vc.get(f"{VERIFIER_URL}/health")
        return resp.status_code == 200
    except Exception as exc:
        logger.warning("Verifier health probe failed: %s", exc)
        return False


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
def get_audit(
    limit: int = 100,
    verify: bool = False,
    _: None = Depends(_require_read_key),
    db: Session = Depends(get_db),
):
    """
    Return audit entries: the structured outcome record from ImmuDB, the
    read-time verification state (D2 - never self-certified by the entry),
    and the raw arguments joined from the erasable content store (D5, D7).

    Scans for all tool_call: keys via REST (no SDK needed for a key listing).
    See docs/adr/0006-verification-states.md for why verification is computed
    here, at read time, rather than stored in the entry. payload_state is
    computed the same way, from the entry's own content_state (D7).

    **Verification is deferred by default (D29, Phase 3c-2).** With
    `verify=false`, which is the default, no verifier call is made for any
    entry and every row comes back `asserted` - the state that has always
    meant "no verifiedGet was attempted for this entry in producing this
    response", which is exactly true of a deferred row. A reader who wants a
    specific record checked calls GET /audit/verify?key= for that one record;
    the dashboard's row-expand control does precisely that.

    `verify=true` restores the pre-D29 behaviour: one verifier round trip per
    entry, with the circuit breaker below. It is still O(min(limit, ledger))
    round trips - **this phase makes that cost opt-in rather than removing
    it** - and it is what the two tests that assert on a real verification
    state through this route pass (tests/test_verification.py::
    test_cross_process, and tests/test_content_states.py's erasure test,
    which compares the state before an erasure to the state after it and
    would compare "asserted" to "asserted" if this parameter did not exist).

    Returns:
        {"entries": [...], "total": <int>, "verifier_reachable": <bool>}

    verifier_reachable is a live GET /health against the verifier, run on
    every request including verify=true - see _probe_verifier_reachable for
    why it is probed rather than inferred, and for the narrow thing it
    establishes.

    Each entry:
        tx_id, call_id, agent_id, timestamp, tool_name  - as recorded; call_id
                          is the key erasure targets (DELETE /content/{call_id})
        ledger_key     - base64 raw ImmuDB key for this record; the
                          identifier GET /audit/bundle takes (P3a-2)
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
                          of verified | failed | unverifiable | asserted |
                          not_found. On the default (deferred) path this is
                          always "asserted" with the other three null (D29);
                          GET /audit/verify?key= returns this same object for
                          one record, actually checked.
        profile        - conformance profile this record was produced under
                          (P13-8): "observed" or "mediated". See
                          docs/adr/0005-outcome-taxonomy.md.
        exclusivity    - "demonstrated" | "declared" | null (D13, Phase 2);
                          only ever set for a "mediated" record - the
                          gateway's own verified answer, never the tool's
                          config claim. null for every "observed" record.
        execution_state - "completed" | "unknown" | "n/a" (D16, Phase 2
                          completion pass): "unknown" means a write-ahead
                          intent record exists for this call_id with no
                          matching completion record - the mediated tool
                          executed but its outcome was never durably
                          recorded (e.g. the ledger became unreachable
                          between the intent write and the completion
                          write). "completed" means both records exist.
                          "n/a" means this call was never subject to the
                          intent/completion protocol at all (every
                          "observed" record, and any mediated call denied
                          or faulted before reaching the intent write).
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

            # D16 (Phase 2 completion pass): a third scan, over
            # tool_call_intent: keys - the write a mediated tool's execution
            # is gated behind (ledger/immudb_ledger.py::log_tool_intent),
            # never tool_call:. Joined against the decision entries below by
            # call_id, the same way tombstones are joined, so an intent with
            # no matching completion record can be surfaced instead of
            # silently missing from this response.
            intent_scan_resp = client.post(
                f"{IMMUDB_URL}/api/v2/db/scan",
                json={
                    "prefix": base64.b64encode(b"tool_call_intent:").decode(),
                    "desc": True,
                    "limit": limit,
                },
                headers={"Authorization": f"Bearer {token}"},
            )
            intent_scan_resp.raise_for_status()
            raw_intents = intent_scan_resp.json().get("entries", [])

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

    # D16: intent records keyed by call_id, for the completion join below.
    # A record_type check (not just the key prefix) mirrors D11's own
    # tombstone-classification discipline.
    intent_by_call_id: dict[str, dict] = {}
    for raw in raw_intents:
        try:
            value = json.loads(base64.b64decode(raw["value"]).decode())
            if value.get("record_type") != "decision_intent" or not value.get("call_id"):
                continue
            intent_by_call_id[value["call_id"]] = {
                **value,
                "tx_id": int(raw.get("tx", 0)),
                "encoded_key": raw.get("key", ""),
            }
        except Exception as exc:
            logger.warning("Skipping malformed intent entry: %s", exc)
            continue

    # --- Verify each entry via the verifier service; join content by call_id ---
    #
    # D29: "verify each entry" is now what verify=true asks for. The default
    # path joins content and computes payload_state exactly as before and
    # attempts no proof check at all.
    verifier_reachable = _probe_verifier_reachable()
    verifier_up = True
    entries = []
    for raw in raw_entries:
        try:
            encoded_key: str       = raw.get("key", "")
            serialized_entry: str  = base64.b64decode(raw["value"]).decode()
            log_entry: dict        = json.loads(serialized_entry)
            tx_id: int             = int(raw.get("tx", 0))

            if not verify:
                # D29, producer 1 of "asserted": deferral. Nothing was
                # attempted for this entry because nothing was asked for.
                # This is the ordinary case since Phase 3c-2, not an outage
                # artifact - verifier_reachable above is what distinguishes
                # the two.
                verification = _deferred_verification()
            elif not verifier_up:
                # D29, producer 2 of "asserted": the circuit breaker. A prior
                # entry in this same scan already failed to reach the verifier
                # - this entry was never attempted at all. Reachable only on
                # the verify=true path, which is one of the reasons that path
                # still exists.
                verification = _deferred_verification()
            else:
                verification, transport_ok = _verify_one_key(encoded_key)
                if not transport_ok:
                    verifier_up = False  # stop hammering; remaining entries become "asserted"
                elif verification["state"] == "failed":
                    logger.warning(
                        "Audit: entry tx=%d failed verification: %s", tx_id, verification["detail"]
                    )
                elif verification["state"] == "not_found":
                    logger.info(
                        "Audit: entry tx=%d has no corresponding ImmuDB write (not_found)", tx_id
                    )

            call_id = log_entry.get("call_id")
            content_row = db.query(CallContent).filter_by(call_id=call_id).first() if call_id else None
            has_tombstone = call_id in tombstoned_call_ids if call_id else False
            payload_state, payload = _payload_state(log_entry.get("content_state"), content_row, has_tombstone)

            entries.append({
                "tx_id":           tx_id,
                # P3a-2: the base64 raw ImmuDB key for this record - the
                # identifier GET /audit/bundle takes. The key carries a
                # random uuid (ledger/immudb_ledger.py::log_tool_call), so it
                # cannot be derived from call_id; without it here, a reader
                # of /audit has no way to name the record they just read.
                "ledger_key":      encoded_key,
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
                # R3 (Phase 1.3 completion pass, red-team V5): a record with
                # no "profile" key at all must render as explicitly unknown,
                # not as a definite, valid-looking value. The previous
                # default (RECORD_PROFILE) rendered a structurally
                # profile-less record identically to a genuine, correctly-
                # produced one - live-demonstrated by forging a raw write
                # with the field omitted entirely. "unknown" is deliberately
                # outside the closed set {observed, mediated, attested}
                # (docs/adr/0005-outcome-taxonomy.md) so it cannot be
                # confused with a real profile value.
                "profile":         log_entry.get("profile", "unknown"),
                # D13/P2-3 (Phase 2): only ever set for a mediated record -
                # decision_service only writes this key at all when
                # resolve_exclusivity returned non-None (immudb_ledger.py's
                # log_tool_call omits the key entirely otherwise, so a
                # missing key here means "not applicable", not "unknown").
                "exclusivity":     log_entry.get("exclusivity"),
                # D16 (Phase 2 completion pass): "completed" if a
                # tool_call_intent: record exists for this call_id (the
                # normal case whenever this completion record itself
                # exists) - "n/a" if none does, meaning this call was never
                # subject to the write-ahead-intent protocol at all (every
                # "observed" tool call, and any read_vault_secret call that
                # was denied or faulted before reaching the intent write).
                # "unknown" is never assigned here - it only ever appears on
                # the synthesized entries below, for an intent with no
                # completion record at all.
                "execution_state": "completed" if call_id in intent_by_call_id else "n/a",
            })
        except Exception as exc:
            logger.warning("Skipping malformed ledger entry (tx=%s): %s", raw.get("tx"), exc)
            continue

    # D16: any intent record whose call_id never showed up as a completion
    # entry above executed (the intent write only happens right before
    # _execute_vault_tool, and a failed intent write never produces an
    # intent record at all - see decision_service/main.py) but never got a
    # durable outcome recorded. Synthesized here, from the intent record's
    # own fields, rather than silently omitted - this is the entire point
    # of D16: the gap between execution and recording becomes visible
    # instead of just absent from /audit.
    completed_call_ids = {e["call_id"] for e in entries if e["call_id"]}
    for call_id, intent in intent_by_call_id.items():
        if call_id in completed_call_ids:
            continue
        try:
            encoded_key = intent.get("encoded_key", "")
            if not verify:
                # D29: a synthesized intent entry defers with the rest of the
                # page. It is an entry in this response like any other, and a
                # default page that verified nothing must not have verified
                # this one either - otherwise the "no per-record verify call"
                # property would hold only for ledgers with no orphaned
                # intents in them, which is not a property at all.
                verification = _deferred_verification()
            else:
                verification, _transport_ok = _verify_one_key(encoded_key)

            content_row = db.query(CallContent).filter_by(call_id=call_id).first()
            has_tombstone = call_id in tombstoned_call_ids
            payload_state, payload = _payload_state(intent.get("content_state"), content_row, has_tombstone)

            entries.append({
                "tx_id":           intent["tx_id"],
                "ledger_key":      encoded_key,
                "call_id":         call_id,
                "agent_id":        intent.get("agent_id"),
                "timestamp":       intent.get("timestamp"),
                "tool_name":       intent.get("tool_name"),
                # This is what the intent recorded: approved, about to
                # execute. It is not a claim about what actually happened -
                # execution_state "unknown" is the honest signal for that.
                "outcome_type":    "policy_allow",
                "fault_class":     None,
                "policy_revision": intent.get("policy_revision"),
                "reasons":         [],
                "input_sha256":    intent.get("input_sha256"),
                "payload":         payload,
                "payload_state":   payload_state,
                "verification":    verification,
                "profile":         intent.get("profile", "unknown"),
                "exclusivity":     None,
                "execution_state": "unknown",
            })
        except Exception as exc:
            logger.warning("Skipping malformed intent entry for call_id=%s: %s", call_id, exc)
            continue

    logger.info(
        "Audit: %d entries; verify=%s verifier_reachable=%s verifier_up=%s "
        "by state: verified=%d failed=%d unverifiable=%d asserted=%d not_found=%d",
        len(entries),
        verify,
        verifier_reachable,
        verifier_up,
        sum(1 for e in entries if e["verification"]["state"] == "verified"),
        sum(1 for e in entries if e["verification"]["state"] == "failed"),
        sum(1 for e in entries if e["verification"]["state"] == "unverifiable"),
        sum(1 for e in entries if e["verification"]["state"] == "asserted"),
        sum(1 for e in entries if e["verification"]["state"] == "not_found"),
    )
    return {"entries": entries, "total": len(entries), "verifier_reachable": verifier_reachable}


@app.get("/audit/verify")
def verify_audit_record(key: str, _: None = Depends(_require_read_key)):
    """
    Verify one record on demand (P3c2-1, D29).

    `key` is the base64-encoded raw ImmuDB key - exactly the identifier
    GET /audit reports as `ledger_key` for every entry, exactly what
    GET /audit/bundle takes, and exactly what the verifier's own /verify
    takes. Following that precedent rather than inventing an identifier is
    what makes this work uniformly for every record shape this project
    writes, with no per-type branch to get wrong for one of them.

    Authorization is Depends(_require_read_key), the same read-scoped
    credential GET /audit and GET /audit/bundle require (ADR-0007, D21). A
    caller who can read the record through /audit can already see its
    verification state, so gating this route with that same key adds no
    reach; leaving it open would hand the ledger's proof surface to an
    unauthenticated caller, which is red-team X5's finding one level along.

    Returns 200 with the same verification object /audit puts on every row:
        {"key": <the key as given>, "verification": {state, state_id, detail, error_class}}

    A key that was never written is a 200 carrying state "not_found", not an
    HTTP 404. This route reports a verification result; it does not model the
    record as a missing resource. GET /audit/bundle does return 404 for the
    same condition, and differently on purpose - a bundle is evidence that a
    record was committed and its proofs checked, so there is no honest bundle
    for a key that was never written, whereas "this key names nothing" is a
    perfectly good answer to "verify this key".

    A verifier that cannot be reached is likewise a 200 carrying
    "unverifiable", for the same reason: the states exist to distinguish
    these conditions from each other, and collapsing them into HTTP status
    codes would undo D2, D8 and D10 at the transport layer.

    This route is what makes `not_found` reachable end to end for the first
    time. ADR-0006 recorded that it was not, because /audit's own scan only
    ever lists keys ImmuDB confirms exist, so a key that is simultaneously
    scanned and never written cannot be constructed. This route takes its key
    from the caller instead of from a scan.
    """
    try:
        raw_key = base64.b64decode(key, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="key must be base64-encoded raw ImmuDB key bytes")
    if not raw_key:
        raise HTTPException(status_code=400, detail="key must not be empty")

    verification, _transport_ok = _verify_one_key(key)
    return {"key": key, "verification": verification}


def _record_type_of(raw_value: bytes) -> str:
    """
    Name the shape of a stored record for the bundle's own description.

    Discriminates on fields inside the record, never on the ImmuDB key
    prefix - the same discipline D11 applies to tombstone classification in
    get_audit above. A record that carries none of the fields this project
    writes is "unknown", deliberately outside every closed set
    (docs/adr/0005-outcome-taxonomy.md), so a forged or foreign record
    cannot be described by a bundle as a genuine outcome type it never
    claimed. This is a label on the bundle, not an input to any proof.
    """
    try:
        value = json.loads(raw_value.decode())
    except Exception:
        return "unknown"
    if not isinstance(value, dict):
        return "unknown"
    record_type = value.get("record_type")
    if record_type in ("content_erasure", "decision_intent"):
        return record_type
    outcome_type = value.get("outcome_type")
    if outcome_type in ("policy_allow", "policy_deny", "schema_deny", "fault"):
        return outcome_type
    return "unknown"


# ---------------------------------------------------------------------------
# D23 (Phase 3b): the anchor store.
#
# anchor_service/ is the only writer. It submits a checkpoint to a public
# transparency log first and records it here second, so a row means the
# submission was accepted - never that one was attempted. GET /audit/bundle
# reads this store to decide whether a bundle may claim external
# corroboration, and that decision has to be a fact about the outside world
# rather than about this deployment's intentions.
# ---------------------------------------------------------------------------

class AnchorCheckpoint(BaseModel):
    db: str
    tx_id: int
    tx_hash: str        # base64
    signature: str      # base64, DER ECDSA, the ImmuDB server's own


class AnchorExternal(BaseModel):
    log_url: str
    log_url_source: str
    log_index: str
    anchor_key_fingerprint: str
    anchor_payload_format: str
    transparency_log_entry: dict


class AnchorRequest(BaseModel):
    checkpoint: AnchorCheckpoint
    external: AnchorExternal


@app.post("/anchors", status_code=201)
def record_anchor(
    payload: AnchorRequest,
    db: Session = Depends(get_db),
    _: None = Depends(_require_write_key),
):
    """
    Record one externally anchored checkpoint (D23).

    Write-scoped (ADR-0007), the same credential that already authorizes
    every other record this service writes. That is deliberately not a new
    grant: anything holding this key can already write an erasure tombstone
    the verifier treats as authentic (readME.md §5's
    tamper-evidence-is-not-forgery-resistance bullet), so accepting anchors
    from it adds no reach. What stops a forged anchor from becoming a
    forged claim is not this gate: the verifier refuses a checkpoint ImmuDB
    did not sign before using it as a proof source, and
    tools/ail_verify_bundle.py re-verifies the whole Rekor chain offline
    against a trust root the checker holds. A forged row yields a bundle
    that fails offline, which is where it should fail.

    Idempotent by transaction id. Re-anchoring the same checkpoint is a
    no-op rather than an error, so a submitter that crashed between the log
    accepting an entry and this call landing can simply run again.
    """
    tx_id = int(payload.checkpoint.tx_id)
    existing = db.query(StateAnchor).filter_by(checkpoint_tx_id=tx_id).first()
    if existing:
        logger.info("Anchor for tx=%d already recorded; leaving it as it stands", tx_id)
        return {"recorded": False, "checkpoint_tx_id": tx_id, "detail": "already recorded"}

    db.add(StateAnchor(
        checkpoint_tx_id=tx_id,
        checkpoint_db=payload.checkpoint.db,
        checkpoint_tx_hash=payload.checkpoint.tx_hash,
        checkpoint_signature=payload.checkpoint.signature,
        log_url=payload.external.log_url,
        log_url_source=payload.external.log_url_source,
        log_index=str(payload.external.log_index),
        anchor_key_fingerprint=payload.external.anchor_key_fingerprint,
        anchor_payload_format=payload.external.anchor_payload_format,
        entry_json=json.dumps(payload.external.transparency_log_entry, separators=(",", ":")),
    ))
    db.commit()
    logger.info(
        "Anchored checkpoint tx=%d in %s at log index %s",
        tx_id, payload.external.log_url, payload.external.log_index,
    )
    return {"recorded": True, "checkpoint_tx_id": tx_id}


def _latest_anchor(db: Session):
    """The newest anchored checkpoint, or None.

    Newest is always the best choice: a checkpoint covers every transaction
    at or below its own, so the highest one covers the most records, and
    an older one covers a strict subset. There is no case where reaching
    past the newest anchor finds a better one.
    """
    return db.query(StateAnchor).order_by(StateAnchor.checkpoint_tx_id.desc()).first()


def _anchor_as_dict(anchor: StateAnchor) -> dict:
    return {
        "checkpoint": {
            "db": anchor.checkpoint_db,
            "tx_id": anchor.checkpoint_tx_id,
            "tx_hash": anchor.checkpoint_tx_hash,
            "signature": anchor.checkpoint_signature,
        },
        "external": {
            "log_url": anchor.log_url,
            "log_url_source": anchor.log_url_source,
            "log_index": anchor.log_index,
            "anchor_key_fingerprint": anchor.anchor_key_fingerprint,
            "anchor_payload_format": anchor.anchor_payload_format,
            "transparency_log_entry": json.loads(anchor.entry_json),
        },
    }


@app.get("/anchors/latest")
def get_latest_anchor(db: Session = Depends(get_db), _: None = Depends(_require_read_key)):
    """The newest anchored checkpoint, or an explicit statement that there is none.

    Read-scoped, the same credential GET /audit already requires: this
    returns a public Merkle root and a public log entry, both of which are
    already world-readable in the transparency log itself.

    Answers with anchored: false rather than 404 for the same reason a
    bundle states its lack of corroboration in a field rather than omitting
    one - "no anchor exists" and "this route is missing" are different
    facts and a caller has to be able to tell them apart.
    """
    anchor = _latest_anchor(db)
    if anchor is None:
        return {"anchored": False, "detail": "no checkpoint has been anchored yet"}
    return {"anchored": True, **_anchor_as_dict(anchor)}


ANCHOR_STATE_ANCHORED = "anchored"
ANCHOR_STATE_NOT_ANCHORED = "not_anchored"


def _external_anchor_section(anchor) -> dict:
    """The bundle's external-corroboration section. Never omitted.

    D23's precise rule is fail-open on the write path, fail-closed on the
    claim: anchoring never blocks a write, but a bundle for a record no
    checkpoint covers cannot claim corroboration. It states that in a field
    rather than by leaving one out, the same discipline
    docs/adr/0006-verification-states.md applies to the read-time states -
    a reader must never have to infer a fact from a missing key.

    When anchored, the section carries the log entry exactly as the log
    returned it. The checkpoint itself is deliberately NOT duplicated here:
    it is already proof.source_state, because it is the transaction the dual
    proof runs to. Carrying a second copy would create two fields that could
    disagree without consequence, which
    tools/bundle_byte_sweep.py found in Phase 3a and ADR-0010 records as the
    reason proof.signing_key_fingerprint is now compared rather than
    ignored. The checker recomputes the anchored payload from
    proof.source_state and binds it to the log entry's digest.
    """
    if anchor is None:
        return {
            "state": ANCHOR_STATE_NOT_ANCHORED,
            "detail": (
                "no checkpoint covering this record has been submitted to a public "
                "transparency log, so this bundle makes no claim of external "
                "corroboration. The local proof chain above is unaffected."
            ),
        }
    return {
        "state": ANCHOR_STATE_ANCHORED,
        "log_url": anchor.log_url,
        "log_url_source": anchor.log_url_source,
        "log_index": anchor.log_index,
        "anchor_key_fingerprint": anchor.anchor_key_fingerprint,
        "anchor_payload_format": anchor.anchor_payload_format,
        "transparency_log_entry": json.loads(anchor.entry_json),
    }


@app.get("/audit/bundle")
def get_audit_bundle(
    key: str,
    db: Session = Depends(get_db),
    _: None = Depends(_require_read_key),
):
    """
    Export one record's portable evidence bundle (D19, Phase 3a).

    `key` is the base64-encoded raw ImmuDB key, exactly the identifier
    GET /audit reports as `ledger_key` for every entry and exactly what the
    verifier's own /verify takes. Taking the raw key rather than a call_id
    is what makes this work uniformly for every record shape this project
    writes - tool_call: decisions (policy_allow, policy_deny, schema_deny,
    fault), content_erasure: tombstones, and tool_call_intent: records -
    with no per-type branch that could be gotten wrong for one of them.

    Authorization is Depends(_require_read_key): the same read-scoped
    credential GET /audit itself requires (ADR-0007), not a third key and
    not a more permissive path. A bundle contains the record and its proof;
    anyone who can read the record through /audit can already see both, so
    granting bundle export to that same credential adds no reach, while
    leaving it ungated would hand the audit trail to an unauthenticated
    caller.

    The bundle carries no key material. It names the ECDSA public key it
    expects by fingerprint only; the checker holds that key independently
    (D18, and the spike's state.publicKey finding). A bundle that shipped
    its own key would verify against itself.

    Returns 404 when the record cannot be verified - a bundle is evidence
    that a record was committed and its proofs checked out, so there is no
    honest bundle for a key that was never written, or whose proof was
    rejected. The verifier's error_class is passed through in the detail so
    the two cases stay distinguishable to the caller.
    """
    try:
        raw_key = base64.b64decode(key, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="key must be base64-encoded raw ImmuDB key bytes")
    if not raw_key:
        raise HTTPException(status_code=400, detail="key must not be empty")

    # D23/P3b-1: ask for the proof to run to the newest anchored checkpoint,
    # not to whatever this deployment's verifier happens to hold. A proof
    # anchored at an internal state is unfalsifiable to an outside party -
    # they have no independent way to learn what that state was. A proof
    # anchored at a checkpoint that is in a public transparency log is not.
    anchor = _latest_anchor(db)

    def _call_verifier(anchor_payload):
        body = {"key": key}
        if anchor_payload is not None:
            body["anchor"] = anchor_payload
        try:
            with httpx.Client(timeout=30.0) as vc:
                vr = vc.post(
                    f"{VERIFIER_URL}/verify",
                    json=body,
                    headers={"X-API-Key": _VERIFIER_READ_KEY},
                )
            vr.raise_for_status()
            return vr.json()
        except Exception as exc:
            logger.error("Verifier unreachable during bundle export: %s", exc)
            raise HTTPException(status_code=503, detail=f"Verifier unavailable: {exc}")

    anchored = False
    if anchor is not None:
        vdata = _call_verifier({
            "db": anchor.checkpoint_db,
            "tx_id": anchor.checkpoint_tx_id,
            "tx_hash": anchor.checkpoint_tx_hash,
            "signature": anchor.checkpoint_signature,
        })
        if vdata.get("verified"):
            anchored = True
        elif vdata.get("error_class") == "anchor_precedes_record":
            # The record is newer than every anchored checkpoint. Not a
            # failure: it is the ordinary state of a record written since
            # the last anchoring cycle, and D23 is explicit that anchoring
            # is asynchronous and off the hot path. Export it, and say in
            # the bundle that no external corroboration exists.
            logger.info("Record is newer than the newest anchor (tx=%d); exporting unanchored",
                        anchor.checkpoint_tx_id)
            anchor = None
            vdata = _call_verifier(None)
        else:
            # Any other refusal is about the record or the anchor's own
            # signature, and is handled by the shared not-verified branch
            # below rather than papered over by silently re-exporting
            # unanchored - that would turn a rejected anchor into a bundle
            # that merely looks uncorroborated.
            pass
    else:
        vdata = _call_verifier(None)

    if not vdata.get("verified"):
        raise HTTPException(
            status_code=404,
            detail=(
                f"No verified record for this key "
                f"(error_class={vdata.get('error_class')}): {vdata.get('detail')}"
            ),
        )

    proof = vdata.get("proof_material")
    if not proof:
        # The verifier verified the record but returned no material. That is
        # a verifier too old for D18, not a tampered record - fail loudly
        # rather than emitting a bundle with an empty proof section that
        # would look like evidence and check out as nothing.
        logger.error("Verifier returned no proof_material for a verified record")
        raise HTTPException(
            status_code=503,
            detail="Verifier returned no proof material; it predates D18 (see ADR-0010)",
        )

    raw_value = base64.b64decode(vdata["value"])

    bundle = {
        "bundle_format": EVIDENCE_BUNDLE_FORMAT,
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "exported_by": "ail-control-plane",
        "record": {
            "ledger_key": key,
            "value": vdata["value"],
            "tx_id": vdata.get("tx_id"),
            "timestamp": vdata.get("timestamp"),
            "record_type": _record_type_of(raw_value),
        },
        "proof": proof,
        # Fingerprint only. See this function's docstring and ADR-0010.
        "signing_key": {"fingerprint": proof.get("signing_key_fingerprint")},
        # D23: always present, always stating which of the two states it is.
        # A bundle that simply omitted this section when nothing anchored the
        # record would make "not corroborated" and "exported by a build that
        # predates anchoring" the same bytes, and would make absence of
        # evidence look like evidence of absence. It says so instead.
        "external_anchor": _external_anchor_section(anchor if anchored else None),
    }

    filename = f"ail-evidence-tx{vdata.get('tx_id')}.json"
    logger.info(
        "Exported evidence bundle for tx=%s record_type=%s",
        vdata.get("tx_id"),
        bundle["record"]["record_type"],
    )
    return Response(
        content=json.dumps(bundle, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
