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
import urllib.parse
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

from provenance.record_signature import (  # noqa: E402
    load_signing_key, load_verifying_key, sign_record, verify_record,
)

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

    Raises when the tombstone did not reach the ledger (non-2xx, transport
    error, or a `verified: false` that is also `committed: false`) - the
    caller treats that as fail-closed: the erasure is refused and the row
    survives.

    P3c3c-12 (Phase 3c-3c): a `verified: false` that is `committed: true` is
    a different thing and returns rather than raising. `verifiedSet` commits
    at service.VerifiableSet and every proof failure is raised after that
    line, so such a tombstone is in the ledger; refusing the erasure on the
    strength of a proof failure about a write we can see happened leaves the
    ledger saying erased and the content store saying present, which is the
    `erasure_conflict` face of _payload_state - P13-4's own finding,
    manufactured by the refusal. Reproduced live on b9f6a1d in
    docs/reports/phase-3c3c.md: DELETE answered 503 while the tombstone was
    committed at tx 6.

    The return value is that distinction, and the caller acts on it.
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
    if result.get("verified"):
        return {"committed": True, "verified": True, "tx_id": result.get("tx_id"),
                "fault_record": None}

    if not result.get("committed"):
        raise RuntimeError(f"Tombstone write not verified: {result.get('detail', 'no detail')}")

    # Committed, unverified. Confirm it from the ledger rather than from the
    # response that just told us a proof failed - one exact read, on a path
    # that has already failed once, and it separates a stale trust anchor
    # (the record is there) from a record that genuinely is not in the tree.
    # A compromised server defeats both, which is why this is stated as
    # confirming presence rather than as re-verifying anything.
    if not _tombstone_present_in_ledger(call_id, result.get("tx_id")):
        raise RuntimeError(
            "Tombstone write reported committed but no record is present under "
            f"content_erasure:{call_id}; refusing the erasure"
        )
    logger.error(
        "Tombstone for call_id=%s committed at tx=%s and failed verification "
        "(%s); the erasure completes and the fault record at %s qualifies it",
        call_id, result.get("tx_id"), result.get("error_class"),
        result.get("fault_record"),
    )
    return {"committed": True, "verified": False, "tx_id": result.get("tx_id"),
            "fault_record": result.get("fault_record"),
            "error_class": result.get("error_class")}


def _tombstone_present_in_ledger(call_id: str, expected_tx: int | None) -> bool:
    """Is THIS call's content_erasure record under this call_id's exact key.

    An exact `getall` against ImmuDB's own REST route, not a verified read:
    this is called precisely when a proof has failed, so a verified read
    would fail the same way and answer a different question than the one
    being asked. What it establishes is narrow and is used narrowly - a
    record exists under this key, at this transaction.

    **P3c3d-7 (Phase 3c-3d): at this transaction.** It used to ask only
    whether a tombstone existed, so a tombstone written by some earlier
    erasure satisfied a later call's confirmation - the confirmation would
    pass for a write that never landed. `expected_tx` is the transaction the
    write response named, and the entry the ledger holds has to be at it.
    Narrow, and it is a correctness question on the GDPR path: this
    confirmation is the only thing standing between a refused-looking write
    and a deleted row.

    No transaction to check against is not a confirmation. It fails closed,
    the same rule the exception handler below applies.
    """
    if not expected_tx:
        logger.error(
            "Could not confirm the tombstone for call_id=%s: the write response "
            "named no transaction, so there is nothing to confirm it against",
            call_id,
        )
        return False
    try:
        with httpx.Client(timeout=15) as client:
            login = client.post(f"{IMMUDB_URL}/api/v2/login", json={
                "user": base64.b64encode(IMMUDB_USER.encode()).decode(),
                "password": base64.b64encode(IMMUDB_PASSWORD.encode()).decode(),
                "database": base64.b64encode(b"defaultdb").decode(),
            })
            login.raise_for_status()
            token = login.json()["token"]
            resp = client.post(
                f"{IMMUDB_URL}/api/v2/db/getall",
                json={"keys": [base64.b64encode(
                    f"content_erasure:{call_id}".encode()).decode()]},
                headers={"Authorization": f"Bearer {token}"},
            )
            resp.raise_for_status()
    except Exception as exc:
        # Fail closed: an erasure must never complete because the check that
        # would have caught a missing tombstone could not run. Same rule
        # _has_tombstone applies in the other direction.
        logger.error("Could not confirm the tombstone for call_id=%s: %s", call_id, exc)
        return False
    for raw in resp.json().get("entries", []):
        try:
            value = json.loads(base64.b64decode(raw["value"]).decode())
        except Exception:
            continue
        if value.get("record_type") != "content_erasure" or value.get("call_id") != call_id:
            continue
        if int(raw.get("tx", 0)) != int(expected_tx):
            logger.error(
                "A content_erasure record exists for call_id=%s at transaction %s, "
                "and this call's write reported transaction %s. That is a different "
                "tombstone; refusing to treat it as confirmation of this one.",
                call_id, raw.get("tx"), expected_tx,
            )
            continue
        return True
    return False


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

    P3c3c-12 (Phase 3c-3c): "if it fails" now means the tombstone did not
    reach the ledger, which is the question D11 was always asking. A
    tombstone that committed and whose proof did not check out is confirmed
    by an exact read and the erasure completes - the durable record of
    having erased exists, a ledger_fault qualifies its standing, and
    refusing instead would leave the ledger saying erased while the content
    it names is still in the store. The one thing that must never happen
    here is a row deleted with no tombstone behind it, and that is unchanged.
    """
    existing = db.query(CallContent).filter_by(call_id=call_id).first()
    if existing is None:
        return

    try:
        outcome = _write_tombstone(call_id)
    except Exception as exc:
        logger.error("Tombstone write failed for call_id=%s: %s", call_id, exc)
        raise HTTPException(
            status_code=503,
            detail=f"Tombstone write failed; erasure refused: {exc}",
        )

    db.delete(existing)
    db.commit()
    if not outcome.get("verified"):
        logger.warning(
            "Erasure for call_id=%s completed against a committed-unverified "
            "tombstone (tx=%s, fault=%s)",
            call_id, outcome.get("tx_id"), outcome.get("fault_record"),
        )


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


# ---------------------------------------------------------------------------
# P3c3a-1 / P3c3a-3 (Phase 3c-3a): reading the ledger, not the page.
#
# Two facts GET /audit used to infer from the page it happened to fetch, and
# now measures directly:
#
#   how many decision records the ledger holds - previously len(entries),
#   which is the page's length and says nothing about the ledger;
#
#   which of the page's call_ids have an erasure tombstone - previously a
#   prefix scan over content_erasure: bounded by the page's own limit, so a
#   tombstone could be excluded by a limit that had nothing to do with it.
#
# Both go through ImmuDB's REST API. Both are described here rather than at
# their call sites because get_audit is long and these are the only two
# places it asks ImmuDB a question that is not "give me a page".
# ---------------------------------------------------------------------------

_TOOL_CALL_PREFIX = b"tool_call:"

# ImmuDB's own hard ceiling on a scan's `limit`, measured against immudb
# 1.9.5 rather than read off a doc: 2500 is served, 2501 is refused with
# "result size limit exceeded". POST /api/v2/db/getall does not inherit it -
# a 3000-key getall was served in the same probe - which is one more reason
# P3c3a-3's tombstone join is a getall rather than a scan.
_MAX_SCAN_LIMIT = 2500

# D32 (Phase 3c-3b): the view indexes the ordered page selects through, and
# the shared counter that scores them. Named to match
# verifier/main.py::_VIEW_SETS - one counter, one position per commit, one
# zset per view, so a later view is a new zset over the same numbers rather
# than a second backfill.
#
# zscan carries the same 2500 ceiling scan does (verified live), so the
# limit+1 handling P3c3a-2 established applies here unchanged.
_VIEW_DECISION = b"ail_view:decision:v1"
_VIEW_INTENT   = b"ail_view:intent:v1"

# D35 (Phase 3c-3c). Named rather than spelled inline at the two places that
# use it, so tests/test_ledger_vocabulary.py can compare this copy against
# verifier/main.py's - these two modules never import each other and both
# have to mean the same key.
_FAULT_KEY_PREFIX  = "ledger_fault:"
_FAULT_RECORD_TYPE = "ledger_fault"

# D38 (Phase 3c-3d). The verifier's copy is verifier/main.py's
# FAULT_KEY_TX_PAD and fault_key_tx_bound, and what has to agree between the
# two modules is the whole key format and not just the prefix: the writer
# builds `ledger_fault:{tx:020d}:{identity}:{nonce}` and this module builds
# the window bounds `[ledger_fault:{lo:020d}, ledger_fault:{hi+1:020d})` from
# the same rule. A pad that disagreed would produce a window that silently
# excludes the faults it was asked for.
# tests/test_ledger_vocabulary.py compares what the two produce.
_FAULT_KEY_TX_PAD = 20


def _fault_key_tx_bound(tx_id: int) -> str:
    """`ledger_fault:{tx_id:020d}` - a bound for the page's range read."""
    return f"{_FAULT_KEY_PREFIX}{tx_id:0{_FAULT_KEY_TX_PAD}d}"


# D41 (Phase 3c-3d): the key a fault record has to be signed by before this
# service renders it as another record's standing. Path, not key material -
# the public half, mounted read-only like every other file this service
# reads from /keys.
_FAULT_WRITER_PUBLIC_KEY = os.getenv("AIL_FAULT_WRITER_PUBLIC_KEY",
                                     "/keys/writer-verifier.pub")


class BoundedReadFault(Exception):
    """D42 (Phase 3c-3d): a bounded read returned something outside its bound.

    ImmuDB's REST route drops an unrecognised field without comment, so a
    bounded read whose bound is misspelled becomes an unbounded read at HTTP
    200 and nothing in the response distinguishes the two - `endkey` for
    `endKey` is the whole distance between a correct read and a wrong one
    (docs/reports/phase-3c3d-keyprobe.md section 2). The assertion that bites
    is therefore on what came back, not on what was sent: a dropped bound
    only reveals itself when something out-of-window arrives.

    Raised rather than logged. A page whose fault join silently widened is a
    page that could name the wrong record's standing, and this project's rule
    for a check that cannot be trusted is to refuse rather than serve with a
    caveat.
    """


class OrderingFault(Exception):
    """D33 (Phase 3c-3b): the index and the ledger disagree about order.

    zscan returns the caller's score and the resolved `entry.tx` in the same
    response, so checking that they agree costs no extra call. Under D32's
    CAS this is no longer a defence against a writer that can misorder - the
    ledger refuses to commit an out-of-order position at all. It is a cheap
    assertion that the enforcement is still in place, and it is what would
    catch the precondition having been dropped.

    **A disagreement is a fault, not a sort order.** Reordering the page to
    match the transaction ids would hide exactly the condition worth
    reporting: an index that no longer describes the ledger it indexes. So
    this raises, `/audit` answers 500, and nobody is shown a page that looks
    fine.

    It carries the pair it disagreed about, so the response can name it
    rather than hand a reader a sentence to parse. See
    _ordering_fault_body.
    """

    def __init__(self, message: str, *, view: str,
                 higher: tuple[float, int], lower: tuple[float, int]):
        super().__init__(message)
        self.view = view
        # (position, transaction) for the two adjacent rows that disagreed,
        # `higher` being the one the index placed later in commit order.
        self.higher = higher
        self.lower = lower


# The condition is deliberately a 500 and deliberately not a 503. It is a
# server-side integrity failure rather than a bad request, so it is not 4xx;
# and it is not the "try again shortly" that 503 promises either, because the
# ledger is append-only and a score that has been written cannot be
# withdrawn.
#
# P3c3c-7 (Phase 3c-3c): what it must not say is `transient: false`. The
# corruption is not transient; this fault is. The check's window is the
# top-of-index page, so newer traffic pushes a disagreement below the window
# and every limit returns 200 again with the corruption still indexed -
# measured, in docs/reports/phase-3c3b-redteam.md C5 and C10 and reproduced
# in docs/reports/phase-3c3c.md. A field asserting durability the code does
# not have is worse than no field: it tells an operator the fault will be
# there tomorrow, so its absence tomorrow reads as repair.
#
# What replaces it is the scope this check actually has, and a pointer to
# the check that does have the durable answer (D37, the reconciliation).
ORDERING_FAULT_ERROR = "audit_ordering_fault"


def _ordering_fault_body(exc: "OrderingFault") -> dict:
    """The response body for a disagreement between the index and the ledger.

    Factored out of the handler so the shape a caller sees is testable
    without fabricating a live disagreement: ImmuDB zsets are append-only, so
    a test that wrote a bad score into a real view would leave every
    subsequent page in the session faulted.
    """
    return {
        "error": ORDERING_FAULT_ERROR,
        "message": str(exc),
        "view": exc.view,
        "disagreement": {
            "higher_position": {"position": exc.higher[0], "transaction": exc.higher[1]},
            "lower_position": {"position": exc.lower[0], "transaction": exc.lower[1]},
        },
        # Stated rather than implied: no page was served, so a caller must
        # not read this as an empty ledger.
        "page_served": False,
        # P3c3c-7: the scope of the check that raised, said plainly, because
        # it is narrower than a reader would assume from a 500 about the
        # ledger's integrity.
        "scope": (
            "this page only: the adjacent rows at the top of the view index at "
            "this limit, and only positions the compare-and-set allocated"
        ),
        # And what that scope implies about repeating the request, without
        # claiming a persistence this check cannot observe. Both directions
        # are named because both mislead on their own.
        "on_retry": (
            "an identical request returns this same fault while the disagreement "
            "is inside the window; a later request can succeed without anything "
            "having been repaired, because newer commits push the disagreement "
            "below the window while it stays in the index. A page that succeeds "
            "is therefore not evidence the index was corrected"
        ),
        "authoritative_check": (
            "the sequence reconciliation in anchor_service walks every position "
            "in every view, so it has no window and its findings persist"
        ),
        "remediation": (
            "The view index does not describe the order the ledger committed in. "
            "Do not reorder or ignore it. Run the sequence reconciliation in "
            "anchor_service to find what else is affected - including "
            "disagreements this page can no longer reach - and see "
            "docs/adr/0014-ordered-audit-view-index.md."
        ),
    }


# The seam. Positions 1 through _RESERVED_POSITIONS belong to backfilled
# history, scored at each record's own transaction id
# (tools/ail_backfill_index.py); the CAS allocates from _RESERVED_POSITIONS + 1
# upward.
#
# D36 (Phase 3c-3c): no longer "must match verifier/main.py" by convention.
# The reserve is bound into the ledger under KeyMustNotExist at first
# allocation, and this reader refuses to serve a page if its own value
# disagrees with the bound one - paging against a different seam than the
# writer allocated against would put live positions inside the reserve,
# where D33 does not check them and reconciliation does not count them.
# P3c3d-9 (Phase 3c-3d): the first integer a float64 cannot follow.
# zscan scores are float64, so no position at or above this is distinct
# from its neighbour. Same constant and same rule as
# verifier/main.py::MAX_POSITION.
MAX_POSITION = 2 ** 53


def _validate_reserve(raw, source: str = "AIL_RESERVED_POSITIONS") -> int:
    """A reserve is a positive integer below 2**53. Anything else refuses at load.

    Same rule and same words as verifier/main.py::validate_reserve. Three
    copies because three images do not import each other; the value bound
    into the ledger is what actually keeps them honest.

    P3c3d-9 (Phase 3c-3d) added the upper bound: a reserve at or above 2**53
    makes allocated positions unrepresentable as distinct float64 scores.
    Measured, six writes produced four scores and /audit was dead at every
    limit from the sixth write on a virgin ledger.
    """
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        raise RuntimeError(f"{source} must be an integer; got {raw!r}.")
    if value < 1:
        raise RuntimeError(
            f"{source} must be a positive integer; got {value}. At or below zero "
            "every allocated position would be at or below zero too, and zscan "
            "under desc omits negatively-scored members and reports a zero score "
            "as no score at all."
        )
    if value >= MAX_POSITION:
        raise RuntimeError(
            f"{source} must be below 2**53 ({MAX_POSITION}); got {value}. A position is a "
            "float64 score in a zset, and above 2**53 consecutive integers are "
            "not distinct scores: allocated positions collapse onto each other, "
            "the write response names a position the index does not hold, and "
            "the order check reads the collapse as a disagreement at every limit."
        )
    return value


_RESERVED_POSITIONS = _validate_reserve(os.getenv("AIL_RESERVED_POSITIONS", "1000000000"))
_FIRST_ALLOCATED_POSITION = float(_RESERVED_POSITIONS + 1)
_RESERVE_KEY = b"ail_seq:reserve"

# Cached so the check costs no round trip per page. Re-read at cold start and
# after a refusal, the same two moments the verifier refreshes its own copy.
_bound_reserve_cache: int | None = None


class ReserveMismatch(Exception):
    """The ledger's bound reserve is not this service's configured reserve."""


def _assert_reserve_agrees(client: httpx.Client, token: str) -> None:
    """Refuse to serve a page against a seam this deployment does not share.

    A ledger with no bound reserve is one that has never allocated, or one
    written before D36. Neither is a disagreement, so neither refuses: there
    is no bound value to disagree with, and inventing a refusal for the
    absence would make every pre-D36 ledger unreadable.
    """
    global _bound_reserve_cache
    if _bound_reserve_cache is None:
        resp = client.post(
            f"{IMMUDB_URL}/api/v2/db/getall",
            json={"keys": [base64.b64encode(_RESERVE_KEY).decode()]},
            headers={"Authorization": f"Bearer {token}"},
        )
        resp.raise_for_status()
        entries = resp.json().get("entries", [])
        if not entries:
            return
        _bound_reserve_cache = _validate_reserve(
            base64.b64decode(entries[0]["value"]).decode(), source="the bound reserve")
    if _bound_reserve_cache != _RESERVED_POSITIONS:
        bound = _bound_reserve_cache
        _bound_reserve_cache = None      # re-read on the next attempt
        raise ReserveMismatch(
            f"this service is configured with AIL_RESERVED_POSITIONS="
            f"{_RESERVED_POSITIONS} and the ledger has {bound} bound into it. Every "
            "position in this ledger was allocated against the bound value, so "
            "paging against a different one would put live positions inside the "
            f"reserve, where they are not order-checked. Set this service to {bound}. "
            "A reserve that is genuinely too small is a re-index into a new view, "
            "not a moved boundary."
        )


def _assert_score_order_matches_commit_order(
    rows: list[tuple[float, int]], view: str = "unknown"
) -> None:
    """D33. `rows` is [(score, tx_id)] in the order zscan returned them, which
    is score-descending.

    A position is allocated under the CAS in the same transaction that commits
    the record, so a higher position must name a higher transaction id. An
    inversion between adjacent rows is the fault.

    **What this covers, stated precisely.** Only positions the CAS allocated,
    which are the integers above the reserve. Backfilled history occupies the
    reserve, scored at each record's own transaction id by an offline pass,
    and those records were never ordered by the CAS - a record written before
    the index existed can carry a higher transaction id than a record indexed
    after it, so comparing the two would report a fault about a rule that
    never applied to either. D33 is an assertion that the CAS enforcement is
    in place; it is scoped to the rows the CAS produced, and it is not
    weakened for them.

    Within the reserve the same relation does hold - a historical score *is*
    its transaction id, so score order and commit order are the same order by
    construction there - but it is not asserted here, because it would be
    asserting that a number equals itself.
    """
    allocated = [(s, tx) for s, tx in rows if s >= _FIRST_ALLOCATED_POSITION]
    for (score_a, tx_a), (score_b, tx_b) in zip(allocated, allocated[1:]):
        if not (score_a > score_b and tx_a > tx_b):
            raise OrderingFault(
                f"the view index and the ledger disagree: position {score_a} resolves to "
                f"transaction {tx_a} and position {score_b} resolves to transaction {tx_b}, "
                "so the index no longer describes the order the ledger committed in",
                view=view,
                higher=(score_a, tx_a),
                lower=(score_b, tx_b),
            )


def _zscan_view(client, token: str, view_set: bytes, limit: int) -> list[dict]:
    """Newest-first rows from a view index.

    Each row carries the score, the resolved entry's key, its transaction id
    and its value, so the ordered page needs no second lookup to build a row
    and D33's comparison is free.

    One measured constraint on what may be used as a position: `desc: True`
    silently omits negatively-scored members, and a score of exactly zero
    arrives with no `score` field at all because protobuf's JSON mapping
    omits a zero-valued field. A backfill that placed history at or below
    zero would produce records that exist, are indexed, and are still absent
    from every page - the defect this index exists to remove, reintroduced
    by the migration meant to fix it. History is scored at each record's own
    transaction id (tools/ail_backfill_index.py), and transaction ids start
    at 1, so both are avoided by construction.
    """
    resp = client.post(
        f"{IMMUDB_URL}/api/v2/db/zscan",
        json={
            "set": base64.b64encode(view_set).decode(),
            "desc": True,          # newest first: highest score is the latest commit
            "limit": limit,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    return resp.json().get("entries", [])


def _ledger_decision_count(client: httpx.Client, token: str) -> int:
    """
    How many `tool_call:` keys the ledger holds, ledger-wide.

    GET /api/v2/db/count/{prefix} counts distinct keys under a prefix, not
    versions of them. That is the right count here for a reason that is a
    property of how records are written rather than a coincidence: every
    ledger key carries a fresh uuid (ledger/immudb_ledger.py::log_tool_call
    mints `tool_call:{agent_id}:{uuid4}:{tool_name}`), so no key is ever
    written twice and distinct-key count and record count are the same
    number.

    The prefix is `tool_call:` and not `tool_call`. The trailing colon is
    load-bearing: `tool_call_intent:` records live under their own prefix
    (D16), and `tool_call` without the colon would capture them, because
    `_` sorts inside the prefix just as `:` does. With the colon they are
    excluded, which is what this count wants - an intent record is not a
    decision.

    Cost. This is a walk over the prefix, bounded by the ledger rather than
    by the page, on a request the dashboard polls every 30 seconds per open
    tab. It is sub-linear but unbounded, and it grows with the ledger
    forever. See docs/reports/phase-3c3a.md for the measured figures and
    README's Residual Limits for the standing statement. A maintained
    counter can replace this later without changing the response contract,
    because the contract is the number, not how it was obtained.
    """
    prefix_b64 = base64.b64encode(_TOOL_CALL_PREFIX).decode()
    resp = client.get(
        f"{IMMUDB_URL}/api/v2/db/count/{urllib.parse.quote(prefix_b64, safe='')}",
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    # immudb returns uint64 as a JSON string, per protobuf's JSON mapping.
    return int(resp.json().get("count", 0))


# --- Phase 3c-3d: the page-side fault read ---------------------------------
#
# Three things happen below and they are separate on purpose.
#
#   _fault_writer_key      D41: the one key a fault must be signed by before
#                          this page presents it as another record's standing.
#   _rendered_fault        D41 + D11: decode, classify, check the signature.
#   _faults_in_tx_window   D38 + D42: one paginated, half-open range scan over
#                          the page's own transaction window.
#
# The legacy exact `getall` is unchanged and stays fused with the tombstone
# join (P3c3d-4). It keeps exactly today's keys - no keys are added to it,
# because under D38's nonce a new-shape key is not derivable from a page row
# and cannot go into a `getall` at all. The whole added cost is the range
# read: two round trips per page against one before.

_fault_writer_key_cache = None
_fault_writer_key_loaded = False


def _fault_writer_key():
    """The verifier's writer public key, or None if it could not be loaded.

    Cached, including the failure: the path comes from this process's own
    environment and does not change under it, and retrying a missing file on
    every page would be a per-request stat for a condition an operator has to
    fix anyway. Logged once, at error, because the consequence is that no
    fault renders.
    """
    global _fault_writer_key_cache, _fault_writer_key_loaded
    if _fault_writer_key_loaded:
        return _fault_writer_key_cache
    _fault_writer_key_loaded = True
    try:
        _fault_writer_key_cache = load_verifying_key(_FAULT_WRITER_PUBLIC_KEY)
    except Exception as exc:
        logger.error(
            "Could not load the fault writer's public key from %s (%s: %s). No "
            "ledger fault will be rendered on any audit page until this is "
            "fixed: a fault is presented as authoritative metadata about "
            "another record, and an unchecked one is an assertion by whoever "
            "wrote it.",
            _FAULT_WRITER_PUBLIC_KEY, type(exc).__name__, exc,
        )
        _fault_writer_key_cache = None
    return _fault_writer_key_cache


def _rendered_fault(raw: dict) -> tuple[str, dict] | None:
    """One ledger entry to (committed_key, the object a page row carries).

    None if the entry is not a fault record, or is a fault this service will
    not present.

    **D41: a fault is verified before it is rendered as a record's standing,
    and this is deliberately not what happens to a decision record.** That
    asymmetry is a considered boundary, not an oversight, and is stated here
    rather than left to be inferred. `/audit` renders a decision record
    without checking its writer signature, and at the default `verify=false`
    without checking its inclusion proof either - but a record's own state is
    explicitly reported as `asserted` and is never self-certified (D2,
    ADR-0006), whereas a fault is presented as authoritative metadata about
    *another* record. Extending this check to every row on the default page
    would be the per-record round trip D29 removed, and it must not be
    extended.

    The ceiling, stated with it: every service mounts `./keys:/keys:ro`, so a
    fingerprint names a key and not a component (ADR-0012, corrected in Phase
    3c-3c). This establishes that a fault was signed by the writer key the
    verifier signs faults with, and the D22 mount split is what would make
    that a statement about which process wrote it. Worth having and bounded.
    """
    try:
        value = json.loads(base64.b64decode(raw["value"]).decode())
    except Exception as exc:
        logger.warning("Skipping an unreadable page-side fault entry: %s", exc)
        return None
    if not isinstance(value, dict) or value.get("record_type") != _FAULT_RECORD_TYPE:
        return None

    committed_key = value.get("committed_key")
    if not committed_key or not isinstance(committed_key, str):
        logger.warning(
            "Skipping a fault record that does not name the record it qualifies"
        )
        return None

    verifying_key = _fault_writer_key()
    if verifying_key is None or not verify_record(value, verifying_key):
        logger.error(
            "Refusing to render a ledger fault for %s: its writer signature is "
            "absent or does not check out against %s. It is in the ledger and "
            "readable there; what it is not is this page's account of that "
            "record's standing.",
            committed_key, _FAULT_WRITER_PUBLIC_KEY,
        )
        return None

    return committed_key, {
        "fault_class": value.get("fault_class"),
        "error_class": value.get("error_class"),
        "committed_tx_id": value.get("committed_tx_id"),
        "committed_position": value.get("committed_position"),
        "timestamp": value.get("timestamp"),
        "ledger_key": raw.get("key", ""),
    }


def _merge_fault(faults: dict, committed_key: str, rendered: dict,
                 entry_tx: int, count: int) -> None:
    """Fold one fault into the page's map, newest-first and counted.

    **The `/audit` contract this settles (P3c3d-11).** With more than one
    fault per record now possible, `ledger_fault` could be a list or stay one
    object. It stays one object - the most recent fault, by the ledger's own
    transaction for the fault record itself - with `count` reporting how many
    faults exist for that record. Reasons: the field answers "what is this
    record's standing", which the most recent fault is; a list would put an
    unbounded structure on every row of a 2500-row page for a field that is
    null on almost all of them; and no consumer changes, which was checked
    rather than assumed (`ledger_fault` appears nowhere in `dashboard/` and no
    test asserts `count`). What is lost is naming the older faults from the
    page; they are readable in the ledger under their own keys, and the write
    response that produced each one names it in `fault_record`.

    Ordering between two faults about one record comes from the entry's own
    `tx`, which the read that already ran returns. No timestamp component is
    needed for it and none was added (D38).
    """
    existing = faults.get(committed_key)
    if existing is None:
        faults[committed_key] = {**rendered, "count": count, "_tx": entry_tx}
        return
    existing["count"] += count
    if entry_tx > existing["_tx"]:
        existing.update(rendered)
        existing["_tx"] = entry_tx


def _faults_in_tx_window(client: httpx.Client, token: str,
                         min_tx: int, max_tx: int) -> list[dict]:
    """Every `ledger_fault:` entry whose qualified record committed in
    [min_tx, max_tx], in one paginated range scan.

    D38 + P3c3d-3. The fault key leads with the qualified record's own
    transaction, zero-padded to 20, so the page's own transaction window is a
    key range and the read is bounded by the page rather than by the ledger.
    Filtering back to the page's rows is client-side membership; the range is
    a superset and never a subset.

    **Half-open, and it has to be.** A composite key is longer than its
    transaction component, so an `endKey` of the bare padded `hi` with
    `inclusiveEnd=True` sorts before that transaction's own faults and
    silently drops them - which surfaces only when `hi` is a transaction that
    has a fault, that is, on the last row of the page. Measured: the bare
    inclusive form returned nothing for a single-transaction window that had a
    fault; `hi + 1` exclusive returned it (keyprobe report section 5).

    **D42: the read asserts on what came back.** An unrecognised or misspelled
    parameter is dropped by the REST route without comment, so a bounded read
    degrades to an unbounded one at HTTP 200 with nothing in the response
    saying so. Every returned key is checked against the bound that was
    actually requested for that page.

    Paginated on `seekKey`, the key analogue of the reconciler's `minScore`
    cursor, because `scan` caps a result at 2500 silently: omitting `limit`
    and passing `limit=0` both return 2500 rows with a 200 and no truncation
    flag (keyprobe report section 3).
    """
    seek = _fault_key_tx_bound(min_tx).encode()
    end = _fault_key_tx_bound(max_tx + 1).encode()
    inclusive_seek = True
    entries: list[dict] = []

    while True:
        resp = client.post(
            f"{IMMUDB_URL}/api/v2/db/scan",
            json={
                "seekKey": base64.b64encode(seek).decode(),
                "inclusiveSeek": inclusive_seek,
                "endKey": base64.b64encode(end).decode(),
                "inclusiveEnd": False,
                "limit": _MAX_SCAN_LIMIT,
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        resp.raise_for_status()
        rows = resp.json().get("entries", [])

        for row in rows:
            key = base64.b64decode(row.get("key", ""))
            in_window = (key >= seek if inclusive_seek else key > seek) and key < end
            if not in_window:
                raise BoundedReadFault(
                    "a bounded read returned a key outside the range it asked "
                    f"for: {key.decode('utf-8', 'replace')!r} is not in "
                    f"[{seek.decode()!r}, {end.decode()!r}) with "
                    f"inclusiveSeek={inclusive_seek}. The bound was not applied, "
                    "which is what a dropped or misspelled parameter looks like "
                    "on this route: an unbounded read at HTTP 200."
                )

        entries.extend(rows)
        if len(rows) < _MAX_SCAN_LIMIT:
            return entries
        seek = base64.b64decode(rows[-1]["key"])
        inclusive_seek = False


def _fault_for_row(page_faults: dict, encoded_key: str) -> dict | None:
    """The fault qualifying the record this row renders, or None.

    The row's `ledger_key` is the base64 raw ImmuDB key; a fault names the
    record it qualifies in `committed_key`, written by the verifier as
    `record_key.decode("utf-8", "replace")`. Decoded the same way here so the
    two are the same string for the same bytes.

    `_tx` is the bookkeeping `_merge_fault` orders on and is not part of the
    response contract, so it is dropped here rather than rendered.
    """
    try:
        record_key = base64.b64decode(encoded_key).decode("utf-8", "replace")
    except Exception:
        return None
    fault = page_faults.get(record_key)
    if fault is None:
        return None
    return {k: v for k, v in fault.items() if k != "_tx"}


def _page_faults(client: httpx.Client, token: str, page_txs: list[int],
                 legacy: dict) -> dict:
    """This page's faults, keyed by the record key each one qualifies.

    `legacy` is what the exact `getall` already found under the old
    `ledger_fault:{call_id}` shape (P3c3d-4). The range read is added beside
    it, over the transaction window of the rows this response will render.

    **An empty page has no window.** Zero rows means min and max are
    undefined, and the range read is skipped rather than run with an invented
    bound. A page with rows and no faults is a different case and runs the
    read normally, returning nothing.

    The window comes from the rows the response will render, after the
    `limit + 1` truncation, and not from the fetched set. Both are safe - a
    window taken from the wider set is a superset, and a superset cannot
    exclude a page row - and the rendered set is chosen anyway, because
    "bounded by the page" is the property, and a reader must not have to work
    out which set was meant.
    """
    faults: dict = dict(legacy)
    if not page_txs:
        return faults

    for raw in _faults_in_tx_window(client, token, min(page_txs), max(page_txs)):
        placed = _rendered_fault(raw)
        if placed is None:
            continue
        committed_key, rendered = placed
        # Each new-shape key is written once, so one entry is one fault.
        _merge_fault(faults, committed_key, rendered, int(raw.get("tx", 0)), 1)
    return faults


def _tombstones_and_faults(
    client: httpx.Client, token: str, call_ids: set[str]
) -> tuple[set[str], dict[str, dict]]:
    """
    Which of exactly these call_ids have a content_erasure tombstone, and
    which of this page's records carry a legacy ledger_fault.

    P3c3a-3. This replaces a prefix scan over `content_erasure:` that ran
    under GET /audit's own `limit`. The two have nothing to do with each
    other: a page of 200 decisions and the 200 lexicographically-largest
    tombstones are different sets, so a tombstone for a record on the page
    could be excluded by a bound that was never about it. The record then
    rendered `lost` where it should have read `erased` (an Article 17
    erasure reported as an operational incident), or `present` with its
    payload attached where it should have read `erasure_conflict` (P13-4's
    finding, undone at read time). Phase 1.2 made erasure a positive
    provable fact; a limit on the read side could take that back.

    Exact by construction rather than by tuning. A tombstone's key is
    `content_erasure:{call_id}` (control_plane/main.py::erase_content), and
    call_id is on every entry, so the exact key for every call_id on the
    page is derivable without a search. POST /api/v2/db/getall takes that
    key list and returns the entries that exist, omitting the ones that do
    not - which is precisely the membership test both consumers of this set
    perform. No limit applies to it.

    Classification still goes through `record_type`, not the key prefix
    alone - D11's own discipline, unchanged by where the bytes came from.

    There is no orphan-tombstone direction to lose: nothing reads this set
    for tombstones whose call_id is not on the page.

    **P3c3d-4 (Phase 3c-3d): the fault half of this request is now the legacy
    half, and it keeps exactly today's keys.** D35 asked for
    `ledger_fault:{call_id}` alongside the tombstone key because that shape
    was derivable from a page row exactly the way a tombstone key is. Under
    D38 the new shape carries a nonce and is not derivable from a page row at
    all, so it cannot go into a `getall` and is read by
    `_faults_in_tx_window` instead. Every `ledger_fault:{call_id}` already
    committed keeps that shape permanently, so this request keeps asking for
    exactly the same keys it asks for today - no keys added, still fused with
    the tombstone join, still one round trip.

    The faults it returns are keyed by the record key each one qualifies and
    not by call_id, which is the same change the range read makes and for the
    same reason: an intent record, a decision record and an erasure tombstone
    for one call share a call_id and are three different records, so a fault
    about one of them is not a fault about the others.
    """
    if not call_ids:
        return set(), {}

    ordered = sorted(call_ids)
    resp = client.post(
        f"{IMMUDB_URL}/api/v2/db/getall",
        json={
            "keys": [
                base64.b64encode(key.encode()).decode()
                # sorted() only so the request is reproducible between
                # identical calls; getall imposes no ordering requirement.
                for call_id in ordered
                for key in (f"content_erasure:{call_id}",
                            f"{_FAULT_KEY_PREFIX}{call_id}")
            ]
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()

    tombstoned: set[str] = set()
    faults: dict[str, dict] = {}
    for raw in resp.json().get("entries", []):
        try:
            value = json.loads(base64.b64decode(raw["value"]).decode())
            record_type = value.get("record_type")
            if record_type == "content_erasure":
                if value.get("call_id"):
                    tombstoned.add(value["call_id"])
                continue
            if record_type != _FAULT_RECORD_TYPE:
                continue
            placed = _rendered_fault(raw)
            if placed is None:
                continue
            committed_key, rendered = placed
            # `revision` on the head entry is the number of times this key
            # has been written, and getall already returns it. Under the old
            # shape a second fault about one record was a new version of this
            # key, so revision is the count of faults it holds and the count
            # is free here. Under D38 each fault is its own key written once,
            # which is why the range read below counts entries instead.
            _merge_fault(faults, committed_key, rendered, int(raw.get("tx", 0)),
                         int(raw.get("revision", 1) or 1))
        except Exception as exc:
            logger.warning("Skipping malformed page-side entry: %s", exc)
            continue
    return tombstoned, faults


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
        {"entries": [...], "total": <int>, "has_more": <bool>,
         "verifier_reachable": <bool>}

    **`total` is the ledger's count, not this page's length (P3c3a-1, Phase
    3c-3a).** It is ImmuDB's own count of distinct `tool_call:` keys, taken
    on every request, and it does not change when `limit` does. Before this
    phase it was len(entries), so a complete ledger of 40 and a truncated
    page of 200 were the same number to a caller.

    What `total` does not count, stated because the difference is real: the
    synthesized rows for orphaned write-ahead intents (D16). Those rows are
    in `entries` but live under `tool_call_intent:`, and whether one is
    orphaned is only knowable after the completion join below, so no key
    count can include them. `total` is therefore a count of decision
    records, and `len(entries)` can exceed it on a short ledger holding an
    orphaned intent. It also counts records this response skipped as
    malformed, for the same reason: it counts keys, not successful decodes.

    **`has_more` says whether anything was left behind (P3c3a-2).** Both
    scans fetch one row past the page and report whether that row existed.
    It is not a claim about recency: this page is ordered by ImmuDB key,
    which for `tool_call:` keys means lexicographic agent-id order, not
    time order (TODO.md, and Phase 3c-3b). `has_more` means more records
    exist behind this page, never that more recent ones do. There is
    deliberately no cursor - see the scan block below.

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
                          bypassing the endpoint). P3c3a-3 (Phase 3c-3a):
                          the tombstone lookup is an exact getall on this
                          page's own call_ids, so no `limit` can hide a
                          tombstone from the record it belongs to - it used
                          to be a prefix scan bounded by the page's limit,
                          which could render an erased record "lost" and a
                          conflicted one "present", payload attached
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
    #
    # P3c3a-2 (Phase 3c-3a): each scan below asks for one row more than the
    # page. The extra row is never returned to the caller; only the fact
    # that it existed is, as `has_more`. That is the entire mechanism -
    # fetch limit + 1, return limit, set a flag.
    #
    # Deliberately not a cursor, and the absence is load-bearing rather
    # than an omission. A cursor names a position in an ordering, and the
    # ordering this page is served in is exactly what Phase 3c-3b replaces:
    # `desc: True` sorts by key, tool_call: keys lead with agent_id, so
    # this page arrives in lexicographic agent-id order and not in time
    # order (TODO.md). A cursor minted against that ordering would either
    # break when the ordering changes or freeze the ordering this phase is
    # deliberately leaving open.
    # ImmuDB's scan refuses a limit above 2500 outright ("result size limit
    # exceeded", HTTP 500), measured live against immudb 1.9.5 - see
    # docs/reports/phase-3c3a.md. That ceiling is why `limit + 1` cannot be
    # asked for unconditionally: GET /audit?limit=2500 served a page before
    # this phase, and a bare limit + 1 would have turned it into a 502.
    #
    # Clamping the scan alone would be worse than the bug it avoids - the
    # extra row would vanish and has_more would silently read false at
    # exactly the largest page. So the page shrinks with it: page_limit is
    # the caller's limit everywhere below 2500, and 2499 at or above it,
    # which keeps the +1 row available and keeps has_more exact at every
    # limit. A caller asking for 2500 gets 2499 rows and has_more, not a
    # 2500-row page that lies about what is behind it.
    scan_limit = max(1, min(limit + 1, _MAX_SCAN_LIMIT))
    page_limit = scan_limit - 1
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

            # D36: before anything is selected. A page drawn against a
            # different seam than the writer allocated against is not a
            # degraded page, it is a page whose ordering guarantees do not
            # apply, so it is refused rather than served with a caveat.
            _assert_reserve_agrees(client, token)

            # P3c3b-3 (Phase 3c-3b): the page is selected through the view
            # index, not by walking keys.
            #
            # What it replaces and why. This was `scan` over the `tool_call:`
            # prefix under `desc: True`, which walks keys - and a
            # `tool_call:` key leads with agent_id, so the page returned the
            # lexicographically-largest agent ids and called them recent. A
            # record written seconds ago was absent once the ledger exceeded
            # `limit` (observed at 211 entries during p3c2-defer: the newest
            # transaction was 573 and the page's first row was not it).
            # `scan` has no ordering parameter and `TxScan` is not routed
            # over REST, so no parameter fixes this - the ordering has to
            # come from somewhere the ledger enforces, which is D32's
            # CAS-allocated sequence.
            #
            # `desc: True` here means highest score first, and the score is
            # the commit position, so this is newest first in the ledger's
            # own commit order rather than in an accident of key layout.
            raw_entries = _zscan_view(client, token, _VIEW_DECISION, scan_limit)

            # D16 (Phase 2 completion pass), now through the intent view
            # (P3c3b-7). The write a mediated tool's execution is gated
            # behind (ledger/immudb_ledger.py::log_tool_intent) lands in its
            # own view index, scored from the same shared counter. Joined
            # against the decision entries below by call_id, so an intent
            # with no matching completion record is surfaced instead of
            # silently missing from this response.
            #
            # Why a view and not a bounded walk of `tool_call_intent:`. The
            # join needs a bound either way, because the intent key's uuid is
            # generated fresh at immudb_ledger.py and exists nowhere but in
            # the key, so no per-row lookup can construct it and the orphan
            # direction has to enumerate. Bounding a key walk would bound it
            # by lexicographic agent id, which is the very defect this phase
            # exists to remove - the stated bound would not mean recency. Over
            # the view it does: this is the newest `scan_limit` intents.
            #
            # P3c3a-3 removed what used to be a third scan here, over
            # content_erasure:. The tombstone join is not a search at all -
            # see _tombstoned_call_ids above.
            raw_intents = _zscan_view(client, token, _VIEW_INTENT, scan_limit)

            # D33: the index selects, the record proves. Checked before the
            # page is built, on both views, so a disagreement never reaches a
            # reader as a quietly reordered page.
            # `.get("score", 0.0)`, and float rather than int, both for
            # reasons measured on the wire: protobuf's JSON mapping omits a
            # zero-valued field entirely, so a score of exactly 0 arrives
            # with no "score" key at all, and a position is a float on the
            # wire, so int() would truncate rather than compare - a
            # difference that matters for any score the backfill or an
            # operator placed between two integers.
            _assert_score_order_matches_commit_order(
                [(float(r.get("score", 0.0)), int(r["entry"]["tx"])) for r in raw_entries],
                view="decision",
            )
            _assert_score_order_matches_commit_order(
                [(float(r.get("score", 0.0)), int(r["entry"]["tx"])) for r in raw_intents],
                view="intent",
            )

            # P3c3a-2: truncation is a measured fact about this response,
            # not an inference the caller is left to make from a row count
            # that happens to equal the limit.
            #
            # Both scans put rows into `entries` below - decision records
            # directly, and orphaned intents as synthesized rows (D16) - so
            # a truncation in either one hides rows from this response, and
            # has_more reports either. What it does not report is which:
            # it is one bit about this response, not a description of where
            # the boundary fell. It is also not a claim about recency. This
            # page is not ordered by time (see the cursor note above), so
            # has_more means more records exist behind this page, never
            # that more recent ones do.
            has_more = len(raw_entries) > page_limit or len(raw_intents) > page_limit
            raw_entries = raw_entries[:page_limit]
            raw_intents = raw_intents[:page_limit]

            # P3c3a-1: the ledger's count, asked of the ledger. Before this,
            # `total` was len(entries) - the page's own length - so a full
            # ledger of 40 and a truncated page of 200 were indistinguishable
            # to a caller, and the four dashboard cards labelled with it all
            # described one page while reading as ledger-wide.
            ledger_decision_count = _ledger_decision_count(client, token)

            # D16: intent records keyed by call_id, for the completion join
            # below. A record_type check (not just the key prefix) mirrors
            # D11's own tombstone-classification discipline.
            #
            # P3c3a-3 moved this decode, and the decision decode after it,
            # inside the client block: the tombstone join needs the page's
            # call_ids before any row is built, and it needs this same
            # authenticated client to ask about them.
            intent_by_call_id: dict[str, dict] = {}
            for raw in raw_intents:
                try:
                    # P3c3b-3: a zscan row nests the resolved record under
                    # "entry" and carries its score alongside. The key, value
                    # and tx all come from there.
                    entry = raw["entry"]
                    value = json.loads(base64.b64decode(entry["value"]).decode())
                    if value.get("record_type") != "decision_intent" or not value.get("call_id"):
                        continue
                    intent_by_call_id[value["call_id"]] = {
                        **value,
                        "tx_id": int(entry.get("tx", 0)),
                        "encoded_key": entry.get("key", ""),
                    }
                except Exception as exc:
                    logger.warning("Skipping malformed intent entry: %s", exc)
                    continue

            # P3c3a-3: decoding the decision records is now its own pass,
            # for the same reason. A record that will not decode is skipped
            # with a warning here instead of in the build loop below - same
            # behaviour, one step earlier.
            decoded_entries: list[tuple[str, dict, int]] = []
            for raw in raw_entries:
                try:
                    # P3c3b-3: same shape as the intent rows above. The list
                    # order is zscan's, which is the commit order, and it is
                    # preserved all the way to the response - nothing below
                    # re-sorts.
                    entry = raw["entry"]
                    decoded_entries.append((
                        entry.get("key", ""),
                        json.loads(base64.b64decode(entry["value"]).decode()),
                        int(entry.get("tx", 0)),
                    ))
                except Exception as exc:
                    logger.warning(
                        "Skipping malformed ledger entry (tx=%s): %s", raw.get("tx"), exc
                    )
                    continue

            # P3c3a-3: exactly the call_ids this response will render, and
            # nothing else. Both sources are included because both produce
            # rows carrying a payload_state: the decision records, and the
            # orphaned intents synthesized from intent_by_call_id below.
            page_call_ids = {
                log_entry["call_id"]
                for _key, log_entry, _tx in decoded_entries
                if log_entry.get("call_id")
            }
            page_call_ids |= set(intent_by_call_id)
            tombstoned_call_ids, legacy_faults = _tombstones_and_faults(
                client, token, page_call_ids)

            # P3c3d-3 (Phase 3c-3d): the page read is bounded by the page.
            #
            # The window is over BOTH zscans, decision and intent, and not
            # over the decision page alone: a synthesized orphaned-intent row
            # carries its own transaction, and a window that excluded it would
            # exclude that row's fault. It is taken after the `limit + 1`
            # truncation above, so it describes the rows this response will
            # render rather than the rows that were fetched.
            page_txs = [int(row["entry"].get("tx", 0))
                        for row in (*raw_entries, *raw_intents)
                        if isinstance(row.get("entry"), dict)]
            page_faults = _page_faults(client, token, page_txs, legacy_faults)

    except ReserveMismatch as exc:
        # D36: fail closed, and name the value rather than the symptom. This
        # is a configuration disagreement with the ledger, not an outage, so
        # a caller must not retry into it.
        logger.error("Audit refused: %s", exc)
        raise HTTPException(status_code=503, detail={
            "error": "audit_reserve_mismatch",
            "message": str(exc),
            "page_served": False,
        })
    except BoundedReadFault as exc:
        # D42: a bounded read that came back with something outside its bound
        # did not apply the bound, and this project does not serve a page
        # whose join it cannot trust. Structured like the ordering fault
        # below, and for the same reason: naming the condition beats an
        # "ImmuDB unavailable" that would send an operator to the wrong
        # place.
        logger.error("Audit refused: %s", exc)
        raise HTTPException(status_code=500, detail={
            "error": "bounded_read_fault",
            "message": str(exc),
            "page_served": False,
        })
    except OrderingFault as exc:
        # D33: surfaced, never smoothed over. Reordering to match the
        # transaction ids would hide the one condition this check exists to
        # find, so the page is refused instead of quietly corrected.
        #
        # A chosen response, not an escaping exception: a structured body
        # naming the error, the view, the two positions that disagreed and
        # the transactions they resolve to, saying plainly that no page was
        # served, and stating the scope of the check that raised. P3c3c-7:
        # it does not claim the condition persists, because this check
        # cannot observe that - see _ordering_fault_body.
        logger.error(
            "Audit ordering fault in view %s: position %s -> tx %s, position %s -> tx %s",
            exc.view, exc.higher[0], exc.higher[1], exc.lower[0], exc.lower[1],
        )
        raise HTTPException(status_code=500, detail=_ordering_fault_body(exc))
    except httpx.HTTPStatusError as exc:
        logger.error("ImmuDB HTTP error during audit scan: %s", exc)
        raise HTTPException(status_code=502, detail=f"ImmuDB returned {exc.response.status_code}")
    except Exception as exc:
        logger.error("ImmuDB unavailable for audit scan: %s", exc)
        raise HTTPException(status_code=503, detail=f"ImmuDB unavailable: {exc}")

    # --- Verify each entry via the verifier service; join content by call_id ---
    #
    # D29: "verify each entry" is now what verify=true asks for. The default
    # path joins content and computes payload_state exactly as before and
    # attempts no proof check at all.
    verifier_reachable = _probe_verifier_reachable()
    verifier_up = True
    entries = []
    # P3c3a-3: these were decoded above, so the tombstone join could be
    # built from their call_ids in the same authenticated client block.
    for encoded_key, log_entry, tx_id in decoded_entries:
        try:
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
                # D35 (Phase 3c-3c): the record's durable standing, as
                # opposed to `verification`, which is recomputed on every
                # read and goes back to "verified" the moment a corrupt
                # trust anchor is repaired. A non-null value here says this
                # record's write-time proof did not check out, whatever the
                # verification state beside it now says. Null is the
                # ordinary case and means no fault was ever recorded for
                # this call_id - never "not checked", because the join that
                # produces it is exact.
                # P3c3d-3/P3c3d-8: joined on the record key this fault
                # names, not on call_id. Exact for every row, including a
                # record that carries no call_id at all - such a record does
                # reach a page (measured, keyprobe report section 7) and its
                # fault was never joined onto it under any key shape,
                # including the old one.
                "ledger_fault":    _fault_for_row(page_faults, encoded_key),
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
            logger.warning("Skipping malformed ledger entry (tx=%s): %s", tx_id, exc)
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
                # D35: same field on a synthesized intent row. An intent
                # write can fault exactly the way a decision write can - and
                # since D38 an intent fault and a decision fault for one
                # call_id are two records rather than one, so this row gets
                # the intent's own fault and not the decision's.
                "ledger_fault":    _fault_for_row(page_faults, encoded_key),
                "profile":         intent.get("profile", "unknown"),
                "exclusivity":     None,
                "execution_state": "unknown",
            })
        except Exception as exc:
            logger.warning("Skipping malformed intent entry for call_id=%s: %s", call_id, exc)
            continue

    logger.info(
        "Audit: %d entries of %d ledger records (has_more=%s); verify=%s "
        "verifier_reachable=%s verifier_up=%s "
        "by state: verified=%d failed=%d unverifiable=%d asserted=%d not_found=%d",
        len(entries),
        ledger_decision_count,
        has_more,
        verify,
        verifier_reachable,
        verifier_up,
        sum(1 for e in entries if e["verification"]["state"] == "verified"),
        sum(1 for e in entries if e["verification"]["state"] == "failed"),
        sum(1 for e in entries if e["verification"]["state"] == "unverifiable"),
        sum(1 for e in entries if e["verification"]["state"] == "asserted"),
        sum(1 for e in entries if e["verification"]["state"] == "not_found"),
    )
    # P3c3a-1 / P3c3a-2: `total` is the ledger's count of decision records,
    # not this page's length, and `has_more` says whether anything was left
    # behind. Before this phase the caller got one number that answered
    # neither question and read as if it answered both.
    return {
        "entries": entries,
        "total": ledger_decision_count,
        "has_more": has_more,
        "verifier_reachable": verifier_reachable,
    }


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
