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

D18 (Phase 3a): /verify no longer reduces the check to a boolean and throws
the inputs away. It returns the proof material an independent party needs to
redo the same check offline: the prior trust anchor, the raw VerifiableEntry
protobuf, and the transaction identifiers. The public key is deliberately not
part of that material (see the ProofMaterial docstring and
docs/adr/0010-portable-evidence-bundles.md).

D21 (Phase 3a completion): /verify and /write now require a credential.
Phase 1.3 deferred authenticating this service, reasoning that Phase 2 would
remove the agent's direct network path here (it did) and Phase 3 would
reshape the record sink (it did not - D18 instead made /verify return
exportable proof material). Red-team X5 showed the consequence: an
unauthenticated caller who cannot pass the control plane's own read-key gate
could reach this service directly and assemble an equivalent evidence bundle
by hand. VERIFIER_READ_KEY and VERIFIER_WRITE_KEY are independent secrets
from CONTROL_PLANE_READ_KEY/WRITE_KEY (ADR-0007) - a compromise of one layer
does not hand out the other's. See docs/adr/0011-verifier-authentication.md.

D23 (Phase 3b): two changes, both about which transaction a proof runs to.
GET /state returns ImmuDB's current signed state - the checkpoint an
anchoring job submits to a public transparency log - after verifying its
signature here, which currentRoot's own handler does not do. And POST
/verify now accepts an optional anchor: the proof runs to that checkpoint
instead of to whatever this service's volume happens to hold, because an
anchor internal to this deployment is unfalsifiable to an external party.
A supplied anchor is verified before use and never persisted. See
docs/adr/0012-writer-signing-and-external-anchoring.md.

D35 (Phase 3c-3c): a write that committed is reported as having committed.
Both write routes commit before their proof runs - verifiedSet commits at
service.VerifiableSet and every ErrCorruptedData raise is after that line,
and the ordered route's ExecAll commits before its verifiedGet. Returning
tx_id null for such a write told the caller the opposite of what happened,
and ledger/immudb_ledger.py reads that shape as "the write did not happen".
The response now carries the real transaction, the real position, and
committed: true beside verified: false. The call still denies: fail-closed
on execution is unchanged, and only the description of the ledger changed.

The durable half is the fault record. A page's `unverifiable` is computed
fresh at read time, so repairing the anchor makes the same record read
verified on the next page and nothing says its write-time proof failed.
`ledger_fault:{call_id}` is a record, so it persists. It is written by the
one path in this service that accepts a committed-unverified write, because
that is exactly what it is describing, and the decision path cannot reach
that path: _set_without_verification refuses any record that is not a
ledger_fault, and POST /write refuses a ledger_fault outright.

D36 (Phase 3c-3c): the reserve is bound into the ledger at first allocation,
under KeyMustNotExist in the same ExecAll. Raising AIL_RESERVED_POSITIONS
after allocation used to put committed positions inside the new reserve,
where they are neither reconciled nor order-checked, permanently. Every
reader refuses on disagreement with the bound value.
"""

import base64
import hashlib
import json
import logging
import os
import pathlib
import sys
import threading
from contextlib import asynccontextmanager
from datetime import datetime

import grpc
import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

# provenance/ is copied next to main.py inside this service's image
# (verifier/Dockerfile, which builds from the repo root for this reason since
# D35) and sits at the repo root in a checkout. Both candidates are tried,
# the same way ledger/immudb_ledger.py and anchor_service/main.py resolve it,
# so this module imports identically in the container and under pytest.
for _provenance_parent in (
    os.path.dirname(os.path.abspath(__file__)),
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
):
    if os.path.isdir(os.path.join(_provenance_parent, "provenance")):
        if _provenance_parent not in sys.path:
            sys.path.insert(0, _provenance_parent)
        break

from provenance.record_signature import load_signing_key, sign_record  # noqa: E402

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

# D21: two independent keys, not one shared key - the same split ADR-0007
# established for the control plane, applied here for the same reason. READ
# authorizes only POST /verify; WRITE authorizes only POST /write. Set both
# in the environment (docker-compose .env); an absent key disables the route
# it gates with a 503 response, matching control_plane/main.py's
# _require_read_key/_require_write_key fail-closed behavior exactly.
_VERIFIER_READ_KEY  = os.getenv("VERIFIER_READ_KEY", "")
_VERIFIER_WRITE_KEY = os.getenv("VERIFIER_WRITE_KEY", "")

# D22, extended by D35 (Phase 3c-3c): this service's own writer key. The
# fault record is a ledger record like any other, and D22's rule is one
# dedicated long-lived key per writer - two writers became three when this
# service acquired a record of its own to write. Not the ImmuDB signing key
# and not either existing writer key: a bundle's writer_key_fingerprint has
# to name which service wrote the record, and one writer has to be
# deny-listable without revoking the others.
#
# Fail-closed, exactly like the decision service's copy: no key means the
# fault record cannot be written, which is loud (see _write_fault_record)
# rather than silent. tools/ail_verify_bundle.py refuses a record carrying
# no writer signature outright, so an unsigned fault record would be a
# record this project's own checker will not check.
_WRITER_SIGNING_KEY_PATH = os.getenv("AIL_WRITER_SIGNING_KEY", "")

_writer_keys = None


def get_writer_keys():
    """Load (signing key, verifying key) once, or raise."""
    global _writer_keys
    if _writer_keys is None:
        if not _WRITER_SIGNING_KEY_PATH:
            raise RuntimeError(
                "AIL_WRITER_SIGNING_KEY is not set; this service cannot sign the "
                "fault records it writes (D22, D35). Run 'make keygen' and mount "
                "keys/writer-verifier.key."
            )
        if not os.path.exists(_WRITER_SIGNING_KEY_PATH):
            raise RuntimeError(
                f"AIL_WRITER_SIGNING_KEY points at {_WRITER_SIGNING_KEY_PATH}, "
                "which does not exist; refusing to write a fault record nothing "
                "can attribute."
            )
        _writer_keys = load_signing_key(_WRITER_SIGNING_KEY_PATH)
        logger.info("Writer signing key loaded from %s", _WRITER_SIGNING_KEY_PATH)
    return _writer_keys


def _require_read_key(x_api_key: str = Header(..., alias="X-API-Key")) -> None:
    """FastAPI dependency: enforces X-API-Key (read-scoped) on POST /verify."""
    if not _VERIFIER_READ_KEY:
        raise HTTPException(
            status_code=503,
            detail="Read-key authentication not configured (VERIFIER_READ_KEY missing)",
        )
    if x_api_key != _VERIFIER_READ_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")


def _require_write_key(x_api_key: str = Header(..., alias="X-API-Key")) -> None:
    """FastAPI dependency: enforces X-API-Key (write-scoped) on POST /write."""
    if not _VERIFIER_WRITE_KEY:
        raise HTTPException(
            status_code=503,
            detail="Write-key authentication not configured (VERIFIER_WRITE_KEY missing)",
        )
    if x_api_key != _VERIFIER_WRITE_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")

# D18: the wire format of the proof material this service exports. Bumped
# only when a field is added, removed, or reinterpreted, so an offline
# checker can refuse material it does not understand rather than guess.
#
# Bumped to /2 by D23 (Phase 3b). No field was added or removed, but
# source_state was reinterpreted: in /1 it was always whatever this
# service's PersistentRootService happened to hold at export time, which is
# an internal implementation detail of this deployment and meaningless to an
# external party. In /2 it is either that, or - when the caller supplies an
# anchor - the externally anchored checkpoint the proof actually runs to.
# A /1 checker reading a /2 bundle would draw the wrong conclusion about
# what the proof is anchored at, which is exactly the case this version
# string exists to refuse.
PROOF_MATERIAL_FORMAT = "ail-proof-material/2"

# Pinned in verifier/requirements.txt. Recorded in the exported material
# because the material is only meaningful to a checker running the same
# SDK's verification code (D20), and immudb-py's proof handling is not
# covered by any stability guarantee across versions.
SDK_IDENTIFIER = "immudb-py==1.5.0"

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


_pubkey_fingerprint_cache: str | None = None


def signing_key_fingerprint() -> str | None:
    """
    D18: name the ECDSA public key this verifier checks state signatures
    against, without exporting the key itself.

    The fingerprint is SHA-256 over the key's DER SubjectPublicKeyInfo
    encoding, not over the PEM text, so it is stable across line-ending and
    whitespace differences in the PEM file (which matters as soon as a
    bundle crosses an operating system). hashlib is used here only to derive
    an identifier; nothing in the verification path is hand-written - see
    docs/adr/0010-portable-evidence-bundles.md.

    Returns None when no signing key is configured, which is the honest
    answer: such a deployment produces material no checker can complete a
    signature check against.
    """
    global _pubkey_fingerprint_cache
    if _pubkey_fingerprint_cache is not None:
        return _pubkey_fingerprint_cache
    if not PUBKEY_FILE or not pathlib.Path(PUBKEY_FILE).exists():
        return None

    import ecdsa

    with open(PUBKEY_FILE) as f:
        vk = ecdsa.VerifyingKey.from_pem(f.read())
    _pubkey_fingerprint_cache = "sha256:" + hashlib.sha256(vk.to_der()).hexdigest()
    return _pubkey_fingerprint_cache


class _CapturedEntryStub:
    """
    D20: the SDK's own verifiedGet.call() takes a gRPC stub only to make one
    RPC; every check after that line is pure computation on the response.
    Handing it this two-line stand-in, holding a VerifiableEntry already
    fetched over the real stub, means the material this service exports is
    provably the exact material its own verdict was computed from, rather
    than a second fetch that might differ.

    tools/ail_verify_bundle.py uses the same mechanism with no live stub in
    the process at all. The two are deliberately separate copies: the
    offline checker must stay runnable with nothing but immudb-py installed,
    and a shared import would tie it to this service's image.
    """

    def __init__(self, ventry):
        self._ventry = ventry

    def VerifiableGet(self, req):
        return self._ventry


class _PinnedRootService:
    """
    D23/P3b-1: drive the SDK's own verification from an externally anchored
    checkpoint instead of from this service's persisted state.

    docs/reports/spike-consistency-proof.md is the whole basis for this
    class, including its limits. `verifiedGet.call()` derives its proof
    source entirely from `rs.get()`, and `rs` is a caller-supplied object -
    probe 6 in that spike enumerated every public ImmudbClient method and
    found none that takes a source or proveSinceTx argument. So this is a
    seam, not an API, and an immudb-py upgrade past the pinned 1.5.0 can
    move it. tests/test_anchored_export.py asserts the seam's shape against
    the installed SDK so an upgrade fails a test rather than silently
    anchoring at the wrong transaction.

    set() records rather than persists, deliberately: verifying a record
    against an anchor must not advance, consume, or otherwise mutate this
    service's real trust anchor. Probe 7a established that the anchor is
    unchanged in this direction anyway (the older transaction is always the
    proof source, so the retained state would be the anchor itself), but
    that is a property of the pair rather than a guarantee about every pair
    a caller could ask for, so it is enforced here as well.
    """

    def __init__(self, state):
        self._state = state
        self.new_state = None

    def init(self):
        return self._state

    def get(self):
        return self._state

    def set(self, new_state):
        self.new_state = new_state


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
    """D35: three states, not two.

    verified true                      the write committed and its proofs check out
    verified false, committed true     the write committed; its proof did not check
    verified false, committed false    the write did not happen

    The caller's rule is unchanged and still keyed on `verified`: anything
    but true raises in ledger/immudb_ledger.py and the decision service
    denies the call. `committed` is what stops the middle state being
    reported as the bottom one, which is the opposite of what happened.
    """
    tx_id: int | None
    verified: bool
    committed: bool = False
    error_class: str | None = None
    # The `ledger_fault:` key qualifying this record's standing, when one
    # was written. Null when nothing needed qualifying, and null with
    # fault_record_error set when the qualification itself could not be
    # written - never silently absent.
    fault_record: str | None = None
    fault_record_error: str | None = None
    detail: str | None = None


class OrderedWriteRequest(BaseModel):
    """D32 (Phase 3c-3b): a write that also takes a position in a view index.

    `view` names which view index this record belongs in - the shared
    sequence is allocated once and every view scores from it, so positions
    are comparable across views and a later view needs no second backfill.
    """
    key: str    # base64-encoded raw key bytes
    value: str  # base64-encoded raw value bytes
    view: str   # logical view name, e.g. "decision" or "intent"


class OrderedWriteResponse(BaseModel):
    """Same three states as WriteResponse, plus the allocated position.

    On a committed-unverified write the position is reported too: the
    ExecAll that committed the record committed the counter advance and the
    index entry with it, so a response withholding `seq` would describe a
    record as unpositioned while the index holds its position.
    """
    tx_id: int | None
    seq: int | None
    verified: bool
    committed: bool = False
    attempts: int = 0
    error_class: str | None = None
    fault_record: str | None = None
    fault_record_error: str | None = None
    detail: str | None = None


class AnchorState(BaseModel):
    """
    D23/P3b-1: the externally anchored checkpoint a caller wants a record
    proven against, rather than whatever this service happens to hold.

    Exactly the four fields immudb's own State carries, minus publicKey -
    which is omitted for the same reason SourceState below omits it: the
    spike established verifiedGet.call() never reads it, so accepting one
    would be accepting a key-shaped field that decides nothing.

    This is untrusted input. Before it is used as a proof source its ECDSA
    signature is checked against the server's public key this service holds
    on its own volume; an anchor that does not verify is refused, never used
    (see verify() below). A caller cannot pin the proof to a state ImmuDB
    never signed.
    """
    db: str
    tx_id: int
    tx_hash: str            # base64 of the 32-byte state hash
    signature: str | None   # base64 of the state's own DER ECDSA signature


class VerifyRequest(BaseModel):
    key: str    # base64-encoded raw key bytes
    # D23/P3b-1: absent means "anchor at this service's persisted state",
    # which is what Phase 3a always did and remains correct for a record no
    # anchored checkpoint covers yet.
    anchor: AnchorState | None = None


class SourceState(BaseModel):
    """
    The trust anchor held *before* this read: what PersistentRootService had
    persisted, and what immudb-py's verifiedGet.call() reads via rs.get().

    Carries db, tx_id, tx_hash and the anchor's own ECDSA signature.

    It deliberately does not carry the State's publicKey field. The spike
    (docs/reports/spike-offline-verify.md, item 4[d]) established that
    verifiedGet.call() never reads state.publicKey - flipping a byte in it
    changes nothing - so shipping it would add a key-shaped field that no
    check consults, next to material that is supposed to be checked against
    an independently held key. Reconstructing the State with publicKey=b""
    verifies identically; see tests/test_evidence_bundle.py.
    """
    db: str
    tx_id: int
    tx_hash: str            # base64 of the 32-byte anchor hash
    signature: str | None   # base64 of the anchor's own DER ECDSA signature


class ProofMaterial(BaseModel):
    """
    D18: everything an offline checker needs to redo this verification, and
    nothing that would let the material certify itself.

    The field list is derived from what the spike's export_material.py
    actually had to capture for offline verification to succeed
    (docs/reports/spike-offline-verify.md, item 2), not from a guess:

      1. the prior trust anchor              -> source_state
      2. the raw VerifiableEntry response    -> verifiable_entry
      3. the ECDSA public key                -> NOT here, named by
                                                signing_key_fingerprint
      4. the raw key bytes being looked up   -> the caller already supplied
                                                these in the request, and
                                                the bundle records them

    prove_since_tx is the value verifiedGet.call() puts in its request
    (state.txId), recorded so the request can be reconstructed exactly.
    entry_tx_id is the transaction the entry itself lives in.
    """
    format: str = PROOF_MATERIAL_FORMAT
    sdk: str = SDK_IDENTIFIER
    source_state: SourceState
    verifiable_entry: str       # base64 of VerifiableEntry.SerializeToString()
    prove_since_tx: int
    entry_tx_id: int
    signing_key_fingerprint: str | None


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
    #
    # D23/P3b-1 adds two more, both about the anchor a caller supplied
    # rather than about the record. They are additions to this vocabulary,
    # never substitutes: nothing that used to report consistency_failure or
    # signature_failure now reports one of these.
    #   "anchor_signature_failure" - the supplied anchor is not a state this
    #       ImmuDB signed, so it was refused before any proof ran. Distinct
    #       from signature_failure, which is the server's signature over the
    #       state the SDK derived from a proof that did run.
    #   "anchor_precedes_record"   - the anchor is older than the record. A
    #       checkpoint published before a record existed cannot corroborate
    #       it, so this is refused rather than answered with a proof running
    #       the other way. Not a statement that the record is bad; the
    #       caller's next move is to export it as unanchored.
    error_class: str | None = None
    # D18 (Phase 3a): the raw material this verdict was computed from, so the
    # check is reproducible by someone who does not have this service, this
    # ImmuDB, or any network. Present only when verified is True - there is
    # no such thing as material proving a failed check, and exporting the
    # inputs of a rejected proof would invite treating a bundle as evidence
    # of something that did not verify.
    proof_material: ProofMaterial | None = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# D35 (Phase 3c-3c): the fault record.
# ---------------------------------------------------------------------------
#
# What it is for. Both write routes commit before their proof runs, so a
# proof failure can no longer prevent the write. The response now says so
# (committed: true), but a response is not durable, and the page's
# `unverifiable` is not the record's standing either - control_plane's
# _verify_one_key computes it fresh at read time, so repairing the anchor
# makes the same record read `verified` on the next page with nothing
# anywhere recording that its write-time proof failed. Demonstrated live in
# docs/reports/phase-3c3c.md.
#
# So the durable qualification is a record. Key `ledger_fault:{call_id}`,
# joined by the same exact `getall` the tombstone join uses (P3c3a-3), and
# classified by `record_type` rather than by key shape - D11's discipline,
# unchanged. call_id is the only thing on every page row from which an exact
# key is derivable, which is what keeps this a join rather than a scan.
#
# A second fault for the same call_id is a new version of the same key,
# written by an unconditional set. Measured on this project's own REST route
# (docs/reports/phase-3c3c-probe.md): a prior version stays readable five
# ways, `getall` already returns `revision` on the head entry so a count of
# faults costs no extra call, and `scan` over a prefix returns one row per
# distinct key so versions do not inflate anything already walking it. An
# unconditional set appends rather than replaces, so there is no read to race
# and no earlier fault is lost.
FAULT_RECORD_TYPE = "ledger_fault"
FAULT_KEY_PREFIX  = "ledger_fault:"


def _set_without_verification(client, key: bytes, value: bytes, record: dict) -> int:
    """An unconditional `set`, with no proof check. Returns the transaction.

    The one write in this system whose success does not require write-time
    proof, which is why it is stated in README's Residual Limits rather than
    left to be discovered.

    **The decision path is structurally unable to reach it.** This function
    refuses any record that is not a fault record, so the only caller that
    gets through is _write_fault_record below; POST /write refuses a
    ledger_fault arriving from outside; and no parameter on either route
    selects this path. tests/test_ledger_faults.py asserts both halves.

    The condition that produces a fault is precisely the condition that
    breaks every proof, so requiring a verified write here would mean the
    qualification can never be recorded exactly when it is needed.
    """
    if record.get("record_type") != FAULT_RECORD_TYPE:
        raise RuntimeError(
            "refusing an unverified write for a "
            f"{record.get('record_type')!r} record: this path exists only for "
            f"{FAULT_RECORD_TYPE!r}, which describes a failed proof and therefore "
            "cannot itself be proven"
        )
    resp = client.set(key, value)
    return int(resp.id)


def _fault_key(record_value: bytes, record_key: bytes) -> str:
    """`ledger_fault:{call_id}`, and a named fallback where no call_id exists.

    Every row `/audit` renders carries a call_id, so the join is exact for
    everything a reader can see. A record with no call_id never reaches a
    page, so its fault is keyed by a digest of the record key instead of
    being dropped - an unjoinable fault is still evidence, and losing one is
    not the alternative to inventing a second join.
    """
    try:
        value = json.loads(record_value.decode())
        call_id = value.get("call_id") if isinstance(value, dict) else None
    except Exception:
        call_id = None
    if call_id:
        return f"{FAULT_KEY_PREFIX}{call_id}"
    digest = hashlib.sha256(record_key).hexdigest()[:32]
    return f"{FAULT_KEY_PREFIX}key:{digest}"


def _write_fault_record(client, *, record_key: bytes, record_value: bytes,
                        tx_id: int, seq: int | None, view: str | None,
                        error_class: str, detail: str) -> tuple[str | None, str | None]:
    """Record that a committed write's proof did not check out.

    Returns (fault_key, error). Exactly one of the two is ever non-None.

    A failure here fails loudly - logged at error, and reported in the write
    response as fault_record_error. The deny already stands either way, so
    this can make no call safer or less safe; what a silent absence would do
    is leave a committed record unqualified with nothing recording why, which
    is the condition this record exists to remove.
    """
    key = _fault_key(record_value, record_key)
    fault = {
        "record_type": FAULT_RECORD_TYPE,
        "fault_class": "write_verification_failed",
        "call_id": key[len(FAULT_KEY_PREFIX):],
        # The committed record this fault qualifies, named as a key rather
        # than described, so a reader joins instead of searching.
        "committed_key": record_key.decode("utf-8", "replace"),
        "committed_tx_id": tx_id,
        "committed_position": seq,
        "view": view,
        "error_class": error_class,
        "detail": detail,
        "timestamp": datetime.utcnow().isoformat(),
        "writer": "verifier",
        "remediation": (
            "The record committed and its write-time proof did not check out. "
            "It is in the ledger and on the ordered page, and its verification "
            "state at read time is computed fresh, so it may read verified once "
            "the trust anchor is repaired - which is why this record exists. Run "
            "the sequence reconciliation in anchor_service to find what else is "
            "affected, and see docs/adr/0014-ordered-audit-view-index.md."
        ),
    }
    try:
        signing_key, verifying_key = get_writer_keys()
        signed = sign_record(fault, signing_key, verifying_key)
        raw = json.dumps(signed, separators=(",", ":")).encode()
        fault_tx = _set_without_verification(client, key.encode(), raw, signed)
    except Exception as exc:
        logger.error(
            "FAULT RECORD NOT WRITTEN for committed tx=%s key=%s: %s: %s. The record "
            "stands in the ledger with nothing recording why its proof failed.",
            tx_id, record_key.decode("utf-8", "replace"), type(exc).__name__, exc,
        )
        return None, f"{type(exc).__name__}: {exc}"
    logger.error(
        "Committed write failed verification: tx=%s seq=%s error_class=%s; fault "
        "recorded at %s (tx=%s)",
        tx_id, seq, error_class, key, fault_tx,
    )
    return key, None


# P3c3c-2 (Phase 3c-3c): what POST /write refuses, and why the route does it.
#
# A decision record reaching the plain route commits with no position, and
# `/audit` selects through the view index, so such a record is absent from
# every page permanently. This used to be prevented by convention plus a
# static parse of two files; the red team defeated the parse by holding the
# route in a variable, and a convention is not a control. The route enforces
# it itself now, and the parse survives as a second line rather than as the
# criterion.
#
# Two independent conditions, either of which refuses, because each covers
# the other's blind spot: `record_type` is the classification discipline D11
# established and it sees a decision record written under any key, while the
# key prefix sees a record whose `record_type` was omitted or renamed. A
# ledger_fault is refused for a different reason - it is written by this
# service about this service's own failed proof, and one arriving from
# outside would be an unverified assertion about another record's standing.
_REFUSED_ON_PLAIN_WRITE = frozenset({"decision", "decision_intent", FAULT_RECORD_TYPE})
_REFUSED_KEY_PREFIXES = (b"tool_call:", b"tool_call_intent:", FAULT_KEY_PREFIX.encode())


def _refuse_reason_for_plain_write(key: bytes, value: bytes) -> str | None:
    """Why this record may not take POST /write, or None if it may."""
    for prefix in _REFUSED_KEY_PREFIXES:
        if key.startswith(prefix):
            return (
                f"key prefix {prefix.decode()!r} does not belong on the plain write "
                "route; a record under it must take POST /write-ordered, which "
                "allocates the commit position /audit pages through"
            )
    try:
        parsed = json.loads(value.decode())
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None
    record_type = parsed.get("record_type")
    if record_type == FAULT_RECORD_TYPE:
        return (
            f"a {FAULT_RECORD_TYPE!r} record is written by this service about its own "
            "failed proof and is never accepted from a caller"
        )
    if record_type in _REFUSED_ON_PLAIN_WRITE:
        return (
            f"a {record_type!r} record must take POST /write-ordered: the plain route "
            "allocates no commit position, and a record with no position is absent "
            "from every ordered audit page"
        )
    return None


@app.post("/write", response_model=WriteResponse)
def write(payload: WriteRequest, _: None = Depends(_require_write_key)):
    """
    Write a key-value pair via verifiedSet.

    The SDK verifies the inclusion proof and the consistency proof from the
    persisted state to the new transaction before updating its local state.
    Returns verified: false (never raises HTTP 500) so callers can fail closed
    without catching exceptions.

    D21: gated by _require_write_key. The one production caller left is
    control_plane/main.py::_write_tombstone (the erasure tombstone); the
    decision and intent writes took the ordered route at D32 and are now
    refused here outright (P3c3c-2).

    D35: `verifiedSet` commits at service.VerifiableSet(rawRequest) and every
    ErrCorruptedData raise is after that line, so this route has the same
    committed-then-proven shape the ordered route has. A proof failure here
    returns the real transaction with committed: true, and a fault record
    qualifying it - not tx_id null, which reads as "the write did not
    happen" and, on the tombstone path, puts the erasure bookkeeping and the
    ledger into exactly the disagreement D11's states describe.
    """
    from ecdsa.keys import BadSignatureError
    from immudb.exceptions import ErrCorruptedData

    key   = base64.b64decode(payload.key)
    value = base64.b64decode(payload.value)

    # P3c3c-2: refused at the route, before anything commits. A 400 rather
    # than verified: false, because this is a caller asking for the wrong
    # thing rather than a ledger that failed - and because verified: false
    # is now a shape that can mean "committed", which this never is.
    refusal = _refuse_reason_for_plain_write(key, value)
    if refusal is not None:
        logger.error("Refused a plain write: %s", refusal)
        raise HTTPException(status_code=400, detail=refusal)

    try:
        client = _get_client()
    except Exception as exc:
        logger.error("verifiedSet error: %s", exc)
        return WriteResponse(tx_id=None, verified=False, committed=False, detail=str(exc))

    try:
        resp   = client.verifiedSet(key, value)
        state  = client.currentState()
        logger.info("Verified write: tx=%d state_id=%d", resp.id, state.txId)
        return WriteResponse(tx_id=resp.id, verified=True, committed=True)
    except (ErrCorruptedData, BadSignatureError) as exc:
        error_class = ("consistency_failure" if isinstance(exc, ErrCorruptedData)
                       else "signature_failure")
        # The commit already happened; the SDK raised on the proof it ran
        # afterwards. Ask the ledger which transaction holds this key rather
        # than inferring one - the exception carries no transaction id, and
        # a response that guessed would be the same kind of claim this item
        # exists to remove.
        tx_id = _committed_tx_for(client, key)
        if tx_id is None:
            # Nothing under this key: the write genuinely did not land, and
            # the bottom state is the honest one.
            logger.error("verifiedSet: proof failed and no record is present for the key")
            return WriteResponse(
                tx_id=None, verified=False, committed=False, error_class=error_class,
                detail="proof verification failed; no record was committed",
            )
        fault_key, fault_error = _write_fault_record(
            client, record_key=key, record_value=value, tx_id=tx_id, seq=None,
            view=None, error_class=error_class, detail="proof verification failed",
        )
        return WriteResponse(
            tx_id=tx_id, verified=False, committed=True, error_class=error_class,
            fault_record=fault_key, fault_record_error=fault_error,
            detail="proof verification failed; the record committed at "
                   f"transaction {tx_id}",
        )
    except Exception as exc:
        logger.error("verifiedSet error: %s", exc)
        return WriteResponse(tx_id=None, verified=False, committed=False, detail=str(exc))


def _committed_tx_for(client, key: bytes) -> int | None:
    """The transaction holding `key`, or None if the ledger holds nothing.

    Read with a plain `get`, deliberately: this is called when a proof has
    just failed, so a verified read would fail the same way and answer
    nothing. What it establishes is narrow and stated as such - a record is
    present under this key at this transaction. It is the same question the
    caller would ask, asked here so the caller does not have to guess from a
    response that withheld it.
    """
    try:
        got = client.get(key)
    except Exception as exc:
        logger.error("Could not read back a key whose proof failed: %s", exc)
        return None
    if got is None:
        return None
    return int(got.tx)


# ---------------------------------------------------------------------------
# D32 (Phase 3c-3b): the ordered write path.
# ---------------------------------------------------------------------------
#
# The problem this exists for. `/audit` used to page the ledger with a key
# walk under `desc: true`, and a `tool_call:` key leads with agent_id, so the
# page returned the lexicographically-largest agent ids and called them
# recent. A record written seconds ago could be absent once the ledger
# exceeded `limit`. ImmuDB's `scan` has no ordering parameter, `TxScan` is
# not routed over REST (verified live, Phase 3c-3b probe), and no key this
# project writes is temporal or monotonic, so no parameter produces a
# time-ordered page. `zscan` is routed and orders by a caller-supplied score.
#
# Why the score is neither a clock nor a per-writer counter. A timestamp is
# globally comparable and wrong under skew. A per-writer sequence is not an
# ordering at all: `p3c3-scoring` had four writers each claim positions 1 to
# 15, and signing that only proves the writer *said* position 3, not that
# position 3 is where the record belongs. The score here is allocated from a
# single counter under a compare-and-set the ledger itself enforces, so a
# writer that read a stale counter is rejected outright and any position it
# does commit is the unique next one from the state it read.
#
# What one call commits. A single ExecAll carries three operations - the
# record, the advanced counter, and the zAdd into the view index - gated by
# a KeyNotModifiedAfterTX precondition on the counter. All three land in one
# transaction or none do (nentries=3, one tx id, verified live), which is
# what makes "a record committed without its index entry" unrepresentable
# rather than merely unlikely.
#
# Why the SDK's own execAll() is not used. immudb-py 1.5.0's execAll wrapper
# builds ExecAllRequest(Operations=..., noWait=...) and has no preconditions
# parameter at all (immudb/handler/execAll.py, read live), so the whole
# mechanism is unreachable through it. This calls the generated gRPC stub
# with the SDK's own protobuf types instead. That is a narrower thing than
# ADR-001's warning about hand-rolling `Alh()`: no verification code is
# reimplemented here, only a request the wrapper cannot express.
#
# Verification. There is no verifiedExecAll in immudb-py 1.5.0, so the proof
# check `verifiedSet` used to run inside the write call is issued separately
# here, as a verifiedGet on the record key immediately after the commit. It
# runs the same inclusion and consistency proofs through the same SDK code,
# and it raises to DENY on the same conditions - the guarantee moved from
# inside the write call to just after it, and did not weaken. Confirmed live
# that a verifiedGet on an ExecAll-written key succeeds and that the
# consistency proof keeps advancing across ExecAll transactions.

# Outside `tool_call:`, `tool_call_intent:` and `content_erasure:` on
# purpose: those three prefixes are counted or scanned by
# control_plane/main.py, and a counter living inside one of them would land
# in Phase 3c-3a's ledger count as though it were a decision.
SEQUENCE_KEY = b"ail_seq:commit"

# The seam between backfilled history and live traffic, made explicit.
#
# Positions 1 through RESERVED_POSITIONS belong to history: a record written
# before the index existed is scored at its own `entry.tx`, which is the
# ledger's own commit order for it and needs no reconstruction. The live
# counter is seeded above the reserve, so its first allocation is
# RESERVED_POSITIONS + 1 and every live position is strictly greater than
# every historical one.
#
# What that buys over the alternative. Scoring history by its rank within one
# backfill pass is monotone only within that pass: a second pass over records
# written since would compute a different rank against a different
# denominator and interleave with the first. A score
# that *is* the transaction id is stable no matter how many passes run, in
# what order, or how much history each one finds - so the seam is monotone
# across the boundary permanently, and no cursor is needed to describe where
# history ends and live traffic begins. The boundary is a number.
#
# The reserve has to exceed every historical transaction id or history would
# collide with live positions. tools/ail_backfill_index.py refuses to run
# rather than guess if it ever finds a record above the reserve.
#
# D36 (Phase 3c-3c): validated where it is read, in all four readers. C4 was
# not refuted, but an unvalidated reserve is the one input that puts every
# position at or below zero, and `zscan` under `desc: true` silently omits a
# negatively-scored member while a score of exactly zero arrives with no
# score field at all. A zero or negative reserve was accepted silently.
def validate_reserve(raw: str, source: str = "AIL_RESERVED_POSITIONS") -> int:
    """A reserve is a positive integer. Anything else refuses at load."""
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        raise RuntimeError(
            f"{source} must be an integer; got {raw!r}. Positions are scores in a "
            "zset and the seam between history and live traffic is this number."
        )
    if value < 1:
        raise RuntimeError(
            f"{source} must be a positive integer; got {value}. At or below zero "
            "every allocated position would be at or below zero too, and zscan "
            "under desc omits negatively-scored members and reports a zero score "
            "as no score at all - the records would be indexed and still absent "
            "from every page."
        )
    return value


RESERVED_POSITIONS = validate_reserve(os.getenv("AIL_RESERVED_POSITIONS", "1000000000"))

# D36: the reserve, bound into the ledger at first allocation.
#
# What it fixes. Raising AIL_RESERVED_POSITIONS after allocation put
# committed CAS positions inside the new reserve, where they are neither
# reconciled (anchor_service counts only positions above the reserve) nor
# order-checked (D33 is scoped to the same range), permanently. Nothing
# distinguished "raised after allocation" from "always was this value", and
# the backfill's own refusal message instructed exactly that raise.
#
# Why binding rather than pairwise agreement checks between the services.
# One mechanism gives both properties: the value is immutable because it is
# written under KeyMustNotExist in the same ExecAll as the first allocation,
# and every reader gets the runtime agreement check for free by comparing
# its own configured value against the bound one. Three services probing
# each other would give the second property and not the first.
#
# The key is outside every counted prefix, the same rule the counter follows
# and for the same reason: inside `tool_call:` it would land in Phase
# 3c-3a's ledger count as though it were a decision.
RESERVE_KEY = b"ail_seq:reserve"


class ReserveMismatch(RuntimeError):
    """The ledger's bound reserve is not the reserve this service is configured
    with. Fail closed: a writer allocating against one seam and a reader
    paging against another is the condition D36 exists to make impossible."""


# Cached so reading it costs no round trip per write. Re-read at cold start
# and after any rejection - the same two moments the counter cache is
# refreshed, for the same reason.
_reserve_cache: int | None = None


def _read_bound_reserve(client) -> int | None:
    """The reserve bound into this ledger, or None if none is bound yet."""
    global _reserve_cache
    if _reserve_cache is not None:
        return _reserve_cache
    got = client.get(RESERVE_KEY)
    if got is None:
        return None
    _reserve_cache = validate_reserve(got.value.decode(), source="the bound reserve")
    return _reserve_cache

# Versioned, and named for the view rather than for the ledger, because the
# index is a view over the ledger and not the ledger's own ordering. A
# second view (incident-first, say) is a second zset scored from this same
# counter, which is why it would need no second backfill.
_VIEW_SETS = {
    "decision": b"ail_view:decision:v1",
    "intent":   b"ail_view:intent:v1",
}

# D34: the retry budget is an availability parameter, not a correctness one.
# An exhausted budget is a failed ledger write, which the existing rule
# turns into a denied call - so raising this trades latency for availability
# and lowering it can deny traffic. `p3c3-scoring` saw zero writers give up
# at 8 concurrent with a cap of 300.
MAX_CAS_ATTEMPTS = int(os.getenv("AIL_SEQUENCE_MAX_ATTEMPTS", "300"))

# D34: the writer caches (seq, tx) from its own last successful commit and
# reads the counter only at cold start or after a rejection. Reading it
# every write cost about 30 percent in `p3c3-scoring`; caching cost about 6.
_seq_cache: tuple[int, int] | None = None
_seq_lock = threading.Lock()

# D34's two write-path costs, both reachable. Default on, which is the
# cheaper one; setting this to 0 makes every write read the counter first.
# It exists so the difference D34 states is a figure this deployment can
# reproduce rather than one taken on trust, and so an operator debugging a
# suspected cache-coherence problem can turn the cache off without a
# rebuild. Correctness does not depend on it either way: the CAS rejects a
# stale read whether it came from the cache or from the ledger.
_SEQ_CACHE_ENABLED = os.getenv("AIL_SEQUENCE_CACHE", "1") != "0"


def _read_counter(client):
    """The counter's value and the transaction it was last modified at.

    Both halves are needed: the value is the last allocated position, and
    the tx is what the KeyNotModifiedAfterTX precondition names. Returns
    None when the counter has never been written, which is the cold-start
    case the KeyMustNotExist precondition covers.
    """
    got = client.get(SEQUENCE_KEY)
    if got is None:
        return None
    return int(got.value.decode()), int(got.tx)


def _ordered_commit(client, key: bytes, value: bytes, view_set: bytes):
    """One CAS-gated ExecAll. Returns (tx_id, seq, attempts).

    Raises after MAX_CAS_ATTEMPTS rejections, which the caller turns into a
    failed write and the middleware turns into a denied call.
    """
    from immudb.grpc import schema_pb2 as schema

    global _seq_cache, _reserve_cache
    stub = client._stub
    attempts = 0

    while attempts < MAX_CAS_ATTEMPTS:
        attempts += 1

        # D36: the reserve first, because a disagreement means this writer
        # would allocate against a different seam than the reader pages
        # against, and no allocation should happen under that condition.
        bound_reserve = _read_bound_reserve(client)
        if bound_reserve is not None and bound_reserve != RESERVED_POSITIONS:
            raise ReserveMismatch(
                f"this service is configured with AIL_RESERVED_POSITIONS="
                f"{RESERVED_POSITIONS} and the ledger has {bound_reserve} bound into "
                "it. The bound value is the one every position in this ledger was "
                "allocated against and it cannot be moved: positions already "
                "committed would fall inside a raised reserve, where they are "
                "neither reconciled nor order-checked. Set this service back to "
                f"{bound_reserve}. A reserve that is genuinely too small is a "
                "re-index into a new view, not a moved boundary."
            )

        with _seq_lock:
            cached = _seq_cache if _SEQ_CACHE_ENABLED else None
        if cached is None:
            observed = _read_counter(client)
        else:
            observed = cached

        if observed is None:
            # First allocation ever. KeyMustNotExist is the precondition that
            # makes exactly one writer win this, verified live: the second
            # such ExecAll is rejected with "precondition failed:
            # KeyMustNotExist".
            #
            # It starts above the reserve, not at 1, so the range history is
            # scored into stays free even on a deployment that never runs a
            # backfill. Making that conditional on whether history exists
            # would put the seam in one place on one deployment and another
            # place on the next.
            next_seq = RESERVED_POSITIONS + 1
            precondition = schema.Precondition(
                keyMustNotExist=schema.Precondition.KeyMustNotExistPrecondition(
                    key=SEQUENCE_KEY
                )
            )
        else:
            last_seq, last_tx = observed
            next_seq = last_seq + 1
            precondition = schema.Precondition(
                keyNotModifiedAfterTX=schema.Precondition.KeyNotModifiedAfterTXPrecondition(
                    key=SEQUENCE_KEY, txID=last_tx
                )
            )

        operations = [
            schema.Op(kv=schema.KeyValue(key=key, value=value)),
            schema.Op(kv=schema.KeyValue(key=SEQUENCE_KEY, value=str(next_seq).encode())),
            schema.Op(zAdd=schema.ZAddRequest(
                set=view_set, score=float(next_seq), key=key, boundRef=False,
            )),
        ]
        preconditions = [precondition]

        if bound_reserve is None:
            # D36: bind it here, in the same transaction, under
            # KeyMustNotExist. On a fresh ledger this is the first
            # allocation. On a ledger that was already allocating before
            # this phase there is no first allocation left to catch, so the
            # binding attaches to the next one instead - which is the
            # earliest moment available and makes the value immutable from
            # then on. A deployment that had already raised its reserve
            # before upgrading binds the raised value; nothing can
            # retroactively distinguish that, and it is stated in the
            # report's Residual Limits rather than silently assumed away.
            operations.append(schema.Op(kv=schema.KeyValue(
                key=RESERVE_KEY, value=str(RESERVED_POSITIONS).encode())))
            preconditions.append(schema.Precondition(
                keyMustNotExist=schema.Precondition.KeyMustNotExistPrecondition(
                    key=RESERVE_KEY
                )
            ))

        request = schema.ExecAllRequest(
            Operations=operations,
            preconditions=preconditions,
            noWait=False,
        )

        try:
            resp = stub.ExecAll(request)
        except Exception as exc:
            if "precondition failed" in str(exc):
                # Someone else advanced the counter, or bound the reserve
                # first. Everything this attempt would have written was
                # refused together, so there is nothing to undo - drop both
                # stale caches and read fresh. Dropping the reserve cache
                # matters because KeyMustNotExist on it is the other
                # precondition that can fail here, and a writer that kept a
                # None reserve cached would retry the same losing bind
                # until the budget ran out.
                with _seq_lock:
                    _seq_cache = None
                _reserve_cache = None
                continue
            raise

        tx_id = int(resp.id)
        with _seq_lock:
            _seq_cache = (next_seq, tx_id)
        if bound_reserve is None:
            _reserve_cache = RESERVED_POSITIONS
        return tx_id, next_seq, attempts

    raise RuntimeError(
        f"sequence allocation gave up after {attempts} rejected attempts; "
        "the ledger write did not happen"
    )


@app.post("/write-ordered", response_model=OrderedWriteResponse)
def write_ordered(payload: OrderedWriteRequest, _: None = Depends(_require_write_key)):
    """
    Write a record, allocate its commit position, and index it, atomically.

    Same contract as POST /write for the caller, and it is still keyed on
    `verified`: anything but true raises in ledger/immudb_ledger.py, which
    the decision service turns into a denied call. Fail-closed on execution
    is unchanged.

    D35 (Phase 3c-3c): what changed is the description of the ledger, not
    the decision. The ExecAll commits before the verifiedGet runs, so a
    proof failure can no longer prevent the write - the record, the counter
    advance and the index entry are all in the ledger by the time the proof
    is checked. This used to answer tx_id null and seq null, which is the
    exact shape ledger/immudb_ledger.py reads as "the write did not
    happen". It now answers with the real transaction, the real position and
    committed: true, and writes a `ledger_fault:` record so the record's
    standing is durable rather than recomputed from a repairable anchor.
    """
    view_set = _VIEW_SETS.get(payload.view)
    if view_set is None:
        # Fail closed on an unknown view rather than inventing a set name:
        # a typo would otherwise silently create a view nothing reads, and
        # the record would be absent from every ordered page. Nothing was
        # attempted, so this is the committed: false state.
        return OrderedWriteResponse(
            tx_id=None, seq=None, verified=False, committed=False,
            detail=f"unknown view {payload.view!r}; known views: {sorted(_VIEW_SETS)}",
        )

    from ecdsa.keys import BadSignatureError
    from immudb.exceptions import ErrCorruptedData

    key   = base64.b64decode(payload.key)
    value = base64.b64decode(payload.value)

    # Split from the commit deliberately: everything before this line can
    # fail without anything having been written, and everything after it
    # has a committed transaction to report.
    try:
        client = _get_client()
        tx_id, seq, attempts = _ordered_commit(client, key, value, view_set)
    except Exception as exc:
        logger.error("ordered write error: %s", exc)
        return OrderedWriteResponse(
            tx_id=None, seq=None, verified=False, committed=False, detail=str(exc),
        )

    try:
        # The proof check verifiedSet used to run inside the write call.
        # Issued here because immudb-py 1.5.0 has no verifiedExecAll; it is
        # the same SDK verification code over the same inclusion and
        # consistency proofs, and it raises on the same conditions.
        client.verifiedGet(key)
    except (ErrCorruptedData, BadSignatureError) as exc:
        error_class = ("consistency_failure" if isinstance(exc, ErrCorruptedData)
                       else "signature_failure")
        fault_key, fault_error = _write_fault_record(
            client, record_key=key, record_value=value, tx_id=tx_id, seq=seq,
            view=payload.view, error_class=error_class,
            detail="proof verification failed",
        )
        # `attempts` is reported as what it was, not as zero. Both the red
        # team and the reproduction saw 0 on this path where the commit had
        # taken 1, which understates the work the ledger actually did on a
        # response whose whole job is to describe what happened.
        return OrderedWriteResponse(
            tx_id=tx_id, seq=seq, verified=False, committed=True, attempts=attempts,
            error_class=error_class, fault_record=fault_key,
            fault_record_error=fault_error,
            detail=f"proof verification failed; the record committed at transaction "
                   f"{tx_id} and holds position {seq}",
        )
    except Exception as exc:
        # The proof did not fail, the check could not be made. The record is
        # still committed, and saying otherwise would be the same lie in a
        # different coat - but this is not tamper evidence, so no fault
        # record is written and error_class stays unset.
        logger.error("ordered write: verification could not be attempted: %s", exc)
        return OrderedWriteResponse(
            tx_id=tx_id, seq=seq, verified=False, committed=True, attempts=attempts,
            detail=f"verification could not be attempted: {exc}",
        )

    logger.info(
        "Verified ordered write: tx=%d seq=%d view=%s attempts=%d",
        tx_id, seq, payload.view, attempts,
    )
    return OrderedWriteResponse(
        tx_id=tx_id, seq=seq, verified=True, committed=True, attempts=attempts,
    )


class CurrentStateResponse(BaseModel):
    db: str
    tx_id: int
    tx_hash: str            # base64
    signature: str          # base64 of the state's own DER ECDSA signature
    signing_key_fingerprint: str | None


@app.get("/state", response_model=CurrentStateResponse)
def current_state(_: None = Depends(_require_read_key)):
    """
    D23: the signed ImmuDB state an anchoring job submits to Rekor.

    Not client.currentState(). That SDK method calls rs.set() on the way out
    (immudb/handler/currentRoot.py), so asking this service what the current
    state is would silently advance its persisted trust anchor - a read that
    mutates the thing every later proof is measured against. The RPC is made
    directly and the persisted anchor is left exactly where it was.

    The signature is verified here, against the ImmuDB public key mounted on
    this service's own volume, before the state is handed out. currentRoot's
    handler does not verify it, and an unverified state would be a state the
    caller has only the server's word for - which is the entire thing
    anchoring exists to stop relying on. No configured key, or a signature
    that does not check out, is a 503: fail closed, like every other
    dependency in this project except the one D23 names.

    Read-scoped (ADR-0011): this returns a public Merkle root and a
    signature over it, which is strictly less than /verify already returns
    to the same credential.
    """
    from ecdsa.keys import BadSignatureError
    from google.protobuf import empty_pb2
    from immudb.rootService import State

    client = _get_client()
    if client._vk is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "No ImmuDB signing key configured (IMMUDB_SIGNING_PUBKEY); this "
                "deployment produces no state a checkpoint could be built from"
            ),
        )
    try:
        state = State.FromGrpc(client._stub.CurrentState(empty_pb2.Empty()))
    except Exception as exc:
        logger.error("CurrentState RPC failed: %s", exc)
        raise HTTPException(status_code=503, detail=f"ImmuDB unavailable: {exc}")

    try:
        state.Verify(client._vk)
    except BadSignatureError as exc:
        logger.error("CurrentState signature did not verify: %s", exc)
        raise HTTPException(
            status_code=503,
            detail="ImmuDB's current state is not signed by the configured key",
        )

    return CurrentStateResponse(
        db=state.db,
        tx_id=state.txId,
        tx_hash=base64.b64encode(state.txHash).decode(),
        signature=base64.b64encode(state.signature).decode(),
        signing_key_fingerprint=signing_key_fingerprint(),
    )


@app.post("/verify", response_model=VerifyResponse)
def verify(payload: VerifyRequest, _: None = Depends(_require_read_key)):
    """
    Retrieve and verify a key via verifiedGet.

    The SDK walks the inclusion proof from the (key, value) leaf to eH, then
    verifies a dual consistency proof from the persisted state to this tx.
    If signing is configured, the returned state is verified against the
    server's ECDSA signature before updating local state.

    D21: gated by _require_read_key. Callers: control_plane/main.py's
    get_audit (per-entry verification), get_audit_bundle (evidence export),
    and _has_tombstone (the erasure-conflict check).

    D18 (Phase 3a): the same verification runs, on the same SDK function,
    with the same result - but the material it consumed is captured and
    returned instead of discarded. The RPC is made explicitly here (the one
    network call verifiedGet.call() would have made itself, with the same
    request it would have built) and the response is fed back into the
    unmodified SDK function through a stand-in stub. This is what makes the
    exported material and the verdict the same evidence rather than two
    separate reads that could disagree.
    """
    from ecdsa.keys import BadSignatureError
    from immudb.exceptions import ErrCorruptedData
    from immudb.grpc import schema_pb2
    from immudb.handler import verifiedGet as sdk_verified_get

    from immudb.rootService import State

    key = base64.b64decode(payload.key)
    try:
        client = _get_client()

        if payload.anchor is None:
            # Phase 3a's behaviour, unchanged and still correct for a record
            # no anchored checkpoint covers yet. The trust anchor as it
            # stands before this read, captured first because
            # verifiedGet.call() replaces it via rs.set() on success and the
            # anchor a checker needs is the one that was in force going in.
            root_service = client._rs
            source_state = client._rs.get()
        else:
            # D23/P3b-1: prove the record against the checkpoint that was
            # actually submitted to Rekor. A dual proof running to whatever
            # this service's volume happened to hold is unfalsifiable to an
            # outside party - they have no way to know what that state was
            # or whether it was ever published.
            source_state = State(
                db=payload.anchor.db,
                txId=int(payload.anchor.tx_id),
                txHash=base64.b64decode(payload.anchor.tx_hash),
                publicKey=b"",
                signature=base64.b64decode(payload.anchor.signature or ""),
            )
            if client._vk is None:
                return VerifyResponse(
                    verified=False,
                    detail=(
                        "no ImmuDB signing key is configured, so a supplied anchor "
                        "cannot be checked and will not be used"
                    ),
                    error_class="anchor_signature_failure",
                )
            try:
                source_state.Verify(client._vk)
            except Exception as exc:
                logger.warning(
                    "Refusing an anchor at tx=%s: %s: %s",
                    payload.anchor.tx_id, type(exc).__name__, exc,
                )
                return VerifyResponse(
                    verified=False,
                    detail=(
                        f"the supplied anchor (tx {payload.anchor.tx_id}) is not a "
                        f"state this ImmuDB signed: {type(exc).__name__}"
                    ),
                    error_class="anchor_signature_failure",
                )
            root_service = _PinnedRootService(source_state)

        req = schema_pb2.VerifiableGetRequest(
            keyRequest=schema_pb2.KeyRequest(key=key),
            proveSinceTx=source_state.txId,
        )
        ventry = client._stub.VerifiableGet(req)

        resp = sdk_verified_get.call(
            _CapturedEntryStub(ventry),
            root_service,
            key,
            verifying_key=client._vk,
        )

        if payload.anchor is not None and int(resp.id) > int(source_state.txId):
            # Proof direction is fixed by the SDK, not by the caller: the
            # older transaction is always the source and the newer always
            # the target (docs/reports/spike-consistency-proof.md item 4).
            # So an anchor older than the record does not fail - it quietly
            # inverts, producing a proof from the checkpoint forward to a
            # record the checkpoint was published before. That proof is
            # sound and says nothing about external corroboration, which is
            # exactly the confusion D23's "fail-closed on the claim" rule
            # exists to prevent. Refused by name instead.
            logger.info(
                "Anchor at tx=%d precedes record at tx=%d; refusing to anchor there",
                source_state.txId, resp.id,
            )
            return VerifyResponse(
                verified=False,
                detail=(
                    f"the supplied anchor is at tx {source_state.txId}, which precedes "
                    f"the record at tx {resp.id}; a checkpoint cannot corroborate a "
                    "record written after it"
                ),
                error_class="anchor_precedes_record",
            )

        # Unchanged from Phase 3a on the unanchored path, deliberately:
        # client.currentState() calls rs.set() on the way out, so it both
        # reports the head and advances this service's persisted anchor to
        # it, and that has been this endpoint's behaviour since Phase 1.3.
        # On the anchored path it is not called at all - the persisted
        # anchor must not move because someone asked a question about an
        # old record, and _PinnedRootService.set() already refuses to move
        # the one the proof itself ran against.
        state = client.currentState() if payload.anchor is None else client._rs.get()
        logger.info(
            "Verified read: tx=%d anchor=%d state_id=%d verified=%s",
            resp.id,
            source_state.txId,
            state.txId,
            resp.verified,
        )
        return VerifyResponse(
            verified=True,
            tx_id=resp.id,
            value=base64.b64encode(resp.value).decode(),
            timestamp=resp.timestamp,
            state_id=state.txId,
            proof_material=ProofMaterial(
                source_state=SourceState(
                    db=source_state.db,
                    tx_id=source_state.txId,
                    tx_hash=base64.b64encode(source_state.txHash).decode(),
                    signature=(
                        base64.b64encode(source_state.signature).decode()
                        if source_state.signature else None
                    ),
                ),
                verifiable_entry=base64.b64encode(ventry.SerializeToString()).decode(),
                prove_since_tx=source_state.txId,
                entry_tx_id=resp.id,
                signing_key_fingerprint=signing_key_fingerprint(),
            ),
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
