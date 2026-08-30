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
"""

import base64
import hashlib
import logging
import os
import pathlib
import threading
from contextlib import asynccontextmanager

import grpc
import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException
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

# D21: two independent keys, not one shared key - the same split ADR-0007
# established for the control plane, applied here for the same reason. READ
# authorizes only POST /verify; WRITE authorizes only POST /write. Set both
# in the environment (docker-compose .env); an absent key disables the route
# it gates with a 503 response, matching control_plane/main.py's
# _require_read_key/_require_write_key fail-closed behavior exactly.
_VERIFIER_READ_KEY  = os.getenv("VERIFIER_READ_KEY", "")
_VERIFIER_WRITE_KEY = os.getenv("VERIFIER_WRITE_KEY", "")


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
    tx_id: int | None
    verified: bool
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
    tx_id: int | None
    seq: int | None
    verified: bool
    attempts: int = 0
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


@app.post("/write", response_model=WriteResponse)
def write(payload: WriteRequest, _: None = Depends(_require_write_key)):
    """
    Write a key-value pair via verifiedSet.

    The SDK verifies the inclusion proof and the consistency proof from the
    persisted state to the new transaction before updating its local state.
    Returns verified: false (never raises HTTP 500) so callers can fail closed
    without catching exceptions.

    D21: gated by _require_write_key. Callers: ledger/immudb_ledger.py (the
    decision service's decision and intent writes) and
    control_plane/main.py::_write_tombstone (the erasure tombstone).
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
# backfill pass (which is what this did first) is monotone only within that
# pass: a second pass over records written since would compute a different
# rank against a different denominator and interleave with the first. A score
# that *is* the transaction id is stable no matter how many passes run, in
# what order, or how much history each one finds - so the seam is monotone
# across the boundary permanently, and no cursor is needed to describe where
# history ends and live traffic begins. The boundary is a number.
#
# The reserve has to exceed every historical transaction id or history would
# collide with live positions. tools/ail_backfill_index.py refuses to run
# rather than guess if it ever finds a record above the reserve.
RESERVED_POSITIONS = int(os.getenv("AIL_RESERVED_POSITIONS", "1000000000"))

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

    global _seq_cache
    stub = client._stub
    attempts = 0

    while attempts < MAX_CAS_ATTEMPTS:
        attempts += 1

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

        request = schema.ExecAllRequest(
            Operations=[
                schema.Op(kv=schema.KeyValue(key=key, value=value)),
                schema.Op(kv=schema.KeyValue(key=SEQUENCE_KEY, value=str(next_seq).encode())),
                schema.Op(zAdd=schema.ZAddRequest(
                    set=view_set, score=float(next_seq), key=key, boundRef=False,
                )),
            ],
            preconditions=[precondition],
            noWait=False,
        )

        try:
            resp = stub.ExecAll(request)
        except Exception as exc:
            if "precondition failed" in str(exc):
                # Someone else advanced the counter. Everything this attempt
                # would have written was refused together, so there is
                # nothing to undo - drop the stale cache and read fresh.
                with _seq_lock:
                    _seq_cache = None
                continue
            raise

        tx_id = int(resp.id)
        with _seq_lock:
            _seq_cache = (next_seq, tx_id)
        return tx_id, next_seq, attempts

    raise RuntimeError(
        f"sequence allocation gave up after {attempts} rejected attempts; "
        "the ledger write did not happen"
    )


@app.post("/write-ordered", response_model=OrderedWriteResponse)
def write_ordered(payload: OrderedWriteRequest, _: None = Depends(_require_write_key)):
    """
    Write a record, allocate its commit position, and index it, atomically.

    Same contract as POST /write for the caller: verified false or a
    transport error means the write did not happen, and
    ledger/immudb_ledger.py turns that into a raise, which the decision
    service turns into a denied call. Nothing about the fail-closed path
    changed; what changed is that the record now also carries a position
    the ledger itself allocated.
    """
    view_set = _VIEW_SETS.get(payload.view)
    if view_set is None:
        # Fail closed on an unknown view rather than inventing a set name:
        # a typo would otherwise silently create a view nothing reads, and
        # the record would be absent from every ordered page.
        return OrderedWriteResponse(
            tx_id=None, seq=None, verified=False,
            detail=f"unknown view {payload.view!r}; known views: {sorted(_VIEW_SETS)}",
        )

    from immudb.exceptions import ErrCorruptedData

    key   = base64.b64decode(payload.key)
    value = base64.b64decode(payload.value)
    try:
        client = _get_client()
        tx_id, seq, attempts = _ordered_commit(client, key, value, view_set)

        # The proof check verifiedSet used to run inside the write call.
        # Issued here because immudb-py 1.5.0 has no verifiedExecAll; it is
        # the same SDK verification code over the same inclusion and
        # consistency proofs, and it raises on the same conditions.
        client.verifiedGet(key)

        logger.info(
            "Verified ordered write: tx=%d seq=%d view=%s attempts=%d",
            tx_id, seq, payload.view, attempts,
        )
        return OrderedWriteResponse(tx_id=tx_id, seq=seq, verified=True, attempts=attempts)
    except ErrCorruptedData:
        logger.error("ordered write: inclusion or consistency proof failed")
        return OrderedWriteResponse(
            tx_id=None, seq=None, verified=False, detail="proof verification failed",
        )
    except Exception as exc:
        logger.error("ordered write error: %s", exc)
        return OrderedWriteResponse(tx_id=None, seq=None, verified=False, detail=str(exc))


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
