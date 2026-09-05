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
A `ledger_fault:` record persists. It is written by the one path in this
service that accepts a committed-unverified write, because that is exactly
what it is describing, and the decision path cannot reach that path:
_set_without_verification refuses any bytes that are not a ledger_fault
record, and both write routes refuse a ledger_fault arriving from a caller.

D38/D39 (Phase 3c-3d): the fault key is
`ledger_fault:{committed_tx_id:020d}:{identity}:{nonce}`, so two faults about
one record are two records rather than two versions of one, and faults about
an intent, a decision and a tombstone sharing a call_id no longer collide.
`/write-ordered` refuses what it used to accept, and a record key is written
once.

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
import pickle
import sys
import threading
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import NamedTuple

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


def _state_verifying_key():
    """The ECDSA public key ImmuDB signs its states with, or None.

    The same key `ImmudbClient` loads into `_vk` from `publicKeyFile`, read
    here as well because `_VerifiedRootService` is constructed before the
    client exists and has to be able to check a state without it.
    """
    if not PUBKEY_FILE or not pathlib.Path(PUBKEY_FILE).exists():
        return None
    import ecdsa

    with open(PUBKEY_FILE) as handle:
        return ecdsa.VerifyingKey.from_pem(handle.read())


class UnverifiedState(RuntimeError):
    """A state this service refused to anchor at, and why."""


class _VerifiedRootService:
    """The persisted trust anchor. Never written or seeded from a state
    nothing verified.

    **D47 (Phase 3c-3f).** This replaces the SDK's `PersistentRootService`,
    which is the sample implementation its own file calls a sample. Three
    things about it put an unchecked state under every later proof:

      * `init()` sets its cache from `CurrentState` when the state file is
        absent or unreadable. That is the first boot of any deployment, and
        the first proof after it runs from whatever the server said.
      * `get()` does the same whenever the cache is `None`.
      * `set()` writes whatever it is handed. `verifiedSet.call` and
        `verifiedGet.call` hand it a state they verified under
        `newstate.Verify(verifying_key)` first; `currentRoot.call` - which is
        what `client.currentState()` reaches - hands it one nothing checked,
        and the SDK's own `# IMPROVEMENT: we could check here, if state is
        valid` sits on that line.

    Neither seed is a `set`, so a rule about writes would not have caught
    either. One class covers all three, which is why this is a class and not
    a guard at the two call sites that used to call `currentState()`.

    **What "verified" means here, stated exactly.** ImmuDB signs the state it
    reports when the server runs with `--signingKey`, and the signature is
    over `(db, txId, txHash)`. Checking it establishes that this state is one
    this ledger published, rather than one the transport handed us. It does
    not establish that a consistency proof ran to it; that is what the SDK's
    verified handlers do, and it is why the two `currentState()` call sites
    were removed rather than made to check a signature. Both controls are
    here: a signature that does not verify is refused, and an anchor that
    would move backwards is refused, because an anchor that can go backwards
    can be replayed to a point before a record was written.

    **Fail closed with no signing key.** A deployment with no
    `IMMUDB_SIGNING_PUBKEY` cannot check any state, so seeding from the
    server would be exactly the thing this class exists to stop. It refuses,
    the way `GET /state` already answers 503 in the same condition. The
    exception is an empty ledger: `txId == 0` has no history to be lied
    about, and refusing there would mean a stack with no signing key cannot
    start at all rather than cannot anchor.

    **The state file itself is read exactly as before, and deliberately.**
    D47 names the two `CurrentState` seeds, not the file. That file is the
    operator's own volume, and corrupting it is the tamper vector ADR-0006's
    `consistency_failure` exists to detect: `tests/anchor_helpers.py` flips a
    byte in `txHash` and expects the next proof to fail. Verifying the file's
    signature here would discard the corruption and re-seed from the server
    instead, which would delete that detection rather than add to it.

    The pickle format is the SDK's - `{dbname: State}` - so the file this
    writes is the file `tests/anchor_helpers.py` and
    `tests/test_committed_is_a_fact.py` already read.
    """

    def __init__(self, filename: str, verifying_key=None):
        self._filename = filename
        self._verifying_key = verifying_key
        self._dbname = None
        self._service = None
        self._cache = None

    # -- the check ---------------------------------------------------------

    def _checked(self, state, source: str):
        """`state`, or a refusal naming where it came from."""
        from ecdsa.keys import BadSignatureError

        if int(getattr(state, "txId", 0)) == 0:
            return state
        if self._verifying_key is None:
            raise UnverifiedState(
                f"refusing to anchor at the state {source} reports: no ImmuDB "
                "signing key is configured (IMMUDB_SIGNING_PUBKEY), so no "
                "state can be checked and anchoring at one would be taking "
                "the server's word for the thing every later proof is "
                "measured against"
            )
        try:
            state.Verify(self._verifying_key)
        except BadSignatureError as exc:
            raise UnverifiedState(
                f"refusing to anchor at the state {source} reports (tx "
                f"{state.txId}): it is not signed by the configured ImmuDB "
                f"key ({exc})"
            ) from exc
        return state

    def _head(self, source: str):
        from google.protobuf import empty_pb2
        from immudb.rootService import State

        state = State.FromGrpc(self._service.CurrentState(empty_pb2.Empty()))
        return self._checked(state, source)

    # -- the SDK's RootService interface -----------------------------------

    def init(self, dbname: str, service):
        """Seed one: the state file, or a checked head when it is not there."""
        self._dbname = dbname
        self._service = service
        self._cache = None
        try:
            with open(self._filename, "rb") as handle:
                states = pickle.load(handle)
            if dbname in states:
                self._cache = states[dbname]
        except FileNotFoundError:
            pass
        except Exception as exc:                      # noqa: BLE001
            logger.warning("Could not read %s: %s", self._filename, exc)
        if self._cache is None:
            self._cache = self._head("ImmuDB, on a first boot with no state file")
            logger.info("Trust anchor seeded from a checked state at tx=%d",
                        self._cache.txId)

    def get(self):
        """Seed two: the same, whenever the cache is empty."""
        if self._cache is None:
            self._cache = self._head("ImmuDB, with no anchor held")
        return self._cache

    def set(self, state):
        """The write. Checked, and never backwards."""
        self._checked(state, "the caller of set()")
        held = self._cache
        if held is not None and int(state.txId) < int(held.txId):
            raise UnverifiedState(
                f"refusing to move the trust anchor backwards, from tx "
                f"{held.txId} to tx {state.txId}: an anchor that can go "
                "backwards can be replayed to a point before a record was "
                "written"
            )
        self._cache = state
        states = {}
        try:
            with open(self._filename, "rb") as handle:
                states = pickle.load(handle)
        except FileNotFoundError:
            pass
        except Exception as exc:                      # noqa: BLE001
            logger.warning("Could not read %s: %s", self._filename, exc)
        states[self._dbname] = state
        with open(self._filename, "wb") as handle:
            pickle.dump(states, handle)


class HeadRead(NamedTuple):
    """The ledger's head, and whether anything checked that this ledger
    published it.

    **R6. The unconfigured-key rule is one rule.** `head_state` and
    `_VerifiedRootService._checked` are the two places a state reaches this
    service from `CurrentState`, and they disagreed about what to do when no
    `IMMUDB_SIGNING_PUBKEY` is configured: `_checked` refused, `head_state`
    returned the state with nothing marking it as unchecked, so a caller
    could not tell a checked head from the server's unverified word for its
    own head.

    They cannot behave identically - one reports and one gates a persist, and
    they have different return contracts. The rule they share is a behaviour:
    **with no verifying key configured, neither presents an unchecked state
    as a checked one.** `_checked` refuses the persist, because a state
    nothing verified must not become the thing every later proof is measured
    against. `head_state` has nothing to refuse - it reports - so it reports
    the head and reports that the head was not checked. One rule, two correct
    expressions.

    `checked` is returned rather than left to be re-derived from `client._vk`
    at each call site. A caller that forgets to ask is the asymmetry coming
    back at a third site.
    """

    state: object
    checked: bool


def head_state(client) -> HeadRead:
    """The ledger's head, reported without moving this service's anchor.

    D47. `client.currentState()` reaches `currentRoot.call`, which ends in an
    unconditional `rs.set(state)`: it reports the head *and* overwrites the
    anchor with it, after `verifiedSet.call` or `verifiedGet.call` has just
    set a state a proof actually ran to. Reporting the head does not require
    persisting it, so the RPC is made directly here and nothing is written.

    `GET /state` reached the same conclusion about the same mutation in
    Phase 3b and made the call directly; this is that argument applied to the
    two remaining call sites, and that route now uses this helper rather than
    holding a second copy of it.

    The signature is checked, so what a caller is told the head is, is a head
    this ledger published - and when no key is configured to check it with,
    the returned `HeadRead.checked` says so rather than leaving the caller to
    assume it was checked. See HeadRead.
    """
    from google.protobuf import empty_pb2
    from immudb.rootService import State

    state = State.FromGrpc(client._stub.CurrentState(empty_pb2.Empty()))
    if client._vk is None:
        # R6: not silently the same as a checked head. See HeadRead.
        return HeadRead(state, False)
    state.Verify(client._vk)          # BadSignatureError on failure
    return HeadRead(state, True)


def _get_client():
    global _client
    if _client is not None:
        return _client

    from immudb import ImmudbClient

    pathlib.Path(STATE_FILE).parent.mkdir(parents=True, exist_ok=True)

    pubkey = PUBKEY_FILE if PUBKEY_FILE and pathlib.Path(PUBKEY_FILE).exists() else None
    # D47 (Phase 3c-3f): not PersistentRootService. Both of that class's
    # seeds take ImmuDB's word for the state every later proof is measured
    # against - see _VerifiedRootService for what replaces them.
    rs = _VerifiedRootService(STATE_FILE, _state_verifying_key())

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
    """D35: three states, not two. D45: four, because one of them was a guess.

    verified true                      the write committed and its proofs check out
    verified false, committed true     the write committed; its proof did not check
    verified false, committed false    the write did not happen
    verified false, committed null     whether the write happened is not established

    The caller's rule is unchanged and still keyed on `verified`: anything
    but true raises in ledger/immudb_ledger.py and the decision service
    denies the call. `committed` is what stops the middle state being
    reported as the bottom one, which is the opposite of what happened.

    D45 (Phase 3c-3e) adds the fourth. `committed: false` is a claim about
    the ledger, and this service can only make it after reading the ledger.
    When the write raised and the confirming read raised too, there is no
    such claim to make, and the false one produced a tombstone in the ledger,
    the payload still in the store, and content writes for that subject
    frozen at 409. Null is not a fifth kind of failure for a caller to
    handle: it is refused exactly like false, because `verified` is what
    every caller keys on, and it differs only in what it says happened.
    """
    tx_id: int | None
    verified: bool
    committed: bool | None = False
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
    """Same four states as WriteResponse, plus the allocated position.

    On a committed-unverified write the position is reported too: the
    ExecAll that committed the record committed the counter advance and the
    index entry with it, so a response withholding `seq` would describe a
    record as unpositioned while the index holds its position.

    D45 (Phase 3c-3e): `seq` is reported on the committed-then-cut branch as
    well, and it is confirmed against the view index rather than asserted
    from what this process intended to write. `seq: null` beside
    `committed: true` means the record is in the ledger and its position
    could not be confirmed, which is a different statement from position
    zero and from no position at all.
    """
    tx_id: int | None
    seq: int | None
    verified: bool
    committed: bool | None = False
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


# R6. The vocabulary of the state read that reports `state_id`. Deliberately
# not the word "failed": `/audit` renders D2's four verification states and
# one of them is "failed", a positive tamper claim about a record. A state
# read that could not run is not a claim about the record at all, and giving
# the two the same word is how they get conflated.
STATE_READ_OK = "ok"
STATE_READ_UNCHECKED = "unchecked"
STATE_READ_UNAVAILABLE = "unavailable"


class StateRead(BaseModel):
    """How `state_id` was read, and whether anything checked what it reports.

    **R6-2. A failed state read is reported, not swallowed.** Before R6 this
    read sat inside the proof's own `try`, so its failure was reported as the
    record's failure. Taking it out of that `try` fixes the tamper claim and
    would, on its own, introduce the opposite defect: `state_id` silently
    null, with nothing saying why. This field is where the read's own outcome
    goes, so the null is never bare.

    `source` names which read produced `state_id`, because the two paths read
    different things and `state_id`'s meaning is unchanged on both:
      * "head"   - the unanchored path, the ledger's head.
      * "anchor" - the anchored path, the anchor this service persists.
    The state the proof actually ran against is not this field and never was:
    it is on the response as `proof_material.source_state.tx_id` and
    `prove_since_tx`.

    `status`:
      * "ok"          - the read succeeded and nothing about it was refused.
      * "unchecked"   - the read succeeded, and no IMMUDB_SIGNING_PUBKEY is
                        configured, so no signature over the state was
                        checked. Reported rather than presented as "ok"; see
                        HeadRead for the rule this expresses.
      * "unavailable" - the read did not produce a state. `state_id` is null
                        and `detail` says why. **Not a statement about the
                        record**, whose proof had already succeeded before
                        this read was attempted.
    """

    source: str
    status: str
    detail: str | None = None


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
    # R6: the sibling of state_id, carrying the outcome of the read that
    # produced it. Null on the failure paths above, which return before any
    # state is read - the field describes a read that was attempted, and
    # absence of the field means none was.
    state_read: StateRead | None = None


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
# So the durable qualification is a record, classified by `record_type`
# rather than by key shape - D11's discipline, unchanged.
#
# D38 (Phase 3c-3d) replaced the key. It was `ledger_fault:{call_id}`, joined
# by the same exact `getall` the tombstone join uses, and that shape lost
# faults in two ways: a second fault about one record was a new version of
# the same key, so a reader saw the last one and none of the others; and an
# intent fault, a decision fault and a tombstone fault for one `call_id`
# collided with each other. The key is now
# `ledger_fault:{committed_tx_id:020d}:{identity}:{nonce}` - see the block
# above _fault_key for what each component closes - and the page reads its
# own transaction window in one bounded range scan, with the old exact
# `getall` kept beside it for the keys already committed under the old shape.
FAULT_RECORD_TYPE = "ledger_fault"
FAULT_KEY_PREFIX  = "ledger_fault:"


def _set_without_verification(client, key: bytes, value: bytes) -> int:
    """An unconditional `set`, with no proof check. Returns the transaction.

    The one write in this system whose success does not require write-time
    proof, which is why it is stated in README's Residual Limits rather than
    left to be discovered.

    **The decision path is structurally unable to reach it.** This function
    refuses any record that is not a fault record, so the only caller that
    gets through is _write_fault_record below; both write routes refuse a
    ledger_fault arriving from outside (D39); and no parameter on either
    route selects this path. tests/test_ledger_faults.py drives the guard
    with a stub client, and tests/test_route_parity.py asserts over every
    write route that a failed proof makes exactly one unverified write whose
    bytes are a fault record about the record just committed.

    **What is NOT bounded, stated rather than implied (P3c3e-9, Phase
    3c-3e).** How many callers this function has. A static parse counted them
    until this phase and was defeated three times - a plainly-named second
    caller, an alias binding, and `globals()[...]` / `getattr(sys.modules
    [__name__], ...)`, which carry the name only as a string literal and are
    invisible to any reference walk. It is retired rather than repaired,
    because a source parse is not a control against anything that can write
    Python. The guard bounds what this path WRITES; nothing bounds how many
    callers reach it. See README section 5.

    The condition that produces a fault is precisely the condition that
    breaks every proof, so requiring a verified write here would mean the
    qualification can never be recorded exactly when it is needed.

    **P3c3d-12 (Phase 3c-3d): the guard reads the bytes it is about to
    write.** It used to take a parallel `record` dict and inspect that, while
    the bytes committed were `value` - two different objects with nothing
    requiring them to agree. Driven live before the fix (red-team A3): a
    `record` argument claiming `ledger_fault` with a decision record as
    `value` wrote `tool_call:a3probe001` at tx 159 with
    `record_type=decision, outcome=policy_allow`, through the one path in
    this system that requires no proof, with no position and no index entry.
    The parameter is gone; there is no longer an argument that can disagree
    with the write.
    """
    try:
        parsed = json.loads(value.decode())
    except Exception as exc:
        raise RuntimeError(
            "refusing an unverified write whose bytes are not a JSON record: "
            f"{type(exc).__name__}: {exc}. This path exists only for "
            f"{FAULT_RECORD_TYPE!r}, and what is not readable cannot be shown "
            "to be one."
        ) from exc
    record_type = parsed.get("record_type") if isinstance(parsed, dict) else None
    if record_type != FAULT_RECORD_TYPE:
        raise RuntimeError(
            "refusing an unverified write for a "
            f"{record_type!r} record: this path exists only for "
            f"{FAULT_RECORD_TYPE!r}, which describes a failed proof and therefore "
            "cannot itself be proven"
        )
    resp = client.set(key, value)
    return int(resp.id)


# D38 (Phase 3c-3d): the fault key carries a transaction and a nonce.
#
#     ledger_fault:{committed_tx_id:020d}:{call_id or "key:"+digest}:{nonce}
#
# **The transaction separates faults about different records; the nonce
# separates faults about the same record. Neither substitutes for the
# other.** Both halves of that sentence are load-bearing and each closes a
# defect the other does not.
#
# What the nonce closes. Under `ledger_fault:{call_id}` a second fault about
# one record was a new version of the same key, so `getall` returned the head
# and a prefix scan returned one row: measured, three faults about one record
# gave one row and two hidden (docs/reports/phase-3c3d-keyprobe.md section
# 10). D38 as originally written - `ledger_fault:{call_id}:{tx_id}` - did not
# close it, because the only transaction available when the key is built is
# `committed_tx_id`, the qualified record's own transaction, which is fixed
# per record. Measured: `revision=2`, one key. That was a rename.
#
# What the transaction closes, separately. `tool_call_intent:` and
# `tool_call:` for one call carry the same `call_id` and both take the
# ordered route; the erasure tombstone takes `POST /write` with that same
# `call_id`. All three can fault. Under `ledger_fault:{call_id}` an intent
# fault, a decision fault and a tombstone fault for one call collide and
# silently replace each other, non-adversarially, with no second writer
# involved. A scheme keyed on `{call_id}:{nonce}` would re-merge them, and
# would also drop the bounded page read: a transaction-leading key is what
# lets the page ask for exactly its own window in one range scan
# (`_faults_in_tx_window` in control_plane/main.py) instead of one prefix
# scan per row.
#
# Ordering between two faults about one record comes from the `scan` entry's
# own `tx`, which the read that already ran returns. No timestamp component
# is needed and none is added.
#
# What is given up, deliberately: the fault key is no longer derivable from a
# page row. That derivability is exactly what the original form preserved by
# closing nothing. Anything that needs to name a specific fault key gets it
# from the write response's `fault_record`, which carries it.

# 20 because uint64 max is 18446744073709551615, twenty digits, so overflow
# is unreachable and the ledger is append-only - a narrower pad is a bet that
# cannot be un-made. Measured at a deliberately small pad, both failure modes
# past it are silent and arrive at HTTP 200: over-width keys are pulled into
# a window that should exclude them, and a window whose own bound is
# over-width returns empty (keyprobe report section 4).
FAULT_KEY_TX_PAD = 20

# P3c3e-6 (Phase 3c-3e): the ledger's own maximum key length, measured.
#
# `POST /api/v2/db/set` on this ImmuDB accepts a key of 1023 bytes and answers
# HTTP 500 "max key length exceeded" at 1024. Measured on the running stack at
# 1000, 1020, 1023, 1024, 1025, 1030 and 1050 bytes.
#
# Why this is here rather than left to the ledger to refuse. The fault key
# carried a caller-supplied `call_id` unvalidated, so a `call_id` past about
# a thousand characters pushed the whole key past this bound and NO FAULT
# RECORD WAS WRITTEN. Driven by the Phase 3c-3d red team (A1) under a live
# proof failure, control first:
#
#     32-char call_id   -> fault_record ledger_fault:...:36eac951...:21c158f1
#                          page row carries the fault
#     1200-char call_id -> fault_record null, "max key length exceeded"
#                          page row: {"outcome_type": "policy_allow",
#                                     "ledger_fault": null}
#
# A committed record whose write-time proof failed, on the audit page reading
# `policy_allow` with nothing recording why - which is exactly the condition
# D35 says the fault record exists to remove, selected by the caller by
# choosing its own call_id.
MAX_LEDGER_KEY_BYTES = 1023

# What is left for the identity once the fixed parts are spent:
# "ledger_fault:" + 20 digits + ":" + identity + ":" + 16 hex nonce.
FAULT_KEY_FIXED_BYTES = len(FAULT_KEY_PREFIX) + FAULT_KEY_TX_PAD + 1 + 1 + 16
MAX_FAULT_IDENTITY_BYTES = MAX_LEDGER_KEY_BYTES - FAULT_KEY_FIXED_BYTES


def fault_key_tx_bound(tx_id: int) -> str:
    """`ledger_fault:{tx_id:020d}` - the bound a page-side range read is built
    from, and the leading component of every fault key.

    A function rather than a pair of constants because the whole format has
    to agree between the writer here and the reader in control_plane, not
    just the prefix. tests/test_ledger_vocabulary.py compares what the two
    modules produce for the same transaction.
    """
    return f"{FAULT_KEY_PREFIX}{tx_id:0{FAULT_KEY_TX_PAD}d}"


def _fault_identity(record_value: bytes, record_key: bytes) -> str:
    """What the fault names: the record's call_id, or a digest of its key.

    A record with no `call_id` does reach a page - measured through
    `/write-ordered` and `GET /audit` (keyprobe report section 7), which
    corrects what this comment used to claim - and the row's `ledger_key` is
    the base64 raw key, so `sha256(record_key)[:32]` is derivable from a page
    row today with no format change. The fallback is not an unjoinable last
    resort; it is a second identity that a reader can compute.
    """
    try:
        value = json.loads(record_value.decode())
        call_id = value.get("call_id") if isinstance(value, dict) else None
    except Exception:
        call_id = None
    if call_id:
        identity = str(call_id)
        # P3c3e-6 (Phase 3c-3e): the call_id is caller-supplied and goes into
        # a key, so it is bounded here rather than at the ledger. Past the
        # budget it is refused AS AN IDENTITY and the digest fallback is used
        # instead, so the fault is still written; the alternative - letting
        # the ledger refuse the key - is how a committed record ended up on
        # the page unqualified with `ledger_fault: null`.
        #
        # Nothing is lost by the substitution. A fault joins onto its record
        # by `committed_key`, not by identity, and the fallback is derivable
        # from a page row: the row's `ledger_key` is the base64 raw key and
        # the fallback is sha256 of those bytes.
        #
        # P3c3f-8 (Phase 3c-3f): and it is judged on whether it can be
        # written, not on its length alone. Both length checks measure with
        # `errors="replace"` and the write is a plain strict `.encode()`, so
        # a call_id of lone surrogates - well-formed JSON, `\ud800` on the
        # wire, a str after `json.loads` - is one character to every check
        # here and unencodable at the ledger. Driven by the Phase 3c-3e red
        # team through the real POST /write route: `fault_record: None`,
        # `UnicodeEncodeError`, and zero unverified writes, which is a
        # committed record left on the page with `ledger_fault: null` - the
        # outcome the fault record exists to prevent, reached past the budget
        # rather than through it.
        #
        # The defect was never that it failed quietly; `fault_record_error`
        # and `_fault_failure_detail` already made it loud. It is that an
        # unusable identity was never judged unusable, so the digest fallback
        # below - which exists for exactly this - was never reached.
        unusable = None
        if len(identity.encode("utf-8", "replace")) > MAX_FAULT_IDENTITY_BYTES:
            unusable = (
                f"it is {len(identity.encode('utf-8', 'replace'))} bytes and a "
                f"fault key has {MAX_FAULT_IDENTITY_BYTES} for its identity "
                "component"
            )
        else:
            try:
                identity.encode("utf-8")
            except UnicodeEncodeError as exc:
                unusable = f"it cannot be encoded for the ledger ({exc})"
        if unusable is None:
            return identity
        logger.error(
            "The call_id on the record at key %s is not a usable key "
            "component: %s. This fault is keyed by the digest of the record "
            "key instead, and the fault is written either way.",
            record_key.decode("utf-8", "replace")[:120], unusable,
        )
    return "key:" + hashlib.sha256(record_key).hexdigest()[:32]


def _fault_key(record_value: bytes, record_key: bytes, committed_tx_id: int,
               nonce: str) -> str:
    """The composite key, assembled from its three named parts.

    P3c3e-6: the assembled key is checked against the ledger's own maximum
    before it is handed to the ledger. `_fault_identity` bounds the one
    component that is caller-supplied, so reaching this raise means an
    invariant in this module is broken rather than that a caller found
    something - and a fault key that cannot be written has to fail here,
    loudly, and not silently at the ledger where the failure lands on a
    response the middleware discards.
    """
    identity = _fault_identity(record_value, record_key)
    key = f"{fault_key_tx_bound(committed_tx_id)}:{identity}:{nonce}"
    encoded = len(key.encode("utf-8", "replace"))
    if encoded > MAX_LEDGER_KEY_BYTES:
        raise ValueError(
            f"the fault key for the record at transaction {committed_tx_id} "
            f"would be {encoded} bytes and this ledger refuses a key above "
            f"{MAX_LEDGER_KEY_BYTES}. A fault that cannot be written must fail "
            "here: a qualification that silently does not exist leaves a "
            "committed record on the page with nothing recording why its "
            "proof failed, which is the condition this record exists to "
            "remove."
        )
    return key


def _fault_failure_detail(fault_error: str | None) -> str:
    """The sentence a response carries when the qualification was not written.

    P3c3e-6 (Phase 3c-3e). `fault_record_error` has always been on the
    response and the middleware discards the response, so the only place an
    unwritten fault was visible was the verifier's own log. It is in `detail`
    now as well, which is the field every caller that logs anything logs, and
    it says what the absence means rather than naming an exception.
    """
    if not fault_error:
        return ""
    return (
        f". NO FAULT RECORD WAS WRITTEN for this record ({fault_error}), so "
        "nothing durable records why its proof failed and the audit page will "
        "show it with ledger_fault null"
    )


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
    # P3c3e-7 (Phase 3c-3e): the transaction in the key is DERIVED from the
    # committed record, not taken from the caller of this function.
    #
    # The key's leading component is what places a fault in a page's
    # transaction window, and the body carries `committed_tx_id` as well. A
    # fault keyed at a transaction its record does not occupy is invisible at
    # HTTP 200 - it falls outside the window of the page its record is on, so
    # nothing fetches it, and nothing on the reading side can compare two
    # numbers it never sees. The red team drove exactly that (A2): record at
    # transaction 100, fault keyed at 1000100, page row `ledger_fault: null`,
    # no error and no log line.
    #
    # Derivation rather than a cross-check, because it is available on both
    # fault-producing paths: both reach here immediately after a commit, and
    # the read is a plain `get`, which is what `_committed_tx_for` already
    # relies on when a proof has just failed. So the two numbers cannot
    # disagree - there is only one, and it comes from the ledger.
    #
    # `tx_id` is still passed in and is still used, for the body and for the
    # response, and it is cross-checked against the derived value. A
    # disagreement is not silently smoothed over: it means this process's
    # account of the write and the ledger's disagree, and a qualification
    # written under either number would be a claim neither supports.
    state, derived_tx = _committed_tx_for_value(client, record_key, record_value)
    if state != PRESENT:
        message = (
            f"the record this fault would qualify is {state} in the ledger, so "
            "the transaction its key must carry cannot be derived. No fault "
            "record was written."
        )
        logger.error(
            "FAULT RECORD NOT WRITTEN for committed tx=%s key=%s: %s The record "
            "stands in the ledger with nothing recording why its proof failed.",
            tx_id, record_key.decode("utf-8", "replace"), message,
        )
        return None, message
    if tx_id is not None and int(tx_id) != derived_tx:
        message = (
            f"this write reported transaction {tx_id} and the ledger holds "
            f"these bytes at {derived_tx}. A fault key names the transaction "
            "its record occupies, and a fault keyed at any other transaction "
            "is absent from that record's page. No fault record was written."
        )
        logger.error(
            "FAULT RECORD NOT WRITTEN for key=%s: %s",
            record_key.decode("utf-8", "replace"), message,
        )
        return None, message
    tx_id = derived_tx

    # D38: the nonce is minted here, once per fault, and is what makes two
    # faults about one record two records rather than two versions of one.
    nonce = uuid.uuid4().hex[:16]
    try:
        key = _fault_key(record_value, record_key, tx_id, nonce)
    except ValueError as exc:
        # P3c3e-6: a key that cannot be written fails at construction, and
        # loudly. It used to reach the ledger and be refused there, on a
        # response field the middleware discards.
        logger.error(
            "FAULT RECORD NOT WRITTEN for committed tx=%s key=%s: %s",
            tx_id, record_key.decode("utf-8", "replace"), exc,
        )
        return None, f"{type(exc).__name__}: {exc}"
    fault = {
        "record_type": FAULT_RECORD_TYPE,
        "fault_class": "write_verification_failed",
        "call_id": _fault_identity(record_value, record_key),
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
        fault_tx = _set_without_verification(client, key.encode(), raw)
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
FAULT_KEY_PREFIX_BYTES = FAULT_KEY_PREFIX.encode()
_REFUSED_KEY_PREFIXES = (b"tool_call:", b"tool_call_intent:", FAULT_KEY_PREFIX_BYTES)


# D39 (Phase 3c-3d): what POST /write-ordered refuses, and why it is not the
# same set POST /write refuses.
#
# The two routes are not symmetric and cannot be. `POST /write` refuses a
# `decision` because a decision with no commit position is absent from every
# ordered page; `/write-ordered` exists to write exactly those, so applying
# the plain route's set here would refuse the route's own purpose. What the
# two share is the `ledger_fault` refusal, and that one is not about which
# route a record belongs on at all: a fault record is this service's own
# account of its own failed proof, and one arriving from a caller on ANY
# route is an unverified assertion about another record's standing.
#
# Measured on the unrefused route (docs/reports/phase-3c3d-keyprobe.md
# section 12), a caller holding only VERIFIER_WRITE_KEY wrote a
# `ledger_fault:` key that `/audit` rendered as the ledger's own account of a
# record's standing, with an attacker-chosen fault_class, committed_tx_id and
# timestamp; and because the ordered route allocates a position, the same
# write became a page row with `outcome_type: null`, so `entries` exceeded
# `total`.
#
# Both conditions again, for the same reason the plain route has two: the key
# prefix sees a record whose `record_type` was omitted or renamed, and
# `record_type` sees a fault record written under any key. FAULT_KEY_PREFIX
# is still a prefix of the composite shape D38 introduces, so this refusal
# covers both key shapes with no change - D39 and D38 are independent.
def _refuse_reason_for_ordered_write(key: bytes, value: bytes) -> str | None:
    """Why this record may not take POST /write-ordered, or None if it may."""
    if key.startswith(FAULT_KEY_PREFIX_BYTES):
        return (
            f"key prefix {FAULT_KEY_PREFIX!r} is written by this service about its "
            "own failed proof and is never accepted from a caller, on this route "
            "or on POST /write"
        )
    try:
        parsed = json.loads(value.decode())
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None
    # `==` rather than a set membership test: a record_type that is not
    # hashable must refuse, not raise (P3c3d-9).
    if parsed.get("record_type") == FAULT_RECORD_TYPE:
        return (
            f"a {FAULT_RECORD_TYPE!r} record is written by this service about its own "
            "failed proof and is never accepted from a caller, on this route or on "
            "POST /write"
        )
    return None


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
    # P3c3d-9 (Phase 3c-3d): `record_type in _REFUSED_ON_PLAIN_WRITE` against
    # an unhashable value raised TypeError and answered 500 on a route whose
    # whole job is to refuse deliberately. Nothing was written, so the effect
    # was fail-closed, but an unhandled exception is not a refusal. A
    # record_type that is not a string is not a classification at all, and it
    # is refused as one rather than reaching the set membership test.
    if record_type is not None and not isinstance(record_type, str):
        return (
            f"record_type must be a string; got {type(record_type).__name__}. A "
            "record_type is how this ledger classifies a record (D11), and a "
            "value that is not one cannot be checked against the classes this "
            "route refuses"
        )
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

    D40 (Phase 3c-3d): `committed` is a fact about the ledger. The state read
    that used to sit inside this route's `try` is a second RPC issued after
    the write has already committed, proved and persisted its anchor, and its
    failure described the whole write as never having happened. It is now
    outside, and the generic handler asks the ledger rather than assuming.
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
        resp = client.verifiedSet(key, value)
    except (ErrCorruptedData, BadSignatureError) as exc:
        error_class = ("consistency_failure" if isinstance(exc, ErrCorruptedData)
                       else "signature_failure")
        # The commit already happened; the SDK raised on the proof it ran
        # afterwards. Ask the ledger which transaction holds this key rather
        # than inferring one - the exception carries no transaction id, and
        # a response that guessed would be the same kind of claim this item
        # exists to remove.
        state, tx_id = _committed_tx_for(client, key)
        if state == UNKNOWN:
            # D45: the proof failed, which means the commit already happened,
            # and the read that would name its transaction could not run.
            # Reporting `committed: false` here would describe a record that
            # is in the ledger as never having been written.
            logger.error(
                "verifiedSet: proof failed and the ledger could not be read back; "
                "the commit precedes the proof, so whether a record is present "
                "under this key is not established"
            )
            return WriteResponse(
                tx_id=None, verified=False, committed=None, error_class=error_class,
                detail="proof verification failed and the ledger could not be "
                       "read back; whether the record committed is not established",
            )
        if state == ABSENT:
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
                   f"transaction {tx_id}" + _fault_failure_detail(fault_error),
        )
    except Exception as exc:
        # D40 (Phase 3c-3d): committed describes what is in the ledger, not
        # whether the call that would have told us succeeded. This branch used
        # to answer committed: false unconditionally, which is the exact shape
        # ledger/immudb_ledger.py reads as "the write did not happen".
        # Reproduced live: a proxy that relayed the write frame and then cut
        # the connection produced `{tx_id: null, verified: false, committed:
        # false}` while the record sat at tx 14 and the verifier's own
        # persisted trust anchor had advanced to 14.
        #
        # So the ledger is asked. Asked with the value as well as the key,
        # which is narrower than the proof-failure branch below on purpose:
        # there, the commit is known to have happened and only its
        # transaction is in question, whereas here nothing is known, and a
        # previous record under the same key would otherwise be reported as
        # this write. Byte equality answers exactly the question being asked.
        #
        # `verified` stays false and no fault record is written: the proof did
        # not fail, it could not be attempted, and that is not tamper evidence
        # - the same rule the ordered route's corresponding branch applies.
        logger.error("verifiedSet error: %s", exc)
        state, tx_id = _committed_tx_for_value(client, key, value)
        if state == UNKNOWN:
            # D45: the write raised AND the read that would settle it could
            # not run. Neither `committed: true` nor `committed: false` is a
            # fact here, and the second one is the guess the red team drove
            # all the way to an unerasable subject record.
            logger.error(
                "verifiedSet: the write raised and the ledger could not be read "
                "back, so whether the record committed is not established: %s", exc,
            )
            return WriteResponse(
                tx_id=None, verified=False, committed=None,
                detail=f"{exc}; the ledger could not be read back, so whether "
                       "the record committed is not established",
            )
        if state == ABSENT:
            return WriteResponse(tx_id=None, verified=False, committed=False,
                                 detail=str(exc))
        logger.error(
            "verifiedSet: verification could not be attempted and the record is "
            "in the ledger at tx=%s: %s", tx_id, exc,
        )
        return WriteResponse(
            tx_id=tx_id, verified=False, committed=True,
            detail=f"verification could not be attempted: {exc}; the record "
                   f"committed at transaction {tx_id}",
        )

    # D40: the state read is outside the proof's own try, and its failure
    # cannot describe the write. It is a second RPC issued after `verifiedSet`
    # has already committed, proved and persisted the new anchor; wrapping it
    # in the same handler let a transport failure on that call report the
    # whole write as never having occurred. It is logged here and changes
    # nothing about the response.
    #
    # D47 (Phase 3c-3f): `head_state`, not `client.currentState()`. This line
    # reports the head for a log message, and the SDK's way of reporting it
    # overwrites the anchor `verifiedSet` had just set under a proof with an
    # unproven one, on the write key.
    try:
        head = head_state(client)
        logger.info("Verified write: tx=%d state_id=%d checked=%s",
                    resp.id, head.state.txId, head.checked)
    except Exception as exc:
        logger.warning(
            "Verified write: tx=%d; the state read after it failed (%s). The "
            "write committed and its proof checked out; this call describes "
            "neither.", resp.id, exc,
        )
    return WriteResponse(tx_id=resp.id, verified=True, committed=True)


# D45 (Phase 3c-3e): a read that could not run is not a read that found
# nothing.
#
# Both helpers below answered `None` for two different facts - the ledger
# holds nothing under this key, and this process could not ask. D40 made
# `committed` a fact about the ledger and then collapsed those two onto the
# same answer, so the one branch that exists to stop a guess made one
# whenever the confirming read was itself unavailable. Driven live by the
# Phase 3c-3d red team (A4.2): a relay that dropped the write's response and
# then refused every connection for 25 seconds produced
# `{tx_id: null, verified: false, committed: false}` with the record at
# transaction 118, and on the erasure path the same cut gave DELETE 503, the
# tombstone committed at 121, 772 bytes of payload still in the store and
# content writes for that call_id frozen at 409.
#
# Three answers, so the caller is never told a fact this service does not
# have. `unknown` is what a response reports as `committed: null`.
PRESENT = "present"
ABSENT = "absent"
UNKNOWN = "unknown"


def _committed_tx_for_value(client, key: bytes, value: bytes) -> tuple[str, int | None]:
    """`(state, tx)` for exactly these bytes under `key`.

    D40. Stricter than _committed_tx_for below, and deliberately so: it is
    called when nothing is known about whether the write landed, so a record
    that was already under this key before the call must not be reported as
    the call's own. Byte equality is the whole check, and it is exact.

    D45: a read that raised answers `unknown`, never `absent`. A record under
    this key holding *different* bytes is `absent` and not `unknown` - that
    is an answer, and it is the answer that says this write did not land.
    """
    try:
        got = client.get(key)
    except Exception as exc:
        logger.error("Could not read back a key whose write raised: %s", exc)
        return UNKNOWN, None
    if got is None or got.value != value:
        return ABSENT, None
    return PRESENT, int(got.tx)


def _committed_tx_for(client, key: bytes) -> tuple[str, int | None]:
    """`(state, tx)` for whatever the ledger holds under `key`.

    Read with a plain `get`, deliberately: this is called when a proof has
    just failed, so a verified read would fail the same way and answer
    nothing. What it establishes is narrow and stated as such - a record is
    present under this key at this transaction. It is the same question the
    caller would ask, asked here so the caller does not have to guess from a
    response that withheld it.

    D45: `unknown` when the read could not run. On this path the commit is
    already known to have happened - `verifiedSet` commits at
    service.VerifiableSet and every proof failure is raised after that line -
    so answering `absent` here reported a committed record as never having
    been written, which is the same false claim D40 removed one branch over.
    """
    try:
        got = client.get(key)
    except Exception as exc:
        logger.error("Could not read back a key whose proof failed: %s", exc)
        return UNKNOWN, None
    if got is None:
        return ABSENT, None
    return PRESENT, int(got.tx)


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
# P3c3d-9 (Phase 3c-3d): the first integer a float64 cannot follow.
# zscan scores are float64, so no position at or above this is distinct
# from its neighbour. Both the reserve and every allocation are bounded
# by it: the reserve check catches a seam that is already past the
# boundary, and the allocator refuses the write that would cross it.
MAX_POSITION = 2 ** 53


def validate_reserve(raw: str, source: str = "AIL_RESERVED_POSITIONS") -> int:
    """A reserve is a positive integer below 2**53. Anything else refuses at load.

    A reserve at or above 2**53 is refused too (P3c3d-9). Positions are
    float64 scores in a zset, and 2**53 is the first integer whose successor
    is not representable, so above it distinct positions collapse onto the
    same score. Measured on a virgin ledger at
    AIL_RESERVED_POSITIONS=9007199254740993: six writes produced four scores,
    three records shared one, the response named a position the index does
    not hold, and /audit was dead at every limit from the sixth write on. All
    four readers agreed with each other about a number that cannot work,
    which is what "bounds below only" bought.
    """
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
    if value >= MAX_POSITION:
        raise RuntimeError(
            f"{source} must be below 2**53 ({MAX_POSITION}); got {value}. A position is a "
            "float64 score in a zset, and above 2**53 consecutive integers are "
            "not distinct scores: allocated positions collapse onto each other, "
            "the write response names a position the index does not hold, and "
            "the order check reads the collapse as a disagreement at every limit."
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


class RecordKeyExists(RuntimeError):
    """This record key is already in the ledger, so the write is refused.

    D39 (Phase 3c-3d). Re-writing an existing key through the ordered route
    is not an update: the record gets a SECOND index entry at a SECOND
    position, and both entries resolve to the key's current transaction.
    D33's order check requires strictly increasing transaction with
    increasing position, so two positions on one transaction is a
    disagreement and `/audit` is refused at every limit for as long as the
    pair stays in the window. Reproduced live before the fix: two ordinary
    well-formed writes, both `verified: true, committed: true`, no
    corruption and no privileged access, and the whole audit page denied.

    Nothing this project writes wants a second version of a record key -
    every ledger key carries a fresh uuid (ledger/immudb_ledger.py) and the
    tombstone key is written once per erasure - so the write is refused
    rather than accommodated. Refused before anything commits: the
    KeyMustNotExist precondition is part of the same ExecAll, so a losing
    writer wrote nothing at all.
    """


class ReserveMismatch(RuntimeError):
    """The ledger's bound reserve is not the reserve this service is configured
    with. Fail closed: a writer allocating against one seam and a reader
    paging against another is the condition D36 exists to make impossible."""


class OrderedCommitUncertain(RuntimeError):
    """The ExecAll was issued and its outcome is not known to this process.

    D45 (Phase 3c-3e). The ordered write is one `ExecAll`, and everything
    before it - the reserve read, the counter read, the ceiling check - can
    fail with nothing written. Once the request is on the wire that stops
    being true, and the two cases need different answers: before it,
    `committed: false` is a fact; at or after it, it is a guess, and the
    guess is what the Phase 3c-3d red team drove. A relay that let the
    ExecAll commit and dropped its response left the record at transaction
    55, the counter advanced, the index entry at position 1000000017 and the
    row on `/audit` reading `policy_allow`, while the response said the write
    did not happen.

    Carries what the route needs in order to ask the ledger instead of
    guessing: the position this attempt would have allocated, and how many
    attempts the commit actually took. `attempts` was reported as 0 on this
    branch while the commit had taken one.
    """

    def __init__(self, cause: Exception, attempted_seq: int, attempts: int):
        super().__init__(str(cause))
        self.cause = cause
        self.attempted_seq = attempted_seq
        self.attempts = attempts


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


def _record_key_present(client, key: bytes) -> bool:
    """Is a record already committed under this key.

    Asked only after a precondition failure, to tell the one unretryable
    cause apart from the two retryable ones (D39). A read that cannot run
    answers False, which retries - the KeyMustNotExist precondition is what
    actually refuses, so a wrong answer here costs an attempt and never
    admits a second write.
    """
    try:
        return client.get(key) is not None
    except Exception:
        return False


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

        # P3c3d-9: the allocator refuses to issue a position that is not a
        # distinct float64 score. The reserve check catches a seam that is
        # already past the boundary; this catches the write that would cross
        # it, which is the other half of the same property. A ledger that
        # reaches it is out of positions and the honest answer is a failed
        # write, which the middleware turns into a denied call.
        if next_seq >= MAX_POSITION:
            raise RuntimeError(
                f"the next commit position would be {next_seq}, at or above 2**53 "
                f"({MAX_POSITION}). A position is a float64 score in a zset, so "
                "beyond that consecutive integers are not distinct scores and the "
                "index stops describing the order the ledger committed in. The "
                "write did not happen."
            )

        # D39: the record key is written once. This is the enforcement, not
        # a read-then-write check - a pre-read races and this does not,
        # because the ledger evaluates it inside the same ExecAll that would
        # do the writing.
        record_key_precondition = schema.Precondition(
            keyMustNotExist=schema.Precondition.KeyMustNotExistPrecondition(key=key)
        )

        operations = [
            schema.Op(kv=schema.KeyValue(key=key, value=value)),
            schema.Op(kv=schema.KeyValue(key=SEQUENCE_KEY, value=str(next_seq).encode())),
            schema.Op(zAdd=schema.ZAddRequest(
                set=view_set, score=float(next_seq), key=key, boundRef=False,
            )),
        ]
        preconditions = [precondition, record_key_precondition]

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
                # D39: three preconditions can fail here and only two of them
                # are worth retrying. ImmuDB names the precondition type and
                # not the key it was about, so the one that is not retryable
                # is identified by asking the ledger: if the record key is
                # present, this attempt lost to it and every later attempt
                # would lose to it too, permanently.
                if _record_key_present(client, key):
                    raise RecordKeyExists(
                        f"a record is already committed under this key "
                        f"({key.decode('utf-8', 'replace')}); the ordered route "
                        "writes a record key once. A second write would give the "
                        "key a second index entry at a second position, both "
                        "resolving to the key's current transaction, which the "
                        "order check reads as a disagreement at every limit."
                    ) from exc
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
            # D45: the request was on the wire when this raised, so whether
            # it committed is not known here. Everything above this call can
            # fail with nothing written; from here it cannot, and the two
            # need different answers.
            raise OrderedCommitUncertain(exc, next_seq, attempts) from exc

        try:
            tx_id = int(resp.id)
        except Exception as exc:
            # Same reason: the ExecAll returned, so it committed, and this is
            # a response this process could not read.
            raise OrderedCommitUncertain(exc, next_seq, attempts) from exc
        with _seq_lock:
            _seq_cache = (next_seq, tx_id)
        if bound_reserve is None:
            _reserve_cache = RESERVED_POSITIONS
        return tx_id, next_seq, attempts

    raise RuntimeError(
        f"sequence allocation gave up after {attempts} rejected attempts; "
        "the ledger write did not happen"
    )


def _committed_position_for(client, view_set: bytes, key: bytes,
                            attempted_seq: int) -> int | None:
    """The position this key actually holds in `view_set`, or None.

    D45 (Phase 3c-3e). The ordered write's ExecAll writes the record, the
    counter advance and the zAdd together, so a record confirmed present in
    the ledger holds the position that ExecAll carried. `attempted_seq` is
    what this process was going to write and is therefore a claim, not a
    fact: it is used only as the bound of the read that confirms it, and the
    position is reported only when the index agrees.

    Bounded to exactly one score, which is why this is not a walk: the
    question is whether THIS key is at THIS position, and a zScan bounded to
    `[seq, seq]` answers it in one call. A view that does not answer, or
    answers with some other key, gives None - reported as `seq: null` beside
    `committed: true`, which says the record is in the ledger and its
    position is not confirmed.

    **P3c3f-4 (Phase 3c-3f): the position returned is read from what came
    back.** This function used to return `attempted_seq` on a key match, so
    the number it reported was the number it asked for and the docstring's
    "the position is reported only when the index agrees" was true only while
    the bound held. D42's whole subject is that a bound can silently not
    hold. Driven by the Phase 3c-3e red team: asked for
    `minscore=maxscore=1000000042.0`, answered with this key at score
    1000000007.0, and it returned 1000000042.

    On a disagreement it answers None and does not raise. `seq: null` beside
    `committed: true` is what D45 already means by "the record is in the
    ledger and its position could not be confirmed", and this path exists to
    report uncertainty honestly; raising would change the response contract
    of the one branch written not to guess. The disagreement is logged at
    error with both scores, because a view answering outside its bound is a
    fact about the ledger and not about this call.
    """
    try:
        entries = client.zScan(zset=view_set, minscore=float(attempted_seq),
                               maxscore=float(attempted_seq), limit=100)
    except Exception as exc:
        logger.error(
            "Could not confirm the position of a record whose write raised: %s", exc)
        return None
    for entry in getattr(entries, "entries", []) or []:
        member = getattr(entry, "key", None)
        if member is None:
            member = getattr(getattr(entry, "entry", None), "key", None)
        if member != key:
            continue
        try:
            returned = float(getattr(entry, "score"))
        except (AttributeError, TypeError, ValueError):
            logger.error(
                "The view %s returned this record with no readable score, so "
                "the position it holds cannot be confirmed: key=%s asked=%s",
                view_set.decode("utf-8", "replace"),
                key.decode("utf-8", "replace")[:120], attempted_seq,
            )
            return None
        if returned != float(attempted_seq):
            logger.error(
                "The view %s answered a read bounded to [%s, %s] with this "
                "record at position %s. The bound was not applied, so the "
                "position this record holds is not confirmed by this read: "
                "key=%s",
                view_set.decode("utf-8", "replace"), float(attempted_seq),
                float(attempted_seq), returned,
                key.decode("utf-8", "replace")[:120],
            )
            return None
        return int(returned)
    return None


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

    D39 (Phase 3c-3d): this route refuses things now. Until this phase it
    refused nothing at all, so every bound P3c3c-2 established sat on the
    plain route only and a caller holding VERIFIER_WRITE_KEY authored the
    ledger's own account of another record's standing by taking this one.
    Two refusals: a `ledger_fault` record or key on any route, and a record
    key that is already in the ledger.
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

    # D39 (Phase 3c-3d): refused at the route, before anything commits. A
    # 400 rather than committed: false, for the same reason POST /write
    # answers 400 - this is a caller asking for something that is never
    # allowed, not a ledger that failed.
    refusal = _refuse_reason_for_ordered_write(key, value)
    if refusal is not None:
        logger.error("Refused an ordered write: %s", refusal)
        raise HTTPException(status_code=400, detail=refusal)

    # P3c3e-2 (Phase 3c-3e): the sentence that used to be here said
    # "everything before this line can fail without anything having been
    # written". That was false, and it is the sentence that would have caught
    # A4.1. `_ordered_commit` issues the ExecAll inside this block, so a
    # failure raised out of it can be a failure of a write that committed.
    #
    # Which one it is, is now carried by the exception type rather than
    # assumed: OrderedCommitUncertain means the request reached the wire, and
    # any other exception means it did not. The uncertain case asks the
    # ledger; the certain case is the only one that may answer
    # `committed: false` without reading anything.
    try:
        client = _get_client()
        tx_id, seq, attempts = _ordered_commit(client, key, value, view_set)
    except RecordKeyExists as exc:
        # D39: nothing was written - the ExecAll carrying this write was
        # refused whole - so this is a refusal and not a failed write. 409
        # rather than 400 because the request is well-formed and the
        # conflict is with the ledger's existing state.
        logger.error("Refused an ordered write: %s", exc)
        raise HTTPException(status_code=409, detail=str(exc))
    except OrderedCommitUncertain as exc:
        # D40 on this route, which never got it (red-team A4.1). The ExecAll
        # was issued; whether it committed is a question for the ledger and
        # not for this process's opinion of its own RPC. Asked with the value
        # as well as the key, exactly as POST /write asks it: a record that
        # was already under this key is not this write.
        logger.error("ordered write error after the ExecAll was issued: %s", exc.cause)
        state, tx_id = _committed_tx_for_value(client, key, value)
        if state == UNKNOWN:
            # D45: neither answer is a fact. Reported as such rather than as
            # the bottom state, which is what put a committed record's row on
            # `/audit` while the response said the write did not happen.
            logger.error(
                "ordered write: the ExecAll was issued and the ledger could not "
                "be read back, so whether the record committed is not established"
            )
            return OrderedWriteResponse(
                tx_id=None, seq=None, verified=False, committed=None,
                attempts=exc.attempts,
                detail=f"{exc.cause}; the ledger could not be read back, so "
                       "whether the record committed is not established",
            )
        if state == ABSENT:
            return OrderedWriteResponse(
                tx_id=None, seq=None, verified=False, committed=False,
                attempts=exc.attempts, detail=str(exc.cause),
            )
        seq = _committed_position_for(client, view_set, key, exc.attempted_seq)
        logger.error(
            "ordered write: the response was lost and the record is in the ledger "
            "at tx=%s position=%s: %s", tx_id, seq, exc.cause,
        )
        return OrderedWriteResponse(
            tx_id=tx_id, seq=seq, verified=False, committed=True,
            attempts=exc.attempts,
            detail=f"the ordered write's own response was not received ({exc.cause}); "
                   f"the record committed at transaction {tx_id}"
                   + (f" and holds position {seq}" if seq is not None
                      else " and its position could not be confirmed"),
        )
    except Exception as exc:
        # Nothing reached the wire: the client could not be built, the
        # reserve disagreed, the ceiling was reached, or the retry budget ran
        # out. `committed: false` is a fact on this branch and on no other.
        logger.error("ordered write error before the ExecAll was issued: %s", exc)
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
                   f"{tx_id} and holds position {seq}"
                   + _fault_failure_detail(fault_error),
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

    D47 (Phase 3c-3f): that direct RPC is `head_state()` now, shared with the
    two call sites in POST /write and POST /verify that were still calling
    `currentState()` when this docstring was written. One copy, so the rule
    and its argument cannot drift apart at three sites.

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
        # `.state` only: this route already refused above when `_vk` is None,
        # so `checked` is True here by construction. R6's rule is met by the
        # refusal, which is the stronger of the two expressions.
        state = head_state(client).state
    except BadSignatureError as exc:
        logger.error("CurrentState signature did not verify: %s", exc)
        raise HTTPException(
            status_code=503,
            detail="ImmuDB's current state is not signed by the configured key",
        )
    except Exception as exc:
        logger.error("CurrentState RPC failed: %s", exc)
        raise HTTPException(status_code=503, detail=f"ImmuDB unavailable: {exc}")

    return CurrentStateResponse(
        db=state.db,
        tx_id=state.txId,
        tx_hash=base64.b64encode(state.txHash).decode(),
        signature=base64.b64encode(state.signature).decode(),
        signing_key_fingerprint=signing_key_fingerprint(),
    )


def _state_read(client, anchor) -> tuple[int | None, StateRead]:
    """`state_id`, and the account of how it was read. Never raises.

    `state_id` keeps the meaning it has always had and is not redefined here:
    on the unanchored path it is the ledger's head, on the anchored path it is
    the anchor this service persists. The state the proof ran against is
    already on the response twice, as `proof_material.source_state.tx_id` and
    as `prove_since_tx`; a third copy of a reported number is not what this
    is.

    What is new is that this read may fail without that failing the record.
    Before R6 it could not fail visibly at all: it ran inside the proof's own
    `try`, so its failure was reported as the record's. Moving it out without
    reporting it would be the opposite defect - `state_id` silently null with
    nothing saying why - so its outcome is returned alongside it and reaches
    the caller in `VerifyResponse.state_read`.

    Not raising is the point rather than an incidental property. Every caller
    of this function has already established that a proof succeeded, and has
    no failure branch left that would be honest to take.
    """
    source = "head" if anchor is None else "anchor"
    try:
        if anchor is None:
            head = head_state(client)
            if not head.checked:
                # R6-3, the reporting half of the one rule. See HeadRead.
                return head.state.txId, StateRead(
                    source=source,
                    status=STATE_READ_UNCHECKED,
                    detail=(
                        "no ImmuDB signing key is configured "
                        "(IMMUDB_SIGNING_PUBKEY), so nothing checked that this "
                        "is a state this ledger published; it is the server's "
                        "word for its own head"
                    ),
                )
            return head.state.txId, StateRead(source=source, status=STATE_READ_OK)

        state = client._rs.get()
        if getattr(client, "_vk", None) is None:
            # Same rule, the other path. `_rs.get()` can answer from the state
            # file, which D47 reads unchecked on purpose (it is the ADR-0006
            # tamper vector), so with no key configured this number is not one
            # this service checked either.
            return state.txId, StateRead(
                source=source,
                status=STATE_READ_UNCHECKED,
                detail=(
                    "no ImmuDB signing key is configured "
                    "(IMMUDB_SIGNING_PUBKEY), so nothing checked the anchor "
                    "this reports"
                ),
            )
        return state.txId, StateRead(source=source, status=STATE_READ_OK)
    except Exception as exc:                                      # noqa: BLE001
        logger.warning(
            "The %s read that reports state_id failed: %s: %s. The record's "
            "own proof is unaffected and is not described by this.",
            source, type(exc).__name__, exc,
        )
        return None, StateRead(
            source=source,
            status=STATE_READ_UNAVAILABLE,
            detail=(
                f"the {source} read that reports state_id failed "
                f"({type(exc).__name__}: {exc}); this says nothing about the "
                "record, whose proof had already succeeded"
            ),
        )


def _verified_response(source_state, ventry, resp,
                       state_id, state_read) -> VerifyResponse:
    """The response for a record whose proof has already succeeded.

    Split out of `verify()` and called from outside that function's `try` so
    that the code running after the verdict is a region with its own name,
    rather than the tail of a block whose every handler answers
    `verified=False`. See the R6 comment at the call site for why.
    """
    logger.info(
        "Verified read: tx=%d anchor=%d state_id=%s verified=%s (%s: %s)",
        resp.id,
        source_state.txId,
        state_id,
        resp.verified,
        state_read.source,
        state_read.status,
    )
    return VerifyResponse(
        verified=True,
        tx_id=resp.id,
        value=base64.b64encode(resp.value).decode(),
        timestamp=resp.timestamp,
        state_id=state_id,
        state_read=state_read,
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

        # The proof has succeeded. Everything that reports it now happens
        # below, outside this `try` - see the R6 block after the handlers.
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

    # ---- R6: past this point the proof has already succeeded -------------
    #
    # Nothing below may turn `verified=True` into a failure response. Six
    # things used to run inside the `try` above after `sdk_verified_get.call`
    # had returned a verified entry - the head read, the anchored path's
    # `_rs.get()`, four base64 encodes, `ventry.SerializeToString()` and
    # `signing_key_fingerprint()` - none of which has any bearing on whether
    # the proof ran, and all of which shared that block's handlers. A
    # `BadSignatureError` out of any of them was reported as
    # `error_class="signature_failure"`, which `/audit` renders as
    # `state: "failed"`: a positive tamper claim, on every record of a sound
    # page, on the read path an auditor uses. A system asserting tampering it
    # has not detected is worse than one failing to detect tampering.
    #
    # This is D40's argument applied to the read path. D40 moved the state
    # read out of `POST /write`'s proof `try` in Phase 3c-3d for exactly this
    # reason and left this route alone.
    #
    # **The guarantee is structural, not a list of six.** The region below
    # cannot reach a handler that answers `verified=False`, because there is
    # no such handler in scope: the one `except` here has a single possible
    # verdict. A seventh thing added to this region inherits that rather than
    # needing its own guard, which is the difference between fixing the
    # property and fixing the line the red team happened to name.
    state_id, state_read = _state_read(client, payload.anchor)
    try:
        return _verified_response(source_state, ventry, resp,
                                  state_id, state_read)
    except Exception as exc:                                      # noqa: BLE001
        logger.error(
            "verifiedGet: tx=%s proved, and assembling the response raised "
            "%s: %s. The record verified; this response describes the "
            "reporting, not the record.",
            getattr(resp, "id", None), type(exc).__name__, exc,
        )
        return VerifyResponse(
            verified=True,
            tx_id=getattr(resp, "id", None),
            state_id=state_id,
            state_read=state_read,
            detail=(
                f"the record's proof succeeded; assembling the response "
                f"around it did not ({type(exc).__name__}: {exc})"
            ),
        )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8003, workers=1)
