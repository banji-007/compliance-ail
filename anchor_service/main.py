"""
AIL Anchor Service - D23, Phase 3b
==================================
A periodic job, not a request handler. Every cycle it asks the verifier for
ImmuDB's current signed state, submits that state's canonical payload to a
public Rekor v2 instance with a self-managed key, and records the resulting
transparency log entry in the control plane's anchor store.

Why there is no second Merkle tree
----------------------------------
ImmuDB's transaction hash is already a Merkle root, and
docs/reports/spike-consistency-proof.md probe 7d confirmed the server signs
the state at an arbitrary transaction, not only at the head. So a checkpoint
is a state ImmuDB already signed, and the only thing this service adds is
publication.

This is the project's one deliberately fail-open subsystem
------------------------------------------------------------
OPA missing, ImmuDB missing, SPIRE missing, the verifier missing: all DENY,
by explicit project rule. Anchoring is the documented exception. If the log
is unreachable, if TUF is unreachable, if the submission is refused, this
process logs an error and waits for the next cycle. Nothing blocks, nothing
denies, no record fails to be written.

The exception is bounded by its other half: fail-closed on the claim. A
record whose state was never anchored gets a bundle that says so in an
explicit field (control_plane/main.py::_external_anchor_section). The store
only ever receives a checkpoint the log actually accepted - submission
happens first and recording second - so "a row exists" and "a public log
holds this" are the same statement rather than two that can drift.

See docs/adr/0012-writer-signing-and-external-anchoring.md.
"""

import hashlib
import json
import base64
import logging
import os
import sys
import time

import httpx

# provenance/ is copied into this service's image next to main.py, and sits
# at the repo root in a checkout. Both candidates are tried, the same way
# ledger/immudb_ledger.py and control_plane/main.py resolve it, so this
# module imports identically in the container and under pytest.
for _provenance_parent in (
    os.path.dirname(os.path.abspath(__file__)),
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
):
    if os.path.isdir(os.path.join(_provenance_parent, "provenance")):
        if _provenance_parent not in sys.path:
            sys.path.insert(0, _provenance_parent)
        break

from provenance.anchor import (  # noqa: E402
    ANCHOR_PAYLOAD_FORMAT,
    anchor_payload_digest,
    canonical_anchor_bytes,
)
from provenance.record_signature import key_fingerprint, load_signing_key  # noqa: E402
from provenance.rekor import (  # noqa: E402
    build_hashedrekord_request,
    discover_log_url,
    fetch_sigstore_config,
    submit,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("anchor-service")

VERIFIER_URL = os.getenv("VERIFIER_URL", "http://verifier:8003")
CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL", "http://ail-control-plane:8002")
VERIFIER_READ_KEY = os.getenv("VERIFIER_READ_KEY", "")
CONTROL_PLANE_WRITE_KEY = os.getenv("CONTROL_PLANE_WRITE_KEY", "")

# The self-managed anchoring key. Never Fulcio, never keyless: B1 confirmed
# Rekor v2 accepts a caller-supplied raw public key as a first-class verifier
# option, and a keyless flow would put an OIDC identity on the public record
# where a bare P-256 point is enough.
ANCHOR_SIGNING_KEY_PATH = os.getenv("AIL_ANCHOR_SIGNING_KEY", "")

# P3c3c-4 (Phase 3c-3c): reconcile-only mode.
#
# The sequence reconciliation lives in this service because this service is
# already the right shape - a periodic loop that observes and never gates a
# write. The cost of that placement was that reconciliation was exercised by
# no test at all, because anchor-service is absent from
# docker-compose.test.yml and that absence is load-bearing: the whole suite
# running with anchoring entirely broken is P3b-5's demonstration, and it
# would be destroyed by adding the anchoring loop to CI, which would also
# make CI depend on egress to a public Rekor instance.
#
# So the mode splits the two halves rather than the file. In reconcile-only
# the loop never calls anchor_once, never reads the verifier's /state, never
# submits anything and needs no signing key. The reconciler is genuinely
# running as a service and anchoring is still entirely absent from the test
# stack.
RECONCILE_ONLY = os.getenv("AIL_ANCHOR_MODE", "").strip().lower() == "reconcile-only"

# Where each pass writes its verdict, when set. A file rather than a log
# line, because a test has to read the running service's own output and a
# file it can parse says the same thing without teaching the suite to scrape
# a log format. Absent by default: docker-compose.yml sets no path, so
# production behaviour is unchanged.
RECONCILE_REPORT_PATH = os.getenv("AIL_RECONCILE_REPORT_PATH", "")

INTERVAL_SECONDS = float(os.getenv("AIL_ANCHOR_INTERVAL_SECONDS", "300"))

# Sigstore's TUF-distributed configuration changes on the order of months,
# and re-fetching it every cycle would hammer the CDN for nothing. Cached for
# the process and refreshed on this interval; a fetch failure keeps the last
# good copy rather than stopping the cycle, which is the fail-open rule
# applied one level down.
CONFIG_TTL_SECONDS = float(os.getenv("AIL_ANCHOR_CONFIG_TTL_SECONDS", "3600"))

_config_cache = {"fetched_at": None, "trusted_root": None, "signing_config": None}


def _sigstore_config(now: float):
    fetched_at = _config_cache["fetched_at"]
    if fetched_at is not None and (now - fetched_at) < CONFIG_TTL_SECONDS:
        return _config_cache["trusted_root"], _config_cache["signing_config"]
    trusted_root, signing_config = fetch_sigstore_config()
    _config_cache.update(
        fetched_at=now, trusted_root=trusted_root, signing_config=signing_config
    )
    return trusted_root, signing_config


def fetch_current_state() -> dict:
    """The ImmuDB signed state to anchor, from the verifier's own /state.

    Read-scoped credential (ADR-0011). The verifier checks the state's ECDSA
    signature against the key on its own volume before handing it over, so
    what arrives here is already a state ImmuDB vouched for rather than one
    a server merely asserted.
    """
    response = httpx.get(
        f"{VERIFIER_URL}/state",
        headers={"X-API-Key": VERIFIER_READ_KEY},
        timeout=15.0,
    )
    response.raise_for_status()
    return response.json()


def record_anchor(checkpoint: dict, external: dict) -> dict:
    """Record the accepted entry in the control plane's anchor store.

    Called only after the log has accepted the entry. The ordering is the
    load-bearing part: a row in that store is what makes a bundle claim
    external corroboration, so a row must never exist for a submission that
    did not happen.
    """
    response = httpx.post(
        f"{CONTROL_PLANE_URL}/anchors",
        json={"checkpoint": checkpoint, "external": external},
        headers={"X-API-Key": CONTROL_PLANE_WRITE_KEY},
        timeout=15.0,
    )
    response.raise_for_status()
    return response.json()


def anchor_once(signing_key, verifying_key, last_anchored_tx: int | None) -> int | None:
    """One anchoring cycle. Returns the transaction anchored, or None.

    Raises on any failure. The caller is what makes this fail-open; keeping
    the raise here means a failure is visible in a test rather than swallowed
    at the point it happens.
    """
    from ecdsa.util import sigencode_der

    state = fetch_current_state()
    tx_id = int(state["tx_id"])
    if last_anchored_tx is not None and tx_id <= last_anchored_tx:
        logger.info("Ledger head is still tx=%d; nothing new to anchor", tx_id)
        return None

    payload = canonical_anchor_bytes(
        state["db"], tx_id, state["tx_hash"], state["signature"]
    )
    digest = anchor_payload_digest(
        state["db"], tx_id, state["tx_hash"], state["signature"]
    )
    signature = signing_key.sign_deterministic(
        payload, hashfunc=hashlib.sha256, sigencode=sigencode_der
    )

    trusted_root, signing_config = _sigstore_config(time.monotonic())
    log_url, source = discover_log_url(trusted_root, signing_config)
    logger.info("Anchoring tx=%d in %s (discovered via %s)", tx_id, log_url, source)

    entry = submit(log_url, build_hashedrekord_request(digest, signature, verifying_key.to_der()))

    checkpoint = {
        "db": state["db"],
        "tx_id": tx_id,
        "tx_hash": state["tx_hash"],
        "signature": state["signature"],
    }
    external = {
        "log_url": log_url,
        "log_url_source": source,
        "log_index": str(entry.get("logIndex")),
        "anchor_key_fingerprint": key_fingerprint(verifying_key),
        "anchor_payload_format": ANCHOR_PAYLOAD_FORMAT,
        "transparency_log_entry": entry,
    }
    result = record_anchor(checkpoint, external)
    logger.info(
        "Anchored tx=%d at log index %s (store: %s)",
        tx_id, external["log_index"], json.dumps(result, separators=(",", ":")),
    )
    return tx_id


def run_reconcile_forever() -> None:
    """P3c3c-4: the reconciliation half, on its own, with no anchoring at all.

    Deliberately not "run_forever with anchoring disabled by a flag inside
    the loop": there is no anchoring key to load, no verifier call, and no
    Rekor submission anywhere on this path, so a stack running this cannot
    accidentally anchor. That is what makes P3b-5's property survive the
    reconciler joining the test stack.
    """
    logger.info(
        "Anchor service starting in reconcile-only mode: interval=%ss report=%s",
        RECONCILE_INTERVAL_SECONDS, RECONCILE_REPORT_PATH or "(none)",
    )
    while True:
        try:
            reconcile_once()
        except Exception as exc:
            logger.error(
                "Reconciliation pass failed (reports only, writes are unaffected): %s: %s",
                type(exc).__name__, exc,
            )
        time.sleep(RECONCILE_INTERVAL_SECONDS)


def run_forever() -> None:
    if RECONCILE_ONLY:
        return run_reconcile_forever()
    if not ANCHOR_SIGNING_KEY_PATH or not os.path.exists(ANCHOR_SIGNING_KEY_PATH):
        # The one startup condition that is worth refusing to start over: a
        # process that cannot sign anything would loop forever producing
        # nothing while reporting itself healthy, which is worse than being
        # absent. Absence is already a state the rest of the system handles
        # correctly - every bundle simply says not_anchored.
        raise SystemExit(
            "AIL_ANCHOR_SIGNING_KEY is unset or points at a missing file; "
            "refusing to start an anchoring loop that cannot anchor."
        )
    signing_key, verifying_key = load_signing_key(ANCHOR_SIGNING_KEY_PATH)
    logger.info(
        "Anchor service starting: interval=%ss key=%s",
        INTERVAL_SECONDS, key_fingerprint(verifying_key),
    )

    last_anchored_tx = None
    last_reconciled_at = 0.0
    while True:
        try:
            anchored = anchor_once(signing_key, verifying_key, last_anchored_tx)
            if anchored is not None:
                last_anchored_tx = anchored
        except Exception as exc:
            # D23's named exception, and the only one in this project. An
            # anchoring failure is not a reason to stop writing records, to
            # deny a decision, or to stop trying: it is a reason for the
            # next bundle to say not_anchored, which it will, because
            # nothing was recorded in the store.
            logger.error(
                "Anchoring cycle failed (fail-open by D23, writes are unaffected): %s: %s",
                type(exc).__name__, exc,
            )

        # P3c3b-6: on its own interval, in its own try, so a reconciliation
        # failure cannot stop anchoring and an anchoring failure cannot stop
        # reconciliation. Neither gates a write.
        now = time.monotonic()
        if now - last_reconciled_at >= RECONCILE_INTERVAL_SECONDS:
            last_reconciled_at = now
            try:
                reconcile_once()
            except Exception as exc:
                logger.error(
                    "Reconciliation pass failed (reports only, writes are unaffected): %s: %s",
                    type(exc).__name__, exc,
                )

        time.sleep(INTERVAL_SECONDS)


# ---------------------------------------------------------------------------
# P3c3b-6 (Phase 3c-3b): sequence reconciliation.
# ---------------------------------------------------------------------------
#
# What gaplessness buys. D32 allocates positions under a compare-and-set, and
# a rejected precondition writes nothing at all - no record, no counter
# advance, no index entry. So a sequence number is consumed only by a commit
# that actually happened, and the allocated positions are dense. That turns
# reconciliation into arithmetic over the index alone rather than a full key
# scan of the ledger: if the counter says N and the views hold N positions,
# every allocation is accounted for.
#
# And it makes a hole *evidence*. On a sequence where a crash could burn a
# number, a missing position means nothing in particular. Here it means a
# position was committed and its index entry is not there, which is either
# index corruption or a record removed from a view - both worth a person
# looking.
#
# Why it lives here. This service is already this shape: a periodic loop that
# observes the ledger, reports, and never gates a write. Reconciliation is a
# detector, so running it in the project's one deliberately fail-open
# subsystem costs nothing that matters - a missed pass denies no call and
# loses no record, and the next pass sees the same hole, because an
# append-only ledger does not heal. Putting it anywhere on the write path
# would be strictly worse: it would let a reporting failure deny traffic.

SEQUENCE_KEY = "ail_seq:commit"

# Positions at or below the reserve were placed by the offline backfill and
# were never handed out by the counter, so reconciling them against it would
# report a shortfall on every pass.
#
# D36 (Phase 3c-3c): no longer "must match verifier/main.py" by convention.
# The reserve is bound into the ledger at first allocation, and this reader
# refuses a pass outright if its own value disagrees with the bound one - a
# reconciliation run against a different seam than the writer allocated
# against would report holes and surpluses that are artefacts of the
# disagreement.
RESERVE_KEY = "ail_seq:reserve"


# P3c3d-9 (Phase 3c-3d): the first integer a float64 cannot follow.
# zscan scores are float64, so no position at or above this is distinct
# from its neighbour. Same constant and same rule as
# verifier/main.py::MAX_POSITION.
MAX_POSITION = 2 ** 53


def validate_reserve(raw, source: str = "AIL_RESERVED_POSITIONS") -> int:
    """A reserve is a positive integer below 2**53. Anything else refuses at load.

    Same rule and same words as verifier/main.py::validate_reserve. Three
    copies because three images do not import each other; the ledger's bound
    value is what actually keeps them honest.

    P3c3d-9 (Phase 3c-3d) added the upper bound: a reserve at or above 2**53
    makes allocated positions unrepresentable as distinct float64 scores.
    Measured, six writes produced four scores and /audit was dead at every
    limit from the sixth write on a virgin ledger.
    """
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        raise RuntimeError(
            f"{source} must be an integer; got {raw!r}."
        )
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


RESERVED_POSITIONS = validate_reserve(os.getenv("AIL_RESERVED_POSITIONS", "1000000000"))

# Must match verifier/main.py::_VIEW_SETS and control_plane/main.py. D37
# makes the mapping from a view to the key prefix its members must carry
# explicit, because "every member of a view belongs to that view" is one of
# the three things reconciliation now checks and it cannot be checked
# against a bare list of set names.
VIEW_PREFIXES = {
    "ail_view:decision:v1": "tool_call:",
    "ail_view:intent:v1":   "tool_call_intent:",
}
VIEW_SETS = tuple(VIEW_PREFIXES)

IMMUDB_URL = os.getenv("IMMUDB_URL", "http://immudb:8080")
IMMUDB_USER = os.getenv("IMMUDB_USER", "immudb")
IMMUDB_PASSWORD = os.getenv("IMMUDB_PASSWORD", "immudb")

RECONCILE_INTERVAL_SECONDS = float(os.getenv("AIL_RECONCILE_INTERVAL_SECONDS", "900"))

_ZSCAN_PAGE = 2500


def _immudb_login(client) -> dict:
    resp = client.post(f"{IMMUDB_URL}/api/v2/login", json={
        "user": base64.b64encode(IMMUDB_USER.encode()).decode(),
        "password": base64.b64encode(IMMUDB_PASSWORD.encode()).decode(),
        "database": base64.b64encode(b"defaultdb").decode(),
    })
    resp.raise_for_status()
    return {"Authorization": f"Bearer {resp.json()['token']}"}


def collect_positions(client, headers) -> dict:
    """Every position in every view, per view, with what is wrong with it.

    D37 (Phase 3c-3c). This used to return one flat set of scores unioned
    across every view, and that union is exactly what made a record indexed
    into the wrong view reconcile clean: the position was present, so the
    arithmetic balanced, while the record was absent from every page it
    could be read on. Per view, that is a finding.

    Returns
        {view: {"positions": {score: [key, ...]},
                "foreign": [ {position, key, expected_prefix}, ... ],
                "malformed": [ {reason, ...}, ... ]}}

    **Never raises on one bad row.** `min_score = float(rows[-1]["score"])`
    used to sit two lines after a correct `.get("score", 0.0)`, so a page
    ending on a zero-scored row - protobuf omits a zero-valued field
    entirely - raised KeyError out of the whole pass, and run_forever's
    handler turned that into one log line per interval forever. A row that
    cannot be read is a finding to report, in the same shape as every other
    finding.
    """
    out = {}
    for view_set in VIEW_SETS:
        expected_prefix = VIEW_PREFIXES[view_set]
        positions: dict[float, list[str]] = {}
        foreign: list[dict] = []
        malformed: list[dict] = []
        min_score = None
        while True:
            body = {"set": base64.b64encode(view_set.encode()).decode(),
                    "desc": False, "limit": _ZSCAN_PAGE}
            if min_score is not None:
                body["minScore"] = {"score": min_score}
            resp = client.post(f"{IMMUDB_URL}/api/v2/db/zscan", json=body, headers=headers)
            if resp.status_code != 200:
                malformed.append({"reason": "zscan_failed",
                                  "status": resp.status_code,
                                  "detail": resp.text[:200]})
                break
            rows = resp.json().get("entries", [])
            if not rows:
                break
            before = len(positions)
            for row in rows:
                # `.get`, because protobuf omits a zero-valued score field.
                # A score that will not parse at all is a different thing
                # from a score that is zero, and only the first is a finding.
                raw_score = row.get("score", 0.0)
                try:
                    score = float(raw_score)
                except (TypeError, ValueError):
                    malformed.append({"reason": "unparseable_score",
                                      "view": view_set, "score": repr(raw_score)})
                    continue
                # D42 (Phase 3c-3d): a bounded read asserts on what came
                # back, in the form its bound takes. This read is bounded by
                # `minScore` and not by keys, so the key-range assertion the
                # page's fault read makes does not apply to it and is not
                # bolted on; the equivalent here is that every returned row's
                # score is inside the score bound that was asked for. Read
                # from the row's own `score` field with `.get`, because
                # protobuf omits a zero-valued score entirely.
                #
                # An unrecognised or misspelled parameter is dropped by this
                # REST route without comment, so a bounded read whose bound
                # did not survive becomes an unbounded one at HTTP 200 with
                # nothing in the response saying so. Reported as a finding
                # rather than raised, which is this function's rule for every
                # bad row: a pass that dies on one row reports nothing about
                # any of the others.
                if min_score is not None and score < min_score:
                    malformed.append({"reason": "score_outside_requested_bound",
                                      "view": view_set, "score": score,
                                      "requested_min_score": min_score,
                                      "key": row.get("entry", {}).get("key", "")})
                if "score" not in row:
                    # protobuf's JSON mapping omits a zero-valued field, so a
                    # row with no `score` key is a row scored at exactly zero.
                    # No write path this project has produces one: history is
                    # scored at a transaction id, which starts at 1, and the
                    # compare-and-set allocates above the reserve. It is also
                    # the row the old detector died on - `float(rows[-1]
                    # ["score"])` raised KeyError out of the whole pass. So it
                    # is a finding, read with `.get` and reported, rather than
                    # an exception or a silent zero.
                    malformed.append({"reason": "score_absent_or_zero",
                                      "view": view_set,
                                      "key": row.get("entry", {}).get("key", "")})
                try:
                    key = base64.b64decode(row["entry"]["key"]).decode("utf-8", "replace")
                except Exception as exc:
                    malformed.append({"reason": "unreadable_key", "view": view_set,
                                      "position": score, "detail": str(exc)[:120]})
                    continue
                positions.setdefault(score, []).append(key)
                # Clause one: every member of a view matches that view's
                # prefix. A decision record in the intent view is indexed,
                # accounted for by the arithmetic, and on no page.
                if not key.startswith(expected_prefix):
                    foreign.append({"position": score, "key": key,
                                    "expected_prefix": expected_prefix})
            # The page cursor comes from the same `.get`, for the same
            # reason. This is the line that used to raise.
            try:
                min_score = float(rows[-1].get("score", 0.0))
            except (TypeError, ValueError):
                malformed.append({"reason": "unparseable_page_cursor", "view": view_set})
                break
            if len(rows) < _ZSCAN_PAGE or len(positions) == before:
                break
        out[view_set] = {"positions": positions, "foreign": foreign, "malformed": malformed}
    return out


def _bound_reserve(client, headers) -> int | None:
    """The reserve bound into this ledger by the first allocation, or None."""
    resp = client.post(f"{IMMUDB_URL}/api/v2/db/getall",
                       json={"keys": [base64.b64encode(RESERVE_KEY.encode()).decode()]},
                       headers=headers)
    if resp.status_code != 200:
        return None
    entries = resp.json().get("entries", [])
    if not entries:
        return None
    return validate_reserve(base64.b64decode(entries[0]["value"]).decode(),
                            source="the bound reserve")


def _write_report(result: dict) -> None:
    """P3c3c-4: the pass's own verdict, where a test can read it."""
    if not RECONCILE_REPORT_PATH:
        return
    try:
        os.makedirs(os.path.dirname(RECONCILE_REPORT_PATH), exist_ok=True)
        tmp = RECONCILE_REPORT_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(result, fh)
        os.replace(tmp, RECONCILE_REPORT_PATH)
    except Exception as exc:
        logger.error("Could not write the reconciliation report: %s", exc)


def reconcile_once() -> dict:
    """One pass. Returns what was found; never raises on a finding.

    A finding is something to report, not an exception to propagate - this
    loop reports, it does not gate.

    **D37 (Phase 3c-3c): this is the authoritative order check.** D33's
    comparison on the `/audit` page stays, but its window is the top of the
    index, so a disagreement below it is unreachable at any limit and newer
    traffic clears the fault while the corruption stays. This walks every
    position in every view, so nothing is outside its window, and what it
    finds persists across passes because an append-only ledger does not
    heal.

    What it checks, per view and stated exactly:

      1. every member of a view matches that view's prefix;
      2. the union across views equals the allocated range exactly, in both
         directions - positions the counter handed out that no view holds,
         and positions no counter ever handed out that a view does;
      3. no position appears in two views.

    Clause 3 is a property of the current view set, not a law. It is
    retired the first time a view legitimately overlaps the existing ones,
    which is the incident-first view D32 anticipated - stated here so that
    is a known consequence rather than a surprise to whoever adds it.

    Clause 2's second direction is new. `missing` was computed one way, so
    2510 positions the counter never handed out sat in a view and the
    verdict was `clean` - which mattered because the ordering fault's own
    remediation tells an operator to run this reconciliation.
    """
    import httpx

    with httpx.Client(timeout=60.0) as client:
        headers = _immudb_login(client)

        # D36: refuse the pass rather than report against a seam this
        # deployment does not share with the writer. A mismatch would put
        # committed positions on the wrong side of the boundary and
        # manufacture both holes and surplus.
        bound = _bound_reserve(client, headers)
        if bound is not None and bound != RESERVED_POSITIONS:
            detail = (
                f"this service is configured with AIL_RESERVED_POSITIONS="
                f"{RESERVED_POSITIONS} and the ledger has {bound} bound into it. "
                "Reconciling against a different seam than the writer allocated "
                f"against reports artefacts, not findings. Set this service to {bound}."
            )
            logger.error("Reconciliation refused: %s", detail)
            result = {"state": "reserve_mismatch", "detail": detail,
                      "configured_reserve": RESERVED_POSITIONS, "bound_reserve": bound,
                      "allocated": 0, "indexed": 0, "backfilled": 0,
                      "missing": [], "missing_count": 0, "unallocated": [],
                      "unallocated_count": 0, "foreign": [], "foreign_count": 0,
                      "shared": [], "shared_count": 0, "malformed": [],
                      "malformed_count": 0, "duplicated": [],
                      "duplicated_count": 0}
            _write_report(result)
            return result

        # getall, not get: ImmuDB has no POST /api/v2/db/get, only
        # GET /api/v2/db/get/{key} and POST /api/v2/db/getall. The missing
        # route answers 404 for every key, which would make this report
        # "the counter has never been written" forever.
        resp = client.post(f"{IMMUDB_URL}/api/v2/db/getall",
                           json={"keys": [base64.b64encode(SEQUENCE_KEY.encode()).decode()]},
                           headers=headers)
        entries = resp.json().get("entries", []) if resp.status_code == 200 else []
        if not entries:
            result = {"state": "no_sequence", "detail": "the counter has never been written",
                      "allocated": 0, "indexed": 0, "backfilled": 0,
                      "missing": [], "missing_count": 0, "unallocated": [],
                      "unallocated_count": 0, "foreign": [], "foreign_count": 0,
                      "shared": [], "shared_count": 0, "malformed": [],
                      "malformed_count": 0, "duplicated": [],
                      "duplicated_count": 0}
            _write_report(result)
            return result
        allocated = int(base64.b64decode(entries[0]["value"]).decode())

        per_view = collect_positions(client, headers)

        foreign = [f for v in per_view.values() for f in v["foreign"]]
        malformed = [m for v in per_view.values() for m in v["malformed"]]

        # Clause 3, over live positions only. Backfilled history is scored at
        # each record's own transaction id, and two records committed by one
        # transaction legitimately share a score (the backfill's own
        # docstring says so), so sharing is only a finding where the CAS
        # allocated - and the CAS allocates one position per commit.
        live_by_view = {
            view: {int(n) for n in data["positions"]
                   if n > RESERVED_POSITIONS and float(n).is_integer()}
            for view, data in per_view.items()
        }
        shared = sorted({
            n for a in VIEW_SETS for b in VIEW_SETS if a < b
            for n in (live_by_view.get(a, set()) & live_by_view.get(b, set()))
        })

        # P3c3d-9 (Phase 3c-3d): a key at more than one position, in any
        # range.
        #
        # The fourth condition the red team found reading clean. Every score
        # below the reserve was assumed to be history and was never checked
        # against anything: an already-indexed record given a second position
        # at score 42 reconciled `clean` with every finding category empty,
        # while the page showed the row twice. That is C2's duplication
        # wearing history's clothes, and the ordering fault's own remediation
        # points an operator at this reconciliation.
        #
        # A key at two positions is always wrong, in either range, and needs
        # no assumption about which range it is in. History is scored at each
        # record's own transaction, one position per record; the CAS
        # allocates one position per commit; and since D39 a record key is
        # written once, so there is no legitimate second zAdd for a key.
        # Two records SHARING a score is a different thing and is
        # `shared`/`backfilled` above - this is one key holding two scores.
        duplicated = []
        for view, data in per_view.items():
            by_key: dict[str, list[float]] = {}
            for score, keys in data["positions"].items():
                for key in keys:
                    by_key.setdefault(key, []).append(score)
            for key in sorted(by_key):
                if len(by_key[key]) > 1:
                    duplicated.append({"view": view, "key": key,
                                       "positions": sorted(by_key[key])})

        live = set().union(*live_by_view.values()) if live_by_view else set()
        all_positions = {n for data in per_view.values() for n in data["positions"]}
        # Above the reserve and not an integer is not a position the
        # compare-and-set could have produced either: it allocates integers.
        # Counted here rather than falling through to `backfilled`, which is
        # what would silently absorb it.
        fractional_above_reserve = {n for n in all_positions
                                    if n > RESERVED_POSITIONS and not float(n).is_integer()}
        backfilled = len(all_positions) - len(live) - len(fractional_above_reserve)

        # An empty counter reads as RESERVED_POSITIONS, so this range is empty
        # before the first allocation rather than spanning the whole reserve.
        first = RESERVED_POSITIONS + 1
        handed_out = set(range(first, allocated + 1))
        # Clause 2, both directions. `missing`: the counter consumed it and no
        # view holds it, which on a CAS-gated allocation means a committed
        # record whose index entry is not there. `unallocated`: a view holds a
        # live-range position the counter never handed out, which no
        # legitimate write path can produce.
        missing = sorted(handed_out - live)
        unallocated = sorted((live - handed_out) | fractional_above_reserve)

        findings = bool(missing or unallocated or foreign or shared or malformed
                        or duplicated)
        result = {
            "state": "findings" if findings else "clean",
            "allocated": max(0, allocated - RESERVED_POSITIONS),
            "indexed": len(live),
            "backfilled": backfilled,
            "missing": missing[:100],
            "missing_count": len(missing),
            "unallocated": unallocated[:100],
            "unallocated_count": len(unallocated),
            "foreign": foreign[:100],
            "foreign_count": len(foreign),
            "shared": shared[:100],
            "shared_count": len(shared),
            "malformed": malformed[:100],
            "malformed_count": len(malformed),
            "duplicated": duplicated[:100],
            "duplicated_count": len(duplicated),
            "views": {view: len(data["positions"]) for view, data in per_view.items()},
        }
        if findings:
            logger.error(
                "Sequence reconciliation found %d hole(s), %d unallocated position(s), "
                "%d record(s) in the wrong view, %d position(s) in two views, %d key(s) "
                "at more than one position and %d unreadable row(s). The counter "
                "allocated %d and the views hold %d. A position is consumed only by a "
                "commit that happened, so each hole is a committed record missing from "
                "its view index. First few holes: %s",
                len(missing), len(unallocated), len(foreign), len(shared),
                len(duplicated), len(malformed), allocated, len(live), missing[:20],
            )
        else:
            logger.info(
                "Sequence reconciliation clean: %d allocated, %d indexed, %d backfilled",
                allocated, len(live), result["backfilled"],
            )
        _write_report(result)
        return result


def run_once() -> int:
    """One cycle, then exit. The form the fixture regeneration command and
    any operator forcing an anchor both use.

    Deliberately NOT fail-open: a person who typed "anchor now" wants to
    know whether it worked. Fail-open is a property of the unattended loop,
    where the alternative would be blocking writes on a public service; it
    is not a property of anchoring itself, and a command that printed
    nothing and exited 0 after failing would make the live-submission claim
    in docs/reports/phase-3b.md unfalsifiable.
    """
    if not ANCHOR_SIGNING_KEY_PATH or not os.path.exists(ANCHOR_SIGNING_KEY_PATH):
        logger.error("AIL_ANCHOR_SIGNING_KEY is unset or points at a missing file")
        return 2
    signing_key, verifying_key = load_signing_key(ANCHOR_SIGNING_KEY_PATH)
    anchored = anchor_once(signing_key, verifying_key, None)
    if anchored is None:
        logger.error("Nothing was anchored")
        return 1
    return 0


if __name__ == "__main__":
    if "--once" in sys.argv:
        sys.exit(run_once())
    run_forever()
