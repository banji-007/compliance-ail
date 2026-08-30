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


def run_forever() -> None:
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

# Must match verifier/main.py::_VIEW_SETS and control_plane/main.py.
VIEW_SETS = ("ail_view:decision:v1", "ail_view:intent:v1")

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


def collect_positions(client, headers) -> set[float]:
    """Every position held across every view, paged past zscan's 2500 cap."""
    positions: set[int] = set()
    for view_set in VIEW_SETS:
        min_score = None
        while True:
            body = {"set": base64.b64encode(view_set.encode()).decode(),
                    "desc": False, "limit": _ZSCAN_PAGE}
            if min_score is not None:
                body["minScore"] = {"score": min_score}
            resp = client.post(f"{IMMUDB_URL}/api/v2/db/zscan", json=body, headers=headers)
            if resp.status_code != 200:
                break
            rows = resp.json().get("entries", [])
            if not rows:
                break
            before = len(positions)
            for row in rows:
                # `.get`, because protobuf omits a zero-valued score field.
                positions.add(float(row.get("score", 0.0)))
            min_score = float(rows[-1]["score"])
            if len(rows) < _ZSCAN_PAGE or len(positions) == before:
                break
    return positions


def reconcile_once() -> dict:
    """One pass. Returns what was found; never raises on a hole.

    A hole is a finding to report, not an exception to propagate - this loop
    reports, it does not gate.
    """
    import httpx

    with httpx.Client(timeout=60.0) as client:
        headers = _immudb_login(client)

        # getall, not get: ImmuDB has no POST /api/v2/db/get, only
        # GET /api/v2/db/get/{key} and POST /api/v2/db/getall. The missing
        # route answers 404 for every key, which would make this report
        # "the counter has never been written" forever.
        resp = client.post(f"{IMMUDB_URL}/api/v2/db/getall",
                           json={"keys": [base64.b64encode(SEQUENCE_KEY.encode()).decode()]},
                           headers=headers)
        entries = resp.json().get("entries", []) if resp.status_code == 200 else []
        if not entries:
            return {"state": "no_sequence", "detail": "the counter has never been written",
                    "allocated": 0, "indexed": 0, "backfilled": 0,
                    "missing": [], "missing_count": 0}
        allocated = int(base64.b64decode(entries[0]["value"]).decode())

        positions = collect_positions(client, headers)

        # Only positions the live counter handed out are reconciled. The CAS
        # allocates integers from 1 up; the backfill places history in the
        # open interval (0, 1) on purpose (see tools/ail_backfill_index.py),
        # and those were never allocated by the counter, so reconciling them
        # against it would report a shortfall on every pass.
        live = {int(n) for n in positions if n >= 1 and float(n).is_integer()}
        missing = sorted(set(range(1, allocated + 1)) - live)

        result = {
            "state": "clean" if not missing else "holes",
            "allocated": allocated,
            "indexed": len(live),
            "backfilled": len(positions) - len(live),
            "missing": missing[:100],
            "missing_count": len(missing),
        }
        if missing:
            logger.error(
                "Sequence reconciliation found %d hole(s): the counter allocated %d "
                "position(s) and the views hold %d. A position is consumed only by a "
                "commit that happened, so each hole is a committed record missing from "
                "its view index. First few: %s",
                len(missing), allocated, len(live), missing[:20],
            )
        else:
            logger.info(
                "Sequence reconciliation clean: %d allocated, %d indexed, %d backfilled",
                allocated, len(live), result["backfilled"],
            )
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
