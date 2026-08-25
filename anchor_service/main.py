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
        time.sleep(INTERVAL_SECONDS)


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
