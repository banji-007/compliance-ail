"""
D23, the write half: discover a Rekor v2 instance and submit one entry.

Imported only by anchor_service/. decision_service/ and control_plane/ carry
provenance/ for record_signature.py and anchor.py and never import this
module, so neither of them needs sigstore or a route to the public internet.

Discovery, never a hardcoded URL
--------------------------------
docs/reports/spike-signing-anchor.md B1 found the current public v2
instance is scheduled for turndown and its URL rotates, so the URL is read
from Sigstore's own TUF-distributed configuration at run time. Two sources, in
order, both fetched through sigstore-python's own TUF client rather than
over plain HTTPS:

  1. SigningConfig's rekorTlogUrls, filtered to majorApiVersion >= 2 and to
     entries whose validFor window is currently in force. This is the source
     D23 names and the one that should win once Sigstore advertises a v2
     instance there.
  2. TrustedRoot's tlogs[], excluding every baseUrl that SigningConfig
     itself advertises at majorApiVersion < 2, and taking the currently
     in-force entry with the latest validFor.start.

The second source exists because of a live observation, recorded in
docs/reports/spike-signing-anchor.md's re-run section: as of 2026-08-24 the
production SigningConfig lists only the v1 instance under rekorTlogUrls,
while TrustedRoot's tlogs[] names the current v2 instance with a
validFor.start in 2025. Both sources are TUF-distributed Sigstore
configuration; neither is a URL written into this repository - not even in
this comment, which is why the instance is described rather than named, and
tests/test_external_anchor.py scans this file's raw text for one. Which
source answered is recorded on the anchor, so a reader can tell.
"""

import base64
import logging

logger = logging.getLogger(__name__)

REKOR_V2_ENTRIES_PATH = "/api/v2/log/entries"

# CLIENTS.md's own name for a raw P-256 verifier key. Read from
# sigstore/rekor-tiles at main during the spike, not from memory.
KEY_DETAILS_P256 = "PKIX_ECDSA_P256_SHA_256"

DISCOVERY_SIGNING_CONFIG = "signing_config.rekorTlogUrls"
DISCOVERY_TRUSTED_ROOT = "trusted_root.tlogs"


class LogDiscoveryFailed(RuntimeError):
    """No Rekor v2 instance could be discovered from Sigstore's own config."""


def _in_force(valid_for: dict, now) -> bool:
    """Is this validFor window open right now?

    An entry with no start is treated as never in force rather than always:
    guessing in favour of an entry Sigstore did not date would pick a log
    instance on the strength of a missing field.
    """
    from datetime import datetime, timezone

    if not isinstance(valid_for, dict):
        return False
    start = valid_for.get("start")
    end = valid_for.get("end")
    if not start:
        return False

    def _parse(value):
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)

    if _parse(start) > now:
        return False
    if end and _parse(end) <= now:
        return False
    return True


def _start_of(valid_for: dict) -> str:
    return (valid_for or {}).get("start") or ""


def fetch_sigstore_config(tuf_url: str | None = None) -> tuple[dict, dict]:
    """Fetch TrustedRoot and SigningConfig through sigstore-python's TUF client.

    Returns the two parsed JSON documents. This is the one network call this
    module makes that is not the submission itself, and it is the same
    mechanism docs/reports/spike-signing-anchor.md B3 used to obtain the
    trust root it then held out of band.
    """
    import json

    from sigstore._internal.tuf import DEFAULT_TUF_URL, TrustUpdater

    updater = TrustUpdater(tuf_url or DEFAULT_TUF_URL, offline=False)
    with open(updater.get_trusted_root_path(), "r", encoding="utf-8") as f:
        trusted_root = json.load(f)
    with open(updater.get_signing_config_path(), "r", encoding="utf-8") as f:
        signing_config = json.load(f)
    return trusted_root, signing_config


def discover_log_url(trusted_root: dict, signing_config: dict, now=None) -> tuple[str, str]:
    """Return (log_url, which_source_answered). Raises LogDiscoveryFailed.

    Never returns a URL this repository wrote down; every candidate comes
    out of one of the two TUF-distributed documents passed in.
    """
    from datetime import datetime, timezone

    now = now or datetime.now(timezone.utc)

    tlog_urls = signing_config.get("rekorTlogUrls") or []
    v2 = [
        entry
        for entry in tlog_urls
        if int(entry.get("majorApiVersion") or 0) >= 2 and _in_force(entry.get("validFor"), now)
    ]
    if v2:
        best = max(v2, key=lambda e: _start_of(e.get("validFor")))
        return best["url"].rstrip("/"), DISCOVERY_SIGNING_CONFIG

    # Every URL SigningConfig itself calls pre-v2. Derived from the document,
    # not from a hostname pattern this project decided meant "v1".
    pre_v2_urls = {
        (entry.get("url") or "").rstrip("/")
        for entry in tlog_urls
        if int(entry.get("majorApiVersion") or 0) < 2
    }

    candidates = [
        tlog
        for tlog in (trusted_root.get("tlogs") or [])
        if (tlog.get("baseUrl") or "").rstrip("/") not in pre_v2_urls
        and _in_force(((tlog.get("publicKey") or {}).get("validFor")), now)
    ]
    if not candidates:
        raise LogDiscoveryFailed(
            "no Rekor v2 instance is currently advertised by either "
            "SigningConfig.rekorTlogUrls or TrustedRoot.tlogs"
        )
    best = max(candidates, key=lambda t: _start_of((t.get("publicKey") or {}).get("validFor")))
    return best["baseUrl"].rstrip("/"), DISCOVERY_TRUSTED_ROOT


def build_hashedrekord_request(digest: bytes, signature: bytes, public_key_der: bytes) -> dict:
    """The exact request shape docs/reports/spike-signing-anchor.md B2 sent.

    Three things go on the wire and no others: a digest, a signature, and a
    raw public key. There is no name, no label, no payload field - B5
    decoded a live canonicalizedBody to confirm that is all the log ends up
    holding.
    """
    return {
        "hashedRekordRequestV002": {
            "digest": base64.b64encode(digest).decode(),
            "signature": {
                "content": base64.b64encode(signature).decode(),
                "verifier": {
                    "publicKey": {"rawBytes": base64.b64encode(public_key_der).decode()},
                    "keyDetails": KEY_DETAILS_P256,
                },
            },
        }
    }


def submit(log_url: str, request_body: dict, timeout: float = 40.0) -> dict:
    """POST one hashedrekord entry and return the TransparencyLogEntry.

    Rekor v2 blocks until a checkpoint covering the new entry is published
    (CLIENTS.md advises a timeout of at least 20 seconds; B4 measured 2 to 4
    seconds across four live submissions), so the response already carries a
    complete inclusion proof and signed checkpoint. Nothing here retries: a
    failed submission is a fail-open no-op by D23, and the next cycle will
    anchor a later state anyway.
    """
    import httpx

    url = log_url.rstrip("/") + REKOR_V2_ENTRIES_PATH
    response = httpx.post(url, json=request_body, timeout=timeout)
    response.raise_for_status()
    return response.json()
