"""tools/ail_backfill_index.py - Phase 3c-3b (P3c3b-5).

Put records written before the view index existed into it, so the ordered
page has no hole at the seam.

Why this is not optional, and not deferrable. `/audit` selects through the
view index since D32. A record with no index entry is not merely unordered,
it is **absent from every page** - so on an append-only ledger a deferred
backfill is not a cosmetic debt that stays the same size, it is a permanently
growing set of records nobody can read through the audit view. That is the
whole reason this ships in the same phase as the index.

Why it is reachable in one offline pass. `zadd` is an ordinary write that
references an existing key rather than rewriting it, so nothing about the
original record changes and its proofs are untouched. And `Entry.tx` is on
every scan row, so the ledger's own commit order for the historical records
is already known and does not have to be reconstructed from their contents.

What order it assigns, and why it is fractional. Historical records are
sorted by their transaction id - the order the ledger actually committed
them in - and placed in the open interval (0, 1), evenly spaced. The CAS
hands out integer positions from 1 up, so history sorts below every
allocated position without renumbering anything and without colliding.

Not negative, which was the first thing tried. ImmuDB's `zscan` under
`desc: true` silently omits negatively-scored members - measured live, and
an explicit minScore does not bring them back. History scored below zero
would be indexed and still absent from every page, which is the defect this
index exists to remove, reintroduced by the migration meant to fix it. Not
zero either: protobuf's JSON mapping omits a zero-valued field, so a score
of exactly 0 comes back with no "score" key at all.

Ordering holds within one run. A second run over records written after the
first would place them in (0, 1) as well, against a larger denominator, so
the two batches can interleave. That is stated rather than defended: this is
a one-time migration, every write after it takes a CAS-allocated position,
and the second run is expected to index nothing at all.

Usage, against a running stack:

    python tools/ail_backfill_index.py --dry-run
    python tools/ail_backfill_index.py

Idempotent: a record already in the view is skipped, so re-running after an
interrupted pass finishes the job rather than double-indexing.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys

import httpx

IMMUDB_URL = os.getenv("IMMUDB_URL", "http://localhost:8080")
IMMUDB_USER = os.getenv("IMMUDB_USER", "immudb")
IMMUDB_PASSWORD = os.getenv("IMMUDB_PASSWORD", "immudb")

SEQUENCE_KEY = "ail_seq:commit"

# Must match verifier/main.py::_VIEW_SETS and control_plane/main.py's
# _VIEW_DECISION / _VIEW_INTENT. Three copies of these names is two too
# many, but they live in three images that do not import each other.
VIEWS = {
    "decision": ("tool_call:", "ail_view:decision:v1"),
    "intent":   ("tool_call_intent:", "ail_view:intent:v1"),
}

SCAN_PAGE = 2500        # ImmuDB's own scan ceiling, measured in Phase 3c-3a


def b64(value) -> str:
    return base64.b64encode(value if isinstance(value, bytes) else value.encode()).decode()


def unb64(value: str) -> bytes:
    return base64.b64decode(value)


def login(client: httpx.Client) -> dict:
    resp = client.post(f"{IMMUDB_URL}/api/v2/login", json={
        "user": b64(IMMUDB_USER),
        "password": b64(IMMUDB_PASSWORD),
        "database": b64("defaultdb"),
    })
    resp.raise_for_status()
    return {"Authorization": f"Bearer {resp.json()['token']}"}


def scan_all(client: httpx.Client, headers: dict, prefix: str) -> list[dict]:
    """Every key under a prefix, walked in pages because scan caps at 2500."""
    out: list[dict] = []
    seek = ""
    while True:
        body = {"prefix": b64(prefix), "desc": False, "limit": SCAN_PAGE}
        if seek:
            body["seekKey"] = seek
        resp = client.post(f"{IMMUDB_URL}/api/v2/db/scan", json=body, headers=headers)
        resp.raise_for_status()
        entries = resp.json().get("entries", [])
        if not entries:
            break
        out.extend(entries)
        if len(entries) < SCAN_PAGE:
            break
        seek = entries[-1]["key"]
    return out


def indexed_keys(client: httpx.Client, headers: dict, view_set: str) -> set[bytes]:
    """Which keys the view already holds, so a re-run does not double-index."""
    seen: set[bytes] = set()
    resp = client.post(f"{IMMUDB_URL}/api/v2/db/zscan", json={
        "set": b64(view_set), "desc": False, "limit": SCAN_PAGE,
    }, headers=headers)
    if resp.status_code != 200:
        return seen
    for row in resp.json().get("entries", []):
        seen.add(unb64(row["key"]))
    return seen


def current_sequence(client: httpx.Client, headers: dict) -> int:
    # getall, not get: ImmuDB routes GET /api/v2/db/get/{key} and POST
    # /api/v2/db/getall, but there is no POST /api/v2/db/get - it answers
    # 404 for every key, which reads exactly like "the counter has never
    # been written" and would silently start every backfill from zero.
    resp = client.post(f"{IMMUDB_URL}/api/v2/db/getall", json={"keys": [b64(SEQUENCE_KEY)]},
                       headers=headers)
    if resp.status_code != 200:
        return 0
    entries = resp.json().get("entries", [])
    if not entries:
        return 0
    try:
        return int(unb64(entries[0]["value"]).decode())
    except Exception:
        return 0


def backfill(dry_run: bool = False) -> dict:
    """Returns a summary. Safe to re-run."""
    summary = {"views": {}, "total_indexed": 0, "dry_run": dry_run}

    with httpx.Client(timeout=120.0) as client:
        headers = login(client)

        pending: list[tuple[str, bytes, int]] = []   # (view, key, tx)
        for view, (prefix, view_set) in VIEWS.items():
            already = indexed_keys(client, headers, view_set)
            rows = scan_all(client, headers, prefix)
            missing = []
            for row in rows:
                key = unb64(row["key"])
                if key in already:
                    continue
                missing.append((view, key, int(row.get("tx", 0))))
            summary["views"][view] = {
                "records": len(rows), "already_indexed": len(already), "to_index": len(missing),
            }
            pending.extend(missing)

        # The ledger's own commit order across both views, so a decision and
        # the intent that preceded it keep their real relative order.
        pending.sort(key=lambda item: item[2])

        live_seq = current_sequence(client, headers)
        summary["sequence_at_start"] = live_seq

        # Evenly spaced strictly inside (0, 1): positive so `desc` returns
        # them, non-zero so the score field survives JSON encoding, and below
        # the CAS's first position (1) so history sorts under live traffic.
        total = len(pending)
        scores = [(j + 1) / (total + 1) for j in range(total)]
        summary["assigned_range"] = [scores[0], scores[-1]] if pending else None

        if dry_run:
            summary["total_indexed"] = 0
            return summary

        for (view, key, _tx), score in zip(pending, scores):
            _prefix, view_set = VIEWS[view]
            resp = client.post(f"{IMMUDB_URL}/api/v2/db/zadd", json={
                "set": b64(view_set), "score": score, "key": b64(key),
            }, headers=headers)
            resp.raise_for_status()

        summary["total_indexed"] = len(pending)
        return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true",
                        help="report what would be indexed and change nothing")
    args = parser.parse_args()

    summary = backfill(dry_run=args.dry_run)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
