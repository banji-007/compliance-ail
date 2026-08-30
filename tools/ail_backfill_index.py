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

What order it assigns: **a historical record's score is its own
`entry.tx`**. That is the ledger's own commit order for it, already known
and requiring no reconstruction, and it makes the seam between history and
live traffic a number rather than a cursor:

    positions 1 .. RESERVED_POSITIONS      backfilled history, score == tx
    positions RESERVED_POSITIONS + 1 ..    allocated by the CAS

The live counter is seeded above the reserve, so every live position is
strictly greater than every historical one and the page is monotone across
the boundary by construction. This pass seeds it if a counter is already
running below the reserve, and verifier/main.py starts a fresh counter above
it, so the seam lands in the same place whether or not a backfill ever runs.

Why `tx` and not a rank within the pass. Ranking was the first
implementation: history sorted by tx and mapped onto evenly spaced values in
(0, 1). It is monotone within one pass and not across two, because a second
pass computes a different rank against a different denominator and
interleaves with the first. A score that *is* the transaction id is stable
however many passes run and in whatever order, so re-running after finding
more history extends the ordering instead of disturbing it.

Two constraints on what may be used as a position, both measured rather than
assumed. ImmuDB's `zscan` under `desc: true` silently omits
negatively-scored members and an explicit minScore does not bring them back,
so history scored below zero would be indexed and still absent from every
page - this index's own defect, reintroduced by the migration meant to fix
it. And protobuf's JSON mapping omits a zero-valued field, so a score of
exactly 0 comes back with no "score" key at all. Transaction ids start at 1,
so both are avoided by construction.

Records sharing one transaction share a score. Two records committed by the
same `ExecAll` or `setAll` are the same commit, so ordering them against
each other is not a question the ledger answers; the page presents them
adjacently in an unspecified order.

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

# Must match verifier/main.py::RESERVED_POSITIONS and control_plane's own
# copy. Positions at or below this belong to backfilled history.
RESERVED_POSITIONS = int(os.getenv("AIL_RESERVED_POSITIONS", "1000000000"))

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


def seed_counter_above_reserve(client: httpx.Client, headers: dict) -> dict:
    """Move a counter that is running below the reserve up to it.

    Only ever raises the counter, never lowers it, and does it under the same
    KeyNotModifiedAfterTX precondition every allocation uses - so a live
    writer racing this either wins and is seen, or loses and retries. A
    counter already above the reserve is left alone.

    Needed because a deployment can have been allocating before this reserve
    existed, in which case its live positions and the range history is about
    to be scored into would overlap.
    """
    observed = _counter_with_tx(client, headers)
    if observed is None:
        # No counter yet: verifier/main.py's first allocation starts above the
        # reserve on its own, so there is nothing to seed.
        return {"seeded": False, "reason": "no counter yet", "value": None}
    value, tx = observed
    if value >= RESERVED_POSITIONS:
        return {"seeded": False, "reason": "already above the reserve", "value": value}

    resp = client.post(f"{IMMUDB_URL}/api/v2/db/execall", json={
        "Operations": [{"kv": {"key": b64(SEQUENCE_KEY),
                               "value": b64(str(RESERVED_POSITIONS))}}],
        "preconditions": [{"keyNotModifiedAfterTX": {"key": b64(SEQUENCE_KEY),
                                                     "txID": str(tx)}}],
        "noWait": False,
    }, headers=headers)
    resp.raise_for_status()
    return {"seeded": True, "from": value, "value": RESERVED_POSITIONS}


def _counter_with_tx(client: httpx.Client, headers: dict):
    """(value, tx it was last modified at), or None if never written."""
    resp = client.post(f"{IMMUDB_URL}/api/v2/db/getall",
                       json={"keys": [b64(SEQUENCE_KEY)]}, headers=headers)
    if resp.status_code != 200:
        return None
    entries = resp.json().get("entries", [])
    if not entries:
        return None
    return int(unb64(entries[0]["value"]).decode()), int(entries[0]["tx"])


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

        summary["sequence_at_start"] = current_sequence(client, headers)
        summary["reserved_positions"] = RESERVED_POSITIONS

        # Fail closed rather than guess. A historical transaction id at or
        # above the reserve would be scored on top of live positions, which
        # is worse than not running: the page would interleave history with
        # current traffic and D33 would fault on it.
        over = [tx for _v, _k, tx in pending if tx >= RESERVED_POSITIONS]
        if over:
            raise SystemExit(
                f"refusing to backfill: {len(over)} record(s) have a transaction id at "
                f"or above the reserve of {RESERVED_POSITIONS} (highest {max(over)}). "
                "Raise AIL_RESERVED_POSITIONS above the ledger's highest transaction "
                "id, on every service, and re-run."
            )

        # The score IS the transaction id. See the module docstring for why
        # this rather than a rank within the pass.
        scores = [float(tx) for _v, _k, tx in pending]
        summary["assigned_range"] = [scores[0], scores[-1]] if pending else None

        if dry_run:
            summary["total_indexed"] = 0
            summary["seed"] = {"seeded": False, "reason": "dry run", "value": None}
            return summary

        # Before any zadd: if the counter is below the reserve, every position
        # it goes on to hand out would collide with the range being written
        # here. Raising it first means a writer racing this backfill cannot
        # take a position inside the reserve.
        summary["seed"] = seed_counter_above_reserve(client, headers)

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
