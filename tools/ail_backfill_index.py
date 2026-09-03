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

Why `tx` and not a rank within the pass. A rank is monotone within one pass
and not across two: a second pass computes a different rank against a
different denominator and interleaves with the first. A score that *is* the
transaction id is stable however many passes run and in whatever order, so
re-running after finding more history extends the ordering instead of
disturbing it.

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

# Positions at or below this belong to backfilled history.
#
# D36 (Phase 3c-3c): no longer "must match verifier/main.py" by convention.
# The reserve is bound into the ledger at first allocation and this pass
# reads the bound value, never its own default - a backfill scoring history
# against a different seam than the writer allocates against is how live
# positions end up inside the reserve, which is exactly what raising the
# setting used to do.
RESERVE_KEY = "ail_seq:reserve"


# P3c3d-9 (Phase 3c-3d): the first integer a float64 cannot follow.
# zscan scores are float64, so no position at or above this is distinct
# from its neighbour. Same constant and same rule as
# verifier/main.py::MAX_POSITION.
MAX_POSITION = 2 ** 53


def validate_reserve(raw, source: str = "AIL_RESERVED_POSITIONS") -> int:
    """A reserve is a positive integer below 2**53. Anything else refuses.

    Same rule and same words as verifier/main.py::validate_reserve.

    P3c3d-9 (Phase 3c-3d) added the upper bound: a reserve at or above 2**53
    makes allocated positions unrepresentable as distinct float64 scores.
    Measured, six writes produced four scores and /audit was dead at every
    limit from the sixth write on a virgin ledger.
    """
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        raise SystemExit(f"{source} must be an integer; got {raw!r}.")
    if value < 1:
        raise SystemExit(
            f"{source} must be a positive integer; got {value}. At or below zero "
            "every allocated position would be at or below zero too, and zscan "
            "under desc omits negatively-scored members and reports a zero score "
            "as no score at all."
        )
    if value >= MAX_POSITION:
        raise SystemExit(
            f"{source} must be below 2**53 ({MAX_POSITION}); got {value}. A position is a "
            "float64 score in a zset, and above 2**53 consecutive integers are "
            "not distinct scores: allocated positions collapse onto each other, "
            "the write response names a position the index does not hold, and "
            "the order check reads the collapse as a disagreement at every limit."
        )
    return value


RESERVED_POSITIONS = validate_reserve(os.getenv("AIL_RESERVED_POSITIONS", "1000000000"))


def bound_reserve(client: httpx.Client, headers: dict) -> int | None:
    """The reserve bound into this ledger, or None if none is bound yet."""
    resp = client.post(f"{IMMUDB_URL}/api/v2/db/getall",
                       json={"keys": [b64(RESERVE_KEY)]}, headers=headers)
    if resp.status_code != 200:
        raise SystemExit(
            f"refusing to backfill: could not read the bound reserve (HTTP "
            f"{resp.status_code}). Scoring history against an unknown seam is "
            "how live positions end up inside the reserve."
        )
    entries = resp.json().get("entries", [])
    if not entries:
        return None
    return validate_reserve(unb64(entries[0]["value"]).decode(),
                            source="the bound reserve")

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
    """Every key under a prefix, walked in pages because scan caps at 2500.

    **P3c3e-4 (Phase 3c-3e): the read asserts on what came back.** D42 stated
    the rule and covered two of the four bounded reads in this repository;
    this is one of the two it missed, and it is the one whose results are
    zAdded straight into a view index (`backfill()` below). ImmuDB's REST
    route drops an unrecognised or misspelled parameter without comment and
    answers 200, so a `prefix` that did not survive turns this into a walk of
    the whole ledger. Driven with a client that answers outside the prefix:

        asked for prefix 'tool_call:', RETURNED, no complaint:
           ail_seq:counter / ail_seq:reserve
           ledger_fault:00000000000000000001:x:y / content_erasure:abc

    Every one of those would then be zAdded into `ail_view:decision:v1` and
    become a row on `/audit` - the sequence counter, the bound reserve, this
    service's own account of a failed proof, and an Article 17 tombstone,
    each rendered as a decision with `outcome_type: null`.

    Raises rather than reporting, which is this module's rule: a backfill is
    an offline pass that writes, and a pass that cannot trust what it read
    must not write.
    """
    out: list[dict] = []
    seek = ""
    seek_key: bytes | None = None
    while True:
        body = {"prefix": b64(prefix), "desc": False, "limit": SCAN_PAGE}
        if seek:
            body["seekKey"] = seek
        resp = client.post(f"{IMMUDB_URL}/api/v2/db/scan", json=body, headers=headers)
        resp.raise_for_status()
        entries = resp.json().get("entries", [])
        if not entries:
            break
        for entry in entries:
            try:
                key = unb64(entry["key"])
            except Exception as exc:
                raise SystemExit(
                    f"refusing to backfill: a row returned for prefix {prefix!r} "
                    f"has an unreadable key ({exc}), so what this pass would "
                    "index cannot be established."
                )
            if not key.startswith(prefix.encode()):
                raise SystemExit(
                    f"refusing to backfill: a bounded read returned a key "
                    f"outside the prefix it asked for: "
                    f"{key.decode('utf-8', 'replace')!r} is not under "
                    f"{prefix!r}. The bound was not applied, which is what a "
                    "dropped or misspelled parameter looks like on this route: "
                    "an unbounded read at HTTP 200. Every key this pass reads "
                    "is zAdded into a view index and becomes a page row."
                )
            # P3c3f-5 (Phase 3c-3f): the SECOND bound, driven.
            #
            # This read carries two selective bounds and only `prefix` was
            # asserted on. `seekKey` is exclusive and this scan is ascending,
            # so every key on a page after the first must sort strictly above
            # the key that page seeked from. A client that honours `prefix`
            # and drops `seekKey` - what a dropped paging parameter looks like
            # on this route - returns the same full page forever, and the
            # loop's only exit is `len(entries) < SCAN_PAGE`, which a full
            # page never satisfies. Measured by the Phase 3c-3e red team at
            # 225 identical pages and about 562,500 accumulated rows in eight
            # seconds, with no refusal and no termination; measured again here
            # at 767 pages in eight seconds before this line existed.
            #
            # The coverage table called this site covered on the strength of
            # the prefix driver alone, which is why the table is keyed by
            # site AND bound now (tests/test_bounded_reads.py).
            if seek_key is not None and key <= seek_key:
                raise SystemExit(
                    f"refusing to backfill: a bounded read seeked past "
                    f"{seek_key.decode('utf-8', 'replace')!r} and returned "
                    f"{key.decode('utf-8', 'replace')!r}, which does not sort "
                    "above it. The seekKey bound was not applied, so this walk "
                    "is reading the same page repeatedly and would index every "
                    "row on it again at a new position."
                )
        out.extend(entries)
        if len(entries) < SCAN_PAGE:
            break
        seek = entries[-1]["key"]
        seek_key = unb64(seek)
    return out


def indexed_keys(client: httpx.Client, headers: dict, view_set: str) -> set[bytes]:
    """Which keys the view already holds, so a re-run does not double-index.

    P3c3c-5 (Phase 3c-3c): paged, like scan_all beside it. This used to
    issue one un-paginated `zscan` at the 2500 ceiling, so once a view held
    more than 2500 rows every row past the ceiling was invisible to the
    snapshot and got indexed a second time - in a *single* pass, not by
    re-running. Reproduced on b9f6a1d at 2535 rows: the snapshot reported
    2499 already indexed and one pass left 25 records holding two positions
    each. A production view reaches 2500 rows after 2500 decisions.

    Paged by score rather than by key because zscan orders by score. Rows
    sharing a score are all read on the page that reaches that score, and
    the next page seeks strictly past it, so the loop terminates and the
    only case it could miss is more than 2500 rows at one identical score -
    which the backfill itself cannot produce (a score is a transaction id)
    and which is stated rather than silently assumed.

    A non-200 raises. It used to return an empty set, which does not mean
    "nothing is indexed" but is indistinguishable from it, so one transient
    zscan error made the pass believe the view was empty and re-index every
    record in it.
    """
    seen: set[bytes] = set()
    min_score = None
    while True:
        body = {"set": b64(view_set), "desc": False, "limit": SCAN_PAGE}
        if min_score is not None:
            body["minScore"] = {"score": min_score}
        resp = client.post(f"{IMMUDB_URL}/api/v2/db/zscan", json=body, headers=headers)
        if resp.status_code != 200:
            raise SystemExit(
                f"refusing to backfill: reading the existing index for {view_set!r} "
                f"failed with HTTP {resp.status_code}: {resp.text[:200]}. An "
                "incomplete snapshot of what is already indexed produces records "
                "at two positions, so this stops rather than guessing."
            )
        rows = resp.json().get("entries", [])
        if not rows:
            break
        before = len(seen)
        for row in rows:
            # P3c3e-4 (Phase 3c-3e): the read asserts on what came back, in
            # the form its bound takes. This one is bounded by `minScore`,
            # the same bound anchor_service::collect_positions carries, and
            # a row scored below the minScore this page asked for means the
            # bound was not applied. That is not a cosmetic difference here:
            # an incomplete snapshot of what a view already holds is what
            # indexes a record a second time, measured at 25 records holding
            # two positions each from one pass over 2535 rows, which kills
            # `/audit` with audit_ordering_fault at every limit permanently.
            #
            # Raised rather than reported, unlike the reconciler's copy: the
            # reconciler reads and describes, this pass reads and then
            # writes.
            if min_score is not None:
                try:
                    score = float(row.get("score", 0.0))
                except (TypeError, ValueError):
                    raise SystemExit(
                        f"refusing to backfill: a row in {view_set!r} has an "
                        "unreadable score, so whether the read stayed inside "
                        "the bound it asked for cannot be established."
                    )
                if score < min_score:
                    raise SystemExit(
                        f"refusing to backfill: a bounded read returned a row "
                        f"outside the score bound it asked for: {score} is "
                        f"below the requested minScore {min_score} in "
                        f"{view_set!r}. The bound was not applied, which is "
                        "what a dropped or misspelled parameter looks like on "
                        "this route: an unbounded read at HTTP 200. An "
                        "incomplete snapshot of this view produces records at "
                        "two positions."
                    )
            seen.add(unb64(row["key"]))
        try:
            min_score = float(rows[-1].get("score", 0.0))
        except (TypeError, ValueError):
            raise SystemExit(
                f"refusing to backfill: a row in {view_set!r} has an unreadable "
                "score, so the index cannot be paged completely."
            )
        if len(rows) < SCAN_PAGE or len(seen) == before:
            break
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


def seed_counter_above_reserve(client: httpx.Client, headers: dict,
                               reserve: int | None = None) -> dict:
    """Move a counter that is running below the reserve up to it.

    Only ever raises the counter, never lowers it, and does it under the same
    KeyNotModifiedAfterTX precondition every allocation uses - so a live
    writer racing this either wins and is seen, or loses and retries. A
    counter already above the reserve is left alone.

    Needed because a deployment can have been allocating before this reserve
    existed, in which case its live positions and the range history is about
    to be scored into would overlap.
    """
    reserve = RESERVED_POSITIONS if reserve is None else reserve
    observed = _counter_with_tx(client, headers)
    if observed is None:
        # No counter yet: verifier/main.py's first allocation starts above the
        # reserve on its own, so there is nothing to seed.
        return {"seeded": False, "reason": "no counter yet", "value": None}
    value, tx = observed
    if value >= reserve:
        return {"seeded": False, "reason": "already above the reserve", "value": value}

    resp = client.post(f"{IMMUDB_URL}/api/v2/db/execall", json={
        "Operations": [{"kv": {"key": b64(SEQUENCE_KEY),
                               "value": b64(str(reserve))}}],
        "preconditions": [{"keyNotModifiedAfterTX": {"key": b64(SEQUENCE_KEY),
                                                     "txID": str(tx)}}],
        "noWait": False,
    }, headers=headers)
    resp.raise_for_status()
    return {"seeded": True, "from": value, "value": reserve}


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

        # D36: the ledger's own value wins over this process's environment.
        # A disagreement is refused rather than resolved in either
        # direction: whichever is wrong, running would score history into a
        # range the writer is allocating from or vice versa.
        bound = bound_reserve(client, headers)
        if bound is not None and bound != RESERVED_POSITIONS:
            raise SystemExit(
                f"refusing to backfill: AIL_RESERVED_POSITIONS is "
                f"{RESERVED_POSITIONS} and the ledger has {bound} bound into it. "
                "The bound value is what every position in this ledger was "
                f"allocated against. Set this to {bound} and re-run."
            )
        reserve = bound if bound is not None else RESERVED_POSITIONS
        summary["bound_reserve"] = bound

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
        summary["reserved_positions"] = reserve

        # Fail closed rather than guess. A historical transaction id at or
        # above the reserve would be scored on top of live positions, which
        # is worse than not running: the page would interleave history with
        # current traffic and D33 would fault on it.
        #
        # D36 (Phase 3c-3c): what this message used to instruct is the
        # attack the red team ran. "Raise AIL_RESERVED_POSITIONS and re-run"
        # moves the seam above positions the compare-and-set has already
        # handed out, which puts committed live positions inside the new
        # reserve - where reconciliation does not count them and D33 does
        # not order-check them, permanently, with the verdict still reading
        # clean. The reserve is bound into the ledger at first allocation
        # and cannot be moved, so the remedy is a re-index into a new view:
        # a second zset, scored from the same counter, that this history
        # fits into. The boundary stays where it is.
        over = [tx for _v, _k, tx in pending if tx >= reserve]
        if over:
            raise SystemExit(
                f"refusing to backfill: {len(over)} record(s) have a transaction id at "
                f"or above the reserve of {reserve} (highest {max(over)}). The reserve "
                "is bound into this ledger and cannot be raised: positions the "
                "compare-and-set has already allocated would fall inside the new "
                "reserve, where they are neither reconciled nor order-checked. This "
                "history needs a re-index into a new view scored from the same "
                "counter, not a moved boundary. See docs/adr/"
                "0014-ordered-audit-view-index.md."
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
        summary["seed"] = seed_counter_above_reserve(client, headers, reserve)

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
