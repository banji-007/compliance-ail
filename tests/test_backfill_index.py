"""tests/test_backfill_index.py - Phase 3c-3c (P3c3c-5).

The backfill sees the whole index.

The attack this carries forward is red-team C2
(docs/reports/phase-3c3b-redteam.md), reproduced on unmodified b9f6a1d
before anything here was written, at 2535 records in one view:

    === DRY RUN ===  {"decision": {"records": 2535, "already_indexed": 2499,
                                   "to_index": 36}}
    === REAL RUN (single pass) ===  "total_indexed": 36
    records at two or more positions: 25
      pad02486  positions = [4991.0, 1000002555.5]
      pad02487  positions = [4993.0, 1000002556.5]

`indexed_keys()` issued one un-paginated `zscan` at the 2500 ceiling while
`scan_all()` beside it paged correctly, so every row past the ceiling was
invisible to the snapshot and was indexed a second time - in a *single*
pass, not by re-running. Passes two and three were idempotent, which is what
made the claim "idempotent" true and beside the point. A production view
reaches 2500 rows after 2500 decisions.

Related, and refused here too: a non-200 returned an empty set, which is
indistinguishable from "nothing is indexed", so one transient error made the
pass re-index every record in the view.

The view is padded with `execall`, several hundred operations per
transaction, so crossing the ceiling costs seconds rather than the minutes
2500 individual writes take. What is being tested is the ceiling, and the
ceiling is the same wherever the rows came from.
"""

import base64
import importlib
import json
import os
import sys
import uuid
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from bounded_read_checks import assert_at_or_above_min_score  # noqa: E402

IMMUDB_URL        = os.getenv("IMMUDB_URL",        "http://localhost:8080")
IMMUDB_USER       = os.getenv("IMMUDB_USER",       "immudb")
IMMUDB_PASSWORD   = os.getenv("IMMUDB_PASSWORD",   "immudb")
CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL", "http://localhost:8002")

VIEW_DECISION = "ail_view:decision:v1"

# Inside the reserve, so these rows are history and no order check applies to
# them, and high enough not to collide with anything another test placed.
_PAD_SCORE_BASE = 500_000

requires_stack = pytest.mark.needs_stack("immudb", "verifier", "control_plane")

_CLIENT = httpx.Client(timeout=120.0)


def _b64(value) -> str:
    return base64.b64encode(value if isinstance(value, bytes) else value.encode()).decode()


def _headers() -> dict:
    resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/login", json={
        "user": _b64(IMMUDB_USER), "password": _b64(IMMUDB_PASSWORD),
        "database": _b64("defaultdb"),
    })
    resp.raise_for_status()
    return {"Authorization": f"Bearer {resp.json()['token']}"}


def _decision_value(agent_id: str) -> str:
    return json.dumps({
        "record_type": "decision", "call_id": uuid.uuid4().hex, "agent_id": agent_id,
        "timestamp": "2026-08-31T00:00:00", "tool_name": "query_database",
        "outcome_type": "policy_allow", "fault_class": None,
        "policy_revision": "p3c3c-test", "reasons": [],
        "input_sha256": uuid.uuid4().hex, "content_state": "unavailable",
        "profile": "observed",
    }, separators=(",", ":"))


def _backfill_module():
    import ail_backfill_index as bf
    importlib.reload(bf)
    bf.IMMUDB_URL = IMMUDB_URL
    return bf


def _view_rows(headers: dict) -> dict[str, list[float]]:
    """Every (key, position) in the decision view, paged past the ceiling."""
    out: dict[str, list[float]] = {}
    min_score = None
    while True:
        body = {"set": _b64(VIEW_DECISION), "desc": False, "limit": 2500}
        if min_score is not None:
            body["minScore"] = {"score": min_score}
        resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/zscan", json=body, headers=headers)
        resp.raise_for_status()
        rows = resp.json().get("entries", [])
        if not rows:
            break
        before = sum(len(v) for v in out.values())
        page = [(base64.b64decode(row["entry"]["key"]).decode(),
                 float(row.get("score", 0.0))) for row in rows]
        # P3c3f-3 (D46): the bound, asserted on what came back. An under-read
        # here hides a record holding two positions, which is what this
        # module exists to detect.
        assert_at_or_above_min_score(page, min_score, "_view_rows")
        for key, score in page:
            out.setdefault(key, []).append(score)
        min_score = float(rows[-1].get("score", 0.0))
        if len(rows) < 2500 or sum(len(v) for v in out.values()) == before:
            break
    return out


def _pad_view_past_the_ceiling(headers: dict, target: int = 2600) -> int:
    """Bring THIS MODULE's own rows in the decision view above zscan's
    2500-row ceiling.

    Records and their index entries in the same execall, in batches, because
    2600 round trips is minutes and 26 is seconds. Each row is a real record
    under a real key, which is what the snapshot has to see.

    **P3c3e-10 (Phase 3c-3e): counted over this module's own rows, not over
    the view.** It used to subtract everything already in the view, so on a
    ledger another module had written to it padded fewer rows and this
    module's own contribution fell below the ceiling - which matters now that
    the duplication assertion below is scoped to this module's records
    (D44). The view is still taken past the ceiling either way; what changed
    is that this module's rows are what take it there, so the pass has to
    page over them.
    """
    existing = len([key for key in _view_rows(headers) if "p3c3c-pad" in key])
    needed = max(0, target - existing)
    written = 0
    batch, score = [], _PAD_SCORE_BASE + existing
    for i in range(needed):
        score += 1
        key = f"tool_call:p3c3c-pad{i:05d}-{uuid.uuid4().hex[:6]}:{uuid.uuid4().hex}:query_database"
        batch.append({"kv": {"key": _b64(key), "value": _b64(_decision_value(f"pad{i}"))}})
        batch.append({"zAdd": {"set": _b64(VIEW_DECISION), "score": float(score),
                               "key": _b64(key), "boundRef": False}})
        if len(batch) >= 200:
            resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/execall",
                                json={"Operations": batch, "noWait": False},
                                headers=headers)
            resp.raise_for_status()
            written += len(batch) // 2
            batch = []
    if batch:
        resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/execall",
                            json={"Operations": batch, "noWait": False}, headers=headers)
        resp.raise_for_status()
        written += len(batch) // 2
    return existing + written


@requires_stack
def test_one_pass_over_a_view_past_the_ceiling_leaves_no_record_at_two_positions():
    """
    C2, carried forward. One pass, over a view larger than the snapshot's
    ceiling, with records the pass has to pick up.

    The assertion is over the whole view, paged, not over the pass's own
    summary - the pass reported `already_indexed: 2499` on b9f6a1d and was
    wrong by exactly the rows it could not see, so its own count is the last
    thing that should be trusted here.
    """
    headers = _headers()
    padded = _pad_view_past_the_ceiling(headers)
    assert padded > 2500, (
        f"this module holds {padded} rows in the view, not past the ceiling"
    )
    assert len(_view_rows(headers)) > 2500, "the view is not past the ceiling"

    # Records with no index entry at all, which is what the pass exists for.
    unindexed = []
    batch = []
    for i in range(12):
        key = f"tool_call:p3c3c-unindexed{i}-{uuid.uuid4().hex[:6]}:{uuid.uuid4().hex}:query_database"
        unindexed.append(key)
        batch.append({"kv": {"key": _b64(key), "value": _b64(_decision_value(f"un{i}"))}})
    resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/execall",
                        json={"Operations": batch, "noWait": False}, headers=headers)
    resp.raise_for_status()

    bf = _backfill_module()
    summary = bf.backfill()
    assert summary["total_indexed"] >= len(unindexed), summary

    # D44 (Phase 3c-3e): scoped to the records this module writes.
    #
    # This asserted over every key in the view. `tests/test_reconciliation.py`
    # gives a record a second position on purpose, to prove the reconciler
    # reports one, so the ledger-wide form failed whenever that module was
    # collected first - which alphabetical collection happens to prevent and
    # nothing else did.
    #
    # The scope is what this module wrote, and that is exactly where C2's
    # defect appears: the pad rows are the ones past the snapshot's ceiling
    # that got indexed a second time (25 of them, at 2535 rows), and the
    # unindexed rows are the ones the pass exists to pick up. The ledger-wide
    # statement is in tests/test_view_invariants.py, where the deliberate
    # violations are named and argued for.
    rows = _view_rows(headers)
    mine = {key: scores for key, scores in rows.items()
            if "p3c3c-pad" in key or "p3c3c-unindexed" in key}
    assert len(mine) > 2500, (
        f"only {len(mine)} of this module's own rows are in the view, so one "
        "pass over it says nothing about the snapshot's ceiling"
    )
    duplicated = {k: v for k, v in mine.items() if len(set(v)) > 1}
    assert not duplicated, (
        f"{len(duplicated)} record(s) written by this module hold more than "
        f"one position after a single backfill pass: "
        f"{dict(list(duplicated.items())[:5])}"
    )
    for key in unindexed:
        assert key in rows, f"the pass did not index {key}"
        assert len(set(rows[key])) == 1, (key, rows[key])


@requires_stack
def test_the_snapshot_sees_rows_beyond_the_first_page():
    """
    The mechanism, stated directly, so the test above cannot pass by
    accident on a view that happened to fit.

    `indexed_keys` must return more keys than one page can hold. Un-paginate
    it and this returns exactly the ceiling.
    """
    headers = _headers()
    _pad_view_past_the_ceiling(headers)
    in_view = len(_view_rows(headers))
    bf = _backfill_module()
    with httpx.Client(timeout=120.0) as client:
        seen = bf.indexed_keys(client, bf.login(client), VIEW_DECISION)
    assert len(seen) > bf.SCAN_PAGE, (
        f"the index snapshot stopped at {len(seen)} keys with {in_view} rows in "
        f"the view and a page size of {bf.SCAN_PAGE}; every row past the ceiling "
        "is invisible to it and will be indexed a second time"
    )


@requires_stack
def test_a_failed_index_read_refuses_the_pass_instead_of_re_indexing_everything():
    """
    The related finding C2 named but did not trigger: a non-200 returned an
    empty set. An empty set is not "nothing is indexed", it is
    indistinguishable from it, so one transient error made the pass believe
    the view was empty and re-index every record in it.

    The failure is produced by pointing the read at a route that answers a
    non-200 rather than by patching the function, so what is exercised is
    the branch as written.
    """
    bf = _backfill_module()
    headers = _headers()
    bf.IMMUDB_URL = CONTROL_PLANE_URL          # no /api/v2/db/zscan there
    try:
        with httpx.Client(timeout=30.0) as client:
            with pytest.raises(SystemExit) as raised:
                bf.indexed_keys(client, headers, VIEW_DECISION)
    finally:
        bf.IMMUDB_URL = IMMUDB_URL
    message = str(raised.value)
    assert "refusing to backfill" in message, message
    assert "two positions" in message, (
        f"the refusal does not say what an incomplete snapshot causes: {message}"
    )
