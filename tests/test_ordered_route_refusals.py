"""tests/test_ordered_route_refusals.py - Phase 3c-3d (P3c3d-1, D39).

The ordered route refuses what the plain route refuses, and a record key is
written once.

The two attacks these carry forward, both reproduced live on `e3d8284`
before anything here was written.

**A caller-authored fault, through the unrefused route.**
`_refuse_reason_for_plain_write` was wired into `POST /write` and was not
called by `write_ordered`, so every bound Phase 3c-3c claimed sat on the
plain route (`docs/reports/phase-3c3d-keyprobe.md` section 12,
`docs/reports/phase-3c3c-redteam.md` A2):

    POST /write         ledger_fault:{cid} -> 400
    POST /write-ordered ledger_fault:{cid} -> 200 tx 2 seq 1000000002 verified
    page row ledger_fault AFTER: {"fault_class": "FORGED-BY-CALLER",
                                  "committed_tx_id": 999999, ...}
    entries=2 total=1     rows with outcome_type None: 1

**Two ordinary writes kill the audit page.** The red team's "not on the
list" finding, the most serious thing in that report. One record key written
twice through `/write-ordered`, both `verified: true, committed: true`:

    index entries for that one key: score=1000000004 entry_tx=4
                                    score=1000000003 entry_tx=4
    GET /audit?limit=1|5|200|2500 -> HTTP 500 audit_ordering_fault

Requires the docker-compose.test.yml stack and the docker CLI: the forged
fault has to replace a genuine one, and a genuine one needs a live proof
failure, which needs the trust-anchor surgery inside the verifier container.
"""

import base64
import json
import os
import sys
import uuid
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tests"))

from anchor_helpers import anchor as _anchor          # noqa: E402
from compose_helpers import requires_docker_cli       # noqa: E402

CONTROL_PLANE_URL  = os.getenv("CONTROL_PLANE_URL",       "http://localhost:8002")
READ_API_KEY       = os.getenv("CONTROL_PLANE_READ_KEY",  "test-read-key")
VERIFIER_URL       = os.getenv("VERIFIER_URL",            "http://localhost:8003")
VERIFIER_WRITE_KEY = os.getenv("VERIFIER_WRITE_KEY",      "test-verifier-write-key")
IMMUDB_URL         = os.getenv("IMMUDB_URL",              "http://localhost:8080")
IMMUDB_USER        = os.getenv("IMMUDB_USER",             "immudb")
IMMUDB_PASSWORD    = os.getenv("IMMUDB_PASSWORD",         "immudb")

VIEW_DECISION = "ail_view:decision:v1"

requires_stack = pytest.mark.needs_stack("immudb", "verifier", "control_plane")

_CLIENT = httpx.Client(timeout=60.0)


def _b64(value) -> str:
    return base64.b64encode(value if isinstance(value, bytes) else value.encode()).decode()


def _immudb_headers() -> dict:
    resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/login", json={
        "user": _b64(IMMUDB_USER), "password": _b64(IMMUDB_PASSWORD),
        "database": _b64("defaultdb"),
    })
    resp.raise_for_status()
    return {"Authorization": f"Bearer {resp.json()['token']}"}


def _zscan_keys(headers: dict, view_set: str) -> list[tuple[float, str, int]]:
    resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/zscan",
                        json={"set": _b64(view_set), "desc": True, "limit": 2500},
                        headers=headers)
    resp.raise_for_status()
    return [(float(r.get("score", 0.0)),
             base64.b64decode(r["entry"]["key"]).decode("utf-8", "replace"),
             int(r["entry"]["tx"]))
            for r in resp.json().get("entries", [])]


def _decision_value(call_id: str, agent_id: str) -> str:
    return json.dumps({
        "record_type": "decision", "call_id": call_id, "agent_id": agent_id,
        "timestamp": "2026-08-31T00:00:00", "tool_name": "query_database",
        "outcome_type": "policy_allow", "fault_class": None,
        "policy_revision": "p3c3d-test", "reasons": [],
        "input_sha256": uuid.uuid4().hex, "content_state": "unavailable",
        "profile": "observed",
    }, separators=(",", ":"))


def _forged_fault_value(call_id: str, record_key: str, fault_class: str) -> str:
    return json.dumps({
        "record_type": "ledger_fault", "fault_class": fault_class,
        "call_id": call_id, "committed_key": record_key,
        "committed_tx_id": 999999, "committed_position": 123, "view": "decision",
        "error_class": "signature_failure", "detail": "FORGED - nothing wrong here",
        "timestamp": "2026-01-01T00:00:00", "writer": "not-the-verifier",
    }, separators=(",", ":"))


def _write_ordered(key: str, value: str, view: str = "decision") -> httpx.Response:
    return _CLIENT.post(f"{VERIFIER_URL}/write-ordered",
                        json={"key": _b64(key), "value": _b64(value), "view": view},
                        headers={"X-API-Key": VERIFIER_WRITE_KEY})


def _tool_key(tag: str) -> str:
    return f"tool_call:{tag}-{uuid.uuid4().hex[:8]}:{uuid.uuid4().hex}:query_database"


def _audit(limit: int = 200) -> httpx.Response:
    return _CLIENT.get(f"{CONTROL_PLANE_URL}/audit", params={"limit": limit},
                       headers={"X-API-Key": READ_API_KEY})


@pytest.fixture(scope="module")
def corrupt_trust_anchor():
    """A live ADR-0006 consistency_failure for the length of this module.

    Module-scoped because each transition costs a container restart, and torn
    down unconditionally: a session that left the anchor corrupt would fail
    every later test in a way that reads as a code regression.
    """
    seed = _write_ordered(_tool_key("p3c3d-seed"),
                          _decision_value(uuid.uuid4().hex, "p3c3d-seed"))
    assert seed.status_code == 200 and seed.json()["verified"], seed.text[:300]
    _anchor("corrupt")
    try:
        yield
    finally:
        _anchor("restore")


# ---------------------------------------------------------------------------
# D39, first half: a fault record is never accepted from a caller, on either
# route.
# ---------------------------------------------------------------------------

@requires_stack
def test_a_caller_authored_fault_is_refused_on_the_ordered_route():
    """
    The refusal itself. `POST /write` has refused this since Phase 3c-3c;
    `/write-ordered` accepted it, which is why every bound that phase claimed
    was a true statement about a route no decision takes any more.
    """
    call_id = uuid.uuid4().hex
    resp = _write_ordered(f"ledger_fault:{call_id}",
                          _forged_fault_value(call_id, "tool_call:whatever", "FORGED"))
    assert resp.status_code == 400, (
        f"a caller-authored fault record was accepted on the ordered route: "
        f"{resp.status_code} {resp.text[:300]}"
    )
    assert "ledger_fault" in resp.text, resp.text[:300]


@requires_stack
def test_a_fault_record_type_is_refused_on_the_ordered_route_under_any_key():
    """The second condition, which covers the first's blind spot: a fault
    record written under a key that does not carry the prefix."""
    call_id = uuid.uuid4().hex
    resp = _write_ordered(_tool_key("p3c3d-disguise"),
                          _forged_fault_value(call_id, "tool_call:whatever", "FORGED"))
    assert resp.status_code == 400, (
        f"a ledger_fault record disguised under a decision key was accepted on "
        f"the ordered route: {resp.status_code} {resp.text[:300]}"
    )


@requires_stack
def test_an_injected_row_is_refused_and_entries_does_not_exceed_total():
    """
    The other consequence of the unrefused route: the ordered route allocates
    a position, so anything it accepts becomes a page row. Measured before the
    fix: `entries` 4, `total` 3, and a row with `outcome_type: null` whose key
    was `ledger_fault:...`.

    **What this asserts, and what it deliberately does not.** D39 refuses a
    `ledger_fault` on both routes, so the measured injection is refused and no
    fault key is a page row. It does **not** make "no page row has a null
    outcome type" true, and this test must not claim otherwise. The ordered
    route still accepts a key of any shape into a view, which is the open item
    in `TODO.md` and README section 5 - and `tests/test_evidence_bundle.py`
    exercises exactly that on purpose, writing `p3b_material_test:` records
    with no `record_type` and no `call_id` through this route to produce real
    proof material. On a shared ledger those are page rows with
    `outcome_type: null`.

    A first draft of this test asserted their absence and failed in CI against
    them (run `33475430028`, 2 failed of 442). The assertion was wrong, not the
    ledger: it claimed a property this phase did not deliver. It is narrowed to
    what D39 does deliver, and the narrowing is stated here rather than left
    for a reader to infer from a weaker assertion.
    """
    call_id = uuid.uuid4().hex
    seeded = _write_ordered(_tool_key("p3c3d-inject"),
                            _decision_value(call_id, "p3c3d-inject"))
    assert seeded.status_code == 200, seeded.text[:300]

    injected = _write_ordered(f"ledger_fault:{call_id}",
                              _forged_fault_value(call_id, "tool_call:whatever", "INJECT"))
    assert injected.status_code == 400, (
        f"an arbitrary row was injected into the audit page: {injected.text[:300]}"
    )

    page = _audit(2500)
    assert page.status_code == 200, page.text[:300]
    entries = page.json()["entries"]

    # No fault key is a page row. This is the direct consequence of the
    # refusal, ledger-wide rather than for this call_id alone, because the
    # refusal is ledger-wide.
    fault_rows = [e for e in entries
                  if base64.b64decode(e["ledger_key"]).startswith(b"ledger_fault:")]
    assert not fault_rows, (
        f"a ledger_fault key is a page row: {fault_rows[:3]}"
    )

    # And this call_id contributed exactly the one record it wrote. That is
    # the "entries no longer exceeds total" claim, stated for the injection
    # that was measured rather than as a property of the whole page: before
    # the refusal, this call_id put two rows on the page for one decision
    # record, and the second carried no outcome type.
    mine = [e for e in entries if e["call_id"] == call_id]
    assert len(mine) == 1, (
        f"one decision record produced {len(mine)} page rows for its call_id: "
        f"{[base64.b64decode(e['ledger_key']).decode('utf-8', 'replace') for e in mine]}"
    )
    assert mine[0]["outcome_type"] == "policy_allow", mine[0]


# ---------------------------------------------------------------------------
# D39, second half: a record key is written once.
# ---------------------------------------------------------------------------

@requires_stack
def test_a_record_key_cannot_be_written_twice_through_the_ordered_route():
    """
    Two ordinary well-formed writes, no corruption and no privileged access,
    denied the whole audit page permanently before this fix. The second write
    is refused under KeyMustNotExist, inside the same ExecAll, so nothing at
    all is committed for it.
    """
    headers = _immudb_headers()
    call_id = uuid.uuid4().hex
    key = _tool_key("p3c3d-once")

    first = _write_ordered(key, _decision_value(call_id, "p3c3d-once-a"))
    assert first.status_code == 200 and first.json()["committed"], first.text[:300]

    second = _write_ordered(key, _decision_value(call_id, "p3c3d-once-b"))
    assert second.status_code == 409, (
        f"the same record key was written twice through the ordered route: "
        f"{second.status_code} {second.text[:300]}"
    )

    indexed = [(score, tx) for score, k, tx in _zscan_keys(headers, VIEW_DECISION)
               if k == key]
    assert len(indexed) == 1, (
        f"one record key holds {len(indexed)} positions in the view index: "
        f"{indexed}. Both resolve to the key's current transaction, which the "
        "order check reads as a disagreement at every limit."
    )


@requires_stack
def test_the_audit_page_survives_a_repeated_record_key():
    """
    The thing the refusal is for. Before it, this sequence answered HTTP 500
    `audit_ordering_fault` at limit 1, 5, 200 and 2500, permanently, from the
    write credential alone.
    """
    call_id = uuid.uuid4().hex
    key = _tool_key("p3c3d-survive")
    assert _write_ordered(key, _decision_value(call_id, "p3c3d-survive")).status_code == 200
    _write_ordered(key, _decision_value(call_id, "p3c3d-survive-2"))

    for limit in (1, 5, 200, 2500):
        page = _audit(limit)
        assert page.status_code == 200, (
            f"GET /audit?limit={limit} is dead after one record key was written "
            f"twice: {page.status_code} {page.text[:300]}"
        )


# ---------------------------------------------------------------------------
# Last in the module on purpose: `corrupt_trust_anchor` is module-scoped, and
# pytest finalizes a module-scoped fixture at the end of the module rather
# than after the last test that asks for it. Anything below it would run
# against a corrupt anchor and report `verified: false` for a healthy write.
# ---------------------------------------------------------------------------

@requires_stack
@requires_docker_cli
def test_a_forged_fault_does_not_replace_a_genuine_one_on_the_page(corrupt_trust_anchor):
    """
    The consequence, on the page. A genuine fault is written by the verifier
    about its own failed proof; the attack replaced it with the caller's own
    account of the same record's standing, and `/audit` rendered that.
    """
    call_id = uuid.uuid4().hex
    key = _tool_key("p3c3d-forge")
    body = _write_ordered(key, _decision_value(call_id, "p3c3d-forge")).json()
    assert body["committed"] is True and body["verified"] is False, body
    assert body["fault_record"], f"no genuine fault was written: {body}"

    def _row():
        page = _audit()
        assert page.status_code == 200, page.text[:300]
        rows = [e for e in page.json()["entries"] if e["call_id"] == call_id]
        assert rows, "the committed record is absent from the page"
        return rows[0]

    genuine = _row()["ledger_fault"]
    assert genuine is not None and genuine["fault_class"] == "write_verification_failed", (
        f"the page does not carry the verifier's own fault for this record: {genuine}"
    )

    forged = _write_ordered(f"ledger_fault:{call_id}",
                            _forged_fault_value(call_id, key, "FORGED-BY-CALLER"))
    assert forged.status_code == 400, (
        f"the forged fault was accepted: {forged.status_code} {forged.text[:300]}"
    )

    after = _row()["ledger_fault"]
    assert after["fault_class"] == "write_verification_failed", (
        f"a caller replaced the ledger's own account of this record's standing: {after}"
    )
    assert after["committed_tx_id"] == body["tx_id"], after
