"""
tests/test_audit_read_correctness.py - Phase 3c-3a (P3c3a-1, -2, -3).

`GET /audit` reported three things it had not measured.

  `total` was `len(entries)`.        The page's own length, returned under a
                                     name that reads ledger-wide, and used
                                     for a dashboard card labelled "Total
                                     Decisions". A complete ledger of 40 and
                                     a truncated page of 200 were the same
                                     number to a caller.

  Truncation was unstated.           A page that filled its limit looked
                                     exactly like a page that did not, and
                                     the only way to guess was to notice
                                     that `len(entries) == limit` and hope.

  The tombstone join was a search.   A prefix scan over `content_erasure:`
                                     bounded by the page's own `limit`, so a
                                     tombstone for a record on the page could
                                     be excluded by a bound that had nothing
                                     to do with it. Phase 1.2 made erasure a
                                     positive provable fact (D11); this could
                                     take it back at read time.

What the third one actually did, which is worse than "renders present":
`_payload_state` maps a missing tombstone two ways depending on whether the
content row survived. A record erased through the real endpoint (row gone)
rendered **`lost`** - defined in that function as "the row disappeared some
other way", an operational incident with no erasure semantics - so a lawful
Article 17 erasure was reported as an incident. A record whose row outlived
its tombstone rendered **`present`**, *with its payload attached*, undoing
P13-4 at read time. Both faces are covered below; the second is the one that
leaks.

Constructing the defect. The old scan was `desc: True` over
`content_erasure:` under the page's `limit`, so pushing a tombstone out of
the window means putting `limit` lexicographically-larger tombstones in
front of it. Tombstone keys are `content_erasure:{call_id}` and call_id is a
uuid hex string, so a forged call_id beginning `zzzz` sorts above every real
one (`z` is 0x7a, hex digits stop at `f`, 0x66). The record's own
`tool_call:` key must still land on the page, and those lead with agent_id
(`tool_call:{agent_id}:{uuid}:{tool_name}`), so the records here use a
`zzzz`-leading agent_id for the same reason and in the same direction. No
other test in this suite uses a z-leading agent id.

Records are forged through the verifier's own `/write`, the idiom
tests/test_content_states.py::_write_tombstone_directly already established
for exactly this: it is a real, verified ledger write, it keeps the
verifier's consistency state coherent (a raw REST `set` behind its back does
not), and what is under test here is the read layer, which cannot tell and
should not care how a well-formed record arrived.

Requires the docker-compose.test.yml stack.
"""

import base64
import json
import os
import re
import urllib.parse
import uuid
from datetime import datetime
from pathlib import Path

import httpx
import pytest

CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL", "http://localhost:8002")
READ_API_KEY = os.getenv("CONTROL_PLANE_READ_KEY", "test-read-key")
WRITE_API_KEY = os.getenv("CONTROL_PLANE_WRITE_KEY", "test-write-key")
VERIFIER_URL = os.getenv("VERIFIER_URL", "http://localhost:8003")
VERIFIER_WRITE_KEY = os.getenv("VERIFIER_WRITE_KEY", "test-verifier-write-key")
IMMUDB_URL = os.getenv("IMMUDB_URL", "http://localhost:8080")
IMMUDB_USER = os.getenv("IMMUDB_USER", "immudb")
IMMUDB_PASSWORD = os.getenv("IMMUDB_PASSWORD", "immudb")

REPO_ROOT = Path(__file__).resolve().parents[1]
AUDIT_PAGE_TSX = REPO_ROOT / "dashboard" / "app" / "audit" / "page.tsx"

requires_stack = pytest.mark.needs_stack("immudb", "verifier", "control_plane")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _b64(value) -> str:
    return base64.b64encode(value if isinstance(value, bytes) else value.encode()).decode()


# One keep-alive connection for the forged writes. Each verified write is
# ~0.5s of gRPC round trip inside the verifier; opening a fresh TCP
# connection per write on top of that dominated this file's first run.
_WRITE_CLIENT = httpx.Client(timeout=30.0)


def _verifier_write(key: str, value: dict) -> None:
    """One verified ledger write, through the verifier's own /write - the
    same route tests/test_content_states.py::_write_tombstone_directly uses,
    with the same write-scoped credential D21 requires."""
    resp = _WRITE_CLIENT.post(
        f"{VERIFIER_URL}/write",
        json={
            "key": _b64(key),
            "value": _b64(json.dumps(value, separators=(",", ":"))),
        },
        headers={"X-API-Key": VERIFIER_WRITE_KEY},
    )
    resp.raise_for_status()
    assert resp.json().get("verified"), f"write not verified: {resp.json()}"


def _write_decision_record(call_id: str, *, agent_id: str, content_state: str = "present") -> str:
    """A well-formed `tool_call:` decision record, keyed exactly the way
    ledger/immudb_ledger.py::log_tool_call keys one."""
    key = f"tool_call:{agent_id}:{uuid.uuid4().hex}:query_database"
    _verifier_write(key, {
        "record_type": "decision",
        "call_id": call_id,
        "agent_id": agent_id,
        "timestamp": datetime.utcnow().isoformat(),
        "tool_name": "query_database",
        "outcome_type": "policy_allow",
        "fault_class": None,
        "policy_revision": "p3c3a-test",
        "reasons": [],
        "input_sha256": uuid.uuid4().hex,
        "content_state": content_state,
        "profile": "observed",
    })
    return key


def _write_tombstone(call_id: str) -> None:
    _verifier_write(f"content_erasure:{call_id}", {
        "record_type": "content_erasure",
        "call_id": call_id,
        "timestamp": datetime.utcnow().isoformat(),
        "actor": "p3c3a-test",
    })


def _write_content_row(call_id: str, payload: dict) -> None:
    resp = httpx.post(
        f"{CONTROL_PLANE_URL}/content",
        json={"call_id": call_id, "payload": payload},
        headers={"X-API-Key": WRITE_API_KEY},
        timeout=30,
    )
    resp.raise_for_status()


def _audit(limit: int, verify: bool = False) -> dict:
    resp = httpx.get(
        f"{CONTROL_PLANE_URL}/audit",
        params={"limit": limit, "verify": str(verify).lower()},
        headers={"X-API-Key": READ_API_KEY},
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()


def _immudb_prefix_count(prefix: str) -> int:
    """The same question P3c3a-1 makes /audit ask, asked independently here
    so the test compares /audit's answer against the ledger rather than
    against another copy of /audit's own arithmetic."""
    with httpx.Client(timeout=30.0) as client:
        login = client.post(f"{IMMUDB_URL}/api/v2/login", json={
            "user": _b64(IMMUDB_USER),
            "password": _b64(IMMUDB_PASSWORD),
            "database": _b64("defaultdb"),
        })
        login.raise_for_status()
        token = login.json()["token"]
        resp = client.get(
            f"{IMMUDB_URL}/api/v2/db/count/{urllib.parse.quote(_b64(prefix), safe='')}",
            headers={"Authorization": f"Bearer {token}"},
        )
        resp.raise_for_status()
        return int(resp.json().get("count", 0))


def _seed_decisions(n: int, agent_id: str) -> list[str]:
    return [_write_decision_record(f"p3c3a-{uuid.uuid4().hex}", agent_id=agent_id) for _ in range(n)]


# ---------------------------------------------------------------------------
# P3c3a-1: the four stat cards report what their labels claim
# ---------------------------------------------------------------------------

@requires_stack
def test_total_is_the_ledger_count_not_the_page_length():
    """
    The defect, stated as a behaviour: with a ledger larger than the page,
    `total` used to equal `len(entries)` - so it described the page while
    being named and rendered as if it described the ledger.

    Two assertions, both of which the named mutation (`return len(entries)
    as total`) fails: total must exceed the page it came back with, and it
    must equal what ImmuDB itself says when asked independently.
    """
    _seed_decisions(12, agent_id=f"p3c3a-count-{uuid.uuid4().hex[:8]}")

    page = _audit(limit=5)

    # Deliberately not asserting len(entries) <= limit. `limit` bounds the
    # decision scan; the synthesized rows for orphaned write-ahead intents
    # (D16) are appended after it, so a page can carry more rows than the
    # limit asked for. That is pre-existing and out of this phase's scope -
    # it is recorded in README's Residual Limits rather than asserted here,
    # because asserting it would encode a behaviour nobody has decided to
    # keep.
    assert page["total"] > len(page["entries"]), (
        "total came back equal to (or below) the number of rows on the page. "
        "That is the page's length, not the ledger's count - the exact "
        f"defect P3c3a-1 closes. total={page['total']} "
        f"rows={len(page['entries'])}"
    )
    assert page["total"] == _immudb_prefix_count("tool_call:"), (
        "total does not match ImmuDB's own count of tool_call: keys. "
        f"total={page['total']} ledger={_immudb_prefix_count('tool_call:')}"
    )


@requires_stack
def test_total_does_not_move_when_the_page_size_does():
    """
    A ledger-scoped number is by definition independent of `limit`. This is
    the same property as the test above approached from the side that needs
    no independent count: if `total` changes when only the page size
    changed, it was never describing the ledger.
    """
    _seed_decisions(3, agent_id=f"p3c3a-stable-{uuid.uuid4().hex[:8]}")

    small = _audit(limit=1)
    large = _audit(limit=50)

    assert small["total"] == large["total"], (
        "total changed when only limit changed, so it is a property of the "
        f"page rather than of the ledger: limit=1 -> {small['total']}, "
        f"limit=50 -> {large['total']}"
    )
    assert len(small["entries"]) < len(large["entries"]), (
        "the two pages were the same size, so this comparison proved "
        "nothing - seed more records"
    )


# Cards are `<StatCard ... />` with no nested JSX, so a match that forbids
# `<` cannot run past the end of one card into the next.
_STAT_CARD_RE = re.compile(r"<StatCard\b[^<]*?/>", re.DOTALL)
_LABEL_RE = re.compile(r'label="([^"]*)"')


def test_every_stat_card_label_states_the_scope_it_is_computed_at():
    """
    Static parse of the dashboard's own TSX, in the style
    tests/test_dashboard_state_rendering.py established - the dashboard has
    no JavaScript test harness, so what holds a rendering claim in place
    here is a parse of the source that makes the claim.

    The rule, derived per card rather than from a maintained list: a card
    whose value is computed from `data.entries` is counting the rows on this
    page and its label must say so; a card whose value is `data.total` is
    reading the ledger's count and its label must say that. A card that
    reads neither, or both, has no determinable scope and fails.

    This is the half of P3c3a-1 that is not about the response contract.
    `total` becoming ledger-scoped fixes one number; it does nothing for the
    three cards beside it, which are still counted in the browser from the
    rows in hand. Those cannot become ledger-scoped at all today -
    `outcome_type` lives inside the record's value, not its key, so ImmuDB's
    prefix count cannot see it, and counting approvals ledger-wide would
    mean reading every record on a request the dashboard polls every 30
    seconds. So they stay page-scoped and say so, and this test is what
    stops one of them drifting back to a bare "Approved".
    """
    source = AUDIT_PAGE_TSX.read_text(encoding="utf-8")
    cards = _STAT_CARD_RE.findall(source)

    assert len(cards) == 4, (
        f"expected the four summary cards, parsed {len(cards)}. If a card "
        "was added or removed, this test needs to see it - do not relax the "
        "count without deciding what the new card's scope is."
    )

    for card in cards:
        label_match = _LABEL_RE.search(card)
        assert label_match, f"StatCard with no literal label:\n{card}"
        label = label_match.group(1)
        lowered = label.lower()

        reads_page = "data.entries" in card
        reads_ledger = "data.total" in card

        assert reads_page != reads_ledger, (
            f'card "{label}" reads '
            f'{"both data.entries and data.total" if reads_page else "neither data.entries nor data.total"}'
            ", so its scope cannot be determined from its own value expression"
        )

        if reads_page:
            assert "page" in lowered, (
                f'card "{label}" is computed from data.entries - the rows on '
                "this page - but its label does not say page, so it reads as "
                "a ledger-wide number. This is the defect P3c3a-1 closes, "
                "one card along."
            )
        else:
            assert "ledger" in lowered, (
                f'card "{label}" is computed from data.total - the ledger\'s '
                "count - but its label does not say ledger, so it is "
                "indistinguishable from the page-scoped cards beside it."
            )


def test_the_empty_state_is_not_keyed_off_the_ledger_count():
    """
    `total` gaining a new meaning silently gave the empty-state condition
    one too. It now counts `tool_call:` keys and excludes the synthesized
    rows for orphaned write-ahead intents (D16), which live under a
    different prefix - so a ledger holding only those has `total === 0`
    while the table below renders rows, and the old condition would have
    printed "No ledger entries yet" directly above them.
    """
    source = AUDIT_PAGE_TSX.read_text(encoding="utf-8")

    assert "data.entries.length === 0" in source, (
        "the empty state must be keyed off the rendered rows"
    )
    assert "data.total === 0" not in source, (
        "the empty state is still keyed off data.total, which since P3c3a-1 "
        "is the ledger's count of decision records and excludes the "
        "synthesized orphan-intent rows the table renders"
    )


# ---------------------------------------------------------------------------
# P3c3a-2: truncation is stated
# ---------------------------------------------------------------------------

@requires_stack
def test_has_more_is_true_when_records_exist_behind_the_page():
    _seed_decisions(5, agent_id=f"p3c3a-more-{uuid.uuid4().hex[:8]}")

    page = _audit(limit=3)

    assert page["has_more"] is True, (
        "the ledger holds more decision records than this page returned and "
        f"has_more still reads {page['has_more']}. total={page['total']} "
        f"rows={len(page['entries'])}"
    )


@requires_stack
def test_has_more_is_false_when_the_page_covers_everything_behind_it():
    """The other half. A flag that is always true states nothing either."""
    _seed_decisions(3, agent_id=f"p3c3a-nomore-{uuid.uuid4().hex[:8]}")

    total = _immudb_prefix_count("tool_call:")
    page = _audit(limit=total + 100)

    assert page["has_more"] is False, (
        f"the page asked for {total + 100} and the ledger holds {total}, so "
        "nothing is behind this page, yet has_more reads true"
    )


@requires_stack
def test_the_response_carries_no_cursor():
    """
    A pre-registered negative, enforced rather than asserted in prose. A
    cursor is a position in an ordering and Phase 3c-3b replaces the
    ordering, so one shipped here would either break there or freeze the
    ordering this phase is keeping open.
    """
    page = _audit(limit=3)

    forbidden = {"cursor", "next_cursor", "next", "continuation",
                 "continuation_token", "next_page_token", "offset", "after"}
    present = forbidden & set(page)
    assert not present, f"/audit's response grew a continuation token: {present}"


# ---------------------------------------------------------------------------
# P3c3a-3: the tombstone join is exact
# ---------------------------------------------------------------------------

# Enough forged tombstones to fill the old scan's window at this limit and
# push the one under test out of it. Larger than PAGE_LIMIT so the window is
# filled with room to spare.
_PAGE_LIMIT = 10
_DECOY_TOMBSTONES = 12


def _bury_tombstone_window() -> None:
    """Fill the old `content_erasure:` scan's descending window with
    tombstones that sort above any real (hex uuid) call_id, so a real one
    written before them falls outside a scan bounded by _PAGE_LIMIT."""
    for i in range(_DECOY_TOMBSTONES):
        _write_tombstone(f"zzzz-p3c3a-decoy-{i:03d}-{uuid.uuid4().hex}")


def _entry_for_key(page: dict, raw_key: str) -> dict:
    """`ledger_key` on an /audit entry is the base64 raw ImmuDB key (P3a-2),
    not the key itself."""
    encoded = _b64(raw_key)
    matching = [e for e in page["entries"] if e["ledger_key"] == encoded]
    assert matching, (
        "the record under test is not on the page, so this test proved "
        "nothing about the tombstone join. Its tool_call: key must sort "
        f"within the top {_PAGE_LIMIT} descending. rows={len(page['entries'])}"
    )
    return matching[0]


@requires_stack
def test_erased_record_reads_erased_even_when_its_tombstone_is_far_down_the_ledger():
    """
    P3c3a-3, first face. A record erased through the real endpoint has no
    content row and a tombstone. With the tombstone outside the old scan's
    limit, `_payload_state` saw content_state="present" and no row and no
    tombstone, and returned **"lost"** - which that function documents as
    "the row disappeared some other way", an operational incident with no
    erasure semantics behind it. An Article 17 erasure reported as an
    incident.

    The assertion is on the record's rendered state, and it holds
    irrespective of how many tombstones the ledger contains, which is the
    property the old scan did not have.
    """
    call_id = uuid.uuid4().hex
    key = _write_decision_record(call_id, agent_id=f"zzzzzzzz-p3c3a-{uuid.uuid4().hex[:8]}")
    _write_tombstone(call_id)
    _bury_tombstone_window()

    entry = _entry_for_key(_audit(limit=_PAGE_LIMIT), key)

    assert entry["payload_state"] == "erased", (
        "an erased record rendered as something else because its tombstone "
        "fell outside a limit that has nothing to do with it. "
        f"payload_state={entry['payload_state']!r} (the pre-fix value here "
        "is 'lost', which means an operational incident, not an erasure)"
    )
    assert entry["payload"] is None, entry


@requires_stack
def test_conflicted_record_withholds_its_payload_even_when_its_tombstone_is_far_down():
    """
    P3c3a-3, second face, and the one that leaks. A tombstone whose content
    row outlived it must render "erasure_conflict" with the payload withheld
    (P13-4, red-team U4 combination 1). With the tombstone outside the old
    scan's limit the record rendered plain "present" **and returned the
    payload** - P13-4 undone at read time by a bound on an unrelated scan.
    """
    call_id = uuid.uuid4().hex
    marker = f"P3C3A-LEAK-MARKER-{uuid.uuid4().hex}"
    key = _write_decision_record(call_id, agent_id=f"zzzzzzzz-p3c3a-{uuid.uuid4().hex[:8]}")
    _write_content_row(call_id, {"marker": marker})
    _write_tombstone(call_id)
    _bury_tombstone_window()

    entry = _entry_for_key(_audit(limit=_PAGE_LIMIT), key)

    assert entry["payload_state"] == "erasure_conflict", (
        "a tombstoned call_id whose row still exists rendered as something "
        f"other than erasure_conflict: {entry['payload_state']!r}"
    )
    assert entry["payload"] is None, (
        "the payload of a tombstoned call_id was returned. A limit on the "
        "tombstone scan undid P13-4 at read time."
    )
    assert marker not in json.dumps(entry), (
        f"the erased content leaked into the entry: {entry}"
    )


@requires_stack
def test_a_tombstone_is_never_rendered_as_a_decision_row():
    """
    D11's structural property, re-checked here because P3c3a-3 changed how
    tombstones are read. They used to arrive from their own prefix scan;
    they now arrive from a keyed getall. Neither may put a tombstone into
    `entries` as if it were a decision.
    """
    call_id = uuid.uuid4().hex
    _write_tombstone(call_id)

    page = _audit(limit=_PAGE_LIMIT)

    for entry in page["entries"]:
        assert entry.get("outcome_type") != "content_erasure", entry
        assert not (entry.get("ledger_key") and
                    base64.b64decode(entry["ledger_key"]).startswith(b"content_erasure:")), entry
