"""tests/test_reserve_binding.py - Phase 3c-3c (P3c3c-6, D36).

The reserve cannot be raised after allocation.

The attack this carries forward is red-team C3
(docs/reports/phase-3c3b-redteam.md), reproduced on unmodified b9f6a1d
before anything here was written, *along the tool's own documented
remediation*: the backfill refused to run and instructed "Raise
AIL_RESERVED_POSITIONS ... on every service, and re-run", and doing exactly
that gave

    before: {"state":"clean","allocated":11,"indexed":14,"backfilled":2548}
    seed:   {"seeded":true,"from":1000000011,"value":2000000000}
    after:  {"state":"clean","allocated":0,"indexed":0,"backfilled":2598}

Eleven committed compare-and-set allocations reclassified as backfilled
history. They are no longer reconciled - `allocated: 0`, so a hole among
them is undetectable - and no longer order-checked, because D33 is scoped to
positions above the reserve. The verdict is still `clean`, permanently.

D36 binds the reserve into the ledger at first allocation, under
KeyMustNotExist in the same ExecAll, and every reader refuses on
disagreement. That gives immutability and the runtime agreement check from
one mechanism rather than pairwise probes between three services.
"""

import base64
import importlib
import importlib.util
import json
import os
import sys
import uuid
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tests"))
sys.path.insert(0, str(REPO_ROOT / "tools"))

from compose_helpers import compose, requires_docker_cli, wait_for_health  # noqa: E402

VERIFIER_URL       = os.getenv("VERIFIER_URL",       "http://localhost:8003")
VERIFIER_WRITE_KEY = os.getenv("VERIFIER_WRITE_KEY", "test-verifier-write-key")
IMMUDB_URL         = os.getenv("IMMUDB_URL",         "http://localhost:8080")
IMMUDB_USER        = os.getenv("IMMUDB_USER",        "immudb")
IMMUDB_PASSWORD    = os.getenv("IMMUDB_PASSWORD",    "immudb")
CONTROL_PLANE_URL  = os.getenv("CONTROL_PLANE_URL",  "http://localhost:8002")
READ_API_KEY       = os.getenv("CONTROL_PLANE_READ_KEY", "test-read-key")

RESERVE_KEY = "ail_seq:reserve"
SEQUENCE_KEY = "ail_seq:commit"
CONFIGURED_RESERVE = int(os.getenv("AIL_RESERVED_POSITIONS", "1000000000"))

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


def _getall(keys: list[str]) -> dict:
    resp = _CLIENT.post(f"{IMMUDB_URL}/api/v2/db/getall",
                        json={"keys": [_b64(k) for k in keys]}, headers=_immudb_headers())
    resp.raise_for_status()
    out = {}
    for entry in resp.json().get("entries", []):
        out[base64.b64decode(entry["key"]).decode()] = entry
    return out


def _decision_value(call_id: str, agent_id: str) -> str:
    return json.dumps({
        "record_type": "decision", "call_id": call_id, "agent_id": agent_id,
        "timestamp": "2026-08-31T00:00:00", "tool_name": "query_database",
        "outcome_type": "policy_allow", "fault_class": None,
        "policy_revision": "p3c3c-test", "reasons": [],
        "input_sha256": uuid.uuid4().hex, "content_state": "unavailable",
        "profile": "observed",
    }, separators=(",", ":"))


def _write_ordered(key: str, value: str) -> httpx.Response:
    return _CLIENT.post(f"{VERIFIER_URL}/write-ordered",
                        json={"key": _b64(key), "value": _b64(value), "view": "decision"},
                        headers={"X-API-Key": VERIFIER_WRITE_KEY})


def _new_decision() -> httpx.Response:
    key = f"tool_call:p3c3c-res-{uuid.uuid4().hex[:8]}:{uuid.uuid4().hex}:query_database"
    return _write_ordered(key, _decision_value(uuid.uuid4().hex, "p3c3c-res"))


def _load(name: str, relative: str):
    """One of the four readers, loaded under its own module name.

    control_plane/main.py and decision_service/main.py are both main.py, so a
    bare import clobbers whichever sys.modules already holds; and
    control_plane/main.py does `from bundle import ...`, which resolves as a
    sibling only when its own directory is on sys.path. Same reasoning as
    tests/test_audit_ordering.py::_load_ordering_check.
    """
    sys.path.insert(0, str(REPO_ROOT / "control_plane"))
    os.environ.setdefault("CONTROL_PLANE_READ_KEY", READ_API_KEY)
    os.environ.setdefault("CONTROL_PLANE_WRITE_KEY", "test-write-key")
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# The binding itself
# ---------------------------------------------------------------------------

@requires_stack
def test_the_reserve_is_bound_into_the_ledger_at_first_allocation():
    """
    The value is in the ledger, and it is the value this deployment
    allocates against.

    Nothing before this distinguished "raised after allocation" from "always
    was this value", because the seam existed only as an environment
    variable in four processes. Now it exists as a record.
    """
    resp = _new_decision()
    assert resp.status_code == 200 and resp.json()["verified"], resp.text[:300]

    found = _getall([RESERVE_KEY])
    assert RESERVE_KEY in found, (
        "the ledger has allocated a position and bound no reserve; nothing "
        "distinguishes this ledger's seam from any other value later"
    )
    bound = int(base64.b64decode(found[RESERVE_KEY]["value"]).decode())
    assert bound == CONFIGURED_RESERVE, (
        f"the ledger has {bound} bound and this stack is configured with "
        f"{CONFIGURED_RESERVE}"
    )

    seq = int(base64.b64decode(_getall([SEQUENCE_KEY])[SEQUENCE_KEY]["value"]).decode())
    assert seq > bound, (
        f"the counter is at {seq}, at or below the bound reserve {bound}; live "
        "positions would sit inside the range history is scored into"
    )


def test_the_reserve_is_bound_under_key_must_not_exist_in_the_allocating_execall():
    """
    Immutability comes from the precondition, not from nobody trying.

    Asserted on the request the writer builds: the reserve operation and its
    KeyMustNotExist precondition must be in the same ExecAll as the record,
    the counter advance and the zAdd, or a second writer could bind a
    different value between the two calls.
    """
    source = (REPO_ROOT / "verifier" / "main.py").read_text(encoding="utf-8")
    body = source[source.index("def _ordered_commit"):]
    body = body[:body.index(chr(10) + "@app.post")]

    assert "keyMustNotExist=schema.Precondition.KeyMustNotExistPrecondition(\n" in body \
        or "KeyMustNotExistPrecondition(" in body, body[:200]
    assert "key=RESERVE_KEY" in body, (
        "the reserve is not covered by a KeyMustNotExist precondition, so two "
        "writers could bind different values"
    )
    assert "operations.append" in body and "preconditions.append" in body, (
        "the reserve is not added to the same ExecAll as the allocation"
    )
    request_at = body.index("schema.ExecAllRequest(")
    assert body.index("key=RESERVE_KEY") < request_at, (
        "the reserve operation is built after the request, so it is not in it"
    )


# ---------------------------------------------------------------------------
# Every reader refuses on disagreement
# ---------------------------------------------------------------------------

@requires_stack
def test_the_backfill_refuses_a_raised_reserve_and_names_re_indexing():
    """
    C3's sequence, refused, and the refusal message no longer instructs the
    attack.

    The old message said "Raise AIL_RESERVED_POSITIONS above the ledger's
    highest transaction id, on every service, and re-run", which is exactly
    what puts committed positions inside the new reserve. A reserve that is
    genuinely too small is a re-index into a new view, not a moved boundary,
    and the message has to say so or the next operator does it again.
    """
    _new_decision()          # make sure something is bound
    os.environ["AIL_RESERVED_POSITIONS"] = str(CONFIGURED_RESERVE * 2)
    os.environ["IMMUDB_URL"] = IMMUDB_URL
    try:
        import ail_backfill_index as bf
        importlib.reload(bf)
        bf.IMMUDB_URL = IMMUDB_URL
        with pytest.raises(SystemExit) as raised:
            bf.backfill(dry_run=True)
    finally:
        os.environ["AIL_RESERVED_POSITIONS"] = str(CONFIGURED_RESERVE)
        import ail_backfill_index as bf
        importlib.reload(bf)
        bf.IMMUDB_URL = IMMUDB_URL

    message = str(raised.value)
    assert "bound into it" in message, message
    assert str(CONFIGURED_RESERVE) in message, message
    assert "Raise AIL_RESERVED_POSITIONS" not in message, (
        "the refusal still instructs the operator to raise the reserve, which "
        f"is the attack: {message}"
    )


@requires_stack
def test_the_backfill_refusal_over_the_reserve_points_at_a_new_view():
    """
    The other refusal in the same tool - history whose transaction ids reach
    the reserve - had the same instruction in it, and it is the one an
    operator actually hits.
    """
    source = (REPO_ROOT / "tools" / "ail_backfill_index.py").read_text(encoding="utf-8")
    refusal = source[source.index("refusing to backfill: {len(over)}"):]
    refusal = refusal[:refusal.index(")\n")]
    assert "re-index into a new view" in refusal, refusal
    assert "Raise AIL_RESERVED_POSITIONS" not in refusal, refusal
    assert "cannot be raised" in refusal, refusal


@requires_stack
def test_the_control_plane_refuses_a_page_on_disagreement():
    """The reader that serves the page refuses rather than paging against a
    seam the writer did not allocate against."""
    _new_decision()
    module = _load("cp_reserve_p3c3c", "control_plane/main.py")
    module.IMMUDB_URL = IMMUDB_URL
    module._RESERVED_POSITIONS = CONFIGURED_RESERVE * 2
    module._bound_reserve_cache = None

    with httpx.Client(timeout=30.0) as client:
        login = client.post(f"{IMMUDB_URL}/api/v2/login", json={
            "user": _b64(IMMUDB_USER), "password": _b64(IMMUDB_PASSWORD),
            "database": _b64("defaultdb")})
        login.raise_for_status()
        token = login.json()["token"]
        with pytest.raises(module.ReserveMismatch) as raised:
            module._assert_reserve_agrees(client, token)
    assert str(CONFIGURED_RESERVE) in str(raised.value), str(raised.value)
    assert "re-index into a new view" in str(raised.value), str(raised.value)


@requires_stack
def test_the_reconciler_refuses_a_pass_on_disagreement():
    """The reader that reconciles refuses rather than reporting artefacts.

    A pass run against a raised reserve is what produced C3's `allocated: 0`
    with every live position reclassified, and reported it as `clean`.
    """
    _new_decision()
    module = _load("recon_reserve_p3c3c", "anchor_service/main.py")
    module.IMMUDB_URL = IMMUDB_URL
    module.RESERVED_POSITIONS = CONFIGURED_RESERVE * 2
    module.RECONCILE_REPORT_PATH = ""

    result = module.reconcile_once()
    assert result["state"] == "reserve_mismatch", (
        f"the reconciler reported a verdict against a seam it does not share "
        f"with the writer: {result}"
    )
    assert result["bound_reserve"] == CONFIGURED_RESERVE, result


@requires_stack
@requires_docker_cli
def test_the_writer_refuses_to_allocate_on_disagreement():
    """
    The reader that matters most, exercised as a service rather than as a
    module: a verifier configured with a different reserve must not allocate
    a single position.

    Recreated with the setting overridden through the compose file's own
    `${AIL_RESERVED_POSITIONS:-...}` substitution, so nothing on disk
    changes, and put back afterwards - unconditionally, because a session
    that left the writer mismatched would fail every later test.
    """
    _new_decision()          # something is bound before the writer is moved
    raised = str(CONFIGURED_RESERVE * 2)
    compose("up", "-d", "--no-deps", "--force-recreate", "verifier",
            env={"AIL_RESERVED_POSITIONS": raised})
    try:
        assert wait_for_health(f"{VERIFIER_URL}/health"), "the verifier did not restart"
        resp = _new_decision()
        assert resp.status_code == 200, resp.text[:300]
        body = resp.json()
        assert body["verified"] is False and body["committed"] is False, (
            f"a writer configured with reserve {raised} allocated against a "
            f"ledger bound to {CONFIGURED_RESERVE}: {body}"
        )
        assert str(CONFIGURED_RESERVE) in (body.get("detail") or ""), body
    finally:
        compose("up", "-d", "--no-deps", "--force-recreate", "verifier",
                env={"AIL_RESERVED_POSITIONS": str(CONFIGURED_RESERVE)})
        assert wait_for_health(f"{VERIFIER_URL}/health"), (
            "the verifier did not come back with its original reserve"
        )
    after = _new_decision()
    assert after.status_code == 200 and after.json()["verified"], (
        f"the writer did not recover after the reserve was put back: "
        f"{after.text[:300]}"
    )


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad", ["0", "-1", "-1000000000", "", "abc", "1.5", None])
def test_a_reserve_that_is_not_a_positive_integer_is_refused_everywhere(bad):
    """
    C4 was not refuted, but it named this: nothing validated
    AIL_RESERVED_POSITIONS in any of its four copies, and a zero or negative
    value is the one input that puts every position at or below zero - where
    `zscan` under `desc: true` silently omits a negatively-scored member and
    a score of exactly zero arrives with no score field at all. The records
    would be indexed and absent from every page.

    All three module copies, because three images do not import each other
    and a rule enforced in one of them is not enforced.
    """
    import ail_backfill_index as bf

    cp = _load("cp_validate_p3c3c", "control_plane/main.py")
    anchor = _load("recon_validate_p3c3c", "anchor_service/main.py")
    verifier = _load("verifier_validate_p3c3c", "verifier/main.py")

    for name, fn, error in (("verifier", verifier.validate_reserve, RuntimeError),
                            ("control_plane", cp._validate_reserve, RuntimeError),
                            ("anchor_service", anchor.validate_reserve, RuntimeError),
                            ("ail_backfill_index", bf.validate_reserve, SystemExit)):
        with pytest.raises(error):
            fn(bad)


def test_each_module_validates_the_reserve_it_actually_uses():
    """
    The validator existing is not the same as the constant going through it.

    A module could define validate_reserve and still read the environment
    variable with a bare int(), which is what all four did before this phase.
    """
    for path, call in (
        ("verifier/main.py",           "RESERVED_POSITIONS = validate_reserve("),
        ("anchor_service/main.py",     "RESERVED_POSITIONS = validate_reserve("),
        ("control_plane/main.py",      "_RESERVED_POSITIONS = _validate_reserve("),
        ("tools/ail_backfill_index.py", "RESERVED_POSITIONS = validate_reserve("),
    ):
        source = (REPO_ROOT / path).read_text(encoding="utf-8")
        assert call in source, (
            f"{path} reads AIL_RESERVED_POSITIONS without putting it through its "
            "own validator"
        )
        assert 'int(os.getenv("AIL_RESERVED_POSITIONS"' not in source, (
            f"{path} still reads the reserve with a bare int()"
        )
