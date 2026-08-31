"""tests/test_ledger_vocabulary.py - Phase 3c-3c completion pass.

Every copy of a ledger key name, view name or ceiling agrees with every
other copy.

Why this exists, and why it is not a shared module. Five modules speak to
the same ledger and none of them imports another, by design: they live in
images that are built separately, which is what ADR-0001's process
isolation buys. `tools/ail_backfill_index.py` says so in a comment - "Three
copies of these names is two too many, but they live in three images that
do not import each other" - and then leaves the copies uncompared.

That is a defect class this phase met twice already and fixed twice
locally: `AIL_RESERVED_POSITIONS`, four copies, closed by D36 binding the
value into the ledger and every reader refusing on disagreement; and
Compose's default project-name rule, two copies, one of which dropped a
hyphen and cost a CI run. In both cases the typo was not the defect. Two
copies of a rule with nothing comparing them is.

So this compares them. It cannot remove the duplication - `provenance/` is
the one rule shared by being copied into three images, and doing that for
every constant would couple the images this project deliberately keeps
apart - but a disagreement now fails a test instead of producing a record
nothing can find.

What it does not cover: a module that renames its constant, or a sixth
module that hardcodes a string and defines no constant at all. Those are
invisible to a comparison of named constants, and the honest scope is
stated rather than implied.
"""

import importlib.util
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))


def _load(name: str, relative: str):
    """One module under its own name.

    control_plane/main.py and decision_service/main.py are both main.py, so
    a bare import clobbers whichever sys.modules holds; and
    control_plane/main.py resolves `from bundle import ...` as a sibling.
    Same reasoning as tests/test_audit_ordering.py::_load_ordering_check.
    """
    sys.path.insert(0, str(REPO_ROOT / "control_plane"))
    os.environ.setdefault("CONTROL_PLANE_READ_KEY", "test-read-key")
    os.environ.setdefault("CONTROL_PLANE_WRITE_KEY", "test-write-key")
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _text(value) -> str:
    return value.decode() if isinstance(value, bytes) else str(value)


def _modules():
    import ail_backfill_index

    return {
        "verifier": _load("vocab_verifier", "verifier/main.py"),
        "control_plane": _load("vocab_control_plane", "control_plane/main.py"),
        "anchor_service": _load("vocab_anchor", "anchor_service/main.py"),
        "backfill": ail_backfill_index,
    }


def _assert_all_agree(label: str, values: dict) -> None:
    distinct = set(values.values())
    assert len(distinct) == 1, (
        f"{label} does not mean the same thing in every module that reads it: "
        f"{values}. These modules never import each other, so nothing but this "
        "test compares them."
    )


def test_the_sequence_counter_key_agrees_everywhere():
    m = _modules()
    _assert_all_agree("the sequence counter key", {
        "verifier": _text(m["verifier"].SEQUENCE_KEY),
        "anchor_service": _text(m["anchor_service"].SEQUENCE_KEY),
        "backfill": _text(m["backfill"].SEQUENCE_KEY),
    })


def test_the_reserve_key_agrees_everywhere():
    """D36 binds the reserve's *value* into the ledger, and every reader
    checks its own against it. Nothing checks that they all look under the
    same key, which is the one disagreement that would make each of them
    read `None` and conclude, correctly by its own lights, that nothing is
    bound."""
    m = _modules()
    _assert_all_agree("the bound-reserve key", {
        "verifier": _text(m["verifier"].RESERVE_KEY),
        "control_plane": _text(m["control_plane"]._RESERVE_KEY),
        "anchor_service": _text(m["anchor_service"].RESERVE_KEY),
        "backfill": _text(m["backfill"].RESERVE_KEY),
    })


def test_the_view_index_names_agree_everywhere():
    m = _modules()
    _assert_all_agree("the decision view's set name", {
        "verifier": _text(m["verifier"]._VIEW_SETS["decision"]),
        "control_plane": _text(m["control_plane"]._VIEW_DECISION),
        "anchor_service": [k for k, v in m["anchor_service"].VIEW_PREFIXES.items()
                           if v == "tool_call:"][0],
        "backfill": m["backfill"].VIEWS["decision"][1],
    })
    _assert_all_agree("the intent view's set name", {
        "verifier": _text(m["verifier"]._VIEW_SETS["intent"]),
        "control_plane": _text(m["control_plane"]._VIEW_INTENT),
        "anchor_service": [k for k, v in m["anchor_service"].VIEW_PREFIXES.items()
                           if v == "tool_call_intent:"][0],
        "backfill": m["backfill"].VIEWS["intent"][1],
    })


def test_the_fault_record_vocabulary_agrees():
    """The verifier writes the fault record and the control plane joins it.
    A disagreement here produces a fault nothing on the page ever finds,
    which is the failure the record exists to prevent."""
    m = _modules()
    _assert_all_agree("the ledger-fault key prefix", {
        "verifier": m["verifier"].FAULT_KEY_PREFIX,
        "control_plane": m["control_plane"]._FAULT_KEY_PREFIX,
    })
    _assert_all_agree("the ledger-fault record_type", {
        "verifier": m["verifier"].FAULT_RECORD_TYPE,
        "control_plane": m["control_plane"]._FAULT_RECORD_TYPE,
    })


def test_the_scan_ceiling_agrees_everywhere():
    """ImmuDB refuses a scan or zscan limit above 2500, measured
    (docs/reports/phase-3c3c-probe.md section 2). Three modules page against
    that number and each holds its own copy; one of them being wrong is how
    a pass silently stops early."""
    m = _modules()
    _assert_all_agree("the scan ceiling", {
        "control_plane": m["control_plane"]._MAX_SCAN_LIMIT,
        "anchor_service": m["anchor_service"]._ZSCAN_PAGE,
        "backfill": m["backfill"].SCAN_PAGE,
    })


def test_the_reserve_default_agrees_everywhere():
    """The bound value in the ledger is what actually keeps these honest at
    runtime (D36). This catches the case before anything is bound: four
    defaults that disagree would put the seam in a different place on a
    fresh deployment depending on which service allocated first."""
    m = _modules()
    _assert_all_agree("the default reserve", {
        "verifier": m["verifier"].RESERVED_POSITIONS,
        "control_plane": m["control_plane"]._RESERVED_POSITIONS,
        "anchor_service": m["anchor_service"].RESERVED_POSITIONS,
        "backfill": m["backfill"].RESERVED_POSITIONS,
    })
