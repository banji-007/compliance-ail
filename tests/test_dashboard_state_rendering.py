"""
tests/test_dashboard_state_rendering.py - P2-10 (Phase 2 completion pass B).

W7 (docs/reports/phase-2-redteam.md): `profile: unknown` rendered with no
colour, icon, or badge, unlike the rich per-state treatment
`VerificationCell` already gives `verification.state` - a forged
profile-less record was visually indistinguishable from a legitimate one.
The completion report (docs/reports/phase-2-completion.md) added
`execution_state` (D16) but did not say whether the dashboard renders it -
same defect on a newer field, if so.

Same shape as tests/test_outcome_types.py::
test_dashboard_fault_class_type_matches_reachable_set (R5, Phase 1.3
completion pass): static parse of the dashboard's own TSX/TS source, no
stack required, comparing the dashboard's rendering map against the set of
values control_plane/main.py::get_audit can actually emit today.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
AUDIT_TABLE_TSX = REPO_ROOT / "dashboard" / "components" / "audit-table.tsx"
TYPES_TS = REPO_ROOT / "dashboard" / "lib" / "types.ts"

# What control_plane/main.py::get_audit can actually put in these two
# fields today. "attested" is defined (docs/adr/0005-outcome-taxonomy.md)
# but no code path produces it yet - same category as a fault_class that
# never reaches the ledger, just from the opposite direction: extra,
# forward-looking coverage in the rendering map is fine, missing coverage
# for a reachable value is not.
_REACHABLE_PROFILE_VALUES = {"observed", "mediated", "unknown"}
_REACHABLE_EXECUTION_STATE_VALUES = {"completed", "unknown", "n/a"}


def _source() -> str:
    return AUDIT_TABLE_TSX.read_text(encoding="utf-8")


def _record_keys(source: str, const_name: str) -> set[str]:
    """Extract the string-literal keys of a `const NAME: Record<...> = { ... };`
    object literal from TSX source, the same style
    test_outcome_types.py::_dashboard_fault_class_union parses a `type`
    union. Stops at the first top-level `};` after the const's own `= {`."""
    marker = f"const {const_name}"
    start = source.index(marker)
    brace_start = source.index("{", start)
    depth = 0
    i = brace_start
    while i < len(source):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    body = source[brace_start:i]
    return set(re.findall(r"^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:", body, re.MULTILINE))


def test_profile_rendering_map_covers_every_value_the_api_can_emit():
    """
    Mutation: delete the "unknown" key (or any reachable key) from
    PROFILE_LABEL or PROFILE_VARIANT in dashboard/components/audit-table.tsx.
    This test must fail.
    """
    source = _source()
    for const_name in ("PROFILE_LABEL", "PROFILE_VARIANT"):
        keys = _record_keys(source, const_name)
        missing = _REACHABLE_PROFILE_VALUES - keys
        assert not missing, (
            f"{const_name} in audit-table.tsx is missing rendering for profile "
            f"value(s) {sorted(missing)} that /audit can actually emit"
        )


def test_profile_rendering_map_gives_reachable_values_distinct_treatment():
    """
    Distinctness, not just presence: two reachable profile values sharing the
    same badge variant would still leave a forged record indistinguishable
    from a genuine one, the exact W7 finding. "unknown" in particular must
    never share a variant with a normal value.
    """
    source = _source()
    variant_keys = _record_keys(source, "PROFILE_VARIANT")
    body_start = source.index("const PROFILE_VARIANT")
    body_start = source.index("{", body_start)
    depth = 0
    i = body_start
    while i < len(source):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    body = source[body_start:i]

    variant_by_key = dict(re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*"([^"]+)"', body))
    assert _REACHABLE_PROFILE_VALUES <= variant_keys

    reachable_variants = {value: variant_by_key[value] for value in _REACHABLE_PROFILE_VALUES}
    assert len(set(reachable_variants.values())) == len(reachable_variants), (
        f"Two or more reachable profile values share the same badge variant: {reachable_variants}"
    )
    assert reachable_variants["unknown"] not in (
        reachable_variants["observed"],
        reachable_variants["mediated"],
    ), f"profile: unknown must not share a variant with a normal value: {reachable_variants}"


def test_execution_state_rendering_covers_every_value_the_api_can_emit():
    """
    execution_state (D16) is rendered with a conditional, not a lookup map:
    "unknown" gets amber styling, "completed"/"n/a" share a quiet default.
    Confirms all three reachable values are named literally in the
    component's rendering branch, and that "unknown" gets a distinct
    (amber) treatment - the same "unknown must not look normal" property
    the profile test above enforces.

    Mutation: remove the `entry.execution_state === "unknown"` conditional
    (collapsing to the single default-styled branch for every value). This
    test must fail.
    """
    source = _source()
    assert 'entry.execution_state === "unknown"' in source, (
        "audit-table.tsx no longer branches on execution_state === \"unknown\" - "
        "the honest-gap signal D16 exists to surface would render identically "
        "to a normal completed/n-a record"
    )

    decision_cell_start = source.index("function DecisionCell")
    decision_cell_end = source.index("function VerificationCell")
    decision_cell_body = source[decision_cell_start:decision_cell_end]

    # "unknown" gets its own literal branch; "completed"/"n/a" share a
    # template-literal default (`execution: {entry.execution_state}`) rather
    # than a per-value literal - confirm that default branch exists and is
    # reached whenever execution_state is not "unknown".
    assert "execution: unknown outcome" in decision_cell_body, (
        "execution_state \"unknown\" has no literal rendering in DecisionCell"
    )
    assert "execution: {entry.execution_state}" in decision_cell_body, (
        "no default execution_state rendering found for the non-unknown values "
        "(\"completed\", \"n/a\") in DecisionCell"
    )

    unknown_branch = decision_cell_body[decision_cell_body.index('=== "unknown"'):]
    assert "amber" in unknown_branch.split("execution: unknown outcome")[0], (
        "execution_state \"unknown\" is not styled distinctly (amber) from the default branch"
    )
