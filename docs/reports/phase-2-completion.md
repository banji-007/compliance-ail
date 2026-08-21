# Phase 2 Completion Pass: Write-Ahead Intent Visibility and Per-Tool Verification

**Run id:** `p2-boundary` (continued). **Working directory:** `C:\Users\banji\OneDrive\Documents\p2-boundary-scratch` (scratch clone, not the primary working directory). **Branch:** `phase-2-boundary`, same branch as `docs/reports/phase-2.md` (PR #8, not merged).

This pass closes two gaps found on review of the Phase 2 build (`docs/reports/phase-2.md`), not by a red-team exercise: D16 (write-ahead intent, then completion - an executed-but-unrecorded mediated call must be detectable, not silently absent from `/audit`) and D17 (exclusivity verification keyed by tool, not by mechanism string - a second tool sharing a verified tool's mechanism must never inherit its verification result). Both are documented in `docs/adr/0009-write-ahead-intent-and-per-tool-verification.md`.

## 1. Verdict per item

| Item | Verdict |
| :--- | :--- |
| P2-7 (D16) | **Holds.** A failed intent write refuses execution outright (mocked unit test, no live stack needed). A real mediated call surfaces `execution_state: "completed"`; an orphaned intent forged directly against the verifier surfaces `execution_state: "unknown"`, live against the real stack. Both mutations caught. |
| P2-8 (D17) | **Holds.** Two tools sharing the identical mechanism string each trigger their own independent verification call (proven by call count). A tool absent from the per-tool verified map - including, structurally, one added after the verification pass ran - never resolves to `demonstrated`. Both mutations caught. |

## 2. Evidence per item

### P2-7 (D16): write-ahead intent, then completion

**Demonstrate (before).** Before this pass, `decision_service/main.py::decide()` executed the vault tool and then wrote exactly one ledger record, after execution, documenting the outcome. If that single write failed - the verifier becoming unreachable in the window between execution finishing and the write starting - the call left no trace anywhere: not in the ledger, not in `/audit`, indistinguishable from a call that had never been attempted. This gap was not exploitable through any committed test before this pass (no test forced the post-execution write to fail while leaving execution's own side effect - the real secret already returned to the caller - in place), which is exactly why it is being closed now rather than carried forward silently.

**Fix.** `ledger/immudb_ledger.py::log_tool_intent` (new) writes a `record_type: "decision_intent"` entry, keyed under a distinct `tool_call_intent:` prefix, immediately before `_execute_vault_tool` is called. `decide()`'s control flow gates on this: the intent write is `try`'d, and `_execute_vault_tool` is only reached in the corresponding `else` branch - a failed intent write returns `outcome_type: fault`, `fault_class: intent_write_failed`, and never executes. `control_plane/main.py::get_audit` now performs a third ImmuDB scan (`tool_call_intent:`), joins it against the completion entries by `call_id`, and computes `execution_state` per entry: `"completed"` (both records exist), `"unknown"` (an intent exists with no completion - synthesized directly from the intent record's own fields), or `"n/a"` (no intent record at all).

**Demonstrate (after), live against the running `docker-compose.test.yml` stack (project `p2-boundary`):**

1. A real `read_vault_secret` call (`middleware.intercept_tool_call("read_vault_secret", {"secret_name": "db_master_password"}, ...)`) produces a ledger record whose `/audit` entry carries `execution_state: "completed"`.
2. A real `provision_cloud_server` call (an `observed` tool, never subject to the intent protocol) produces `execution_state: "n/a"`.
3. An intent record forged directly against the verifier's `/write` (the same live-forgery style `tests/test_record_profile.py::test_audit_forged_profile_less_record_renders_as_unknown_not_observed` already uses for a different field), with `record_type: "decision_intent"`, `tool_name: "read_vault_secret"`, and no matching completion record for its `call_id`, is picked up by `/audit` and rendered with `execution_state: "unknown"`, `outcome_type: "policy_allow"` (what the forged intent claimed was approved) - not silently absent, and not rendered identically to case 1.

**Enforce.** `tests/test_intent_completion_visibility.py`:
- `test_failed_intent_write_refuses_execution` (mocked, no live stack) - asserts `_execute_vault_tool` is never called when the intent write raises, and the response is `fault`/`intent_write_failed` with no `result` key.
- `test_real_mediated_call_surfaces_execution_state_completed`, `test_observed_tool_call_surfaces_execution_state_na`, `test_orphaned_intent_with_no_completion_surfaces_as_unknown` (live, `@requires_stack`) - the three cases above, reproduced as committed tests.

**Mutation, write side.** In `decide()`, moved the `_execute_vault_tool` call out of the intent write's `else` branch so it runs unconditionally regardless of whether the intent write raised. `test_failed_intent_write_refuses_execution` failed as expected (`execute_called["n"] == 1`, not `0`). Reverted; test passes again.

**Mutation, read side.** In `get_audit`'s orphan-detection loop, added `continue` as the loop's first statement, silently dropping every unmatched intent. Required rebuilding and restarting the `ail-control-plane` container (code runs inside the container, not accessible to a host-side pytest patch). `test_orphaned_intent_with_no_completion_surfaces_as_unknown` failed as expected (`matching == []` - the forged call_id vanished from `/audit` entirely). Reverted, rebuilt, restarted; test passes again.

### P2-8 (D17): exclusivity verification keyed by tool

**Demonstrate (before).** `decision_service/schemas.py::_MECHANISM_VERIFIED` was `Dict[str, bool]` keyed on the mechanism string. `resolve_exclusivity_for` read `_MECHANISM_VERIFIED.get(reg.mechanism)`, not anything tool-specific. With exactly one tool (`read_vault_secret`) declaring `mcp_stdio_secret_mount` today, this was not exploitable through the existing registry, but the shape itself meant a second tool later declaring the identical mechanism string would read the first tool's cached result without its own check ever running in its own name - config alone (naming an already-verified mechanism) would then be sufficient for `demonstrated`, which is exactly what D13 states the gateway must never do.

**Fix.** `_TOOL_VERIFIED: Dict[str, bool]` replaces `_MECHANISM_VERIFIED`, keyed by tool name. `run_verification_pass()` (new) iterates every tool in `TOOL_REGISTRY`, and for each one whose mechanism is verifiable, calls that mechanism's registered check function (`register_mechanism_verifier`) independently, storing the result under the tool's own name - even for two tools naming the identical mechanism string, each triggers its own call. `resolve_exclusivity_for(tool_name, reg)` now takes the tool's name explicitly and checks only `_TOOL_VERIFIED.get(tool_name)`.

**Demonstrate (after).** Two synthetic tool registrations (`tool_a`, `tool_b`) both declaring `mcp_stdio_secret_mount`, with a check function instrumented to count its own calls: `run_verification_pass()` invokes it twice, once per tool, and both tools resolve independently (`_TOOL_VERIFIED["tool_a"] is True`, `_TOOL_VERIFIED["tool_b"] is True` - reached by two separate calls, not one cached one). A third synthetic registration added to `_TOOL_VERIFIED`'s absence (simulating a tool added after the verification pass already completed - there is no runtime registration API in this codebase today, so this is the structural case, exercised directly) resolves to `declared`, not `demonstrated`, even with another tool's verified-True result already present in the map.

**Enforce.** `tests/test_exclusivity_verification.py`:
- `test_two_tools_sharing_a_mechanism_are_each_independently_verified` - call-count assertion (2, not 1), since the one real check function today takes no tool-specific parameter and so can't be distinguished by differing return values alone.
- `test_tool_registered_after_the_verification_pass_never_gets_demonstrated` - the late-registration refusal.
- The four pre-existing P2-2 tests in the same file were updated for the new `resolve_exclusivity_for(tool_name, reg)` signature (call sites changed; assertions unchanged) and still pass.

**Mutation, independence.** Reintroduced a per-mechanism cache inside `run_verification_pass()` (a local `_mechanism_cache` dict; the second tool sharing a mechanism reads the cached value instead of invoking the check again). `test_two_tools_sharing_a_mechanism_are_each_independently_verified` failed as expected (`call_count["n"] == 1`, not `2`). Reverted; test passes again.

**Mutation, late-registration refusal.** Changed `resolve_exclusivity_for` to `if reg.mechanism in _VERIFIABLE_MECHANISMS and any(_TOOL_VERIFIED.values())` - "demonstrated if any tool sharing this mechanism was ever verified," not this tool specifically. `test_tool_registered_after_the_verification_pass_never_gets_demonstrated` failed as expected (`'demonstrated' == 'declared'` assertion failed). Reverted; test passes again.

## 3. Mapping table

Same format as `docs/reports/phase-2.md` §3 / `docs/reports/phase-1-3-complete.md` §9.

| Location | Claim | Maps to |
| :--- | :--- | :--- |
| `docs/adr/0009-write-ahead-intent-and-per-tool-verification.md` | D16 and D17 in full | This report §2 |
| `docs/adr/0005-outcome-taxonomy.md` | `fault_class` set extended with `intent_write_failed`; `spiffe_unavailable` correction (already stale pre-Phase-2-completion, fixed in the same pass); Documented Boundary section extended for the intent/completion asymmetry | `decision_service/main.py::FAULT_INTENT_WRITE_FAILED`; `tests/test_outcome_types.py::test_dashboard_fault_class_type_matches_reachable_set` |
| `ledger/immudb_ledger.py` | `log_tool_intent`, new | `tests/test_intent_completion_visibility.py` |
| `decision_service/main.py` | Intent-write gate around `_execute_vault_tool`; `FAULT_INTENT_WRITE_FAILED`; `run_verification_pass()` wired into `lifespan` | `tests/test_intent_completion_visibility.py`; `tests/test_exclusivity_verification.py` |
| `decision_service/schemas.py` | `_TOOL_VERIFIED`, `run_verification_pass`, `register_mechanism_verifier`, `resolve_exclusivity_for(tool_name, reg)` | `tests/test_exclusivity_verification.py` |
| `control_plane/main.py::get_audit` | Third scan (`tool_call_intent:`); `execution_state` field, closed set `{"completed", "unknown", "n/a"}` | `tests/test_intent_completion_visibility.py` |
| `dashboard/lib/types.ts` | `FaultClass` gains `intent_write_failed`; `AuditEntry` gains `execution_state` | `tests/test_outcome_types.py::test_dashboard_fault_class_type_matches_reachable_set` (fault class only - `execution_state` is not covered by an existing closed-set-matching test; see §5) |
| `dashboard/components/audit-table.tsx` | Renders `execution_state`, with `"unknown"` visually distinguished | Manual review; no automated UI test in this codebase's existing suite (same scope boundary `phase-2.md` §3 drew for its own dashboard sweep) |
| `readME.md` §3.4, §5, §6 | `execution_state` mentioned in the record-fields paragraph; new Residual Limits bullet for the intent/completion asymmetry; ADR-0009 summary added | This report §2 |

**What was not reached:** `agent/base_agent.py` (unchanged by this pass, same as `phase-2.md`'s own note). The dashboard's rendering of `execution_state` (`audit-table.tsx`) was written and reviewed but not exercised in a running browser - no UI test framework runs in this codebase's existing suite for either phase.

## 4. Pre-registered negatives, individually confirmed

- [x] **Any code path that executes the vault tool without a prior successful intent write.** `_execute_vault_tool` is called only from the `else` branch of the intent-write `try`; there is no other call site. `tests/test_intent_completion_visibility.py::test_failed_intent_write_refuses_execution`.
- [x] **Any orphaned intent record silently absent from `/audit`.** The third scan and join are unconditional on every `/audit` call; `tests/test_intent_completion_visibility.py::test_orphaned_intent_with_no_completion_surfaces_as_unknown` reproduces this live via direct verifier forgery.
- [x] **Any tool resolving to `demonstrated` without its own name present in `_TOOL_VERIFIED` as `True`.** `resolve_exclusivity_for`'s only True branch is `_TOOL_VERIFIED.get(tool_name) is True`; `tests/test_exclusivity_verification.py::test_tool_registered_after_the_verification_pass_never_gets_demonstrated`.
- [x] **Any mechanism-sharing tool inheriting another tool's verification without its own check running.** Proven by call count, not by differing outcomes (the one real check has no tool-specific branch). `tests/test_exclusivity_verification.py::test_two_tools_sharing_a_mechanism_are_each_independently_verified`.
- [x] **Any claim not in the mapping.** §3 above enumerates every changed file's substantive claims.
- [x] **Any assertion weakened.** None changed shape from a prior pass; `resolve_exclusivity_for`'s signature changed (added `tool_name`) but every existing assertion it backs is unchanged.
- [x] **Any item met by live evidence alone with no test enforcing it.** Both items have a committed, named, mutation-tested test; P2-7's read-side additionally has a live reproduction.

## 5. Could not verify / known gaps

- **`execution_state`'s dashboard rendering (`audit-table.tsx`) has no automated test**, closed-set or otherwise - this mirrors the existing gap for `profile`/`exclusivity` rendering before this pass; neither phase's suite runs a browser.
- **Disk exhaustion during this pass (documented for transparency, not a code gap).** The scratch clone's host ran out of disk space entirely mid-session (`ENOSPC` on a file write), traced to ~40GB of accumulated Docker build cache and ~60 stale tagged images from past, now-deleted scratch-clone directories going back to earlier phases of this project. Reclaimed with the user's explicit, scoped approval (build-cache prune, then removal of images whose source directories were individually confirmed deleted before removal). This constrained how much of the live-stack verification could be done in one pass: the full existing regression suite (134 tests, `phase-2.md`'s own baseline) was not re-run in full against the live stack this pass, in favor of a targeted run covering every test file this pass's changes touch or could regress (`test_outcome_types.py`, `test_record_profile.py`, `test_exclusivity_verification.py`, `test_intent_completion_visibility.py` - 35 tests, all passing) plus CI's own full run on push. This is a real scoping trade-off, stated plainly rather than presented as a full re-run.
- **The intent record's own tamper-evidence was not independently re-demonstrated.** It is written via the same verifier `/write` path every other ledger record uses, so it inherits the same ImmuDB inclusion/consistency proof guarantees `docs/adr/0006-verification-states.md` already establishes - not re-proven from scratch here, since nothing about D16 changes that mechanism.

## 6. CI run id

Recorded after push; see the follow-up commit in this same PR (#8) for the run URL.
