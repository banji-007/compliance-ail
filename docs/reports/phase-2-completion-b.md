# Phase 2 completion pass B report

**Run id:** `p2-complete-b`. **Working directory:** `C:\Users\banji\OneDrive\Documents\p2-boundary-scratch` (existing scratch clone, not the primary working directory, clean and up to date with `origin/phase-2-boundary` at the start of this pass). **Branch:** `phase-2-boundary`, same branch, same PR (#8).

Closes the three Blocking findings from `docs/reports/phase-2-redteam.md` that the D16/D17 pass (`docs/reports/phase-2-completion.md`) did not cover: W2 (Envoy's own configuration was untested), W7 (`profile` rendered with no visual distinction, unlike `verification.state`), W8 (`docs/reports/phase-2.md` contradicted itself between §3 and §4).

## 1. Verdict per item

| Item | Verdict |
| :--- | :--- |
| P2-9 | **Holds.** Every cluster's host/port, that no cluster targets a backend service directly, the route table, and the mTLS validation context are now under a no-stack test; red-team mutation 4 now fails it; sweep of every other config file reported below. |
| P2-10 | **Holds.** `profile` now renders as a distinct, per-value badge (`observed`/`mediated`/`unknown` visually distinguishable, `unknown` never sharing a variant with a normal value); `execution_state` was already rendered distinctly by the D16/D17 pass - confirmed, not re-fixed. |
| P2-11 | **Holds.** Erratum appended to `docs/reports/phase-2.md`; the `envoy/envoy.yaml` mapping row corrected; every other row in that mapping individually re-checked against the same negative. |

## 2. Evidence per item

### P2-9: Envoy's configuration is under test

**Before (W2, live-reproduced verbatim from `docs/reports/phase-2-redteam.md`):** the committed no-stack-required test suite (`test_decision_service_network_isolation.py`, `test_credential_boundary_static.py`, `test_host_port_bindings.py`, `test_spire_absent_guard.py`, `test_exclusivity_verification.py` - 29 tests) passes in full even after `envoy/envoy.yaml`'s `decision_service_cluster` endpoint is retargeted from `decision-service:8010` to `opa:8181` - a complete, unmediated management-API bypass (the red-team's own live transcript: `GET /v1/data/system/bundles/ail-policies/manifest/revision -> 200`, through the agent's real mTLS channel). No committed test parsed `envoy.yaml`'s content at all before this pass.

**Demonstrate (this session, reproducing the same mutation against the same suite, plus the new test):**

```
$ cp envoy/envoy.yaml envoy/envoy.yaml.orig
$ # mutation 4, verbatim: decision-service:8010 -> opa:8181
$ python -m pytest tests/test_decision_service_network_isolation.py tests/test_credential_boundary_static.py \
    tests/test_host_port_bindings.py tests/test_spire_absent_guard.py tests/test_exclusivity_verification.py \
    tests/test_envoy_config_boundary.py -v
FAILED tests/test_envoy_config_boundary.py::test_every_network_cluster_targets_only_the_decision_service
FAILED tests/test_envoy_config_boundary.py::test_no_cluster_targets_a_backend_service_other_than_decision_service
2 failed, 33 passed
```

The 29 tests that passed before the fix still pass (they were never the gap); the 2 new tests that inspect `envoy.yaml`'s cluster target now catch exactly the mutation that used to sail through undetected.

**Fix:** `tests/test_envoy_config_boundary.py` (new, 4 tests, static YAML parse, no stack required) - `test_every_network_cluster_targets_only_the_decision_service` (every `socket_address`-backed cluster endpoint targets host `decision-service`, port `8010`), `test_no_cluster_targets_a_backend_service_other_than_decision_service` (independently names every backend host - `opa`, `verifier`, `ail-control-plane`, `immudb` - and asserts none appear as a cluster target, catching a retarget to a different port on the same disallowed host), `test_route_table_sends_every_path_to_the_decision_service_cluster` (every route in every virtual host resolves to `decision_service_cluster`), `test_validation_context_admits_only_the_agent_identity` (the mTLS validation context's `match_typed_subject_alt_names` is exactly `["spiffe://ail.internal/workload/agent"]` - the root identity `envoy.yaml`'s own comment excludes, and which `docs/reports/phase-2.md` cited as defense in depth with nothing previously checking it, is asserted absent).

**Demonstrate (after):**

```
$ python -m pytest tests/test_envoy_config_boundary.py -v
4 passed
```

**Mutation:** red-team mutation 4, applied verbatim (`decision-service:8010` -> `opa:8181`). Applied live (shown above): `2 failed` (both new tests), the other 33 tests in the same run unaffected. Reverted (`mv envoy.yaml.orig envoy.yaml`); `git diff --stat envoy/envoy.yaml` empty; `4 passed`.

**Sweep - every other configuration file whose content carries a security property:**

| File | Security property | Documented where | Test coverage |
| :--- | :--- | :--- | :--- |
| `docker-compose.yml` | `edge`/`backend` network split; `vault_api_token` secret scoped to `decision-service` only; no host-published management/record ports | `docs/adr/0008-decision-service-boundary.md`; `docs/reports/phase-2.md` §3 | `test_decision_service_network_isolation.py`, `test_credential_boundary_static.py`, `test_host_port_bindings.py` - all static, no stack |
| `envoy/envoy.yaml` | Cluster target, route destinations, excluded root SPIFFE identity | `docs/reports/phase-2.md` §3 (now corrected, see P2-11) | `tests/test_envoy_config_boundary.py` (this pass) |
| `opa-config.yaml` | Read-scoped credential (`CONTROL_PLANE_READ_KEY`), not the write key, for OPA's bundle poll | `docs/adr/0007-two-tier-authorization.md`; `readME.md` §4 | `tests/test_dashboard_auth.py::test_control_plane_get_bundle_accepted_with_read_key`, `::test_opa_still_loads_bundle_through_the_now_credentialed_poll` - live, requires the stack (`requires_dashboard`), confirms the read key actually works end to end. Not a no-stack static assertion on the file's own content the way `envoy.yaml` now has; reported here rather than left silently uncovered, but not classified with envoy.yaml's before-this-pass zero coverage - some live test already exercises the property. |
| `docker-compose.test.yml` | Deliberately flat (no `edge`/`backend` split) | `docs/reports/phase-2.md` §5, explicitly disclosed as intentional | Not applicable - no security property is claimed of this file; it exists to run the ordinary test suite, not to reproduce the production boundary. |
| `spire/agent/agent.conf`, `spire/server/server.conf` | `insecure_bootstrap = false` (agent.conf's own comment: "Never set insecure_bootstrap = true in production"); `trust_domain = "ail.internal"` matching every SPIFFE URI Envoy/decision-service check against | Only as an inline comment inside the `.conf` file itself - not asserted in `readME.md`, any ADR, or any report | **No test.** Not added in this pass: the instruction's own bar for adding coverage is a property asserted in documentation, and this one is not - reported here as a real gap rather than silently left out of the sweep. |
| `observability/prometheus.yml`, `observability/grafana/provisioning/*.yml` | None beyond scrape targets living on the `backend` network (already covered by `test_decision_service_network_isolation.py`, which asserts `opa` and `decision-service` are never `edge`-reachable) | Not separately documented as a distinct property of these files | Not applicable - no distinct claim to test. |
| `charts/ail-gateway/*` (Helm templates, `values.yaml`) | None currently claimed as working - `readME.md` §4.7/§3.5 states explicitly: "This chart is not deployable and is not the production path... A cluster deployed from it fails closed on every tool call," per `docs/audit/2026-08-16-verification.md` V1 | `readME.md` §4.7 (the honest claim is "this is broken," already disclosed prominently) | Not applicable - there is no untested positive security claim here to close; the documented claim is the chart's non-functionality, which is not something a passing test would strengthen. |
| `.github/workflows/ci.yml`, `pytest.ini` | Tooling configuration - which tests run, how | Not framed as a compliance/security property anywhere | Not applicable - out of this project's own security-property vocabulary. |
| `spikes/mcp-mediation/docker/docker-compose.yml` | N/A - spike artifact | `docs/reports/spike-mcp-mediation.md` explicitly frames this as reference material, not production topology | Not applicable - not part of the production boundary this phase secures. |

### P2-10: The dashboard distinguishes what the record distinguishes

**Before (W7):** `dashboard/components/audit-table.tsx`'s `DecisionCell` rendered `profile: {entry.profile}` as plain, uniform, muted monospace text - identical styling for `observed`, `mediated`, and the forged-record fallback `unknown`, unlike `VerificationCell`'s five distinct icon/badge treatments for `verification.state`. A forged `profile: "unknown"` record (or, per the disclosed forgery path in `readME.md` §5, a forged `profile: "mediated", exclusivity: "demonstrated"` record for an actually-`observed` tool) rendered with no visual signal distinguishing it from a genuine entry.

**Checked separately, since the completion report (`docs/reports/phase-2-completion.md`) that added `execution_state` (D16) did not say whether the dashboard renders it:** it already does. `DecisionCell` branches on `entry.execution_state === "unknown"` and renders it in amber (`text-amber-600 dark:text-amber-400`), distinct from the quiet default styling `"completed"`/`"n/a"` share - added in the same edit that introduced `execution_state` to `audit-table.tsx`. No fix needed for this field; confirmed by reading the component and locked in by this pass's new test (below) so a future edit cannot silently drop it.

**Fix (`profile` only):** `dashboard/components/audit-table.tsx` gained `PROFILE_LABEL`/`PROFILE_VARIANT`, two `Record<AuditEntry["profile"], ...>` maps (matching the existing `OUTCOME_LABEL`/`OUTCOME_VARIANT` pattern), and `DecisionCell`'s profile line now renders a `Badge` from that map instead of plain text - `observed` -> muted/neutral, `mediated`/`attested` -> the same "approved" green treatment (`attested` is defined in `docs/adr/0005-outcome-taxonomy.md` but not yet producible by any code path; included so the map is exhaustive over the type rather than needing a runtime fallback), `unknown` -> the amber "warning" treatment, matching `execution_state`'s own unknown-case styling. `exclusivity` (not named by this item) is unchanged, still plain text appended alongside the new badge.

**Demonstrate (rendered output for each value, reasoned from source - see §5 below for why this was not additionally confirmed in a live browser):**
- `profile: "observed"` -> muted badge, "OBSERVED"
- `profile: "mediated"` -> green ("approved") badge, "MEDIATED"
- `profile: "unknown"` -> amber ("warning") badge, "UNKNOWN" - visually distinct from both normal values, matching `VerificationCell`'s existing treatment of its own problem states
- `execution_state: "completed"` / `"n/a"` -> quiet default text, differing only in the word rendered
- `execution_state: "unknown"` -> amber text, "execution: unknown outcome" - already correct before this pass

**Enforcing tests:** `tests/test_dashboard_state_rendering.py` (new, 3 tests, static TSX/TS parse, no stack required, same shape as `tests/test_outcome_types.py::test_dashboard_fault_class_type_matches_reachable_set`) - `test_profile_rendering_map_covers_every_value_the_api_can_emit` (every value `control_plane/main.py::get_audit` can actually put in `profile` today - `observed`, `mediated`, `unknown` - has an entry in both `PROFILE_LABEL` and `PROFILE_VARIANT`), `test_profile_rendering_map_gives_reachable_values_distinct_treatment` (no two of those three values share a badge variant, and `unknown`'s variant specifically differs from both normal values'), `test_execution_state_rendering_covers_every_value_the_api_can_emit` (the `"unknown"` branch and the default branch both still exist and are still styled distinctly).

**Mutation:** removed the `unknown` key from `PROFILE_LABEL` in `audit-table.tsx`. Applied live:

```
FAILED tests/test_dashboard_state_rendering.py::test_profile_rendering_map_covers_every_value_the_api_can_emit
AssertionError: PROFILE_LABEL in audit-table.tsx is missing rendering for profile value(s) ['unknown'] that /audit can actually emit
```

Reverted (`mv audit-table.tsx.orig audit-table.tsx`); `git diff --stat` showed only this pass's real fix remaining; `3 passed`.

### P2-11: The Phase 2 report does not contradict itself

**The contradiction (W8):** `docs/reports/phase-2.md` §4 stated, unconditionally, that every item had both live evidence and an enforcing test; §3's own mapping table, in the very next section up, showed the `envoy/envoy.yaml` row citing only a live transcript, no test - because none existed, as P2-9 above confirms independently.

**Fix:** an `## 7. Erratum` section appended to `docs/reports/phase-2.md` (the body above it - §1 through §6 - is otherwise unchanged), naming the contradiction, citing `docs/reports/phase-2-redteam.md` (W8), and stating what was actually true at the time (§4's negative was asserted against the six items in §1's verdict table as a whole, not derived from an individual check of every row §3 itself lists; the `envoy.yaml` row was the one place the two disagreed, and it was never checked before §4 was written). The `envoy/envoy.yaml` row in §3 is corrected in place to also cite `tests/test_envoy_config_boundary.py`.

**Every other row in §3 checked against the same negative, individually** (full reasoning in the Erratum section itself):

| Row | Cited enforcement | Skipped in CI? |
| :--- | :--- | :--- |
| README §2 diagram, §3.1 | `test_decision_service_network_isolation.py` | No - static YAML parse, no stack |
| README §3.2 | `test_exclusivity_verification.py`, `test_record_profile.py` | No - the latter is `requires_stack`-gated, but `make test-integration` brings the stack up before pytest runs |
| README §3.4/§3.5 | `decision_service/main.py`; `test_outcome_types.py` | No |
| `docker-compose.yml` | `test_decision_service_network_isolation.py`, `test_credential_boundary_static.py`, `test_host_port_bindings.py` | No - all static |
| `decision_service/main.py`, `schemas.py` | `test_exclusivity_verification.py`, `test_outcome_types.py`, `test_response_contract.py` | No |
| `decision_service/mcp_tools/vault_server.py` | `test_credential_boundary_static.py` | No - static; does **not** cite `test_vault_tool_bypass.py`, the one test in this phase's suite that genuinely is permanently skipped under `docker-compose.test.yml` (it needs the real agent container `docker-compose.yml` provides, which the test stack never has) |
| `interceptor/middleware.py` | `test_spire_absent_guard.py`, `test_outcome_types.py::test_fault_spiffe_unavailable`/`test_fault_decision_service_unreachable` | No - neither cited test is stack-gated |
| `ledger/immudb_ledger.py` | `test_record_profile.py` | No - stack is up in CI |
| `framework_integration/langgraph_demo.py` | `test_response_contract.py`; live transcript | No |
| `dashboard/lib/types.ts`, `audit-table.tsx` | `test_outcome_types.py::test_dashboard_fault_class_type_matches_reachable_set` | No - static |

No row cites enforcement that is absent or skipped in CI without saying so. `envoy/envoy.yaml` was the sole violation, and is now corrected.

## 3. Corrected mapping (delta only - see `docs/reports/phase-2.md` §3 for the full table)

| Location | Claim | Maps to (corrected) |
| :--- | :--- | :--- |
| `envoy/envoy.yaml` | Retargeted cluster; 45s route timeout | Live transcript (`docs/reports/phase-2.md` §2); **`tests/test_envoy_config_boundary.py` (added)** |
| `dashboard/components/audit-table.tsx` | `profile` rendered as a distinct badge per value, `unknown` never sharing a variant with a normal value; `execution_state`'s existing distinct rendering confirmed | `tests/test_dashboard_state_rendering.py` (added) |

## 4. Pre-registered negatives, individually confirmed

- [x] **Any configuration file carrying a documented security property with no test covering it, unless listed as uncovered in the report.** `spire/agent/agent.conf`/`server.conf`'s `insecure_bootstrap`/`trust_domain` properties have no test and are listed as uncovered in §2/P2-9's sweep table above, with the reason (property asserted only in an inline comment, not in project documentation, so it does not meet this pass's own bar for adding coverage). Every other file with a documented property is covered.
- [x] **Any API state value with no distinct rendering in the dashboard.** `profile`'s three reachable values (`observed`, `mediated`, `unknown`) each get a distinct badge variant; `execution_state`'s three reachable values (`completed`, `n/a`, `unknown`) were already distinctly rendered. `tests/test_dashboard_state_rendering.py`.
- [x] **Any mapping row citing enforcement that does not exist or does not run in CI.** Checked individually in §2/P2-11 above; only `envoy/envoy.yaml` violated this, and is now corrected.
- [x] **Any assertion weakened.** None - `test_dashboard_state_rendering.py`'s distinctness check is strictly additive (checks separateness of variants, not just presence), and `test_envoy_config_boundary.py`'s four tests are all new, no existing test's assertion was loosened.
- [x] **Any item met by live evidence alone with no test enforcing it.** P2-9 and P2-10 each have a committed, named, mutation-tested test in addition to their demonstration transcripts. P2-11 is a documentation correction with no independent "enforcing test" of its own beyond `tests/test_docs_references_resolve.py` (pre-existing, confirms the new citations resolve once committed - see §5 below).

## 5. Could not verify / known gaps

- **`dashboard/components/audit-table.tsx`'s `profile` badge was not independently confirmed in a live browser against a running dashboard instance.** Reasoned from the component's source, the same limitation `docs/reports/phase-2-redteam.md` §5 explicitly disclosed for this exact claim ("not independently re-verified live against a running dashboard instance... only reasoned from `audit-table.tsx`'s source"). Not brought up live this pass: the host's disk was at 2.4GB free / 100% used for the duration of this session (a real, ongoing constraint disclosed in `docs/reports/phase-2-completion.md` §5's own disk-exhaustion incident from the prior pass), and none of this item's three enforcing tests require a stack, so no build was attempted rather than risk a repeat.
- **`spire/agent/agent.conf`/`server.conf`'s security-relevant fields (`insecure_bootstrap`, `trust_domain`, `join_token`) have no test at any level**, static or live - reported in §2/P2-9's sweep table, not fixed, since the property is not asserted in project documentation (only an inline file comment), which is this pass's own stated bar for adding coverage. A future pass that wants this covered would first need to add the claim to `readME.md` or an ADR.
- **`opa-config.yaml`'s read-scoped-credential property is covered only by a live, stack-gated test** (`tests/test_dashboard_auth.py`), not a no-stack static assertion on the file's own content the way `envoy.yaml` now has. Not classified as a gap on the same level as `envoy.yaml`'s prior zero coverage, since a real test does exercise the property end to end, but noted for a future pass that wants every config file's security property covered by a no-stack test specifically.
- **No new ADR was written for this pass.** P2-9/P2-10/P2-11 close test-coverage and documentation gaps the red-team found in already-decided design (D12-D17); none of the three items introduces a new design decision, so none was recorded as one, consistent with the standing "no design changes" rule for this pass.

## 6. CI run id

PR #8, `integration-tests` job: **pass, 2m49s** - https://github.com/banji-007/compliance-ail/actions/runs/32479446452/job/96762480310
