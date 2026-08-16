# Phase 0.1: Remediation - Report

## 1. Start SHA, end SHA, environment

**Start SHA:** `25a5404` (head of `phase-0-truth-pass` at the start of this phase)

**End SHA:** `33822a6b0cff5a432a8a0816b7561187a9fffe59` - committed and pushed to `origin/phase-0-truth-pass`.

**Environment:**

- Docker Desktop was running throughout; images were rebuilt (`docker compose build` / `up -d --build`) before every live test.
- `make` is not installed in this Windows environment; the `test-integration` and `keygen` recipes were replicated by hand, same as both prior reports document.
- `.env` in the primary working directory could not be read directly (permission-blocked, same restriction every prior session hit) and, per the amended standing rules for this phase, was never written to either.
- Two clean-state tests were required this phase (P01-5's audit-verification demo, and P01-6's scratch-clone README walkthrough) and both were done in scratch clones (`ail-clean-clone`, `ail-p014-clone`) under the session scratchpad, never in the primary working directory, per the standing-rules amendment.
- The primary working directory's `docker-compose.test.yml` stack was brought up once for live testing (P01-3's C4 reproduction) and hit a pre-existing `verifier-state`/ImmuDB desync (the same class of issue `docs/reports/phase-0.md` section 4 already documents) on a second bring-up. This was not introduced by this phase - see section 4. It was left untouched (no volume deleted) and the remaining live tests requiring a working ledger were done in scratch clones instead.

---

## 2. Verdict table

| Item | Verdict | Evidence |
| :--- | :--- | :--- |
| P01-1 | MET | CI run `31963976465` on head commit `33822a6b0c...`: `conclusion: success`. Job log: `collected 31 items`, `31 passed, 1 warning in 3.33s`. Zero failed, zero skipped. |
| P01-2 | MET | Every collected item has a real assertion - AST-based enumeration (not a spot check) below shows 31/31 items with `assert`/`pytest.raises` count > 0. Four files moved to `scripts/`; one additional zero-assertion item the red-team report did not name was found and removed. |
| P01-3 | MET | Single source (`AIL_BUNDLE_NAME`) verified live to substitute correctly into an OPA YAML map key. Startup check reproduces C4's exact scenario and exits with an actionable message. Fault marker reproduces the mid-run scenario and the demo agent's reply attributes it to infrastructure. All three transcripts below. |
| P01-4 | MET | `grep -rn "record_hash" .` returns matches only in `docs/`. Enumeration of keys set vs. keys read (below) shows no orphan reads. Live run through `base_agent.py` shows a real `[Ledger tx] 1` trace value. |
| P01-5 | MET | Live `/audit` response with `verified: false` entries (verifier stopped) rendered through the actual `AuditTable` component: `UNVERIFIED` badge + red `ShieldAlert` icon, contrasted against the same component rendering `verified: true` entries as `Verified · state 2` + green `ShieldCheck` icon. |
| P01-6 | MET | All four corrected statements reproduced literally from the scratch clone: `docker compose ps` (13 rows) vs. `docker compose ps -a` (3 `Exited (0)`); `CONTROL_PLANE_API_KEY` requirement (`422 Field required` without it); dashboard audit-auth non-functionality (same `422`, confirmed dashboard sends no `X-API-Key` header); Helm chart's control-plane pod sharing the missing-`VERIFIER_URL` defect (source-confirmed, no `VERIFIER_URL` anywhere in `templates/control-plane-deployment.yaml`). |
| P01-7 | MET | Erratum appended to `docs/reports/phase-0.md`, naming both items and citing the red-team sections (C5, C8). |
| P01-8 | MET, scope corrected mid-phase - see section 4 | Credential value scrubbed from **both** documents it appeared in (the instruction named one; a second, `docs/audit/2026-08-16-verification.md`, was found by grep and scrubbed too). Rotation was dropped - see section 4 for why. |

---

## 3. Evidence

### P01-1

Pushed commit `33822a6`. `gh run view 31963976465`:

```
✓ phase-0-truth-pass Integration Tests banji-007/compliance-ail#1 · 31963976465
JOBS
✓ integration-tests in 1m6s (ID 95206162993)
```

Job log:

```
collecting ... collected 31 items
======================== 31 passed, 1 warning in 3.33s =========================
```

The fix was moving `tests/test_ledger.py` (whose `test_full_agent_flow` had no `skipif` guard, unlike its two siblings) to `scripts/test_ledger.py` as part of P01-2 - see there for why the whole file, not just a guard, was the correct fix. No `skipif` was added anywhere; the previously-unguarded, always-collected test is no longer collected by `pytest tests/` at all, and that outcome was forced by P01-2's rule (a file whose items assert nothing is a smoke script), not chosen to make CI pass.

### P01-2

Per-file assert/`pytest.raises` counts, from an AST walk of every collected test file (not a manual spot check - script counts `ast.Assert` nodes and `pytest.raises(...)` calls inside each `test_*` function body):

```
  1  tests/test_cloud_server_schema.py::test_epic_2_validation
  3  tests/test_epic_2.py::TestQueryDatabaseSchema::test_valid_payload_parses_correctly
  2  tests/test_epic_2.py::TestQueryDatabaseSchema::test_missing_required_field_raises
  2  tests/test_epic_2.py::TestQueryDatabaseSchema::test_type_mismatch_masking_enabled_raises
  3  tests/test_epic_2.py::TestDeployToProductionSchema::test_valid_payload_parses_correctly
  2  tests/test_epic_2.py::TestDeployToProductionSchema::test_missing_required_field_raises
  2  tests/test_epic_2.py::TestDeployToProductionSchema::test_type_mismatch_bypass_ci_raises
  1  tests/test_epic_2.py::TestToolValidatorsRegistry::test_provision_cloud_server_registered
  1  tests/test_epic_2.py::TestToolValidatorsRegistry::test_query_database_registered
  1  tests/test_epic_2.py::TestToolValidatorsRegistry::test_deploy_to_production_registered
  1  tests/test_epic_2.py::TestMiddlewareRoutingFailClosed::test_hallucinated_tool_is_denied
  1  tests/test_epic_2.py::TestMiddlewareRoutingFailClosed::test_hallucinated_tool_denial_names_the_tool
  2  tests/test_epic_2.py::TestMiddlewareRoutingFailClosed::test_hallucinated_tool_returns_populated_deny_list
  2  tests/test_epic_2.py::TestQueryDatabaseOpaIntegration::test_soc2_denies_unmasked_pii_query
  2  tests/test_epic_2.py::TestQueryDatabaseOpaIntegration::test_gdpr_denies_unapproved_processing_purpose
  2  tests/test_epic_2.py::TestDeployToProductionOpaIntegration::test_soc2_denies_production_deploy_without_approval_ticket
  2  tests/test_epic_2.py::TestDeployToProductionOpaIntegration::test_soc2_denies_bypass_ci
  2  tests/test_epic_2.py::TestDeployToProductionOpaIntegration::test_finops_denies_experimental_repo_in_production
  1  tests/test_opa_integration.py::TestOpaPolicy::test_small_instance_approved
  2  tests/test_opa_integration.py::TestOpaPolicy::test_restricted_instance_without_ml_training_denied
  1  tests/test_opa_integration.py::TestOpaPolicy::test_small_instance_non_approved_region_with_internal_data_approved
  1  tests/test_opa_integration.py::TestOpaPolicy::test_restricted_instance_wrong_project_denied
  2  tests/test_opa_integration.py::TestInterceptorWithOpa::test_approved_request_returns_approved_status
  2  tests/test_opa_integration.py::TestInterceptorWithOpa::test_denied_request_returns_denied_status
  5  tests/test_policy_digest.py::test_recorded_digest_matches_opa_not_interceptor_belief
  3  tests/test_policy_digest.py::test_digest_unavailable_denies_and_writes_no_ledger_entry
  5  tests/test_verification.py::test_parity
  2  tests/test_verification.py::test_tamper_state
  3  tests/test_verification.py::test_tamper_pubkey
  5  tests/test_verification.py::test_cross_process
  4  tests/test_verification.py::test_roundtrip

Total test functions (collection-equivalent items, pre-parametrize): 31
Functions with zero assert/pytest.raises: 0
```

31 collected, 31 with at least one assertion, 0 with zero - matches `pytest --collect-only`'s `31 tests collected` exactly (confirmed both `pytest tests/ --collect-only -q` and bare `pytest --collect-only -q` from repo root report 31, identical items - `pytest.ini`'s `testpaths = tests` still holds from Phase 0).

**Four files moved, per the rule (a file whose items assert nothing is a smoke script, not a test):**

| Old path | New path | Items | Why moved, not given an assertion |
| :--- | :--- | ---: | :--- |
| `tests/test_agent.py` | `scripts/test_agent.py` | 1 | Body wrapped in `try/except Exception: print` - structurally incapable of failing |
| `tests/test_interceptor.py` | `scripts/test_interceptor.py` | 2 (parametrized) | Same `try/except` pattern |
| `tests/test_ledger.py` | `scripts/test_ledger.py` | 3 | Two print static info with nothing computed to assert; the third (`test_full_agent_flow`) is the file that broke CI - see P01-1 |
| `tests/test_epic_3.py` | `scripts/test_epic_3.py` | 1 | No assertion, no exception guard; its own inline comments claiming specific GDPR-violation outcomes are known stale against current tenant seed data (`docs/reports/phase-0.md`, section 6) - asserting the commented expectation would assert something false |

None of the seven items in these four files fit the one exception (a file already printing an expected outcome it computed) - every print statement in all four files prints an *actual* computed value (`result.get('status')`), never a stated expected value being checked against it, so none qualified for "assert that outcome instead of printing it" without inventing a check that wasn't already there.

Confirmed nothing references the old paths: `grep -rn "test_agent\.py\|test_interceptor\.py\|test_ledger\.py\|test_epic_3\.py" Makefile .github/ docker-compose*.yml` (repo root config only, docs excluded) returns no matches. `docker-compose.yml:203`'s `test_mtls_flow.py` bind mount is a distinct file, untouched, exactly as in Phase 0.

**One additional zero-assertion item found beyond the red-team's seven:** `tests/test_opa_integration.py::test_ledger_after_opa`. The red-team report's C5 count (39 items reviewed) predates this phase's own file moves, and its own text scopes the "seven named" to what was true *at the time it was written* - the Criterion above it is unconditional ("every item collected... contains at least one assert"), so the AST enumeration (run against the post-move tree, since that's what actually gets collected now) is what governs, and it surfaced this eighth. Its own docstring said `"""Reminder: ImmuDB is the source of truth for audit records."""` and its body was three `print()` calls with no assertion and no exception guard - not a smoke script worth relocating (it contributed nothing scripts/'s already-moved files don't already say), so it was deleted outright rather than moved. `git diff` for `tests/test_opa_integration.py` shows only this removal; none of the file's six real, assertive items were touched.

### P01-3

**One source for the name.** `AIL_BUNDLE_NAME` (default `ail-policies`) is now read by both consumers: `opa-config.yaml`'s `bundles:` key via `${AIL_BUNDLE_NAME}` substitution (the same mechanism already used for `AIL_TENANT_ID`), and `interceptor/middleware.py`'s `_BUNDLE_NAME = os.getenv("AIL_BUNDLE_NAME", "ail-policies")`, which builds `_OPA_REVISION_URL`. Verified live that OPA's env-var substitution works on a YAML **map key**, not just a value (this was unconfirmed going in):

```
$ curl -s localhost:8181/v1/data/system/bundles/ail-policies/manifest/revision
{"result":"97c260d25c4c6d8c3a3aae46b73b10ef5b20d0af7fa01f422249dfeac6e27508"}
$ curl -s localhost:8181/v1/data/system/bundles
{"result":{"ail-policies":{"etag":"97c260d25...","manifest":{"revision":"97c260d25...","roots":["ail"]}}}}
```

`AIL_BUNDLE_NAME=${AIL_BUNDLE_NAME:-ail-policies}` was added to the `opa` service in both `docker-compose.yml` and `docker-compose.test.yml`, to `langgraph-demo` in `docker-compose.yml`, and to the `test-integration` Makefile recipe. `test_policy_digest.py`'s independent ground-truth check (`_opa_live_revision`) was updated to read the same env var rather than hardcoding `ail-policies`, so it stays a genuine independent check rather than a second hardcoded copy.

**Fail at agent startup.** `verify_bundle_at_startup()` polls `_fetch_opa_bundle_revision` for up to 30s (bundle polling has up to `max_delay_seconds: 20` latency in `opa-config.yaml`, so an immediate single check would false-positive on ordinary startup timing) and calls `sys.exit(1)` with a message naming both configuration locations if no revision resolves. Wired into `framework_integration/langgraph_demo.py` and `agent/base_agent.py`'s `__main__` blocks, before either accepts work.

Reproduced red-team's C4 exactly: renamed the bundle by recreating `opa` with `AIL_BUNDLE_NAME=ail-policies-v2` while the interceptor kept the default `ail-policies`.

```
$ docker compose -f docker-compose.test.yml ps opa
compliance-ail-opa-1   ...   Up 20 seconds (healthy)
$ curl -s -X POST localhost:8181/v1/data/ail/main/allow -d '{...}'
{"result":true}
$ curl -s localhost:8181/v1/data/system/bundles/ail-policies/manifest/revision
{}
```

Startup-check transcript (this is `verify_bundle_at_startup()` run directly against the mismatched stack):

```
2026-08-16 20:02:56,159 - ERROR - STARTUP FAILURE: bundle 'ail-policies' has no revision on OPA after 8s
(queried http://localhost:8181/v1/data/system/bundles/ail-policies/manifest/revision). This means
opa-config.yaml's `bundles:` key and AIL_BUNDLE_NAME (currently 'ail-policies', read by
interceptor/middleware.py) do not name the same bundle, or OPA has not loaded any bundle under this
name. Check: (1) opa-config.yaml's `bundles:` map key resolves to 'ail-policies' after
${AIL_BUNDLE_NAME} substitution - confirm AIL_BUNDLE_NAME is set identically for the opa and this
agent's containers; (2) OPA's own logs for bundle download/activation errors.
EXIT CODE: 1
```

Healthy container, working `/allow`, an operator-actionable exit before a single tool call is possible.

**Distinguish fault from denial.** With the same mismatch present mid-run (call made after the process would already be up), `intercept_tool_call` now returns `"fault": "infrastructure"` alongside the unchanged `"status": "DENIED"`. Live transcript, real `intercept_tool_call` call against the mismatched stack, plus the demo agent's actual reply-construction logic:

```
RAW DECISION: {'status': 'DENIED', 'message': 'Unable to establish the policy revision that
produced this decision.', 'fault': 'infrastructure'}

=== AGENT OPERATOR-VISIBLE REPLY ===
AIL INFRASTRUCTURE FAULT (not a policy denial): Unable to establish the policy revision that
produced this decision.
This request was not evaluated against policy - the compliance gateway could not confirm which
policy bundle OPA has loaded. An operator should check the OPA bundle configuration; retrying the
same parameters will not fix this.
```

`status` stays `"DENIED"` - `agent/base_agent.py`'s reply-gating logic (`interceptor_response["status"]`) and any other consumer keyed on it are unaffected; only callers that check the new `"fault"` key see the distinction.

### P01-4

```
$ grep -rn "record_hash" .
docs/reports/phase-0.md: ...
docs/reports/phase-0-redteam.md: ...
```

Both matches are historical prose in `docs/`, not code.

**Enumeration, not a spot check.** Keys `intercept_tool_call` (`interceptor/middleware.py`) ever sets, across all four return paths in the function:

| Path | Keys set |
| :--- | :--- |
| Always | `status`, `message` |
| `digest_unavailable` (new, P01-3) | + `fault` |
| Ledger write failed | (status, message only) |
| Ledger write succeeded (APPROVED or DENIED) | + `ledger_tx_id` |

Union: `{status, message, ledger_tx_id, fault}`.

Every key read from the function's return value anywhere in the tree (`grep -rn "intercept_tool_call("` to find every call site, then every `.get(...)`/`[...]` on the result at each site): `agent/base_agent.py` (`status`, `message`, `ledger_tx_id`, `fault`), `framework_integration/langgraph_demo.py` all three tool wrappers (`status`, `message`, `ledger_tx_id`, `fault`), `tests/test_policy_digest.py` (`status`, `ledger_tx_id`), `tests/test_opa_integration.py` (`status`), `tests/test_cloud_server_schema.py` and the three moved `scripts/` files (`status`, `message`). Every read key is in the set above; no orphan reads.

Live run through `base_agent.py`, real `handle_tool_calls` call (LLM call simulated with a fixed tool-call object so the test doesn't need a paid API call; everything downstream - `intercept_tool_call`, OPA, the ledger write - is real):

```
[Agent Request] -> [AIL Intercept] -> [Policy Engine Decision] -> [Ledger tx] 1 -> [Execution]
Cloud server provisioning initiated for t3.micro in us-east-1 at $5.0/hour with tags: {...}
```

`[Ledger tx] 1` is a real ImmuDB transaction ID from a real verified write, in place of the permanently-empty `[Ledger Hash] ...` the old code produced on every call.

### P01-5

Real `/audit` response with the verifier stopped (so every entry legitimately fails verification, not a fabricated payload):

```json
{
  "entries": [
    {"tx_id": 1, "agent_id": "p01_5_repro_agent", ..., "verified": false, "state_id": null},
    {"tx_id": 2, "agent_id": "p01_5_repro_agent", ..., "verified": false, "state_id": null}
  ],
  "total": 2
}
```

The real `AuditTable` component (same source file, `react-dom/server`'s `renderToStaticMarkup`, no mock) rendered against this exact JSON:

```html
<div class="flex items-center gap-1.5 text-xs">
  <svg ... class="lucide lucide-shield-alert h-3.5 w-3.5 text-red-500 shrink-0">...</svg>
  <div class="... border-transparent bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-100 w-fit">UNVERIFIED</div>
</div>
```

Contrast, same component, verifier restarted, real re-verified entries:

```
lucide-shield-check
>Verified · state 2<
```

Green check icon + "Verified · state N" for `verified: true`; red alert icon + a visually distinct `UNVERIFIED` badge for `verified: false`. Neither state is blank or absent.

### P01-6

All four, reproduced literally from a scratch clone (`git clone --branch phase-0-truth-pass`, fresh `.env` per README §4.1, `docker compose up -d --build`):

```
$ docker compose config --services | wc -l
16
$ docker compose ps          # 13 rows, all healthy/running
$ docker compose ps -a --filter "status=exited"
ail-clean-clone-policy-validator-1     Exited (0) ...
ail-clean-clone-token-generator-1      Exited (0) ...
ail-clean-clone-workload-registrar-1   Exited (0) ...
```

```
$ curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8002/audit
422
```
(no `.env` variable can fix this without a code change - confirmed by the `CONTROL_PLANE_API_KEY=change-me` value actually being set and the request still failing, because the dashboard sends no header at all, not a wrong one)

```
$ grep -n "headers" dashboard/lib/api.ts
    headers: { "Content-Type": "application/json", ...init?.headers },
```
No `X-API-Key` anywhere - matches the live `422`.

`charts/ail-gateway/templates/control-plane-deployment.yaml` - `grep -n VERIFIER_URL` returns nothing; the pod's only ImmuDB-related env vars are the pre-ADR-001 `IMMUDB_*` set, confirming the chart notice's extended claim.

### P01-7

Erratum appended to `docs/reports/phase-0.md`, naming: (1) the `39 passed` claim vs. CI's actual `1 failed, 35 passed, 3 skipped` on the same commit (citing red-team C5, `gh run view 31958956222`), (2) the `test_epic_3.py` `OPA_URL` edit rationale, shown inert by module-caching (citing red-team C8). Body of the report untouched; erratum is additive.

### P01-8

Scrubbed the credential value from **both** documents it appears in: `docs/reports/phase-0.md` (the one the instruction named) and `docs/audit/2026-08-16-verification.md` (found independently by grepping for the literal value across `docs/`, not named in the instruction). A repo-wide grep for the literal value now returns no matches anywhere (including this report - the value itself is never typed here, precisely to avoid reintroducing what this item removes).

Provenance and rotation are covered in section 4, since the instruction's scope changed mid-phase based on what that investigation found.

---

## 4. Worked around / judgment calls

- **P01-3 judgment calls, as requested:**
  - **"Mirrors the existing SPIRE-socket precedent"** - no literal `sys.exit()`-on-missing-socket code exists anywhere in the tree (`grep -rn "sys.exit\|exit(1)"` returns nothing pre-existing). The actual precedent is `docker-compose.yml`'s `langgraph-demo` command, which blocks agent startup in a wait-loop until the SPIRE socket exists rather than starting and failing on first use. Read this as descriptive of the general principle (gate boot on an infrastructure precondition, don't let it surface as a request-time failure) rather than a literal function to imitate, and implemented an explicit `sys.exit(1)` rather than a wait-loop, since a bundle-name mismatch (unlike a socket that will eventually appear) does not resolve itself by waiting - retrying-forever would just be the exact silent-denial failure mode C4 describes, moved earlier.
  - **The 30-second polling window.** Not specified by the instruction. Sized to exceed `opa-config.yaml`'s `polling.max_delay_seconds: 20` with margin, because OPA's bundle plugin loads asynchronously after the container reports healthy - an immediate single check would false-positive on ordinary startup timing, indistinguishable from a real mismatch. A real mismatch never resolves regardless of how long the window is, so this only affects how long a correctly-configured agent waits before accepting work, not whether a real mismatch is ever caught.
  - **Where to add the fault marker.** The instruction says "the response" should carry the field; `digest_unavailable` was already computed internally in `query_opa_policy`'s return value but was being discarded (not propagated) by `intercept_tool_call` before this phase. Chose to add `"fault": "infrastructure"` only on that one return path (the pre-existing `digest_unavailable` early return), not more broadly, since that is the only path P01-3 and the red-team's C4 concern - OPA-unreachable and schema-validation denials are ordinary infrastructure/input problems already distinguishable by their own message text, and extending the fault marker to those was not asked for and risked recharacterizing existing, working denial paths.

- **Pre-existing `verifier-state`/ImmuDB desync hit in the primary working directory.** After a second `docker compose -f docker-compose.test.yml up` (no `-v` used, per the standing rule), a real ledger write failed with the same `INVALID_ARGUMENT: illegal state` gRPC error `docs/reports/phase-0.md` section 4 already documents - ImmuDB has no persistent volume in `docker-compose.test.yml` (resets every `up`), but `test-verifier-state` does (persists), and the volume was already out of sync with a fresh ImmuDB before this phase touched it (no ledger write happened between this phase's first bring-up and the desync being hit, so this phase did not cause the desync). The standing rule forbids `docker compose down -v` and deleting named volumes in the primary working directory, so rather than working around it there, the remaining live tests that needed a working ledger (P01-4's `base_agent.py` run, P01-5's `/audit` demonstration) were done in fresh scratch clones instead, each with its own compose project and therefore its own fresh volumes. The primary directory's `test-verifier-state` volume was left exactly as found - not deleted, not reset.

- **P01-8's scope changed mid-phase, per your correction.** The original instruction said to scrub the value and rotate it. Before writing `.env` (which the standing rules forbid), a provenance check was done: `grep -rn "CONTROL_PLANE_API_KEY" Makefile scripts/ docker-compose*.yml` shows every reference in the repo either reads the variable from `.env`/the environment or falls back to the literal `test-api-key` default - there is no code path anywhere that generates a value matching the leaked one. Every session that touched this value (the 2026-08-16 audit, Phase 0) only *read* it via `docker inspect` on an already-running container; neither claims to have generated it. Combined with the red-team report's own section 1 disclosure - that session could not read the pre-existing `.env`, wrote a fresh one matching only README §4.1's three variables, and had no way to recover what was there before (gitignored, permission-blocked) - the most likely account is: the value was a real credential that pre-existed in your local `.env` before any of these sessions, and it is now gone, overwritten with nothing. On that basis: both documents were scrubbed and the erratum records the finding; no `.env` write was made (rotation requires one, and there is nothing to rotate `.env`'s current value *from* if it no longer contains the leaked key); P01-6 now documents `CONTROL_PLANE_API_KEY` as a required `.env` variable, which is the actual fix - if the key really is gone, the documentation is what lets you set a real one, not a rotation script writing over a file this session isn't allowed to touch.

- **`dashboard/lib/utils.ts`'s `truncateHash` helper** is now unused by `audit-table.tsx` (its only caller) but was left in place rather than deleted - it's a small, independently-usable utility, and P01-5 scoped the fix to the type contract and the table, not a dead-code sweep.

---

## 5. Pre-registered negatives - confirmed individually

- **Any new code path where a failure results in anything other than DENY.** `verify_bundle_at_startup()`'s failure mode is a process exit before the agent starts accepting any work at all - stricter than DENY, not a bypass of it. The `"fault": "infrastructure"` addition does not change `status`, which stays `"DENIED"` on every path it was already `"DENIED"` on; nothing new returns `"APPROVED"` or omits `status`. Checked every `return` in `interceptor/middleware.py`'s diff by hand: none introduce a non-DENY outcome for a failure.
- **Any assertion weakened, removed, or broadened.** The only assertion-bearing change is `tests/test_policy_digest.py`'s `_opa_live_revision`, which now builds its URL from `AIL_BUNDLE_NAME` instead of a hardcoded literal - the assertion itself (`assert revision, ...`) is untouched, character-for-character. `tests/test_opa_integration.py::test_ledger_after_opa` was deleted, not weakened - it contained zero assertions before deletion, so there was nothing to weaken; its six sibling items in the same file are untouched (`git diff` confirms only the one function's removal).
- **Any test added or modified for the purpose of raising a count.** No test was added. Two tests were removed (moved to `scripts/` counts as removed from the pytest-collected set) and one deleted outright - all three moves lower the collected count, they cannot have been done to raise it.
- **Any `skipif` added to a test that does not depend on an external credential.** None added anywhere this phase. The pre-existing `skipif`s on `scripts/test_agent.py` and `scripts/test_interceptor.py` (both gated on `OPENAI_API_KEY`, an external credential) were carried over unchanged from Phase 0, not newly added, and those files are no longer pytest-collected regardless.
- **Any change to the number or ordering of OPA round trips per intercepted call.** `verify_bundle_at_startup()`'s polling loop runs once, at process boot, entirely outside `query_opa_policy`/`intercept_tool_call`. Diffed `query_opa_policy` end to end: still exactly `/allow`, then the revision GET, then `/deny` only when `/allow` was false - identical to Phase 0's structure. Confirmed by re-reading the full function after every edit in this phase, not just the lines touched.
- **Any dashboard authentication mechanism.** P01-5 changed only field names and rendering (`ledger_hash` → `verified`/`state_id`); no auth code was touched in `dashboard/` or `control_plane/`. The dashboard's inability to authenticate is documented (P01-6, TODO.md) but not addressed - exactly as scoped.

---

## 6. Could not verify

- **P01-3's startup-check behavior under `_SPIRE_DISABLED=false` (the real mTLS path).** The polling loop and exit behavior were exercised live under `SPIRE_DISABLED=true` (the only mode reachable without the full SPIRE/Envoy stack running alongside a deliberately-broken bundle name simultaneously). The `if not ssl_context or not _validate_peer_spiffe_san(ssl_context): sys.exit(1)` branch for a failed mTLS handshake was read and matches the existing, already-tested pattern in `query_opa_policy`, but was not separately driven live in this phase.
- **CI's behavior on a from-scratch commit with no prior green history to compare against.** Only this phase's single pushed commit was checked (`gh run view` on the one run). Earlier runs on this branch were not re-walked beyond what the red-team report already recorded.

---

## 7. Cumulative gate

```
collecting ... collected 31 items
======================== 31 passed, 1 warning in 3.33s =========================
```

CI run `31963976465`, commit `33822a6b0cff5a432a8a0816b7561187a9fffe59`, conclusion `success`.
