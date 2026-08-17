# Phase 1.2: Record integrity - Report

## 1. Start SHA, end SHA, environment

**Base confirmed:** `phase-1-1-remediation` at `e7e9607` - matches the instruction's expected base and PR #2's head at session start (`gh pr view 2` confirmed `headRefOid: e7e9607`, state OPEN, base `main`, `mergeable: MERGEABLE`, and the `integration-tests` check `success`).

**Start SHA:** `e7e9607`.

**End SHA - the commit to audit:** `832c5e630cce31ea6d40d001cc65e2749ede9737`. Two commits went onto `phase-1-1-remediation`, pushed to origin: `82777b2` (the code change - policy, interceptor, control plane, ledger, tests) and `832c5e6` (docs-only, this report's own end-of-report pointers). `832c5e6` is the actual branch head and the one to check out for audit - it contains everything in `82777b2` plus nothing else code-relevant. An earlier version of this report named `82777b2` as the end SHA, written before the docs-only commit was pushed; that was stale the moment it was superseded and is corrected here. PR #2 confirmed `OPEN`, `mergedAt: null` at `832c5e6` - not merged.

**Environment:**

- Windows 11, Docker Desktop, Docker Compose v2 (`docker compose`), OPA `1.14.1` (the pinned image in `docker-compose.test.yml`). `make` is not installed in this environment (same as Phase 1.1's own report noted) - `test-integration`'s steps were run by hand, the same commands the fixed Makefile issues.
- Work was done in a fresh scratch clone (`phase12-work`, a directory name not used by any earlier session), `git clone` + `git checkout phase-1-1-remediation` at `e7e9607`, origin repointed at the GitHub remote. Docker images were built with `docker compose build --no-cache` for all three custom services (`ail-control-plane`, `verifier`, `dashboard`) before any test ran.
- The full suite was `84 passed, 1 warning` clean on a fresh stack (`down -v` / `up -d --build --wait`) at the end of the session - see section 7.
- One environmental flake was hit and is disclosed here, not counted as evidence against any claim below: after several hours of mutation testing (many `intercept_tool_call`s accumulating ledger entries, several container stop/start cycles), a single mid-session run of `tests/test_dashboard_auth.py::test_read_credentialed_get_audit_succeeds` hit `httpx.ReadTimeout` against `/audit` (confirmed independently: a direct `curl` of `/audit?limit=500` at that point took 40.8s). This is the same O(n) per-entry-verify scaling characteristic Phase 1.1's own report disclosed (`docs/reports/phase-1-1-redteam.md`, finding #3) - not a functional regression, not part of this phase's mandate (D9-D11 only), and not reproducible against a fresh ledger (confirmed: the final full-suite run against a freshly reset stack passed clean with no timeout).

---

## 2. Verdict table

| Item | Status | Key evidence |
| :--- | :--- | :--- |
| P12-1 (D9: revision resolves from the root-owning bundle) | **DONE** | T7 reproduced live pre-fix conceptually (S2 already unreachable post-fix since `input.bundle_name` no longer exists); disjoint-root decoy does not affect attribution; two-`ail`-claimant case is undefined live; `input.bundle_name` confirmed absent from every request; mutation (restore the lookup) caught |
| P12-2 (D10: unrecognized verifier errors are `unverifiable`) | **DONE** | T1 reproduced live verbatim (mutated `verifier/main.py`'s matched string, rebuilt, redeployed); confirmed `unknown` maps to `unverifiable` not `failed`, both real tamper classes still map to `failed`; mutation (restore `failed`-by-default) caught |
| P12-3 (D11: erasure is a recorded event, `lost` vs `erased`) | **DONE** | T5 reproduced live verbatim (direct SQLite delete inside the control-plane container, bypassing the endpoint); `lost` vs `erased` distinguishable; refused erasure live (verifier stopped, DELETE returns 503, row survives); tombstone excluded from `/audit`'s decision view and from `ail_policy_decisions_total`; mutation (delete without tombstone) caught by 2 of 3 named tests |
| P12-4 (evaluator-independent deny messages) | **DONE** | All 4 affected rules assert exact expected strings live against the real OPA server; `spikes/wasm-parity`'s own harness re-run against the fixed policy tree: **42/42 matches, 0 mismatches** (was 32/42 before the fix); mutation (restore one `sprintf("%v", [set])`) caught by exactly its own named test |
| P12-5 (test target always rebuilds) | **DONE** | `docker-compose.test.yml`'s `up -d --wait` in the Makefile changed to `up -d --build --wait`; demonstrated live: a source-only change to `control_plane/main.py` (a marker field on `/health`) was picked up by that single command with no separate manual build step |
| P12-6 (erratum on the Phase 1.1 report) | **DONE** | Appended to `docs/reports/phase-1-1.md`, naming the P11-7/S2 over-claim, citing T7, and stating precisely what P11-7 actually guarded |

---

## 3. Evidence

### P12-1 - D9: bundle revision resolves from the root-owning bundle

**Attack reproduced (T7, verbatim mechanism):** a decoy bundle written into a running OPA's `data.system.bundles` (via OPA's Data API, `PUT /v1/data/system/bundles/<name>` - the exact shape a real second Bundle-API-served bundle would populate, and the only path `policy/core/main.rego`'s new rule reads at all) alongside the real `ail-policies` bundle.

**Before:** `evaluation`'s revision came from `data.system.bundles[input.bundle_name].manifest.revision` - `input.bundle_name` traveled in the request body, set from `AIL_BUNDLE_NAME`. A caller who could reach OPA directly (or an attacker-controlled decoy served alongside the real bundle) could get any loaded bundle's revision attributed to a real deny reason simply by naming it. T7's live repro against `e7e9607` confirmed this exactly, and confirmed P11-7's own startup check (`_check_bundle_root_ownership`) never caught it, because it only ever flagged a *second bundle claiming the same root* - never a bundle claiming a disjoint root providing an attacker-chosen `bundle_name`.

**After:** `input.bundle_name` is removed from the request document entirely (`interceptor/middleware.py::query_opa_policy`). `policy/core/main.rego` derives the revision from `_ail_bundle_name`, a rule that resolves only when exactly one loaded bundle's `manifest.roots` contains `"ail"`. Live confirmed three ways against the real OPA server (`docker-compose.test.yml`):

```
$ curl -X PUT .../v1/data/system/bundles/decoy-bundle-<id> \
    -d '{"manifest":{"revision":"DECOY-REVISION-<id>-NOT-AIL-POLICIES","roots":["decoy"]}}'
$ curl -X POST .../v1/data/ail/main/evaluation -d '{"input":{"tool_name":"provision_cloud_server","tool_args":{...}}}'
{"result":{"allow":true,"reasons":[],"revision":"14387ebd...861c06e3c"}}   # the REAL ail-policies revision
# never the decoy's - there is no bundle_name for a caller to redirect with

$ curl -X PUT .../v1/data/system/bundles/decoy-ail-<id> \
    -d '{"manifest":{"revision":"DECOY-AIL-REV","roots":["ail"]}}'          # now claims "ail" too
$ curl -X POST .../v1/data/ail/main/evaluation -d '{"input":{...}}'
{}                                                                          # undefined - two claimants
```

Also run: the case where two bundles both claim `ail` (above) - undefined, and the interceptor's own handling of an undefined `/evaluation` result (`FAULT_REVISION_UNAVAILABLE`, unchanged code path from Phase 1) already treats this as a fault, confirmed by `tests/test_outcome_types.py::test_fault_revision_unavailable` (adapted - see below).

Confirmed `input.bundle_name` is gone from every caller: `interceptor/middleware.py`'s request body now has exactly two keys (`tool_name`, `tool_args`); no schema in `interceptor/schemas.py` ever referenced `bundle_name` (it only validates `tool_args`, unaffected). Three tests that previously forced `FAULT_REVISION_UNAVAILABLE` live by pointing `_BUNDLE_NAME` at a bundle OPA never loaded (`tests/test_outcome_types.py::test_fault_revision_unavailable`, `tests/test_policy_digest.py::test_digest_unavailable_denies_and_writes_a_fault_record`, `tests/test_response_contract.py::_live_response_keys`) could no longer do so - that lever no longer exists - and were adapted to force the same `result is None` response shape by pointing `_OPA_EVAL_URL` at a rule path OPA has never heard of. This changes *how* the fault is forced, not what is asserted about the fault's resulting shape; all three still pass.

**Enforce (`tests/test_bundle_revision_attribution.py`, new):**
- `test_decoy_bundle_with_disjoint_root_does_not_get_attributed` - T7's live repro; asserts the real revision is returned, never the decoy's.
- `test_two_claimants_of_ail_root_is_undefined` - the two-claimant case; asserts an undefined result.
- `test_bundle_name_not_sent_in_evaluation_request` - a unit test (mocked `httpx.Client`) asserting the exact key set OPA receives.

**Mutation:** reverted `policy/core/main.rego`'s `evaluation` rule to `data.system.bundles[input.bundle_name].manifest.revision`. Rebuilt into OPA (bundle poll, ~20s). Result:

```
tests/test_bundle_revision_attribution.py::test_decoy_bundle_with_disjoint_root_does_not_get_attributed FAILED
  AssertionError: Expected a defined result with one real claimant, got: {}
tests/test_bundle_revision_attribution.py::test_two_claimants_of_ail_root_is_undefined PASSED
tests/test_bundle_revision_attribution.py::test_bundle_name_not_sent_in_evaluation_request PASSED
```

Named test failed as required (the two-claimant test still passes on this mutation, coincidentally - both zero-bundle-name-support and two-claimants produce "undefined", so that test alone would not distinguish the mutation; the disjoint-root test is the one that does, and it caught it). Reverted; `tests/test_bundle_revision_attribution.py` confirmed `3 passed` clean afterward.

`_check_bundle_root_ownership`, `_fetch_opa_bundles_map`, `_OPA_BUNDLES_URL`, and `tests/test_bundle_ownership.py` are removed entirely, not survived-with-real-assertions - the function no longer exists at all; D9's own per-evaluation check supersedes it structurally (see `docs/reports/phase-1-1.md`'s erratum, P12-6).

### P12-2 - D10: unrecognized verifier errors are `unverifiable`

**Attack reproduced (T1, verbatim):** mutated `verifier/main.py`'s matched string (`"key not found"` -> `"key absent from tree"`), rebuilt and redeployed only the `verifier` container.

**Before/after, live:**

```
$ pytest tests/test_verification.py::test_not_found_state -v
FAILED: assert 'unknown' == 'not_found'
  {'verified': False, 'detail': '...StatusCode.UNKNOWN\n\tdetails = "tbtree: key not found"...', 'error_class': 'unknown'}
```

The guard still fails loudly (T1's first half held before this phase too). Then, feeding this exact drifted `error_class: "unknown"` response into `control_plane/main.py::_verification_from_200` (unmutated):

```python
>>> _verification_from_200({'verified': False, 'detail': '<...StatusCode.UNKNOWN...>', 'error_class': 'unknown'})
{'state': 'unverifiable', 'state_id': None, 'detail': '<...StatusCode.UNKNOWN...>', 'error_class': 'unknown'}
```

`state: "unverifiable"`, not `"failed"` - confirmed live against the real drifted verifier, not a fabricated body. `detail` is preserved, nothing lost. Reverted the verifier mutation, rebuilt, redeployed; `tests/test_verification.py` confirmed `9 passed` clean afterward.

**Enforce (`tests/test_verification.py`, extended):**
- `test_control_plane_maps_unknown_error_class_to_unverifiable_not_failed` - asserts `"unknown"` and a never-before-seen `error_class` both map to `unverifiable`, detail preserved.
- `test_control_plane_maps_both_tamper_classes_to_failed` - asserts `consistency_failure` and `signature_failure` both still map to `failed` (D10 narrows the default, it does not touch these two).

**Mutation:** collapsed `_verification_from_200`'s three-way branch (`not_found` / two tamper classes / everything else) back to the old two-way branch (`verified` / `not_found` / else -> `failed`). Result:

```
tests/test_verification.py::test_control_plane_maps_unknown_error_class_to_unverifiable_not_failed FAILED
  AssertionError: Expected 'unverifiable', got: {'state': 'failed', ..., 'error_class': 'unknown'}
tests/test_verification.py::test_control_plane_maps_both_tamper_classes_to_failed PASSED
```

Named test failed as required. Reverted; `2 passed` clean afterward.

### P12-3 - D11: erasure is a recorded event, `lost` distinguishable from `erased`

**Attack reproduced (T5, verbatim):** issued a real approved call, confirmed `payload_state: "present"`, then bypassed `DELETE /content/{call_id}` entirely with a raw SQL delete inside the control-plane container's own SQLite file (`docker compose exec ail-control-plane python -c "sqlite3... DELETE FROM call_content WHERE call_id=?"`).

**Before (as T5 found it, pre-Phase-1.2):** this rendered byte-for-byte identical to a legitimate erasure - `payload_state: "erased"` either way, no distinguishing field.

**After, live:**

```
$ docker compose -f docker-compose.test.yml exec -T ail-control-plane python -c "sqlite3.connect(...).execute('DELETE FROM call_content WHERE call_id=?', (call_id,))..."
$ curl .../audit | jq '.entries[] | select(.call_id==$call_id) | .payload_state'
"lost"
```

Distinguishable from a legitimate erasure through the real endpoint:

```
$ curl -X DELETE .../content/$call_id -H "X-API-Key: ..."
204
$ curl .../audit | jq '.entries[] | select(.call_id==$call_id) | .payload_state'
"erased"
```

**Refused erasure on tombstone-write failure, live:** stopped the `verifier` container (`docker compose stop verifier`), issued `DELETE /content/{call_id}` for a present row:

```
$ curl -X DELETE .../content/$call_id -H "X-API-Key: ..."
503   {"detail": "Tombstone write failed; erasure refused: ..."}
$ curl .../audit | jq '.entries[] | select(.call_id==$call_id) | .payload_state'
"present"   # row survives
```

Restarted the verifier, confirmed healthy, re-ran the full suite clean afterward.

**Tombstone excluded from the decision view and metric, live:** before/after an erasure, `/audit`'s total entry count is unchanged (the tombstone - written under a `content_erasure:` key, a different prefix than `/audit`'s own `tool_call:` scan, and additionally classified by its `record_type` field rather than trusted by key shape alone - never surfaces as a second entry), and `ail_policy_decisions_total`'s summed value across every series (scraped from the interceptor's own in-process metrics server) is unchanged (the erasure runs entirely inside the control-plane container, a different process from the one that owns that metric - structurally incapable of incrementing it).

**Enforce (`tests/test_content_states.py`, extended):**
- `test_direct_sqlite_delete_produces_lost_not_erased` - T5's live repro; asserts `lost`, not `erased`.
- `test_erasure_refused_when_tombstone_write_fails` - live verifier outage; asserts 503 and the row survives.
- `test_erasure_tombstone_not_a_second_decision_entry` - asserts `/audit`'s entry count and `ail_policy_decisions_total`'s sum are both unchanged by an erasure.
- `test_present_then_erased_via_delete_content` (existing, Phase 1.1) now additionally exercises the tombstone mechanism end-to-end without modification: under D11's new `_payload_state`, the state can only read `"erased"` if a tombstone was actually found, so this test's continued pass is itself evidence the real endpoint's tombstone write succeeds.

**Mutation:** reverted `erase_content` to delete the row directly, with no tombstone write. Rebuilt and redeployed the control plane. Result:

```
tests/test_content_states.py::test_direct_sqlite_delete_produces_lost_not_erased PASSED   (unaffected - different attack vector)
tests/test_content_states.py::test_erasure_refused_when_tombstone_write_fails FAILED
  assert 204 == 503   (erasure succeeded when it should have been refused)
tests/test_content_states.py::test_erasure_tombstone_not_a_second_decision_entry FAILED
  assert 'lost' == 'erased'   (no tombstone was written, so the real endpoint's own erasure now reads as 'lost')
```

Two of the three named tests failed as required (the third, T5's own direct-SQL-delete repro, is a different attack vector and is unaffected by this particular mutation - correctly so). Reverted; `tests/test_content_states.py` confirmed `6 passed` clean afterward.

### P12-4 - deny messages are evaluator-independent

**Attack reproduced (the spike's own W3 finding, verbatim):** `spikes/wasm-parity`'s 42-case corpus, re-run against the fixed policy tree.

**Before (spike report):** 32/42 matched byte-for-byte; 10/42 differed only in `sprintf("%v", [set])`'s rendering (OPA server: `{"eu-central-1", "us-east-1"}`, braced/quoted/sorted; WASM: `eu-central-1,us-east-1`, unbraced/unquoted/unsorted), across exactly four rules: GDPR's pci-dss region rule, GDPR's unclassified-data region rule, GDPR's purpose-limitation rule, and FinOps's cost-center rule.

**After, live (spike tooling re-run against the fixed `policy/packs/gdpr/gdpr.rego` and `policy/packs/finops/finops.rego`, same corpus, same pinned OPA v1.19.0, same `@open-policy-agent/opa-wasm` harness):**

```
$ node scratch/run_parity.mjs
Total cases: 42
Matches: 42
Mismatches: 0
```

**42/42, zero mismatches** - the required result exactly. Also confirmed live against the real OPA server (the evaluator this project actually runs today), one exact-string assertion per affected rule:

```
GDPR pci-dss:        "...Approved: eu-central-1, us-east-1"
GDPR unclassified:    "...Approved: eu-central-1, us-east-1"
GDPR purpose limit.:  "...Approved purposes: billing, customer_support"
FinOps cost center:   "...Approved values: engineering, finance, marketing, operations."
```

**Enforce (`tests/test_deny_message_formatting.py`, new):** one test per affected rule, asserting the exact expected string live against the real OPA server.

**Mutation:** restored `sprintf("%v", [approved_regions])` (the un-fixed form) in the pci-dss rule only. Result:

```
tests/test_deny_message_formatting.py::test_gdpr_pci_dss_region_message_is_sorted_concat_not_set_format FAILED
  Expected exact message in ['...Approved: {"eu-central-1", "us-east-1"}']
tests/test_deny_message_formatting.py::test_gdpr_unclassified_region_message_is_sorted_concat_not_set_format PASSED
tests/test_deny_message_formatting.py::test_gdpr_purpose_limitation_message_is_sorted_concat_not_set_format PASSED
tests/test_deny_message_formatting.py::test_finops_cost_center_message_is_sorted_concat_not_set_format PASSED
```

Exactly the one named test for the mutated rule failed - the other three, untouched, correctly kept passing. Reverted; `4 passed` clean afterward.

### P12-5 - the test target always builds

**Criterion:** `docker-compose.test.yml`'s `up -d --wait` in `Makefile`'s `test-integration` target does not rebuild an image that already exists under this Compose project's tag, even when the source it was built from has changed (Phase 1.1's own report, section 1: "two full `docker compose build <service>` passes were needed this session"; a prior session hit 30 spurious failures at once).

**Fix:** `docker compose -f docker-compose.test.yml up -d --wait` -> `up -d --build --wait`.

**Demonstrated live:** added a marker field to `control_plane/main.py`'s `/health` response (a source-only change, no manual build step run):

```
$ curl localhost:8002/health
{"status":"ok"}
$ docker compose -f docker-compose.test.yml up -d --build --wait ail-control-plane
 Image phase12-work-ail-control-plane Built
 Container phase12-work-ail-control-plane-1 Recreated
 ...Healthy
$ curl localhost:8002/health
{"status":"ok","p12_5_rebuild_marker":"source-changed-since-last-build"}
```

The single command in the Makefile's own fixed form picked up the source change with no separate `docker compose build` step. Reverted the marker; rebuilt clean.

### P12-6 - erratum on the Phase 1.1 report

Appended to `docs/reports/phase-1-1.md`: names the P11-7/S2 over-claim in row 34 of that report's verdict table, cites T7's re-run, and states precisely what P11-7 actually guarded (exactly one loaded bundle claims `ail`, checked once at boot, never against a disjoint-root claimant) versus what S2 actually exploited (a caller-suppliable `bundle_name`, unrelated to root ownership, rechecked never).

---

## 4. What required judgment and what was decided

**D9's "undefined, not an error" requirement.** A naive Rego translation of "exactly one claimant" (`some name; data.system.bundles[name]; ...` feeding directly into a single-value rule with a `some` over a multi-element set) risks a hard eval error ("complete rules must not produce multiple outputs") rather than a clean "undefined" for the two-claimant case, which the spec requires to surface as an ordinary fault, not a 500. Decided: build the claimant set as its own partial-set rule (`_ail_root_owners contains name if {...}`), then gate a *separate* single-value rule (`_ail_bundle_name`) on `count(_ail_root_owners) == 1` before ever binding a scalar `name` from it. Zero and two-or-more claimants both fail the count guard and leave `_ail_bundle_name` cleanly undefined - confirmed live, no eval error in either case (§3, P12-1).

**Where the D9 fault-forcing tests should point once `bundle_name` is gone.** Three existing tests (`test_outcome_types.py`, `test_policy_digest.py`, `test_response_contract.py`) forced `FAULT_REVISION_UNAVAILABLE` by setting `_BUNDLE_NAME` to a bundle OPA never loaded - a lever D9 removes entirely. The alternative considered was deleting these tests' fault-forcing sub-case, since the *mechanism* was inherently mocking something that no longer exists. Decided instead to redirect them at an equally-legitimate cause of the same `result is None` response shape (`_OPA_EVAL_URL` pointed at a rule path OPA has never heard of) - this preserves the assertion under test (the interceptor's handling of an undefined `/evaluation` result) without inventing a new claim, and keeps the fault-handling code path covered independently of D9's own dedicated live tests in `test_bundle_revision_attribution.py`.

**How to test the D11 tombstone mechanism without a per-user identity layer.** D11 calls for an `actor` field with "no personal data." This codebase has no per-caller identity at the control-plane layer at all - `CONTROL_PLANE_WRITE_KEY` is one shared secret (ADR-0007), not a credential per caller. Decided against inventing one (out of scope - D9 to D11 only, no design changes) or leaving the field blank (loses information about which authorization boundary was crossed). Set `actor: "control-plane-write-key"`, a static, honest label naming the boundary, not a person - documented as such in the field's own docstring.

**How to reproduce T5 and the tombstone-write failure without host access to the container's SQLite file.** `docker-compose.test.yml` uses a named volume for the control plane's data dir, not a host bind mount, so the host-side pytest process cannot touch the file directly the way a red-team session with an interactive shell can. Decided to shell out to `docker compose exec` from inside the test itself (T5's repro) and to `docker compose stop`/`start` the verifier container (the tombstone-failure repro) - both mirror the actual live technique from `docs/reports/phase-1-1-redteam.md` more faithfully than a mocked equivalent would, at the cost of both tests depending on the `docker` CLI being on the runner's PATH (true for this environment and for GitHub Actions' hosted runners).

---

## 5. Pre-registered negatives - confirmed individually

- **Any failure path returning something other than DENY.** Confirmed false: the full `84 passed` suite includes every existing fault-path test (`test_outcome_types.py`'s five `test_fault_*` cases, `test_content_states.py`'s fail-closed content-store case), none altered in behavior, all still asserting `status == "DENIED"`.
- **Any caller-supplied value determining which bundle's revision is recorded.** Confirmed false: `input.bundle_name` no longer exists in the request document at all (`tests/test_bundle_revision_attribution.py::test_bundle_name_not_sent_in_evaluation_request`); a disjoint-root decoy in `data.system.bundles` cannot redirect attribution (`test_decoy_bundle_with_disjoint_root_does_not_get_attributed`, live).
- **Any unrecognized condition mapping to `failed`.** Confirmed false: `"unknown"` and a never-before-seen `error_class` both map to `unverifiable` (`test_control_plane_maps_unknown_error_class_to_unverifiable_not_failed`), confirmed against the live T1-drifted verifier directly, not only a fabricated body.
- **Any payload absence rendering identically across two causes.** Confirmed false: a direct SQL delete (`lost`) and a real endpoint erasure (`erased`) render distinctly (`test_direct_sqlite_delete_produces_lost_not_erased`), live, for the same underlying row-absence condition.
- **Any tombstone appearing in a decision view or decision metric.** Confirmed false: `/audit`'s entry count and `ail_policy_decisions_total`'s summed value are both unchanged by a live erasure (`test_erasure_tombstone_not_a_second_decision_entry`).
- **Any assertion weakened.** Confirmed false: `git diff -- tests/` contains no `assert True`, no commented-out assertion, no loosened comparison (checked directly, not by review alone); every changed test file either adds new assertions or changes only the mechanism used to force an existing, unchanged assertion's precondition (P12-1's three adapted fault-forcing tests, §4).
- **Any item met by live evidence alone with no test enforcing it.** Confirmed false: every item in §3 has both a live reproduction and a named, committed test; the mutation for every item was independently confirmed to fail exactly the test(s) named for it.
- **Any red-team attack from Phase 1.1 that still reproduces.** Confirmed false for T1, T5, T7 (this phase's mandate) via the live repros in §3, each now producing the required post-fix result rather than the original attack's result. T2's two zero-assertion tests no longer exist to reproduce against - `tests/test_bundle_ownership.py` was deleted in full, not patched (§3, P12-1). T3, T4, T6, T8 (outside this phase's mandate, already `HOLDS` per `docs/reports/phase-1-1-redteam.md`) were re-confirmed passing, unmodified, in the same `84 passed` full-suite run (`tests/test_dashboard_auth.py` 10/10, `tests/test_opa_request_count.py` 2/2).

---

## 6. Could not verify

- **The exact GitHub Actions CI run for this phase's changes**, as of the point this report's evidence sections were written - see section 7 for the run once the branch is pushed and CI completes.
- **A live second real bundle-serving OPA container for P12-1's decoy scenarios** (as opposed to writing the equivalent shape directly into `data.system.bundles` via OPA's Data API). The Data API write produces the identical data shape a real second Bundle-API-served bundle would populate, and D9's rule only ever reads that shape - judged equivalent for what D9 changes, and consistent with `docs/reports/phase-1-1-redteam.md`'s own T7 methodology (a decoy bundle "served from a throwaway container" - same end state in `data.system.bundles`, reached by a lighter mechanism here).
- **Cloudflare-production WASM parity beyond `spikes/wasm-parity`'s own local harness** - the harness re-run (§3, P12-4) is local (`opa eval` + `@open-policy-agent/opa-wasm` under Node), matching the spike's own stated scope; a deployed-Worker re-run was not attempted, same limitation the spike itself disclosed.

---

## 7. Cumulative gate

Full suite, `docker-compose.test.yml`, fresh volumes (`down -v` / `up -d --build --wait`), run clean after all six items' mutations above were applied, confirmed caught, and reverted:

```
84 passed, 1 warning in 197.15s (0:03:17)
```

No test skipped, no test newly `xfail`ed, no assertion weakened (§5). 84 = 78 (Phase 1.1's own baseline) - 6 (`tests/test_bundle_ownership.py`, removed as obsolete, P12-1) + 12 new (3 in `test_bundle_revision_attribution.py`, 4 in `test_deny_message_formatting.py`, 3 new in `test_content_states.py`, 2 new in `test_verification.py`).

**Code commit:** `82777b2ace8de04c0fca3d941fd28c2aee92a8d1` - CI run `32073638413` (`integration-tests`, `success`, 2m9s) ran at this head.

**End SHA - the commit to audit:** `832c5e630cce31ea6d40d001cc65e2749ede9737` (docs-only, on top of `82777b2`, no code or test changes - see §1) - CI run `32073875146` (`integration-tests`, `success`, 2m1s) ran at this head, confirming the docs-only commit didn't disturb anything. This is the actual branch head; check it out for audit, not `82777b2`. PR #2 confirmed `OPEN`, `mergedAt: null` at this head - not merged.
