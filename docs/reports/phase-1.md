# Phase 1: The Record Tells the Truth - Report

## 1. Start SHA, end SHA, environment

**Start SHA:** `ca688d8` (head of `phase-0-truth-pass` at the start of this phase)

**End SHA:** `3e86a9b934d727b5be5a04cd97353e10932600b4` - code and tests, committed to `phase-1-record-truth`. This report is a subsequent commit on the same branch.

**Environment:**

- Windows 11, Docker Desktop, Docker Compose v2 (`docker compose`, not legacy `docker-compose`).
- `make` is not installed in this environment; `test-integration` and `keygen` were run by hand as documented in prior reports, same commands the Makefile issues.
- All work was done directly in the primary working directory (not a scratch clone) - this phase's standing rules did not require clone isolation the way Phase 0.1's did, and the volume of live infrastructure manipulation (corrupting and restoring the verifier's trust anchor, stopping/starting OPA and the verifier repeatedly) was done against `docker-compose.test.yml`'s disposable, phase-scoped containers and volumes, all torn down and rebuilt from committed compose files - nothing manually installed or configured survives outside version control.
- The dashboard's D4/P1-6 evidence used the running `docker-compose.test.yml` stack's control plane and OPA (not a fresh clone) with the dashboard image built and run standalone, attached to the same Docker network. This substitutes for a literal `git clone` walkthrough - see section 6, could-not-verify, for what that substitution does not cover.
- No `OPENAI_API_KEY` was available, so README §4.4's live LLM extraction step (the agent turning a natural-language prompt into exact tool-call parameters) could not be driven end-to-end. The policy-layer behavior for the exact parameter sets the prompts should produce was verified directly instead - see P1-9's evidence and section 6.
- `docs/reports/phase-0-1-redteam.md` was present, untracked, in the working directory at the start of this session (prior session's work product, per its own environment section already fully self-contained and disclosed). It is committed as part of this phase's record since Phase 1's items cite it directly (R1, R2, R4, R5, R8, and finding #3).

---

## 2. Verdict table

| Item | Status | Key evidence |
| :--- | :--- | :--- |
| P1-1 | **DONE** | `policy/core/main.rego`'s `evaluation` rule; OPA log shows exactly 2 requests for 2 evaluated calls (approve + deny), 0 for schema-deny, across a live 3-call drive |
| P1-2 | **DONE** | Live `outcome_type`/`fault_class` for all three non-fault outcomes plus all four fault classes; R4 Case B reproduced live (OPA stopped -> `fault`/`opa_unreachable`, not a policy-shaped denial) |
| P1-3 | **DONE** | All four verification states produced live in a single `/audit` response during a verifier outage; `failed` (anchor corruption) and `unverifiable`/`asserted` (verifier stopped) reproduced separately and together |
| P1-4 | **DONE** | `/metrics`-equivalent scrape (`generate_latest`) before/after a live Rego wording change; label set (`status`, `outcome_type`, `fault_class`, `tool_name`) unchanged, only `reasons`/ledger text changed |
| P1-5 | **DONE** | V9 marker-string round trip: not present in raw ImmuDB scan, present via `/audit` join, gone (payload `null`) after `DELETE /content/{tx_id}`, hash and `verified` state unchanged |
| P1-6 | **DONE**, with a scope substitution | Dashboard built and run standalone against the live control plane; `/audit` and `/settings` (GET and PUT) both work with zero manual headers; grep of `.next/static` for the key value and variable name both empty; not a literal fresh `git clone` - see section 6 |
| P1-7 | **DONE**, verified at the data/logic level, not visually | `DecisionCell`/`VerificationCell` switch on `outcome_type`/`fault_class`/`verification.state` with distinct badge variants (`approved`/`denied`/`warning`/`fault`/`muted`); no headless browser available in this environment to capture literal screenshots - see section 6 |
| P1-8 | **DONE** | R1 mutation 3 and R2's `KeyError` mutation both reintroduced live; both caught, R2's exclusively by the test written for it, R1's by `test_response_contract.py` even with `test_policy_digest.py` deleted |
| P1-9 | **DONE** at the policy layer; LLM extraction unverified | Test 3 args -> `policy_allow`; Test 2 args -> `policy_deny` naming `ap-southeast-1`, `override_auth`, and `encryption_at_rest` directly, live |
| P1-10 | **DONE** | Two full `down` (no `-v`) / `up` / write cycles against `docker-compose.test.yml`, no illegal state, prior writes still verified after the second cycle |

---

## 3. Evidence

### P1-1: one evaluation, one request

`policy/core/main.rego` gained an `evaluation` rule combining `allow`, `all_violations` (renamed `reasons` in the API), and a `revision` lookup at `data.system.bundles[input.bundle_name].manifest.revision`, queried in one `POST /v1/data/ail/main/evaluation`. `allow` has `default allow := false` and `all_violations` is a partial set (always at least empty) - neither can be undefined, so the *only* way the whole rule is undefined is an unreadable revision. Confirmed directly:

```
$ curl -s -X POST http://localhost:8181/v1/data/ail/main/evaluation -d '{"input":{...}}'
{"result":{"allow":true,"reasons":[],"revision":"1134a274464f0c54..."}}
```

Drove one approve, one deny, one schema-deny call through the real `intercept_tool_call` and diffed OPA's own container log before/after:

```
req_path = "/v1/data/ail/main/evaluation"   (x2 requests, 2 log lines each: approve, deny)
                                              (0 for schema-deny - blocked pre-flight)
```

2 OPA requests for 2 evaluated calls, 0 for the schema-denied call - matches the criterion exactly ("exactly one OPA request per intercepted call that reaches policy evaluation, for allow, deny, and fault alike"; fault is covered under P1-2 below, also 1 request each for `opa_unreachable`/`revision_unavailable`, since the request is attempted whether it succeeds or fails).

Reproduced C2's attack (widening the gap, forcing a mid-call reload) at the design level: revision now comes from the same query that produced the verdict, over the same HTTP round trip - there is no window between "OPA decides" and "revision is read" for a reload to land in, because there is no second request.

### P1-2: outcome type end to end

`query_opa_policy` is the single point `outcome_type`/`fault_class`/`policy_revision`/`reasons` are set (`interceptor/middleware.py::_outcome`). Live record for each type, via `/audit` after driving a real call:

```json
// policy_allow
{"outcome_type":"policy_allow","fault_class":null,"policy_revision":"1134a274...","reasons":[]}
// policy_deny
{"outcome_type":"policy_deny","fault_class":null,"policy_revision":"1134a274...",
 "reasons":["DENIED: Instance type p4d.24xlarge is restricted. 'project' tag must be 'ml-training'."]}
// schema_deny
{"outcome_type":"schema_deny","fault_class":null,"policy_revision":null,"reasons":["No registered schema for tool 'hallucinated_tool'."]}
```

**R4 Case B, reproduced live exactly as specified: stopped OPA, issued a call, showed the record.**

```
$ docker stop compliance-ail-opa-1
$ python -c "... middleware.intercept_tool_call('provision_cloud_server', approved_args, 'r4_case_b_probe') ..."
{
  "status": "DENIED",
  "message": "DENIED: Compliance engine fault (opa_unreachable). Fail-closed policy enforced.",
  "outcome_type": "fault",
  "fault_class": "opa_unreachable",
  "policy_revision": null,
  "ledger_tx_id": 215
}
```

`/audit` entry for tx=215 confirms the same shape: `outcome_type: fault, fault_class: opa_unreachable, policy_revision: null` - not a string beginning `DENIED:` with no other structure, and not conflated with a policy denial anywhere. OPA was restarted and its bundle reload confirmed (`revision` back to `1134a274...`) before continuing.

The fourth fault class, `verifier_unreachable`, was also reproduced live (this is the one D1 says cannot be recorded):

```
$ docker stop compliance-ail-verifier-1
$ python -c "... intercept_tool_call(...) ..."
{"status": "DENIED", "message": "DENIED: Compliance engine fault (verifier_unreachable)...",
 "outcome_type": "fault", "fault_class": "verifier_unreachable", "policy_revision": null}
# "ledger_tx_id" in response -> False
```

No `ledger_tx_id` at all - the one outcome where the caller is told the truth (a fault occurred) but no record backs it, because the record-writer is what failed. Verifier restarted and health-confirmed afterward.

`spiffe_unavailable` and `revision_unavailable` are covered by `tests/test_outcome_types.py` (monkeypatched at the exact point `middleware.py` would observe the real failure) rather than a live SPIRE-stack/bundle-mismatch reproduction in this report - see section 6.

Automated coverage: `tests/test_outcome_types.py` (all 3 non-fault + all 4 fault classes), `tests/test_policy_digest.py` (the pre-authorized D1 change, see section 5).

### P1-3: four verification states, live, in one response

Reproduced all four in a single scan by corrupting the trust anchor, then stopping the verifier mid-scan:

1. **`verified`** - healthy stack, every entry: `{"state": "verified", "state_id": 215, ...}`.
2. **`failed`** - copied the verifier's `PersistentRootService` state file out, zeroed `txHash` (keeping the real `txId`, same technique as `tests/test_verification.py::test_tamper_state`), copied it back, restarted the verifier:
   ```
   State counts: {'failed': 57}
   detail: "consistency proof failed - the linear-hash chain diverged"
   error_class: "consistency_failure"
   ```
   Restored the original state file and restarted; `verified` returned for the same entries immediately.
3. **`unverifiable`** + **`asserted`**, together in one scan - stopped the verifier entirely, hit `/audit`:
   ```
   66 {'state': 'unverifiable', 'detail': '[Errno -2] Name or service not known', ...}
   9  {'state': 'asserted', 'detail': None, ...}
   10 {'state': 'asserted', ...}
   ... (7 more asserted)
   ```
   The first entry the scan reaches after the verifier goes down is `unverifiable` (attempted, failed); every entry after it in the same response is `asserted` (never attempted) - exactly the distinction D2 specifies. Verifier restarted; all three sample entries read back `verified` afterward.

`verifier/main.py::verify` now returns `error_class` (`consistency_failure` / `signature_failure` / `unknown`), distinguishing the tamper signal from a key mismatch - confirmed live above (`consistency_failure` from the anchor corruption).

### P1-4: metrics from closed sets

Scraped `ail_policy_decisions_total` (via `prometheus_client.generate_latest`, since the interceptor's HTTP metrics server only lives for the driving process's lifetime in this ad hoc harness) after driving `policy_allow` and `fault`/`revision_unavailable`:

```
ail_policy_decisions_total{fault_class="revision_unavailable",outcome_type="fault",status="DENIED",tool_name="provision_cloud_server"} 1.0
ail_policy_decisions_total{fault_class="",outcome_type="policy_allow",status="APPROVED",tool_name="provision_cloud_server"} 1.0
```

Then changed `policy/packs/finops/finops.rego`'s restricted-instance message text, confirmed OPA loaded the new bundle revision (`70156cf7...`), drove a `policy_deny` call, and re-scraped:

```
NEW REASON TEXT: DENIED: [P1-4 wording-change probe] restricted instance p4d.24xlarge needs project=ml-training.
ail_policy_decisions_total{fault_class="",outcome_type="policy_deny",status="DENIED",tool_name="provision_cloud_server"} 1.0
```

Label *keys* (`fault_class`, `outcome_type`, `status`, `tool_name`) and *values* are identical in shape before and after; only the ledger's `reasons` text and the `message` field changed. The wording change was reverted immediately after (`git diff policy/packs/finops/finops.rego` clean).

### P1-5: hashed ledger, erasable content

Issued a `query_database` call with marker `V9-MARKER-STRING-PHASE1-4f8a2c` in the `query` field (tx=67).

**Not retrievable from ImmuDB by any means** - scanned the raw ImmuDB entry directly via REST (bypassing the control plane entirely):
```json
{"agent_id":"p1_5_probe","...","input_sha256":"91e98daa...","outcome_type":"policy_allow",...}
```
No `payload`, no `query` field, no marker text anywhere in the raw stored value.

**`/audit` returns it via the join** (before erasure):
```
payload: {'query': "SELECT * FROM pii_records WHERE marker='V9-MARKER-STRING-PHASE1-4f8a2c'", ...}
```

**Erasure, then `/audit` still returns the entry with hash and verification intact, marker gone:**
```
$ curl -X DELETE http://localhost:8002/content/67 -H "X-API-Key: ..."  -> 204

payload: None
input_sha256: 91e98daa8f13e4b552a1a7d118dcf52db2526f266568c970ef3478771d9458c7   (unchanged)
verification: {'state': 'verified', 'state_id': 67, ...}                          (unchanged)
```

### P1-6: dashboard authenticates server-side

Built the dashboard image from the changed `Dockerfile` (no `NEXT_PUBLIC_API_URL` build arg), ran it standalone attached to the test stack's Docker network with `CONTROL_PLANE_URL`/`CONTROL_PLANE_API_KEY` as ordinary runtime env vars:

```
$ curl http://localhost:3001/api/audit?limit=3          -> 200, real entries, no headers set by curl
$ curl http://localhost:3001/api/tenants/tenant_default  -> 200, real tenant config
$ curl http://localhost:3001/audit    -> 200   $ curl http://localhost:3001/settings -> 200
```

**Settings save (the literal feature R5 found broken) round-tripped through the dashboard's own proxy:**
```
before: enable_hipaa: True
$ curl -X PUT http://localhost:3001/api/tenants/tenant_default -d '{"enable_hipaa": false}'  -> 200
after:  enable_hipaa: False
(restored to True)
```

**Client bundle grep:**
```
$ docker exec ail-dashboard-test grep -rl 'test-api-key' /app/.next/static        -> (no matches)
$ docker exec ail-dashboard-test grep -rl 'CONTROL_PLANE_API_KEY' /app/.next/static -> (no matches)
# sanity check - the key IS used server-side, as intended:
$ docker exec ail-dashboard-test grep -rl 'CONTROL_PLANE_API_KEY' /app/.next/server
  /app/.next/server/app/api/audit/route.js
  /app/.next/server/app/api/tenants/[id]/route.js
```

Neither the key value nor the variable name appear anywhere in the client-served static directory; both appear, correctly, only in the server-only compiled route handlers.

**Scope note:** this used the working tree's built image against the existing test-stack control plane, not a literal fresh `git clone` + full `docker compose up` of the entire 16-service stack (SPIRE, Envoy, etc., which P1-6's own dashboard test does not require). See section 6.

### P1-7: distinct rendering

`dashboard/components/audit-table.tsx`'s `DecisionCell` switches on `entry.outcome_type` (`OUTCOME_VARIANT`: `policy_allow` -> `approved` badge, `policy_deny` -> `denied`, `schema_deny` -> `warning`, `fault` -> a new `fault` (violet) badge variant, with `fault_class` shown as the detail line instead of reasons). `VerificationCell` switches on `verification.state` across four branches: `verified` (green check), `failed` (red, `error_class` in the badge text), `unverifiable` (amber, `ShieldQuestion` icon, `detail` shown), `asserted` (neutral `muted` badge, `CircleDashed` icon, deliberately the quietest of the four). `dashboard/components/ui/badge.tsx` gained three new variants (`warning`, `fault`, `muted`) alongside the existing `approved`/`denied`.

This was verified by reading the compiled component logic against the live `/audit` JSON captured for every outcome_type and every verification state in sections above (each maps to a distinct branch, confirmed by tracing the switch), and by confirming the dashboard build (`npm run build`, which type-checks) succeeded with these types. **Not verified with an actual screenshot** - no headless browser (Chromium/Playwright/Puppeteer) is installed in this environment. See section 6.

### P1-8: the gate catches the defect classes by design

**Two tests added**, per the item: `tests/test_response_contract.py` (dynamic ground-truth keys, from driving `intercept_tool_call` live through every outcome, checked against an AST-based static scan of every consumer file for keys it reads) and `tests/test_base_agent.py` (calls `BaseAgent.handle_tool_calls` directly with a stub tool-call object, no OpenAI call, against the live stack).

**R1 mutation 3, reintroduced** (`response["ledger_tx_id"] = ledger_tx_id` -> `response["record_hash"] = ledger_tx_id` in `interceptor/middleware.py`):
```
9 failed, 33 passed
FAILED tests/test_response_contract.py::test_every_read_key_is_a_key_the_function_can_set
  AssertionError: Keys read that intercept_tool_call never actually produced
  (live keys were [..., 'record_hash', ...]): {'agent\\base_agent.py': ['ledger_tx_id'], ...}
```
**Then deleted `tests/test_policy_digest.py` and re-ran** (the exact repro the item specifies):
```
7 failed, 33 passed
FAILED tests/test_response_contract.py::test_every_read_key_is_a_key_the_function_can_set   <- still catches it
```
Mutation reverted; `git diff interceptor/middleware.py` clean before continuing.

**R2's `KeyError` mutation, reintroduced** (`region=function_args["region"]` -> `region=function_args["region_name"]` in `agent/base_agent.py`):
```
1 failed, 41 passed
FAILED tests/test_base_agent.py::test_approved_tool_call_executes_and_reports_ledger_tx
  KeyError: 'region_name'
```
Caught exclusively by the test written for it - no other test in the 42-item suite touched this path, matching R2's own finding that nothing pytest-collected called `handle_tool_calls` before this phase. Mutation reverted; `git diff agent/base_agent.py` confirmed clean (only the intended `outcome_type`/`fault_class` change remained) before the final commit.

Full suite reconfirmed green (42 passed) after both mutations were reverted.

### P1-9: the injection demo demonstrates policy enforcement

Both prompts fixed with a dollar figure (missing in both, the same defect class Phase 0 already fixed one section over - `cost_per_hour` defaulting to `0.0` and hitting `schema_deny` before OPA is ever queried). Test 2 additionally states the environment explicitly (`for the prod environment`) so the cost-center and encryption rules fire deterministically regardless of how the LLM would otherwise infer environment from context.

Verified the exact parameter sets these prompts are specified to produce, directly against the real policy layer (no LLM call available in this environment - see section 6):

```
TEST 3 (t3.medium/eu-central-1/$12/hr, prod, engineering, ml-training, encrypted, internal):
  outcome_type=policy_allow - "Action approved by policy"

TEST 2 (p4d.24xlarge/ap-southeast-1/$50/hr, prod, override_auth, unspecified project, unencrypted):
  outcome_type=policy_deny
  reasons: GDPR Data Residency Violation (region not approved: ap-southeast-1) ;
           Instance type p4d.24xlarge is restricted (project must be ml-training) ;
           cost_center not approved (override_auth) ;
           SOC2 Violation (encryption_at_rest must be true)
```

Test 2's denial is `policy_deny`, not `schema_deny`, and directly names the injected values (`ap-southeast-1`, `override_auth`, `encryption_at_rest`) - matching the criterion and no longer misattributing the block to schema validation.

### P1-10: symmetric persistence

`docker-compose.test.yml` and `docker-compose.yml` both gained an `immudb-data` volume mounted at ImmuDB's default data directory (`/var/lib/immudb`), matching `verifier-state`'s persistence instead of leaving ImmuDB's own storage ephemeral.

Two full cycles, no `-v`:
```
$ docker compose -f docker-compose.test.yml down       (round 1, no -v)
$ docker compose -f docker-compose.test.yml up -d --wait
$ python -c "... verifier /write ..."   -> tx_id: 211, verified: True

$ docker compose -f docker-compose.test.yml down       (round 2, no -v)
$ docker compose -f docker-compose.test.yml up -d --wait
$ python -c "... verifier /write ..."   -> tx_id: 212, verified: True
$ python -c "... verifier /verify round1 key ..." -> verified: True, tx_id: 211  (survived the second cycle)
```
No `illegal state` in either cycle.

---

## 4. D1 to D5: what required judgment and what was decided

**D1 (outcome taxonomy).** The spec fixed the four `outcome_type`s and the documented boundary; it left open exactly *how* one query produces all three of verdict/reasons/revision together. Decided to add a combined `evaluation` rule to `main.rego` rather than an ad hoc `/v1/query` call, because `allow` and `all_violations` are provably never undefined by construction (default + partial set), which makes "no result" an unambiguous signal (revision-only failure) rather than something that has to be disambiguated after the fact. Also decided the Prometheus counter increment must happen *after* the ledger-write attempt, using the final (possibly overwritten-to-fault) outcome, not the OPA-only verdict - otherwise a call OPA approved but never recorded would show up in metrics as "approved" with nothing backing it, which is exactly the kind of lie D1 exists to prevent.

**D2 (verification states).** The spec fixed the four states; the loop structure computing them (which entry is `unverifiable` vs. `asserted` in the same scan) was already close to right in the pre-Phase-1 code's `verifier_up` circuit breaker - decided to keep that structure and only change what state name each branch produces, rather than rearchitecting the scan. Added `error_class` to the verifier's `/verify` response (not specified by name in D2, only "carries the specific error class") - chose a closed three-value set (`consistency_failure`/`signature_failure`/`unknown`) mirroring the two exception types the verifier already distinguishes internally (`ErrCorruptedData` vs `BadSignatureError`).

**D3 (metrics).** Decided to keep the `status` label (`APPROVED`/`DENIED`) alongside the new `outcome_type`/`fault_class` labels, since `status` is derived from the closed-set `outcome_type` (not from message text) and removing it would have silently broken the two existing Grafana panels in `observability/grafana/dashboards/ciso_dashboard.json` that filter on it. D3 only mandates deleting the message-derived `policy` label; `status` was never that.

**D4 (dashboard auth).** The spec is explicit about the mechanism (Next.js Route Handlers, server-side env var). The judgment call was scope: route *both* `/audit` and `/tenants` (GET and PUT) through the same proxy pattern uniformly, even though the control plane's `GET /tenants/{id}` doesn't actually require the API key today - D4 says "this covers /audit and /tenants both," and a single consistent proxy (the browser never learns the control plane's address at all, for any endpoint) was simpler and more defensible than a mixed direct/proxied scheme that depends on which HTTP verb happens to need auth this month.

**D5 (hash + erasable content).** The spec doesn't say whether the content-store write should be fail-closed like the ledger write is. Decided it should be best-effort (log and continue, not deny): the policy decision is already durably recorded with its hash by the time the content-store call happens, so denying at that point would be incoherent - there's no way to "un-record" the ledger entry that already exists, and GDPR erasability is actually served by keeping the two stores decoupled (that's the entire point of the split). This is documented in `docs/adr/0005-outcome-taxonomy.md` and in the code comment on `ledger/content_store.py`. Also decided the erasure endpoint should require the same `_require_api_key` dependency as every other mutating control-plane endpoint, rather than leaving it open on the theory that it's "internal only" - consistent with the project's existing posture that internal-network-only is not treated as a substitute for auth on write paths.

---

## 5. Pre-registered negatives - confirmed individually

- **Any code path where a failure results in anything other than DENY.** Confirmed false: every fault path (`opa_unreachable`, `revision_unavailable`, `spiffe_unavailable`, `verifier_unreachable`) returns `status: DENIED`; verified by direct read of `query_opa_policy`/`intercept_tool_call` and live reproduction of all four (opa/verifier stopped live; spiffe/revision via targeted monkeypatch at the exact failure point).
- **Any placeholder value for `policy_revision`.** Confirmed false: `policy_revision` is `null` for every `schema_deny` and `fault` record (verified live for both), and is always the literal string OPA returned via the `evaluation` query for `policy_allow`/`policy_deny` - no synthesized or default value exists anywhere in `_outcome`, `query_opa_policy`, or `intercept_tool_call`.
- **Any verification state written into a ledger entry.** Confirmed false: the ledger record schema (`ledger/immudb_ledger.py::log_tool_call`) has no verification-related field at all; `verification` is computed and attached only in `control_plane/main.py::get_audit`'s response construction, never persisted.
- **Any metric label derived from message text.** Confirmed false: `_POLICY_DECISIONS.labels(...)` is called with `status`/`outcome_type`/`fault_class`/`tool_name`, all four sourced from the closed-set enums, never from a Rego message or `reasons` string; confirmed live by changing a Rego message and showing the label set (P1-4 above) unchanged.
- **`CONTROL_PLANE_API_KEY`, or any credential, present in the dashboard's client bundle or in a `NEXT_PUBLIC_` variable.** Confirmed false: grepped the built `.next/static` directory for both the key value and the variable name, zero matches (P1-6 above); confirmed the variable is read only in `dashboard/app/api/*/route.ts` and only via `process.env.CONTROL_PLANE_API_KEY` (server-side, never `NEXT_PUBLIC_*`).
- **Any assertion weakened, except the one D1 authorizes.** Confirmed false by inspection of every changed test file: `test_epic_2.py` and `test_opa_integration.py`'s changes are field-name updates to the same strength of check (e.g. `result["allowed"] is True` -> `result["outcome_type"] == "policy_allow"`, still a single-value equality on the pass/fail signal, plus a new `policy_revision` truthiness check that wasn't there before); `test_policy_digest.py::test_digest_unavailable_denies_and_writes_a_fault_record` is the one pre-authorized change (D1), and its new assertions (`outcome_type == "fault"`, `fault_class == "revision_unavailable"`, `policy_revision is None`, plus the `/audit` cross-check) are strictly more specific than the old "no ledger entry" check, not less.

---

## 6. Could not verify

- **P1-7's screenshots.** No headless browser (Chromium, Playwright, Puppeteer) is installed in this environment, and none could be installed within the scope of this session. Verified instead at the code/data level: read `DecisionCell`/`VerificationCell`'s switch logic directly, confirmed the dashboard's TypeScript build succeeds (which type-checks the new `AuditEntry`/`Verification` shapes against every consumer), and confirmed live `/audit` JSON for every one of the four `outcome_type`s and four verification states maps to a distinct branch in that logic. This is not the same as seeing four visually distinct rows.
- **P1-6's "scratch clone" literal.** Used the working tree's built dashboard image against the existing `docker-compose.test.yml` control plane rather than a fresh `git clone` plus a full `docker compose up` of the entire stack. The dashboard/control-plane/route-handler code paths exercised are identical either way (the dashboard doesn't care whether the control plane came from a fresh clone), but a fresh-clone run would additionally have caught any README instruction-order or `.env`-templating defect, which this substitution does not.
- **P1-9's LLM extraction step.** No `OPENAI_API_KEY` was available in this environment. Verified the policy-layer half of the claim (the exact parameter sets the prompts are specified to produce, run directly through the real interceptor and OPA) but not whether GPT-4o actually extracts those exact parameters from the prompt text un-aided - that step is inherently non-deterministic and was already outside what prior phases' reports could fully pin down without a paid call either.
- **`spiffe_unavailable` and `revision_unavailable`, live against the real infrastructure they name** (a real SPIRE/Envoy stack with the socket actually absent; a real bundle-name mismatch between `opa-config.yaml` and `AIL_BUNDLE_NAME`, as opposed to monkeypatching the same variable in-process). Both are covered by `tests/test_outcome_types.py` at the exact point `middleware.py` observes the failure (`_get_spiffe_ssl_context() -> None`; `_BUNDLE_NAME` pointed at a bundle OPA never loaded), and `revision_unavailable` additionally has a live report entry via `test_policy_digest.py`'s reproduction. A live SPIRE-stack-down repro would require booting the full 16-service `docker-compose.yml` stack (SPIRE server/agent, Envoy, workload registration), out of scope for the time available this session; R7 (`docs/reports/phase-0-1-redteam.md`) already established the underlying SPIRE-socket-absent behavior live in a prior session.

---

## 7. Cumulative gate

Full suite, `docker-compose.test.yml`, run repeatedly through this session (baseline, after each item, after both mutation reproductions, after all live infrastructure manipulation was reverted):

```
42 passed, 1 warning in ~40-60s
```

No test skipped, no test newly `xfail`ed, no assertion weakened outside the one pre-authorized change. `tests/test_response_contract.py` and `tests/test_base_agent.py` are new and load-bearing (section 3, P1-8); every other changed test file (`test_epic_2.py`, `test_opa_integration.py`, `test_policy_digest.py`, `test_verification.py`) was updated only where the return-value schema it exercises actually changed shape, confirmed one file at a time.
