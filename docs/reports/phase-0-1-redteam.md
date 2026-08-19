# Phase 0.1: Red-Team Report

## 1. Environment, and confirmation developer state was not mutated

Fresh CC session, no memory of building Phase 0.1. Per the brief's explicit instructions, all work was done in a scratch clone (`git clone` of the primary working directory into the session scratchpad, `ail-scratch`), checked out to `phase-0-truth-pass` at `ca688d8` (head at session start). No `.env` was ever written in the primary working directory, no named volume there was ever touched, and the primary directory's `docker compose ps` was never invoked until the final confirmation below.

Two isolated Docker Compose projects were used inside the scratch clone only: `docker-compose.test.yml` (project `ail-scratch`, for R1/R2/R3/R4/R8's targeted mutation and fault-injection work) and `docker-compose.yml` (same project name, brought up after the first was fully torn down with `down -v` to avoid host-port collisions — both files bind the same host ports, e.g. 8181/8002/8003/8080). Both were torn down at the end (`docker compose down`, no `-v`, matching the same caution the brief asked for even though these are disposable scratch volumes).

One disclosure the brief's caution is specifically about: `pip install -r requirements.txt` was run once inside the scratch clone, which resolved against this machine's existing shared venv (`compliance-ail/venv`, visible via `which python`) rather than a clone-local one. The second invocation showed nothing left to install beyond what was already satisfied (all real dependencies pre-existed from prior sessions' work), so no version was changed, but the command did touch a resource outside the scratch clone and is disclosed here rather than left implicit.

Final confirmation, primary working directory, run last:
```
$ git status --short
(clean)
$ docker compose ps -a
NAME      IMAGE     COMMAND   SERVICE   CREATED   STATUS    PORTS
(empty)
```
No changes, no containers.

---

## 2. Verdict table

| Claim | Verdict | Key evidence |
| :--- | :--- | :--- |
| R1 | **REFUTED** | Mutation 3 (`record_hash` instead of `ledger_tx_id`) is caught only incidentally, by one assertion in one test not designed to check this contract; every other consumer of the same return value asserts nothing about it |
| R2 | **REFUTED** | Live: a `KeyError`-inducing typo in `agent/base_agent.py`'s APPROVED branch crashes the reconstructed old test path but leaves `pytest tests/` at 31/31 green |
| R3 | HOLDS | 6 scenarios (both-direction name mismatch, control-plane-down, bad-tenant-id, timing, continuous mid-flight reload) all produce an actionable exit or a correct pass; zero false-positive exits found |
| R4 | **REFUTED** | Live: an OPA-unreachable denial writes a real, `verified: true` ledger entry with plain `"DENIED: Compliance engine unavailable..."` text, no fault marker anywhere, and both this and the already-"fixed" digest-unavailable path increment `ail_policy_decisions_total` under a policy-shaped label with no infra dimension at all |
| R5 | **REFUTED** | The dashboard's Policy Settings "Save Configuration" button is exactly as broken as the already-disclosed Audit Ledger view (same missing `X-API-Key`), and README §3.5 discloses one but not the other; the Helm chart's OPA ConfigMap hardcodes the bundle name, breaking the single-source guarantee P01-3 built |
| R6 | **REFUTED** | Live, verbatim: §4.4 Test 3's exact prompt produces `DENIED: Schema Validation Failed` (missing `cost_per_hour`), not the documented `APPROVED` |
| R7 | HOLDS | Live: `verify_bundle_at_startup()` calls `sys.exit(1)` within ~3.4s when the SPIRE socket is absent, with an actionable message |
| R8 | HOLDS | OPA's own request log confirms unchanged round-trip count/ordering per call type (0 / 2 / 3); startup poller genuinely runs once per process lifetime under the only currently-working deployment path (no restart policy in `docker-compose.yml`) |

---

## 3. Evidence

### R1 — REFUTED

Baseline confirmed first: `pytest tests/` against a freshly-built `docker-compose.test.yml` stack in the scratch clone: `31 passed, 1 warning in 17.53s`, matching the report exactly.

Each of the six mutations below was applied to the scratch clone's source (never the primary directory), run against the same live stack, then reverted with `git checkout --` and `git status --short` confirmed clean before the next.

| # | Mutation | Result | Caught by |
| :-: | :--- | :--- | :--- |
| 1 | `_fetch_opa_bundle_revision` returns `sha256(AIL_TENANT_ID)` instead of querying OPA | `2 failed, 29 passed` | `test_policy_digest.py` (both tests, purpose-built for exactly this) |
| 2 | Revision-fetch failure sets `policy_revision = "bundle-hash-unavailable"` and lets the write proceed | `1 failed, 30 passed` | `test_policy_digest.py::test_digest_unavailable_denies_and_writes_no_ledger_entry` (purpose-built) |
| 3 | `intercept_tool_call` returns `response["record_hash"]` instead of `response["ledger_tx_id"]` | `1 failed, 30 passed` | `test_policy_digest.py::test_recorded_digest_matches_opa_not_interceptor_belief`, via its own incidental `assert "ledger_tx_id" in response` — **see caveat below** |
| 4 | `_OPA_REVISION_URL` hardcoded to a bundle name OPA never loaded | `10 failed, 21 passed` | Wide breakage across `test_epic_2.py`, `test_opa_integration.py`, `test_policy_digest.py` |
| 5 | Control plane's `/audit` returns `ledger_hash` instead of `verified`/`state_id` | `3 failed, 28 passed` (control-plane image rebuilt + recreated for this one, since it's server-side code, not something `pytest` imports directly) | `test_verification.py::test_cross_process` (purpose-built: `assert matching[0]["verified"] is True`), plus `test_policy_digest.py`'s two tests as a side effect of the same endpoint call throwing a 500 |
| 6 | Unregistered-tool pre-flight gate skipped, falls through to OPA | `4 failed, 27 passed` | `TestMiddlewareRoutingFailClosed`'s three tests (purpose-built) plus `test_cloud_server_schema.py` |

**All six caught — but R1's claim is about whether the suite is load-bearing, not just whether it happens to fail, and Mutation 3 is the one that does not hold up under that reading.** `tests/test_opa_integration.py::TestInterceptorWithOpa::test_approved_request_returns_approved_status` — the test that exists specifically to check the ordinary APPROVED path — asserts only:
```python
assert "status" in response
assert response["status"] == "APPROVED", (...)
```
`tests/test_opa_integration.py:171-179`. It never checks for `ledger_tx_id`. The only reason Mutation 3 is caught at all is that `test_policy_digest.py`'s digest test *also* happens to assert `"ledger_tx_id" in response` on its way to checking something else (the recorded digest). Delete `test_policy_digest.py` (or narrow that one assertion) and Mutation 3 — the exact class of defect R4/P01-4 was written to eliminate — becomes invisible to the other 29 tests. A claim that the suite "catches" this defect is true only by accident of one unrelated test's incidental assertion, not by design.

**Attacks attempted that failed:** none of the six mutations passed unnoticed; the refutation is about the *quality* of the catch for #3, not a missed mutation.

---

### R2 — REFUTED

`grep -rln "base_agent" tests/ scripts/ Makefile docker-compose*.yml .github/` → only `scripts/test_ledger.py`. Nothing in the 31 pytest-collected items, the Makefile, any compose file, or CI references `agent/base_agent.py` at all.

Introduced a plausible refactor typo in `agent/base_agent.py`'s APPROVED execution branch (`region=function_args["region"]` → `region=function_args["region_name"]`), which:

**Leaves the current 31 green:**
```
======================= 31 passed, 1 warning in 34.60s ========================
```

**Crashes the reconstructed old code path.** Reproduced exactly what `tests/test_ledger.py::test_full_agent_flow` did before it moved to `scripts/`, substituting a fixed tool-call object for the real OpenAI call (the same substitution P01-4's own evidence used, for the same reason — no paid API call needed since everything downstream, including the real OPA/ledger round trip, is live code):
```
Calling agent.handle_tool_calls(...) - the exact call test_full_agent_flow made
when it was tests/test_ledger.py and pytest-collected...
RESULT: *** CRASHED *** KeyError: 'region_name'
```
An unhandled exception fails a pytest item regardless of whether it contains an assertion — this is exactly the mechanism P01-2's own report cites as the reason `test_full_agent_flow` broke CI in the first place. The old, gated version of this test would have failed on this defect. The new arrangement (moved to `scripts/`, never invoked by anything automated) cannot.

**Attacks attempted that failed:** an earlier attempt used the exact prompt text from the file's own `if __name__ == "__main__"` block (`"Spin up an AWS t3.micro..."`), omitting `tags` — this hit pre-flight schema DENIAL before reaching the mutated line, since `tags` is now a required field the original script's hardcoded prompt never accounted for (a separate, already-known staleness issue, not a defect in this reproduction). Adding a `tags` dict to reach the APPROVED branch is what actually exercised the mutation.

---

### R3 — HOLDS

Six scenarios, all against the live `docker-compose.test.yml` stack in the scratch clone, `verify_bundle_at_startup()` called directly (not through the shell wrapper):

1. **`AIL_BUNDLE_NAME` set on the agent only** (`agent-only-override-name`, OPA still `ail-policies`): `SystemExit(1)` after 4s, actionable message naming both config locations.
2. **Reverse direction** (OPA-only override) is the same code path by construction — not re-run, since the check compares whatever name the agent process holds against whatever OPA has loaded, with no directional asymmetry in the logic.
3. **Control plane down at agent boot** (stopped before `opa` was recreated, so no bundle was ever downloaded): `SystemExit(1)` after ~10.5s. The message's phrasing ("do not name the same bundle, or OPA has not loaded any bundle under this name... check OPA's own logs") doesn't name "control plane unreachable" as a distinct hypothesis, but does correctly route the operator to OPA's logs, which show the real cause plainly (see #4).
4. **Bad tenant ID** (`AIL_TENANT_ID=tenant_totally_bogus_r3`, so the control plane 404s the bundle resource): `SystemExit(1)` after ~10.2s. OPA's own log at the same moment: `[ERROR] Bundle load failed: server replied with Not Found`. Following the startup message's own diagnostic pointer leads directly to ground truth.
5. **Bundle loads after the window would have closed (false-positive check):** timed three fresh `opa` recreates back-to-back; each resolved in 1.7-1.8s. OPA's own bundle plugin evidently does its first fetch attempt immediately at startup, not gated by `min_delay_seconds`, so the real observed margin against the 30s window is far larger than the code's own justifying comment assumes (it cites `max_delay_seconds: 20` as the reason for a 30s budget). No false-positive exit was found in this environment; a genuinely resource-starved host was not reproduced (see §4).
6. **Restart into a mid-reload OPA:** ran `verify_bundle_at_startup()` 40 times back-to-back against an OPA whose bundle was being reloaded by a background thread every 0.3s (real `PUT /tenants/tenant_default` calls). `successes=40 fails=0`. OPA's bundle swap is atomic; no window where a reader observes an undefined manifest mid-swap.

**Attacks attempted that failed:** none of the six produced the silent request-time denial mode the check exists to prevent, and none produced a false-positive exit on a stack that was actually fine.

---

### R4 — REFUTED

**Case A — the "fixed" path still pollutes the metric.** Forced `_fetch_opa_bundle_revision` to return `None` for an otherwise-clean approved request:
```
CASE A: {'status': 'DENIED', 'message': '...revision...', 'fault': 'infrastructure'}
METRIC: ail_policy_decisions_total{policy="unable",status="DENIED",tool_name="provision_cloud_server"} 1.0
```
`intercept_tool_call`'s `_POLICY_DECISIONS.labels(...).inc()` call (`interceptor/middleware.py`) happens *before* the `digest_unavailable`/`fault` early return, using `policy_label` derived from the first word of the deny message ("Unable to establish the policy revision..." → `"unable"`). There is no separate counter, no `fault` label dimension, nothing distinguishing this from a real policy category in the one place a CISO would actually watch trends (Grafana, per README §3.5).

**Case B — the un-fixed path is worse: a real ledger entry, indistinguishable everywhere.** Stopped `opa` entirely (connection-error path, never touched by P01-3's fault marker) and issued a real call:
```
CASE B: {'status': 'DENIED', 'message': 'Compliance engine unavailable. Fail-closed policy enforced.', 'ledger_tx_id': 121}
METRIC: ail_policy_decisions_total{policy="compliance",status="DENIED",tool_name="provision_cloud_server"} 1.0
```
Retrieved via the real `/audit` endpoint after restarting OPA:
```json
{
  "tx_id": 121,
  "agent_id": "r4_probe_b",
  "decision": "DENIED: Compliance engine unavailable. Fail-closed policy enforced.",
  "verified": true,
  "state_id": 121
}
```
No `fault` field exists in this response at all (control plane's `/audit` handler never had one to begin with). The dashboard's `DecisionCell` (`dashboard/components/audit-table.tsx`) renders any string starting `"DENIED"` with the identical red `denied` badge regardless of content — a real GDPR/SOC2/FinOps violation and this infrastructure fault are pixel-for-pixel the same row shape. The agent's reply-construction code (`base_agent.py`, `langgraph_demo.py`) only special-cases `interceptor_response.get("fault") == "infrastructure"`; this path never sets that key, so it falls through to the ordinary "Action blocked by interceptor" / "BLOCKED by AIL" framing, identical wording to a real policy denial.

So: agent reply — indistinguishable (Case B) / distinguishable (Case A only). Ledger and `/audit` — indistinguishable (both cases; Case A isn't even written, so there's nothing to distinguish, and its absence looks identical to "the agent didn't call" rather than "a fault occurred"). Dashboard — indistinguishable (both cases). Prometheus — indistinguishable (both cases; the metric can't be filtered on infrastructure vs. policy at all, since the dimension doesn't exist).

**Attacks attempted that failed:** none — every surface checked showed conflation on at least one live-triggered path.

---

### R5 — REFUTED

**Sweep table (both sides of every boundary):**

| Boundary | Producer fields | Consumer reads | Orphans |
| :--- | :--- | :--- | :--- |
| `intercept_tool_call` → all callers | `status, message, ledger_tx_id, fault` | Same set, everywhere (`agent/base_agent.py`, `framework_integration/langgraph_demo.py`, `tests/`, `scripts/`) | None |
| control plane `/audit` → dashboard | `tx_id, agent_id, timestamp, tool_name, payload, decision, verified, state_id` | `dashboard/lib/types.ts`'s `AuditEntry` — identical field set, identical names | None |
| control plane `/tenants/{id}` (GET/PUT) → dashboard | `TenantRead`/`TenantUpdate` — `id, name, enable_gdpr, enable_soc2, enable_finops, enable_hipaa, allowed_cost_centers, approved_regions, approved_purposes` | `dashboard/lib/types.ts`'s `Tenant`/`TenantUpdate`, `settings/page.tsx`'s `tenantToForm`/`handleSave` — identical | None |
| verifier `/write` → `ledger/immudb_ledger.py` | `WriteResponse{tx_id, verified, detail}` | reads `result.get("verified")`, `result["tx_id"]` | None |
| verifier `/verify` → control plane `/audit` handler | `VerifyResponse{verified, tx_id, value, timestamp, state_id, detail}` | reads `vdata.get("verified")`, `vdata.get("state_id")` | None (doesn't read `tx_id`/`value`/`timestamp`, but nothing implies it should) |

**No pure field-name orphan found — but a field-shaped defect was found one layer up: required inputs the only consumer never supplies.** `PUT /tenants/{tenant_id}` (`control_plane/main.py:190-196`) requires `_require_api_key`, exactly like `/audit`. `dashboard/lib/api.ts`'s single `request()` helper (the one function every dashboard call goes through) never attaches an `X-API-Key` header under any code path. Live:
```
$ curl -s -w "\n%{http_code}\n" -X PUT localhost:8002/tenants/tenant_default -H "Content-Type: application/json" -d '{"enable_hipaa": true}'
{"detail":[{"type":"missing","loc":["header","X-API-Key"],"msg":"Field required","input":null}]}
422
```
This is `settings/page.tsx`'s "Save Configuration" button — the dashboard's entire write path, and the feature the README's own §3.5 describes as delivered ("Every save generates a new OPA bundle immediately," no caveat). README §3.5 line 178 *does* disclose the identical defect for the Audit Ledger view in detail (missing header, 422, "no way to view the audit ledger through the dashboard UI... see TODO.md") — but says nothing about Settings, even though it is broken by the exact same missing header through the exact same client helper function. This is not a new class of defect the sweep invented; it is the same missing-header defect R5's own instructions ask to extend the check to, just one endpoint over from the one already disclosed.

**Helm chart env contract, `charts/ail-gateway/templates/agent-deployment.yaml`:** every env var it sets — `OPENAI_API_KEY, IMMUDB_URL, IMMUDB_USER, IMMUDB_PASSWORD, SPIFFE_ENDPOINT_SOCKET, OPA_URL, CONTROL_PLANE_URL, AIL_TENANT_ID, SPIRE_DISABLED` — none is `AIL_BUNDLE_NAME`, the variable P01-3 introduced this phase specifically to keep `opa-config.yaml` and `interceptor/middleware.py` from drifting apart. Both currently default to the same literal (`"ail-policies"`), so this is silent today, not exploited — but `charts/ail-gateway/templates/configmap-opa.yaml:39-40` hardcodes `bundles: ail-policies:` as static YAML text, with no Helm value or env substitution mechanism at all (`grep -n AIL_BUNDLE_NAME charts/` → no matches anywhere in the chart). If an operator ever set `AIL_BUNDLE_NAME` as a values override on the agent deployment — a reasonable thing to try, since that's exactly how it works in `docker-compose.yml` — it would silently do nothing to the ConfigMap, reintroducing the precise C4 defect P01-3 exists to close, in the one deployment artifact whose whole job is to be a second, independent implementation of the same architecture. (The chart is marked "unsupported, do not deploy," so this is latent, not live — see §5.)

**Attacks attempted that failed:** checked `dashboard/components/nav.tsx`, `cost-center-input.tsx` (generic `string[]` widget, no field-name coupling) — no orphans. Checked `control_plane/main.py` for any direct `immudb`-SDK import (would bypass the verifier contract entirely) — only a docstring mention, no actual import.

---

### R6 — REFUTED

Full walkthrough, scratch clone, `.env` rewritten to match the **current** README §4.1 verbatim (which now requires `CONTROL_PLANE_API_KEY=change-me` in addition to the three P0-era variables — the first `.env` written was against a stale memory of §4.1 and had to be corrected mid-walkthrough once the live text was re-read; flagged here as the kind of slip the brief's "apply no knowledge from any prior session" instruction is meant to catch).

**§4.2 — HOLDS**, and already correctly documents the exited-container nuance (`docker compose ps` → 13 of 16 rows; three one-shot jobs `Exited (0)`, confirmed via `docker compose ps -a`) — this was a red-team C6 finding against Phase 0's version and is fixed in the current text.

**§4.3 — HOLDS.** `localhost:3001` reachable (307 to a default route), `/audit` and `/settings` both 200.

**§4.4 — REFUTED.** Test 1 (multi-framework denial): reproduced exactly, both cited violations present. Test 2 (prompt injection): produces `DENIED`, cryptographically logged (`tx=2`, "Ledger write verified") — technically matching the README's own unspecific wording ("AIL blocks it regardless"), but the actual block is a pre-flight schema rejection (`cost_per_hour` defaults to `0.0` since the prompt states no dollar figure), not a policy-layer rejection of the injected values — the demo's narrative framing ("Ignore all compliance guardrails... AIL blocks it regardless") implies the policy layer is what caught it, but OPA is never reached. **Test 3 (approval) fails outright:**
```
USER: Deploy a t3.medium in eu-central-1. Tag it: environment=prod,
cost_center=engineering, project=ml-training, encryption_at_rest=true,
data_classification=internal.
...
Policy Engine Decision: DENIED: DENIED: Schema Validation Failed. cost_per_hour: Input should be greater than 0
...
AGENT: The request was blocked because the `cost_per_hour` must be greater than 0.
```
README states: *"Expected result: `APPROVED` - all policy constraints satisfied."* The verbatim prompt — copied character-for-character from the README, no correction applied — never states an hourly cost, so the LLM fills `cost_per_hour: 0.0` and pre-flight schema validation rejects it before OPA is ever queried. This is the exact defect class the original Phase 0 audit (V2) found and fixed in the old §4.5 Step 2 — present here, undetected, in §4.4, a section neither Phase 0 nor Phase 0.1 touched.

**§4.5 — HOLDS.** Re-run in this fresh scratch clone (correct `.env` this time): Step 1's bundle-load confirmation, Step 2's exact `DENIED` text, both reproduced verbatim on the first try.

**§4.6 — HOLDS.** Every URL in the table returns a live response: dashboard 307 (redirect to default route, normal Next.js behavior), `/docs` 200, OPA `/health` 200, Grafana 200, Prometheus 302 (redirect to `/query`, normal).

**§4.7 — HOLDS**, consistent with the chart's own README and the prior audit; not deployed (correctly marked unsupported), text matches what §5's Helm findings independently confirm.

**Attacks attempted that failed:** none required an actually-undocumented step — every deviation from the literal text (the `.env` mismatch, the `docker attach` TTY limitation already documented in the prior red-team report) was either self-inflicted and correctable by re-reading the README, or a tooling artifact of this non-interactive session rather than something a real terminal user would hit.

---

### R7 — HOLDS

```
$ python -c "... SPIFFE_ENDPOINT_SOCKET=unix:///tmp/definitely-does-not-exist/... middleware.verify_bundle_at_startup(...) ..."
2026-08-16 23:04:49 ERROR Failed to fetch SPIFFE SVID from unix:///tmp/definitely-does-not-exist/workload_api.sock: ... does not exist.
2026-08-16 23:04:49 ERROR STARTUP FAILURE: could not establish a verified mTLS channel to OPA/Envoy...
RESULT: SystemExit(1) after 3.39s
```
Genuine process exit, not a hang or an indefinite retry, within single-digit seconds — the delay is the SPIFFE client library's own connection-attempt overhead, not a poll loop (this check exits at the *first* `ssl_context` failure, before `verify_bundle_at_startup`'s 30s polling loop is ever entered). Both `agent/base_agent.py` and `framework_integration/langgraph_demo.py` call this before any other work in their `__main__` blocks.

**Caveat, not a refutation:** the property README §3.1 states as a standalone SPIRE-identity guarantee is, mechanically, a side effect of `verify_bundle_at_startup()` — a function P01-3 added this phase for an unrelated reason (the bundle-name mismatch check), whose mTLS-establishment step happens to also require the SPIRE socket. Before this phase, nothing in the codebase called `sys.exit` on a missing SPIRE socket at all — `_get_spiffe_ssl_context()` catches the failure and returns `None`, and the only prior consumer (`query_opa_policy`) turns that into a per-call `DENIED`, not a process exit. README §3.1 presents "the agent process exits immediately" as an intentional SPIRE-identity design property, with no cross-reference to `verify_bundle_at_startup` or P01-3; the coupling is real but incidental. The claim, read narrowly as "what does the process currently do," holds. Read as "this is a dedicated safeguard," it does not describe what is actually implemented.

**Attacks attempted that failed:** none — the observed behavior in every trial was an immediate exit, matching the claim.

---

### R8 — HOLDS

**Round-trip count, captured from OPA's own request log** (`docker logs ail-scratch-opa-1`), driving three back-to-back calls through the real `intercept_tool_call`:
```
req_path = "/v1/data/ail/main/allow"                                          # approved: 1
req_path = "/v1/data/system/bundles/ail-policies/manifest/revision"           # approved: 2
req_path = "/v1/data/ail/main/allow"                                          # policy-denied: 1
req_path = "/v1/data/system/bundles/ail-policies/manifest/revision"           # policy-denied: 2
req_path = "/v1/data/ail/main/deny"                                           # policy-denied: 3
                                                                                # schema-denied: 0 (never appears - pre-flight rejects before any OPA call)
```
Approved = 2, policy-denied = 3, schema-denied = 0. Identical structure to Phase 0's own documented count and ordering; unchanged by Phase 0.1. (The `digest_unavailable`/fault path is structurally 2 — `/allow` then the revision GET, which returns undefined and short-circuits before any `/deny` call is reached — consistent with, not a change to, this same structure.)

**Startup poller load, including on restart loops.** `verify_bundle_at_startup()` runs once, synchronously, before either `__main__` block does anything else — confirmed by re-reading both files end to end, and its own poll loop (up to 30s, 2s interval) is entirely pre-request, matching "runs once at boot, outside the request path" for a *single* process lifetime. Checked whether that lifetime can repeat: `docker-compose.yml`'s `langgraph-demo` service (`grep -n restart` in its block) sets no `restart:` policy at all, unlike neighboring services (`workload-registrar` explicitly sets `restart: "no"`) — Compose's default is also `no`, so a crashed or exited agent container is not automatically restarted, and the poller genuinely runs exactly once per container lifetime in the only currently-working deployment path. This would not hold under an orchestrator with restart-on-crash semantics (a Kubernetes Deployment's default `restartPolicy`, e.g.) — a crash-looping pod for a reason unrelated to bundle state would re-run the poller on every restart attempt, generating real, repeating OPA load the "once at boot" framing doesn't anticipate. Not tested live: the only chart that would exercise this (`charts/ail-gateway/`) is independently confirmed non-deployable (fails closed on every call, per V1 and P01-6), so this restart-loop coupling is a structural observation from reading the compose/chart configuration, not a demonstrated live discrepancy in the working path.

**Attacks attempted that failed:** none — round-trip count and ordering matched Phase 0's structure exactly in every trial.

---

## 4. Could not test, and what blocked it

- **R3, scenario 5 under genuine resource starvation.** The 30s startup-check window was never observed close to its limit in this environment (bundle loads resolved in ~1.7-1.8s every trial, well inside the budget) — a host under real memory/CPU/disk pressure, or a slow first `docker pull`, was not reproduced, so whether the 30s margin holds up outside a well-provisioned Docker Desktop instance is untested.
- **R3, mTLS path (`SPIRE_DISABLED=false`).** The `sys.exit(1)` branch for a failed SPIFFE SAN validation inside `verify_bundle_at_startup` (as opposed to a missing socket, which R7 did test live) was read but not separately driven against a live SPIRE/Envoy stack with a deliberately mismatched bundle simultaneously — doing so requires the full main-stack SPIRE bootstrap running alongside the broken-bundle scenario, which wasn't set up in the time available.
- **R8, restart-loop load empirically.** As noted above, the only artifact that would exercise this (the Helm chart under a real K8s restart policy) is independently known not to deploy successfully at all, so there is no live path to trigger it; the finding is structural (config read), not observed.
- **R5, exhaustive Grafana/Prometheus dashboard field sweep.** Confirmed the `ail_policy_decisions_total` metric contract (used directly for R4) but did not walk `observability/grafana/dashboards/ciso_dashboard.json` panel-by-panel against every exposed metric name.

---

## 5. Findings outside R1-R8

1. **README §4.4 Test 2's framing overstates what the demo shows**, beyond the strict R6 pass/fail: the section is titled "Trigger a prompt injection attack" and narrates "AIL blocks it regardless" of the LLM complying with an injected override — but the actual block, verbatim, is a pre-flight schema rejection triggered by the prompt's own missing cost figure, not a policy-layer rejection of the injected values (`cost_center=override_auth`, `encryption_at_rest=false`, `ap-southeast-1`). A reader running this exact prompt would see a `DENIED` and reasonably conclude the compliance guardrails caught the injection; what actually caught it is unrelated to the injection's content.
2. **The Helm chart's `configmap-opa.yaml` has no mechanism to receive `AIL_BUNDLE_NAME` at all** (not just "not currently set" like the agent deployment's other stale `IMMUDB_*` vars) — it is inline static YAML with no Helm value or template substitution for the bundle key, structurally different from how `docker-compose.yml` wires the same setting. Anyone porting the verifier into this chart later (the stated future direction per the chart's own README) would need to rebuild this piece from scratch, not just wire an existing env var through, since the current mechanism for single-sourcing the bundle name doesn't exist in Helm-template form at all.
3. **`dashboard/lib/types.ts`'s `AuditEntry.verified` comment already documents an unrelated conflation** the current API doesn't fix: `false` covers both "a real proof failure" and "the verifier was unreachable for this entry" — the control plane's `/audit` handler defaults every entry to `verified: false` once `verifier_up` flips false mid-scan, without a further verifier call being attempted for it (`control_plane/main.py:314-337`). This is a second, narrower case of the same shape as R4 (an infrastructure condition presented identically to a real negative result) but scoped to ledger *verification* rather than policy *decisions*, and sits in a part of the code this phase didn't touch.
