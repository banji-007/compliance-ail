# Phase 1: Red-Team Report

## 1. Environment, actual head SHA, developer-state confirmation

**Discrepancy noted per the brief.** `docs/reports/phase-1.md` states end SHA `3e86a9b` with the report as "a subsequent commit on the same branch." The actual pushed head of `phase-1-record-truth` at session start was `96d14d7` (`docs(reports): add Phase 1 report`), one commit past `3e86a9b` (`fix(interceptor,ledger,control-plane,dashboard): Phase 1 truth pass...`). This matches the handoff summary, not the build report's own "end SHA" line taken alone — the report's line is accurate about where the *code* lands, just not the branch's actual tip once the report itself was committed. **Audited head: `96d14d7`.**

Fresh CC session, no memory of building Phase 1. Per the brief, all work was done in a scratch clone (`git clone` into the session scratchpad, checked out to `phase-1-record-truth` at `96d14d7`). No `.env` was written in the primary working directory; no named volume there was touched. The primary directory's own `docker compose ps` was confirmed empty and `git status` clean both before starting and at the end.

**A real cost of scratch-clone reuse, disclosed:** this session's scratch clone used the same directory basename (`ail-scratch`) as the Phase 0.1 red-team session's clone, which Docker Compose uses to derive image tags. The first `docker compose -f docker-compose.test.yml up -d --wait` (without `--build`) silently reused Phase 0.1's cached `ail-scratch-ail-control-plane`/`ail-scratch-verifier` images rather than building Phase 1's actual code — `/audit` returned the *old* `decision`/`verified` shape and `/content` 404'd. This was caught immediately (the shape was obviously wrong) and fixed with `docker compose build --no-cache`; every result in this report is against the rebuilt images, confirmed by `/content` returning 204 and `/audit` returning the new schema before any claim was tested. Flagged here because it is exactly the class of trap every prior phase report has separately rediscovered, and scratch-clone directory-name collision is a new variant of it worth naming for future sessions.

**CI never ran against this branch.** `gh run list` shows no "Integration Tests" run for `phase-1-record-truth` at all — the workflow triggers on `push: branches: [main]` and on `pull_request`, and this branch was neither pushed to `main` nor opened as a PR. This isn't one of S1-S9, but it means the review-protocol's own expectation ("work is committed to a branch and pushed before step 4, so CI runs") was not met for this phase; the "42 passed" result is local-only, confirmed nowhere else. Noted in §5.

---

## 2. Verdict table

| Claim | Verdict | Key evidence |
| :--- | :--- | :--- |
| S1 | **REFUTED** | 5 of 7 named mutations leave `pytest tests/` fully green (42/42): a self-asserted `verified` field in the ledger, a message-derived metric label, raw arguments written into the immutable ledger, `DELETE /content` with auth removed, and a reintroduced second OPA round trip. Only 2 of 7 are caught, both by `test_outcome_types.py`. |
| S2 | **REFUTED** | Live: a two-bundle OPA config produces `{"allow": false, "reasons": [the real "ail-policies" FinOps denial], "revision": "DECOY-REVISION-1234-NOT-AIL-POLICIES"}` — verdict from one bundle, revision from another, in a single query |
| S3 | **REFUTED** | Live: non-dict `tool_args` (a JSON list/string/null/int the LLM can emit as `arguments`) crashes `intercept_tool_call` with an uncaught `AttributeError` before any classification — no record, not even a fault. Separately: OPA 200 with `revision` missing from an otherwise-normal body produces `outcome_type: policy_allow, policy_revision: None`, violating the ADR-0005 table's own "policy_allow always carries a set revision" |
| S4 | **REFUTED** | Live: an erased entry and a never-stored entry (content store down at write time) are byte-for-byte identical in `/audit` except for their own inputs — both `payload: null`, nothing else differs |
| S5 | **REFUTED** | Live: an approved call executes and gets a real `ledger_tx_id` while the content store is down; the response and every later `/audit` read carry no signal that the argument detail is gone rather than erased |
| S6 | **REFUTED** | Live: an anonymous `curl` with zero headers reads the full audit log (including other agents' raw payloads) and mutates tenant policy (`enable_hipaa`) through the dashboard's own `/api/*` routes — the credential never reaches the browser, but the dashboard is an unauthenticated open relay to everything the credential protects |
| S7 | **REFUTED** | Live: 500 distinct caller-supplied `tool_name` values produce exactly 500 distinct `ail_policy_decisions_total` time series — unbounded by construction |
| S8 | **REFUTED** | Live: `/verify` on a key that was never written (no tampering involved) returns `verified: false, error_class: "unknown"` at HTTP 200, which the control plane promotes to `state: "failed"` — the tamper signal — for a condition that is not tampering |
| S9 | HOLDS | Diffed every changed test file against its pre-Phase-1 form; all changes are same-or-stronger field renames plus the one D1-authorized reversal; no third weakening found |

---

## 3. Evidence

### S1 — REFUTED

Baseline (after the stale-image correction in §1): `42 passed, 1 warning in 23.76s`.

Each mutation applied to the scratch clone alone, `pytest tests/` run, reverted with `git checkout --`, `git status --short` confirmed clean before the next. Two required a container rebuild (server-side code); the rest run in-process with `pytest` since `interceptor/`, `ledger/` are imported directly.

| # | Mutation | Result | Caught by |
| :-: | :--- | :--- | :--- |
| 1 | `schema_deny` returns a placeholder `policy_revision` instead of `null` | `2 failed, 40 passed` | `test_outcome_types.py::test_schema_deny_unregistered_tool` and `::test_schema_deny_invalid_payload` (purpose-built) |
| 2 | `ledger/immudb_ledger.py`'s `log_entry` gains `"verified": True` — a ledger entry asserting its own verification status, the thing D2 forbids | **42 passed — uncaught** | *(none)* |
| 3 | Metric label reshaped from deny-message text (`outcome_type` becomes `"policy_deny:<first-word-of-reason>"`, restoring pre-D3 behavior) | **42 passed — uncaught** | *(none)* |
| 4 | Raw `tool_args` written into the immutable ledger entry alongside `input_sha256` (defeats D5 erasability at the source) | **42 passed — uncaught** | *(none)* |
| 5 | An `opa_unreachable` fault (`httpx.ConnectError`) recorded as `outcome_type: policy_deny` instead of `fault` | `1 failed, 41 passed` | `test_outcome_types.py::test_fault_opa_unreachable` (purpose-built) |
| 6 | `DELETE /content/{tx_id}` with `_require_api_key` removed — control-plane rebuilt+recreated for this one | **42 passed — uncaught** | *(none)* |
| 7 | A second OPA round trip reintroduced for deny reasons (a real extra `httpx` POST after the combined `/evaluation` call decides `policy_deny`) | **42 passed — uncaught** | *(none)* |

**5 of the 7 named mutations are completely invisible to the 42-item suite** — not "caught incidentally," genuinely uncaught, confirmed by an unchanged `42 passed`. Every root cause is structural, not a coverage gap that happened to be missed:
- **#2, #4**: nothing in the suite ever inspects the *raw stored ImmuDB value* for the absence of extra keys — `/audit`'s handler only reads the keys it expects (`log_entry.get("outcome_type")` etc.) and silently ignores anything else present, so an extra field is invisible everywhere a test could observe it.
- **#3**: no test asserts on the metric label *set* at all — P1-4's own live evidence (report §3, P1-4) is the only place this was ever checked, and it was checked by hand, once, not by an automated test.
- **#6**: no test exercises `DELETE /content/{tx_id}` at all — P1-5's own evidence (report §3) drives it once, live, by hand; there is no `test_content_store.py` or equivalent.
- **#7**: no test counts OPA requests. P1-1's "exactly one OPA request per intercepted call" claim (report §3) is demonstrated live, by hand, via a container log diff — not gated by anything that runs in CI.

**Attacks attempted that failed:** none of the seven mutations was rejected as inapplicable; all seven ran cleanly to a pytest result. The "attack" that failed, in the sense the brief means it, is the two that *were* caught (#1, #5) — both were caught, cleanly, by tests written for exactly that purpose, which is the one place S1's claim holds up.

---

### S2 — REFUTED

Structural read: `policy/core/main.rego`'s `evaluation` rule computes `allow`/`reasons` from `data.ail.frameworks.*.deny` (unscoped — whatever is currently loaded under the `ail` root, from *any* bundle that claims it) but reads `revision` from `data.system.bundles[input.bundle_name].manifest.revision` — a lookup keyed entirely by a string the *interceptor* supplies (`_BUNDLE_NAME`, a fixed env var) with no structural link to which bundle's Rego actually produced `allow`/`reasons`.

**Attack — configure OPA with two bundles claiming non-overlapping roots** (`ail-policies`, the real one; a second, minimal `decoy-bundle` claiming only root `decoy`, served by a throwaway static file server added to the scratch clone's compose file, manifest `{"revision": "DECOY-REVISION-1234-NOT-AIL-POLICIES", "roots": ["decoy"]}`). Both loaded successfully (OPA raises no conflict since the roots don't overlap):
```
$ curl -s localhost:8181/v1/data/system/bundles
{"ail-policies": {"manifest": {"revision": "1134a274...", "roots": ["ail"]}},
 "decoy-bundle":  {"manifest": {"revision": "DECOY-REVISION-1234-NOT-AIL-POLICIES", "roots": ["decoy"]}}}
```
Queried `/v1/data/ail/main/evaluation` with a real policy-relevant payload (a restricted instance type, denied by the FinOps pack — content that exists *only* in `ail-policies`) but `input.bundle_name` pointed at the decoy:
```
$ curl -s -X POST http://localhost:8181/v1/data/ail/main/evaluation -d '{"input":{"tool_name":"provision_cloud_server","tool_args":{...p4d.24xlarge, project=webapp...},"bundle_name":"decoy-bundle"}}'
{"result":{
  "allow": false,
  "reasons": ["DENIED: Instance type p4d.24xlarge is restricted. 'project' tag must be 'ml-training'."],
  "revision": "DECOY-REVISION-1234-NOT-AIL-POLICIES"
}}
```
The deny reason is real and correct — it can only have come from `ail-policies`' FinOps rule, since that text exists nowhere else. The reported revision names a bundle that contains no policy rules at all. Reproduced identically for an `allow: true` case. A sanity check with `bundle_name: "ail-policies"` against the same request correctly reports `1134a274...` — confirming the mechanism works correctly when the name happens to be right, and silently doesn't when it doesn't.

This does not require a second attacker-controlled request field — `_BUNDLE_NAME` is fixed server-side in the single-bundle deployment today, so this is not externally triggerable *right now*. What it demonstrates is that the architecture provides no binding between "the bundle whose rules decided" and "the bundle whose revision was reported" beyond the operational assumption that exactly one bundle ever owns the `ail` root — an assumption nothing in the code enforces, checks, or would notice violating.

**Attacks attempted that failed:** the single-round-trip design change (P1-1) does close the *timing* half of the original Phase 0 C2 race — revision and verdict now come from literally the same HTTP response object, so there is no window between two separate requests for a reload to land in. That specific sub-question holds; it just isn't the whole claim.

---

### S3 — REFUTED

**Attack 1 — non-dict `tool_args`.** An LLM emitting `"arguments": "[]"`, `"null"`, a bare string, or a number for a tool call's arguments is valid JSON that `json.loads` parses without error into something that isn't a `dict` — nothing before `intercept_tool_call` guarantees the shape.
```python
for bad_args in ([], None, 'not-a-dict', 42):
    middleware.intercept_tool_call('provision_cloud_server', bad_args, 'probe')
```
```
*** UNCAUGHT EXCEPTION: AttributeError: 'list' object has no attribute 'items'
*** UNCAUGHT EXCEPTION: AttributeError: 'NoneType' object has no attribute 'items'
*** UNCAUGHT EXCEPTION: AttributeError: 'str' object has no attribute 'items'
*** UNCAUGHT EXCEPTION: AttributeError: 'int' object has no attribute 'items'
```
The crash is in `_redact_args`, the very first thing `intercept_tool_call` does (`for k, v in args.items()`), before schema validation, before OPA, before the ledger. **No `outcome_type` is ever assigned. No record — durable or otherwise — is created.** `agent/base_agent.py::handle_tool_calls` has no try/except around this call either; in the full agent loop this propagates to `chat_loop`'s outermost `except Exception as e: print(f"\nError: {e}")`, so the entire interaction — including what the user asked for — vanishes with nothing durable behind it. This is worse than the one documented boundary (`verifier_unreachable`, ADR-0005): that path still tells the caller `outcome_type: fault` and increments the metric; this path tells no one anything.

**Attack 2 — OPA 200 with a malformed/partial body.** Mocked `httpx.Client` to return `{"result": {"allow": True}}` (no `reasons`, no `revision` — a plausible response if a future Rego change or a version skew drops a key):
```python
result = middleware.query_opa_policy('provision_cloud_server', ARGS)
# {'outcome_type': 'policy_allow', 'fault_class': None, 'policy_revision': None, 'reasons': []}
```
ADR-0005's own table: `policy_allow | ... | null | set`. `policy_revision` is `None` here — `policy_allow` with an unset revision, contradicting the taxonomy's own documented invariant.

**Attacks attempted that failed (conditions that were fine):** OPA 500 → `fault/opa_unreachable`, correct. Connection drops mid-response (`httpx.RemoteProtocolError`) → `fault/opa_unreachable`, correct. Neither produces a misclassified or absent record.

**Could not test:** a genuine Rego runtime error (as opposed to a compile error or an undefined result) inside `evaluation`'s dependencies — reproducing this needs a deliberately broken pack loaded into a live bundle and was not attempted given time; OPA's documented behavior for a builtin error during evaluation is an HTTP 500, which (per Attack 2's sibling test above) is already handled correctly, so this is a plausible but unconfirmed HOLDS, not a tested one.

---

### S4 — REFUTED

Issued a real approved call (tx=233, marker in `tags.note`), confirmed `/audit` returned the real payload, then `DELETE /content/233` (204). Separately, stopped `ail-control-plane` (the content store's own process), issued a second real approved call (tx=234) — the content-store POST fails but the call still completes — then restarted control-plane and re-queried.

```
tx=233 (erased):        "payload": null   (everything else unchanged: outcome_type, policy_revision, input_sha256, verification.state=verified)
tx=234 (never stored):  "payload": null   (identical shape)
```
The two entries are structurally indistinguishable except for their own distinct inputs (`agent_id`, `timestamp`, `input_sha256` — different requests). Nothing — no timestamp field, no reason code, no separate boolean — marks one as "erased on request" and the other as "never captured." `dashboard/lib/types.ts`'s own `AuditEntry.payload` comment concedes this explicitly: *"Null if never stored or erased."*

**Third state ("content never attempted"):** read through `intercept_tool_call` — `store_content` is called unconditionally whenever `ledger_tx_id is not None`, which is every outcome except `verifier_unreachable` (which has no `ledger_tx_id` and therefore no `/audit` row to compare against at all). There is no code path that produces a ledger entry with content "never attempted" as a third, distinct state from "attempted and failed" — structurally, only two states exist today, and they're indistinguishable. Reported as **UNTESTABLE** for the specific "never attempted" framing, not because it's fine, but because the third case the brief names doesn't appear to be constructible in the current code at all — which is itself worth knowing.

---

### S5 — REFUTED

With `ail-control-plane` stopped (content store down, everything else — OPA, verifier, ImmuDB — healthy):
```python
r = middleware.intercept_tool_call('provision_cloud_server', ARGS, 'probe')
# {'status': 'APPROVED', 'message': 'Action approved by policy', 'outcome_type': 'policy_allow',
#  'fault_class': None, 'policy_revision': '1134a27...', 'ledger_tx_id': 234}
```
`status: APPROVED`, a real `ledger_tx_id` — the call executes exactly as if nothing were wrong. `fault_class` is `None`; there is no field anywhere in this response indicating the content write is about to fail. After restarting control-plane, `/audit` for tx=234 shows `payload: null` permanently (§S4) — the arguments are gone forever, with nothing in the response the caller received, or in any later read, ever having flagged the gap.

**Agent-induced failure, attempted:** `CloudServerProvisionSchema.tags: Dict[str, str]` (`interceptor/schemas.py`) has no `max_length` on values and no bound on key count — nothing stops an LLM-controlled `tags` dict from being arbitrarily large while still passing schema validation. Tried a ~10MB `tags` payload (2,000 keys × 5KB values): it succeeded end-to-end in 3.36s, including the content-store write (`204 No Content`) — this environment's stack (Uvicorn default limits, SQLite TEXT column, the 10s `httpx` timeout in `content_store.py`) absorbed it without failing. **Attack attempted that failed**: did not find the threshold at which size alone induces a failure within reasonable test bounds (did not push into 100MB+ territory). The structural absence of any bound remains real and unmitigated even though this specific session didn't trigger it live; the control-plane-down reproduction above already independently satisfies S5's core claim regardless.

---

### S6 — REFUTED

Built the dashboard image fresh (`docker build ./dashboard`, matching P1-6's own Dockerfile with no `NEXT_PUBLIC_API_URL` build arg) and ran it standalone against the live control plane.

**The narrow claim (credential in anything browser-reachable) holds**: `curl` of server-rendered HTML for `/audit` and `/settings`, and of `__NEXT_DATA__`, found no match for the key value or `CONTROL_PLANE_API_KEY`. Response headers carry nothing sensitive. A second dashboard instance run with `CONTROL_PLANE_API_KEY` unset returns a generic `503 {"detail": "CONTROL_PLANE_API_KEY not configured on the dashboard server"}` — no value leaked in the error path either.

**The broader claim — "a way to use it" — fails decisively.** Neither `/api/audit` nor `/api/tenants/{id}` requires any credential from the caller; `dashboard/app/api/*/route.ts` never reads the incoming request's own headers at all, only `process.env.CONTROL_PLANE_API_KEY`. This means the dashboard's own routes are unauthenticated:
```
$ curl -s "localhost:3001/api/audit?limit=2"
{"entries": [{"tx_id": 126, ..., "payload": {"instance_type": "p4d.24xlarge", ...}, ...}]}   # full audit log, zero headers sent

$ curl -s "localhost:3001/api/tenants/tenant_default" | ... enable_hipaa: True
$ curl -s -X PUT "localhost:3001/api/tenants/tenant_default" -d '{"enable_hipaa": false}'
200
$ curl -s "localhost:3001/api/tenants/tenant_default" | ... enable_hipaa: False    # real, persisted mutation, zero headers sent
```
(Reverted immediately after.) Anyone who can reach the dashboard's port — no browser, no session, no credential of any kind — can read every agent's raw call arguments and rewrite which compliance frameworks (GDPR/SOC2/FinOps/HIPAA) OPA enforces for a tenant. D4 achieves its literal goal (the key never reaches client-side JavaScript) by turning the entire dashboard server into an unauthenticated proxy for everything that key was gatekeeping. The security property `CONTROL_PLANE_API_KEY` existed to provide — restricting *who* can read the ledger or mutate policy — is fully defeated for anyone on the network path to the dashboard, which is a strictly larger population than "anyone who has the key" was before.

**Attacks attempted that failed:** checked for a caller-supplied `X-API-Key` being forwarded or overriding the server's own (it isn't — the proxy never reads the incoming request's headers at all, so this specific sub-attack doesn't apply, but only because the bigger problem — no check of any kind — makes it moot). Checked `.next/server`, source maps, and build output outside `static` for the literal key value — none found; the server-side compiled route handlers correctly hold the env-var reference, not a baked-in value.

---

### S7 — REFUTED

```python
for i in range(500):
    middleware.intercept_tool_call(f'hallucinated_tool_variant_{i}', {'anything': 'goes'}, 'probe')
```
```
Distinct time series for ail_policy_decisions_total after 500 distinct hallucinated tool_name values: 500
  ail_policy_decisions_total{fault_class="",outcome_type="schema_deny",status="DENIED",tool_name="hallucinated_tool_variant_0"} 1.0
  ...
```
Linear, unbounded growth — `tool_name` is written straight from the caller's own string into a Prometheus label with no allowlist against the closed `TOOL_VALIDATORS` registry (or anything else) before being used as a label value. Every distinct hallucinated name is a new permanent Prometheus time series. This is the textbook cardinality-explosion shape and is trivially reachable by exactly the `schema_deny` path Phase 1 introduced no new gate on — an agent that hallucinates tool names (which the whole schema-validation layer exists because LLMs do) grows the metric's cardinality by one series per hallucination, forever.

**Rego-author sub-question:** `status`, `outcome_type`, `fault_class` are all sourced from the closed Python-side enums (`OUTCOME_*`/`FAULT_*` constants), never from Rego message text under the current (unmutated) code — confirmed by reading `_outcome`/`intercept_tool_call` and cross-checked against S1 mutation #3's own before/after diff. A policy author cannot reshape these three labels. Only `tool_name` is open, but that alone is sufficient to refute the claim's "any label" wording.

---

### S8 — REFUTED

**Attack — `/verify` for a key that was never written (no tampering, no prior write at all):**
```
$ curl -s -X POST http://localhost:8003/verify -d '{"key": "<base64 of a fabricated key that was never verifiedSet>"}'
{"verified": false, "detail": "...tbtree: key not found...", "error_class": "unknown"}
```
HTTP 200. `control_plane/main.py::get_audit`'s handler treats any `vr.status_code == 200` with `vdata.get("verified")` falsy as `state: "failed"` — the tamper signal, D2's most severe category — regardless of *why* `verified` came back false. A generic "key not found" from the gRPC layer (caught by the verifier's blanket `except Exception` and mapped to the catch-all `error_class: "unknown"`) is structurally indistinguishable, at the control-plane layer, from an actual rejected inclusion/consistency proof. A CISO reading the dashboard would see the same red "failed" badge for "someone tampered with this entry" and for "this key reference doesn't point at anything" — two completely different operational situations (the second isn't a security event at all; it's more consistent with an application bug, a stale reference, or a race in what the scan returned) collapsed into one signal.

This is distinct from, and not covered by, the pre-registered `unverifiable`/`asserted` distinction (D2's own worked example) — this is a `failed` (tamper) result for a condition that involves no proof having been rejected, because there was never a proof to check in the first place.

**Attacks attempted that failed:** could not construct `state: "failed"` with `error_class: None` — every code path in `verifier/main.py::verify` that sets `verified=False` also sets one of the three closed `error_class` values in the same statement; this specific literal sub-condition from the brief appears genuinely unreachable, which is a HOLDS on this one narrow point. A verifier timeout was read (not re-driven live) and correctly maps to `unverifiable` via the same `except Exception` branch already exercised by the "verifier stopped" case Phase 1's own report reproduced — structurally sound. The "recovers mid-scan" behavior is pre-disclosed by ADR-0006 itself ("by design... worth knowing") and matches the code exactly on reading; not re-tested live since it isn't a discovery.

---

### S9 — HOLDS

Diffed `test_epic_2.py`, `test_opa_integration.py`, `test_policy_digest.py`, `test_verification.py` against their `ca688d8` (pre-Phase-1) form directly, not via the report's own characterization.

- `test_epic_2.py`, `test_opa_integration.py`: every change is `result["allowed"] is True/False` → `result["outcome_type"] == "policy_allow"/"policy_deny"` and `result.get("deny", [])+result.get("reason", "")` → `result.get("reasons", [])` — same-strength single-value/substring checks on the renamed fields, plus one net-new assertion (`assert result["policy_revision"]`, `assert result["fault_class"] is None`) added, not removed, in two places. No case found where the new assertion is satisfiable by a broader set of values than the old one.
- `test_verification.py`: one line, `matching[0]["verified"] is True` → `matching[0]["verification"]["state"] == "verified"` — equivalent strength, mechanical schema follow-through.
- `test_policy_digest.py::test_digest_unavailable_denies_and_writes_a_fault_record`: the one D1-authorized reversal (old: asserted *no* ledger entry; new: asserts a fault record *is* written, with `outcome_type`, `fault_class`, and `policy_revision` all checked, plus a live `/audit` cross-check the old version didn't have). This is the pre-registered change and is strictly more specific than what it replaced, not broader.

**Attacks attempted that failed:** looked for a second, undisclosed weakening beyond the one named in D1 — none found. Checked whether the new tests added this phase (`test_outcome_types.py`, `test_response_contract.py`, `test_base_agent.py`) contain any assertion that's trivially satisfiable (e.g. `assert True`, bare exception swallowing) — none do; every assertion in all three checks a specific value against the real live response.

---

## 4. Could not test, and what blocked it

- **S3's Rego-runtime-error condition** (a builtin error during `evaluation`'s dependency evaluation, as opposed to a compile error or an undefined result) — would require deliberately loading a broken pack into a live bundle; not attempted given the time already spent on the two S3 findings that were confirmed live.
- **S5's exact failure threshold for size-induced content-store failure** — a 10MB `tags` payload succeeded end-to-end; did not push further into payload sizes large enough to find where (or whether) FastAPI/Uvicorn/SQLite actually reject it in this environment.
- **S8's verifier-timeout state, live** — read the code path (identical exception handler to the already-tested "verifier stopped" case) rather than re-driving a live slow-response simulation; a genuine network-level delay (as opposed to a stopped container) was not separately reproduced.
- **No `OPENAI_API_KEY`-dependent testing was needed** — none of S1-S9 require live LLM extraction (unlike the build report's own P1-9); an `OPENAI_API_KEY` was available in this environment's shell but was not needed for any claim in this brief.

---

## 5. Findings outside S1-S9

1. **CI has never run against this branch.** `gh run list` shows no "Integration Tests" run for `phase-1-record-truth` — the workflow triggers only on push to `main` or on an open PR, and neither happened for this branch. The review-protocol's own step 4 precondition ("work is committed to a branch and pushed... so CI runs") was not met; the "42 passed" claim in the build report has no independent confirmation anywhere, only the same local environment that produced it.
2. **The stale-image trap recurred in a new form this session** (§1): reusing a scratch-clone directory name across red-team sessions silently reuses cached Docker images tagged from the *other* session's code, producing a fully-plausible-looking but wrong result (`/audit` returning the pre-Phase-1 shape) that required noticing the anomaly rather than trusting the compose output. Worth a standing note for future red-team sessions that reuse a scratchpad path: `--build`/`--no-cache` is not optional, even on a claimed-fresh `up`.
3. **S1's five uncaught mutations share a common shape**: every one of them is a property the build report itself demonstrates only via a one-off, hand-run, live reproduction (P1-1's log-diff, P1-4's before/after metrics scrape, P1-5's marker-string round trip) rather than an automated assertion. The two mutations that *are* caught (#1, #5) are exactly the two properties `test_outcome_types.py` was written to check. This suggests the gap is not random coverage misses but a direct consequence of which properties got a dedicated test file this phase and which didn't.
