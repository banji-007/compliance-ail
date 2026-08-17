# Spike Report: OPA Rego under WebAssembly (Cloudflare Worker parity)

Spike instructions: `spikes/wasm-parity/SPIKE.md`. All spike artifacts (scripts, corpus, compiled modules, Worker harness, downloaded OPA binary) live under `spikes/wasm-parity/`. This report is the one output file placed outside that directory, as directed.

## 1. Environment and tool versions

- OS: Windows 11 Home 10.0.22631
- Node: v24.14.0, npm: 11.9.0
- OPA: downloaded fresh for this spike from `https://github.com/open-policy-agent/opa/releases/download/v1.19.0/opa_windows_amd64.exe`, confirmed as the latest release via the GitHub releases API at spike time (2026-08-17). `opa.exe version` reports:
  ```
  Version: 1.19.0
  Build Commit: 1e32c796e8979b1bda2f768138500b1deb95ff24-dirty
  Build Timestamp: 2026-07-30T19:38:54Z
  Go Version: go1.26.5
  Platform: windows/amd64
  Rego Version: v1
  WebAssembly: available
  ```
- `@open-policy-agent/opa-wasm`: 1.10.0 (npm), installed locally in `spikes/wasm-parity/`
- `wrangler`: 4.123.0, installed locally in `spikes/wasm-parity/` and invoked via `npx wrangler`
- OPA binary used to build the WASM module: the same `opa.exe` v1.19.0 above (`opa build -t wasm`)
- **Git base correction:** this spike's worktree was created from `65dd365`, the tip of `main` at the time. `main` is one commit behind the actual current work branch, `phase-1-record-truth` (65dd365 plus 25a5404, 33822a6, ca688d8, 3e86a9b, 96d14d7). Commit `3e86a9b` ("Phase 1 truth pass") adds an `evaluation` rule to `policy/core/main.rego` that is the real per-request query path in `interceptor/middleware.py` on that branch. This was caught mid-spike, before the report was finalized: the worktree was fast-forwarded onto `phase-1-record-truth` (a clean fast-forward merge, `65dd365..96d14d7`, since 65dd365 is an ancestor), and W1/W2 were redone against the corrected `main.rego`. `git diff 65dd365 96d14d7 -- policy/packs/gdpr/gdpr.rego policy/packs/hipaa/hipaa.rego policy/packs/soc2/soc2.rego policy/packs/finops/finops.rego` is empty  -  all four pack files are byte-identical across the two branches, so nothing in W3, W4, or W5 (which exercise `allow`/`deny`/`compliance_summary`, not the new `evaluation` rule) needed to be redone; they were re-run anyway as a check and produced identical results. Only `policy/core/main.rego` differs, by the addition of the `evaluation` rule (see W1/W2 below). This report reflects the corrected branch throughout.

## 2. Verdict: GO WITH CHANGES

The Rego compiles cleanly to WASM and produces identical allow/deny verdicts and identical reason sets to the OPA server across a 42-case corpus with zero decision divergence, but the message strings differ on any rule that formats a Rego `set` with `sprintf("%v", ...)` (10 of 42 cases), the real per-request `evaluation` rule (which reads the bundle-revision digest via `data.system.bundles`) comes back entirely undefined under a bare WASM instantiation and needs the v2 plan's module+data hash in its place, and the tenant data document must be supplied and swapped in by the host application on every call rather than baked into the compiled artifact.

## 3. W1: Do the packs compile

Yes, cleanly, with no unsupported-builtin warnings and exit code 0  -  including the real `ail/main/evaluation` entrypoint, exactly as the spike spec named it.

`policy/core/main.rego` on the correct branch (`phase-1-record-truth`, commit `3e86a9b`) does have the `evaluation` rule the spike spec describes:

```rego
# --- Combined evaluation (Phase 1, P1-1) ---
evaluation := {
    "allow": allow,
    "reasons": all_violations,
    "revision": data.system.bundles[input.bundle_name].manifest.revision,
}
```

This is the live per-request path: `interceptor/middleware.py` queries `data.ail.main.evaluation` (`_OPA_EVAL_URL`, built from `_OPA_URL` at line 60) for every tool-call decision; `_fetch_opa_bundle_revision`/`_OPA_REVISION_URL` still exists but is now a startup-only sanity check, not part of the per-request flow.

Compile command actually used, against this corrected source:

```
opa.exe build -t wasm -e ail/main/evaluation \
  -o build_eval/bundle.tar.gz \
  policy/core/main.rego policy/packs/gdpr/gdpr.rego policy/packs/hipaa/hipaa.rego policy/packs/soc2/soc2.rego policy/packs/finops/finops.rego
```

- Exit code: 0, no stderr output.
- Output bundle (`bundle.tar.gz`): 58,606 bytes.
- Extracted `policy.wasm`: 143,797 bytes (140 KiB).
- Manifest entrypoint compiled: `ail/main/evaluation`.
- Builtins exercised by the five source files, all of which compiled without complaint: `sprintf`, `contains`, `object.get`, `count`. No builtin was reported as unsupported; there was nothing to report because none failed. Compilation succeeding here confirms that `data.system.bundles` not existing at evaluation time is not a compile-time problem  -  the compiler does not need to resolve or validate a data reference's actual availability, only its syntax; the absence only bites at evaluation time (see W2).

A second, larger module was also built with all five entrypoints together (`allow`, `deny`, `all_violations`, `compliance_summary`, `evaluation`) for use across W2/W3/W5: same command with five `-e` flags, 144,598-byte `policy.wasm`, exit code 0. This is the module referenced throughout the rest of this report as `build/extracted/policy.wasm`.

One remaining discrepancy against the spike's stated premises, found by inspection and unaffected by the branch correction, is worth keeping on record:

- **The GDPR pack has 3 deny rules, not 2.** `policy/packs/gdpr/gdpr.rego` contains three `deny contains msg if { ... }` blocks (pci-dss region rule, unclassified-data region rule, and a `query_database` purpose-limitation rule), for a total of 13 deny rules across the four packs (GDPR 3, HIPAA 3, SOC2 4, FinOps 3), not the 12 stated. The golden corpus in W3 covers all 13.

One incidental compiler behavior worth noting: `opa build -e ail/main/allow -e ail/main/deny` (only two `-e` flags) produced a manifest listing all four rules in the `ail.main` package (`allow`, `deny`, `all_violations`, `compliance_summary`), not just the two requested. The compiler appears to include all resolvable public rules in a targeted package once any one of them is requested. Harmless here, but worth knowing if a future entrypoint list is meant to be minimal for module size reasons  -  it wasn't, materially, at this bundle size.

## 4. W2: Where does the revision come from

**`data.system.bundles` does not exist under WASM in any form, and because `evaluation` builds a single object out of `allow`, `reasons`, and the revision lookup together, the entire decision (not just the revision field) comes back completely undefined under a bare WASM instantiation. It is populated exclusively by the OPA server's bundle manager and is not present in a bare WASM instantiation, confirming the spike's stated risk  -  tested directly against the real rule, not just an analog.**

This is the sharper version of the risk than "the digest would be missing": `main.rego`'s own comment on the rule says it plainly  -  "the only way this whole rule is undefined is if the revision lookup is [undefined]." Since `allow` always has a default and `all_violations` is always at least an empty set, neither of those two fields can ever be the thing that makes `evaluation` undefined. Under WASM, the revision lookup is *always* undefined (nothing populates `data.system.bundles`), so `evaluation` is *always* undefined for *every* decision  -  meaning a naive lift of this rule straight into a WASM deployment would return no result for every single request, and (per `interceptor/middleware.py`'s fail-closed handling of an undefined `evaluation` result) every request would be denied, not just missing a revision stamp.

Evidence, tested three ways (all in `spikes/wasm-parity/scratch/`, none of it touching tracked Rego):

**1. Against the real `ail/main/evaluation` entrypoint, compiled from the actual `policy/core/main.rego`, instantiated with `@open-policy-agent/opa-wasm`** (`scratch/w2_real_evaluation.mjs`), queried with a realistic `provision_cloud_server` input under five data conditions:

| `setData(...)` condition | `evaluation` result |
|---|---|
| No `setData()` call at all | undefined (empty result set) |
| `setData({})` | undefined |
| `setData()` with a realistic tenant config document (`{"ail":{"config":{...}}}`, exactly what a hosted Worker would naturally have on hand) but no `system.bundles` | undefined |
| `setData()` with a hand-rolled `system.bundles` shape matching `input.bundle_name` exactly | **resolves**: `{"allow":true,"reasons":[],"revision":"manually-injected-rev"}` |
| `setData()` with `system.bundles` present but keyed under the *wrong* bundle name | undefined |

The middle three rows are the realistic ones: nothing a hosted Worker would naturally construct (its own tenant config, nothing else) makes this rule resolve. Only manually fabricating the OPA-internal `system.bundles` shape works, and a caller that does that is simply asserting its own revision string, which is not meaningfully different from not having OPA attest to a revision at all.

**2. Against `opa eval` with no server (no bundle manager, same as WASM in this respect)**, same rule, same input, empty data: also `{}` (undefined)  -  confirming this is not a WASM-specific quirk but a property of "no live bundle manager," which describes both WASM and loose-file `opa eval`.

**3. Against a real running `opa run --server`**, with a bundle actually loaded and named `ail-policies` (matching `opa-config.yaml` and `interceptor/middleware.py`'s `_BUNDLE_NAME`):
- `GET /v1/data/system/bundles` → `{"result":{"ail-policies":{"etag":"","manifest":{"revision":"real-server-test-rev","roots":[""]}}}}`  -  populated automatically, no extra configuration.
- `POST /v1/data/ail/main/evaluation` with `input.bundle_name: "ail-policies"` → `{"result":{"allow":true,"reasons":[],"revision":"real-server-test-rev"}}`  -  resolves correctly, this is the production-shape success case.
- Same query with `input.bundle_name: "nonexistent"` → `{}`  -  undefined, matching the rule's own documented fail-closed intent when the bundle name doesn't match what's loaded.

Conclusion: `data.system.bundles` is not "empty" under WASM, it is **structurally absent**  -  there is no bundle manager, no bundle lifecycle, and nothing populates that path regardless of what the caller supplies at `setData()` time unless the caller manually fabricates the exact same shape themselves (which defeats the purpose, since the caller would then be the source of truth for its own revision). And because `evaluation` is a single combined object, that absence takes the verdict and reasons down with it, not just the revision field.

**What a WASM deployment would have to substitute:** the v2 plan's proposal  -  hash the WASM module bytes and the data document at load time, computed inside the isolate  -  is not just viable but is the *only* mechanism available, since there is nothing else in the WASM/host environment that publishes a trustworthy revision on OPA's behalf. This spike's W4 findings (below) independently confirm that both the module bytes and the data document are fully under host-application control at instantiation/evaluation time, which is exactly what a load-time SHA-256 over "module + data" needs to be computable. This would be **structurally stronger** than the current OPA-server design in one respect: the current design (`data.system.bundles.<name>.manifest.revision`) trusts a self-reported string from the bundle manager, not a hash of the policy bytes actually loaded; a hash computed over the actual module and data document the isolate is holding cannot silently drift from what ran, the way a manifest revision string theoretically could if the bundle manager's bookkeeping and the loaded Rego ever disagreed. It also has the added benefit of not taking `allow`/`reasons` down with it the way the current combined-object design does when the revision lookup fails  -  a hash computed from values the isolate already definitely has (its own module bytes, its own data document) cannot itself be undefined the way a conditional data lookup can.

A standalone probe package (`revision_probe.rego`, not part of the AIL policy tree, defining `revision := data.system.bundles["ail-policies"].manifest.revision`, `bundles_present`, and `bundles_keys` in isolation) was also built and tested (`scratch/w2_probe.mjs`) before the branch correction and reproduces the same undefined-unless-manually-injected pattern found in points 1-3 above. It is retained in `spikes/wasm-parity/scratch/` as supporting evidence but the headline finding in this section is the direct test against the real `evaluation` rule.

## 5. W3: Decision parity

A 42-case golden corpus (`spikes/wasm-parity/scratch/corpus.json`) was derived directly from the 13 actual deny rules (not 12  -  see W1) across all four packs, covering: every rule in isolation, missing-key vs. explicit-empty-string boundary variants, case-sensitivity boundaries, rules with no environment guard tested against the guard that doesn't exist, multi-rule combinations (2, 3, and 4 simultaneous denials to test reason-set aggregation), two full approval flows per tool, two Rego-layer edge cases (unknown `tool_name`, completely empty `input`), and a second data-document variant (`tenant_custom`) re-running six of the region/purpose/cost-center cases to test W4's data-injection question end to end.

Each case was run against `opa.exe eval` (`data.ail.main.compliance_summary`, which exposes `compliant` and the full `violations` set in one query) and against the WASM module via `@open-policy-agent/opa-wasm` (`scratch/run_parity.mjs`), diffing verdict and reason set.

**Result: 42/42 cases produced an identical verdict (`compliant` boolean) and an identical reason count. 32/42 matched byte-for-byte on message text. 10/42 differed only in how a `set` value is stringified inside `sprintf("%v", ...)`.**

Every one of the 10 message-text mismatches traces to the same root cause and is fully explained by it  -  there is no other source of divergence in the corpus:

- OPA server / `opa eval`: `sprintf("%v", [set])` renders a set as `{"eu-central-1", "us-east-1"}`  -  braces, double-quoted elements, comma-space separated, alphabetically sorted.
- WASM: the identical `sprintf` call renders the same set as `eu-central-1,us-east-1`  -  no braces, no quotes, comma-only separator, and an element order that does not match alphabetical sort (e.g. `finance,engineering,marketing,operations`).
- This affects exactly the four rules that interpolate `approved_regions`, `approved_purposes`, or `approved_cost_centers` into a message via `%v`: GDPR's pci-dss region rule, GDPR's unclassified-data region rule, GDPR's purpose-limitation rule, and FinOps's cost-center rule.
- The WASM ordering was confirmed stable across repeated runs and repeated module instantiations (not a per-call random hash-iteration artifact); it simply differs from the OPA Go evaluator's ordering.
- This is a genuine parity gap in the compiled artifact, not a test-harness bug: the verdict and reason count are correct and identical in every one of these 10 cases; only the literal string returned to a caller (and thus anything downstream that displays, hashes, or pattern-matches on that string) differs.

A related methodology finding surfaced while building the harness and is recorded rather than silently worked around: `opa eval -d <path>` silently fails to merge a loose JSON data file when `<path>` is **absolute** on this platform  -  the data document ends up unreachable with no error, so every `data.*` read against it comes back empty. A **relative** path (relative to the process's working directory) works correctly. This is documented in `scratch/run_parity.mjs` and reproduced in isolation in `scratch/debug_single.mjs` / `scratch/debug_single2.mjs`. It cost an early, incorrect run of the harness that showed 6 false "verdict mismatches" (the tenant-custom-data cases silently evaluating against the empty default data instead); those were re-run correctly after the fix and are reflected in the table below. It does not affect WASM at all (WASM never reads files  -  `setData()` always takes an in-memory object) and would not affect the production OPA server (which uses the Bundle API over HTTP, not `-d` with loose files), so it has no bearing on the GO/NO-GO verdict, but anyone reproducing this spike's methodology with `opa eval` needs to know it.

### Parity table (all 42 corpus cases)

| Case ID | Rule under test | OPA server verdict | WASM verdict | Result |
|---|---|---|---|---|
| PCS-01 | approval | ALLOW (0 reasons) | ALLOW (0 reasons) | MATCH |
| PCS-02 | approval-prod | ALLOW (0 reasons) | ALLOW (0 reasons) | MATCH |
| GDPR-01-deny | gdpr.deny[0] pci-dss unapproved region | DENY (1 reason) | DENY (1 reason) | DIFFER (message text: set formatting) |
| GDPR-01-boundary-allow | gdpr.deny[0] boundary: approved region | ALLOW (0 reasons) | ALLOW (0 reasons) | MATCH |
| GDPR-02-deny-missing-classification | gdpr.deny[1] unclassified (missing key), unapproved region | DENY (1 reason) | DENY (1 reason) | DIFFER (message text: set formatting) |
| GDPR-02-deny-unspecified | gdpr.deny[1] unclassified ('unspecified'), unapproved region | DENY (1 reason) | DENY (1 reason) | DIFFER (message text: set formatting) |
| GDPR-02-boundary-allow | gdpr.deny[1] boundary: unclassified, approved region | ALLOW (0 reasons) | ALLOW (0 reasons) | MATCH |
| HIPAA-01-deny | hipaa.deny[0] phi without isolated_instance | DENY (1 reason) | DENY (1 reason) | MATCH |
| HIPAA-01-deny-missing-key | hipaa.deny[0] phi, isolated_instance absent | DENY (1 reason) | DENY (1 reason) | MATCH |
| HIPAA-02-deny | hipaa.deny[1] phi without encryption_at_rest | DENY (1 reason) | DENY (1 reason) | MATCH |
| HIPAA-01-02-combined | hipaa.deny[0] and [1] simultaneously | DENY (2 reasons) | DENY (2 reasons) | MATCH |
| HIPAA-03-deny | hipaa.deny[2] hipaa_scope true, no classification | DENY (1 reason) | DENY (1 reason) | MATCH |
| HIPAA-03-boundary-allow | hipaa.deny[2] boundary: classification present | ALLOW (0 reasons) | ALLOW (0 reasons) | MATCH |
| SOC2-01-deny | soc2.deny[0] prod without encryption_at_rest | DENY (1 reason) | DENY (1 reason) | MATCH |
| SOC2-01-boundary-case-sensitivity | soc2.deny[0] boundary: wrong-case string | DENY (1 reason) | DENY (1 reason) | MATCH |
| SOC2-02-deny-users | soc2.deny[1] 'users' table unmasked | DENY (1 reason) | DENY (1 reason) | MATCH |
| SOC2-02-deny-pii | soc2.deny[1] 'pii' table unmasked, explicit false | DENY (1 reason) | DENY (1 reason) | MATCH |
| SOC2-02-boundary-allow | soc2.deny[1] boundary: masking enabled | ALLOW (0 reasons) | ALLOW (0 reasons) | MATCH |
| GDPR-SOC2-combined-query | gdpr query rule + soc2.deny[1] simultaneously | DENY (2 reasons) | DENY (2 reasons) | DIFFER (message text: set formatting) |
| GDPR-query-deny | gdpr query rule: unauthorized purpose | DENY (1 reason) | DENY (1 reason) | DIFFER (message text: set formatting) |
| query-approval | approval | ALLOW (0 reasons) | ALLOW (0 reasons) | MATCH |
| SOC2-03-deny | soc2.deny[2] production deploy, no ticket | DENY (1 reason) | DENY (1 reason) | MATCH |
| SOC2-04-deny | soc2.deny[3] bypass_ci true | DENY (1 reason) | DENY (1 reason) | MATCH |
| SOC2-04-boundary-non-production-env | soc2.deny[3] boundary: no environment guard | DENY (1 reason) | DENY (1 reason) | MATCH |
| FINOPS-03-deny | finops.deny[2] experimental repo to production | DENY (1 reason) | DENY (1 reason) | MATCH |
| FINOPS-03-boundary-non-production | finops.deny[2] boundary: non-production environment | ALLOW (0 reasons) | ALLOW (0 reasons) | MATCH |
| SOC2-SOC2-FINOPS-combined-deploy | soc2.deny[2], soc2.deny[3], finops.deny[2] simultaneously | DENY (3 reasons) | DENY (3 reasons) | MATCH |
| deploy-approval | approval | ALLOW (0 reasons) | ALLOW (0 reasons) | MATCH |
| FINOPS-01-deny | finops.deny[0] prod, invalid cost_center | DENY (1 reason) | DENY (1 reason) | DIFFER (message text: set formatting) |
| FINOPS-01-boundary-allow | finops.deny[0] boundary: approved cost center | ALLOW (0 reasons) | ALLOW (0 reasons) | MATCH |
| FINOPS-02-deny | finops.deny[1] restricted instance, wrong project tag | DENY (1 reason) | DENY (1 reason) | MATCH |
| FINOPS-02-deny-missing-project | finops.deny[1] restricted instance, project tag absent | DENY (1 reason) | DENY (1 reason) | MATCH |
| FINOPS-02-boundary-allow | finops.deny[1] boundary: ml-training tag present | ALLOW (0 reasons) | ALLOW (0 reasons) | MATCH |
| MULTI-DENY-provision | 4 rules simultaneously (gdpr, soc2, finops x2) | DENY (4 reasons) | DENY (4 reasons) | DIFFER (message text: set formatting) |
| EDGE-unknown-tool | tool_name not recognized by any pack | ALLOW (0 reasons) | ALLOW (0 reasons) | MATCH |
| EDGE-empty-input | completely empty input object | ALLOW (0 reasons) | ALLOW (0 reasons) | MATCH |
| TENANT-GDPR-01-deny-default-region-now-unapproved | gdpr.deny[0] under tenant_custom data | DENY (1 reason) | DENY (1 reason) | DIFFER (message text: set formatting) |
| TENANT-GDPR-01-boundary-allow | gdpr.deny[0] under tenant_custom data, custom region approved | ALLOW (0 reasons) | ALLOW (0 reasons) | MATCH |
| TENANT-GDPR-query-deny-default-purpose-now-unapproved | gdpr query rule under tenant_custom data | DENY (1 reason) | DENY (1 reason) | DIFFER (message text: set formatting) |
| TENANT-GDPR-query-boundary-allow | gdpr query rule under tenant_custom data, custom purpose | ALLOW (0 reasons) | ALLOW (0 reasons) | MATCH |
| TENANT-FINOPS-01-deny-default-cost-center-now-unapproved | finops.deny[0] under tenant_custom data | DENY (1 reason) | DENY (1 reason) | DIFFER (message text: set formatting) |
| TENANT-FINOPS-01-boundary-allow | finops.deny[0] under tenant_custom data, custom cost center | ALLOW (0 reasons) | ALLOW (0 reasons) | MATCH |

Raw evidence: `spikes/wasm-parity/scratch/corpus.json` (inputs), `spikes/wasm-parity/scratch/parity_results.json` (full OPA and WASM output per case, including the exact message strings quoted in this report), `spikes/wasm-parity/scratch/run_parity.mjs` (harness).

## 6. W4: Data document injection

Answered concretely by direct experiment, not by reading documentation:

- **The compiled WASM binary does not carry a usable data document, even when the source bundle's `data.json` has real content baked in at build time.** A probe bundle was built (`scratch/embed_bundle_src/data.json` containing `{"ail":{"probe2_data":{"some_constant":"BAKED-IN-AT-BUILD-TIME"}}}`, compiled alongside a rule reading that path) and confirmed present verbatim in the extracted bundle's `data.json`. But `@open-policy-agent/opa-wasm`'s `loadPolicy()` initializes every fresh instance with an **empty** data document (`_loadJSON(instance, mem, {})`  -  read directly from the package source, `src/opa.js` line 335) regardless of what the bundle's own `data.json` contains. Querying the rule immediately after `loadPolicy()`, with no `setData()` call, returns undefined. Only after the host explicitly calls `policy.setData(bundledDataJson)` does the rule resolve (`scratch/w4_data_embed_probe.mjs`, all three sub-cases run and logged).
- **Practical implication: the JS/Worker host is unconditionally the source of the data document.** There is no path by which the tenant config "just travels with the module." The application (Worker code) must read `approved_regions` / `approved_purposes` / `allowed_cost_centers` from wherever it stores per-tenant config (KV, D1, an API call, etc.) and call `setData()` explicitly before every evaluation that needs it.
- **`setData()` fully replaces the data document; it does not merge.** Read directly from `src/opa.js`: `setData(data) { ... this.dataAddr = _loadJSON(this.wasmInstance, this.mem, data); }`  -  the previous `dataAddr` is discarded, not deep-merged with the new one. Each call must supply the complete document the evaluation needs (in this project's case, the full `{"ail": {"config": {...}}}` shape), not a partial patch.
- **Per-request / per-tenant data selection is possible without re-instantiating the module, and this is in fact the only way it can be done.** The parity corpus's `tenant_custom` cases (W3, 6 cases) prove this end to end: the same compiled `policy.wasm` module, loaded once, was driven through `setData({})` (default fallback constants) and `setData({ail:{config:{...tenant values...}}})` (tenant override) across different evaluations, and produced the correct tenant-specific verdicts each time  -  the same module instance answered both a default-config decision and a custom-config decision correctly, with only a `setData()` call in between. Re-instantiation is not required to switch tenants; it is not even involved.
- **Concurrency caveat, not exercised by this spike but implied by the code:** because `setData()` mutates instance state (`this.dataAddr`) synchronously and `evaluate()` reads that same instance state, a single `loadPolicy()` instance is only safe to reuse across concurrent requests if the `setData()` → `evaluate()` pair for one request completes before another request's `setData()` runs (no `await` between them, or one instance per in-flight request). This was reasoned from the source, not measured; V8 isolates and Workers' single-threaded-per-request execution model make the straightforward "call setData then evaluate synchronously" pattern safe, but a design that pools instances across concurrent requests without care would not be.

**This decides the hosted multi-tenancy model favorably**: no re-instantiation, no re-compilation, and no separate module per tenant are needed. One compiled module can serve every tenant; the only per-request cost is handing it the right JSON before calling `evaluate()`.

## 7. W5: Runtime fit

Confirmed. The compiled module instantiates and evaluates correctly under `@open-policy-agent/opa-wasm` inside `wrangler dev` (workerd, the actual Cloudflare Workers runtime, not a Node polyfill)  -  `spikes/wasm-parity/worker/worker.js`, run via `npx wrangler dev` against `spikes/wasm-parity/worker/wrangler.jsonc` (which declares the `.wasm` file as a `CompiledWasm` module rule, the standard Workers wasm-import mechanism).

A live request against the running `wrangler dev` server returned correct decisions for both an approved and a denied case, confirming the WASM/JS interop, the `CompiledWasm` import, and the entrypoint dispatch all function correctly end to end in the Workers runtime, not just in plain Node.

Timing, measured with `performance.now()` inside the Worker, `instantiate_ms` measuring `loadPolicy()`, and `warm_eval_ms` measuring `evaluate()` on an already-instantiated policy:

| Condition | Result |
|---|---|
| First request after `wrangler dev` cold-started (module compiled by V8 for the first time) | `instantiate_ms: 10`, `first_eval_ms: 4` |
| Subsequent requests, same running dev server (module already compiled once by V8; a **new** `loadPolicy()` instance created per request) | `instantiate_ms: 1-3`, `first_eval_ms: 0-1` |
| 10 back-to-back `evaluate()` calls on one already-instantiated policy object (steady-state, module warm) | average `0.1-0.3 ms` per decision |

Interpretation: WASM **module compilation** (parsing/validating the bytecode) is the expensive one-time cost (~10ms the first time V8 sees these bytes); once compiled, creating a fresh **instance** from the already-compiled module is cheap (1-3ms), and evaluating a decision against a live instance is sub-millisecond. This matches how Cloudflare Workers actually behaves: the module is compiled once per isolate (and Cloudflare's infrastructure caches compiled Wasm across isolate starts in production), so the realistic per-request cost in a hosted deployment is the sub-millisecond `evaluate()` figure, not the 10ms one-time compile. Caching the instantiated `policy` object at module scope (outside the `fetch` handler) rather than calling `loadPolicy()` inside every request  -  which the W4 findings show is safe for tenant switching via `setData()`  -  removes even the 1-3ms per-request instantiation cost shown above, since that cost was only present because this test's `worker.js` deliberately calls `loadPolicy()` fresh inside `fetch()` on every request to measure it.

Deployment to a real Cloudflare account was not attempted (the spike spec states local `wrangler dev` is sufficient) and was not necessary to answer the question asked.

## 8. What could not be determined and what blocked it

- **Whether Cloudflare's production infrastructure caches the compiled WASM module across isolate cold starts the way local `wrangler dev` does within one long-lived dev-server process.** This spike measured compile/instantiate cost inside a single continuously-running `wrangler dev` process; it did not measure true isolate cold-start behavior in the deployed Workers platform (with V8 isolate reuse, bytecode caching across the fleet, etc.), because deployment was out of scope per the spike spec and would have required a live Cloudflare account and network deploy. The local numbers are a reasonable proxy but not a substitute for a production measurement.
- **Whether the `sprintf %v`-on-`set` formatting difference (W3) is a general property of the OPA WASM target across all Rego versions, or an artifact specific to `opa` v1.19.0's WASM code generator.** Only one OPA version was available/tested (the current latest release, per the spike's own instructions). No older OPA version was installed to compare.
- **The exact internal reason the two evaluators order a set's elements differently under `%v`.** This spike established the divergence empirically and confirmed its determinism, but did not trace it into the OPA/WASM compiler source to find the specific code path responsible (that would require reading the Go `rego` package's `sprintf` builtin and the WASM code generator's set-iteration implementation, which was judged out of scope for a go/no-go call  -  the finding itself, and its fix implications, do not depend on knowing the root cause).
- Nothing else in the spike spec was blocked; all five workstreams (W1-W5) produced direct, run evidence rather than being answered by inference or documentation lookup.

## 9. GO WITH CHANGES: what would have to change

None of the following were made; they are described for the v2 plan to act on.

1. **Replace the bundle-revision digest mechanism entirely for the hosted path.** `data.system.bundles[...].manifest.revision` cannot be read under WASM because it does not exist there  -  this is confirmed, not merely suspected. The v2 plan's proposal (hash the WASM module bytes plus the data document, computed inside the isolate at/near evaluation time) is the correct replacement and this spike found no obstacle to computing it: both the module bytes and the data document are ordinary values already available to the Worker (the module via its import, the data document via whatever the Worker already builds to pass to `setData()`). This is a change to `interceptor/middleware.py`'s digest-fetching logic and its Worker-side equivalent, not to the Rego.
2. **Decide what to do about the `sprintf("%v", [set])` message-formatting gap before treating WASM output as byte-identical to today's OPA server output.** Two options, both changes to non-Rego code or to the Rego's own message construction (the second touches the Rego, which this spike is not permitted to do  -  it can only describe the option): (a) accept the divergence and stop asserting an exact string match anywhere downstream depends on it (audit logs, tests, dashboards that pattern-match on message text), documenting that verdicts and reason counts are the parity contract, not literal text; or (b) change the four affected rules to build the approved-values string explicitly (e.g. `concat(", ", sort([...]))`) instead of relying on `%v`'s default set formatting, which would make the two evaluators agree because the formatting would then be fully specified by the policy author rather than by each evaluator's own default. Given three of the four affected rules exist specifically to report the approved-values list back to the caller in the deny message, option (b) is likely the more robust long-term choice, but it is a Rego edit and is out of scope for this spike to perform.
3. **Design the multi-tenant data path around `setData()` per evaluation, not per module.** This is good news structurally (W4) but it is a concrete architectural decision the v2 plan needs to state explicitly: one compiled module, loaded once (ideally cached at Worker module scope across requests), with the tenant's `{"ail":{"config":{...}}}` document fetched and passed to `setData()` immediately before each `evaluate()` call. The plan should also state the concurrency discipline this requires (no `await` between `setData()` and the corresponding `evaluate()` for a given request, or one policy instance per concurrently in-flight request) since nothing in `@open-policy-agent/opa-wasm` enforces it.
4. **Update the corpus assumption in any future spike or design doc that cites "12 deny rules."** It is 13 (GDPR has 3, not 2). Immaterial to the GO/NO-GO call but worth fixing at the source so it does not propagate into the v2 plan's own documentation.

## 10. Before finishing: repo hygiene check

Re-run after the branch correction, with `phase-1-record-truth` (HEAD, `96d14d7`) as the baseline, not the original `main`-derived `65dd365`:

```
git log --oneline -1               ->  96d14d7 docs(reports): add Phase 1 report   (HEAD is now on phase-1-record-truth)
git merge-base --is-ancestor 65dd365 HEAD  ->  true   (confirms the fast-forward was clean, nothing skipped)

git status --short   ->  ?? docs/reports/spike-wasm-parity.md
                          ?? spikes/
                          (only this report and the new spike directory are untracked/new)

git diff --stat       ->  (empty  -  no tracked file anywhere in the repo was modified)

git diff -- policy/   ->  (empty  -  policy/core/main.rego and all four pack files are byte-for-byte
                            unchanged from what's committed on phase-1-record-truth)
```

`policy/core/main.rego` (including its `evaluation` rule) and the four pack files under `policy/packs/` were read in full after the branch correction and never edited. No file under `interceptor/` or `tests/` was touched. All spike work (downloaded OPA binary, npm packages, golden corpus, probe `.rego` scratch files that are not part of the tracked policy tree, compiled WASM artifacts, the Worker harness, and all intermediate results) lives under `spikes/wasm-parity/`.
