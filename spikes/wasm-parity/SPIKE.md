# WASM Parity Spike

## The primary risk, stated up front

`policy/core/main.rego`'s `evaluation` rule reads the bundle revision from `data.system.bundles[input.bundle_name].manifest.revision`. `data.system.bundles` is a construct of the OPA server's bundle manager. A compiled WASM module has no bundle manager and no bundle lifecycle; it receives a data document at instantiation and evaluates against it.

If that lookup does not exist under WASM, the single-evaluation decision contract that Phase 1 built cannot be carried over as written, and the hosted design needs a different source for the policy digest. The v2 plan proposes hashing the WASM module and its data document at load time, computed in the isolate, which would be structurally stronger. Determine which is true. This is the most important output of the spike.

## W1. Do the packs compile

Compile the four packs plus main.rego with `opa build -t wasm`, entrypoint `ail/main/evaluation`.

Report: whether it compiles, the module size, and every builtin the compiler reports as unsupported. If it fails, the exact error and the rule responsible.

## W2. Where does the revision come from

Instantiate the module and query the `evaluation` entrypoint. Determine whether `data.system.bundles` resolves, is empty, or is absent entirely.

If absent, state what a WASM deployment would have to substitute, and whether the digest can be computed inside the isolate over the module plus data document rather than read from the policy result.

## W3. Decision parity

Build a golden corpus covering every deny rule across all four packs, plus approvals and boundary cases. Derive the cases from the rules themselves; do not hand-pick.

Run each case against the OPA server (`opa.exe run --server` or `opa.exe eval`) and against the WASM module with the same data document, and diff.

Parity means the verdict, the reason set, and the message strings are identical. Report any case where they differ, and do not adjust a rule or a message to close a gap.

## W4. Data document injection

The tenant data document (`allowed_cost_centers`, `approved_regions`, `approved_purposes`) currently arrives as `data.json` inside a bundle. Determine how it is supplied to an instantiated WASM module and whether per-request or per-tenant data selection is possible without re-instantiating.

This decides whether the hosted multi-tenancy model works, so answer it concretely rather than by reference to documentation.

## W5. Runtime fit

Confirm the module instantiates under the `@open-policy-agent/opa-wasm` package in a Workers-compatible runtime. `wrangler dev` locally is sufficient; a deployed Worker is not required.

Report instantiation time and evaluation time for a single decision. If instantiation is slow enough to matter per-request, say so, since that shapes whether the module is cached across requests.

## Report

Write the final report to `docs/reports/spike-wasm-parity.md`.

Structure:
1. Environment, tool versions, OPA version used to build.
2. Verdict: GO, NO-GO, or GO WITH CHANGES, in the first paragraph, with the reason in one sentence.
3. W1 to W5 with evidence.
4. The parity table: every corpus case, both results, match or differ.
5. What could not be determined and what blocked it.
6. If the answer is GO WITH CHANGES, what would have to change in the current Rego or in the v2 plan. Describe the change; do not make it.

## Before finishing

Run `git status` and `git diff --stat` and confirm nothing outside `spikes/wasm-parity/` and `docs/reports/spike-wasm-parity.md` was modified.

---

## Note on a git-base discrepancy found and corrected mid-spike

The spike's worktree was originally created from commit `65dd365`, the tip of `main` at the time. On first inspection of that commit's `policy/core/main.rego`, no `evaluation` rule was present and no `.rego` file referenced `data.system.bundles` - the revision lookup appeared to live entirely in Python (`interceptor/middleware.py`'s `_fetch_opa_bundle_revision`, a separate HTTP call to OPA's system API). An initial version of this file (and the report) recorded that as a discrepancy against the spike spec.

That was wrong, not because the observation was inaccurate for `65dd365`, but because `65dd365` was the wrong commit to be looking at. The actual current work branch is `phase-1-record-truth`, which is `65dd365` plus five further commits (`25a5404`, `33822a6`, `ca688d8`, `3e86a9b`, `96d14d7`). Commit `3e86a9b` ("Phase 1 truth pass") adds exactly the `evaluation` rule the spike spec describes, reading `data.system.bundles[input.bundle_name].manifest.revision`, and repoints `interceptor/middleware.py` to query it (`_OPA_EVAL_URL`, `data.ail.main.evaluation`) as the live per-request path; the old `_fetch_opa_bundle_revision` call is retained only as a startup-only sanity check.

This was caught by the coordinator reviewing the first draft of the report and corrected: the worktree was fast-forwarded onto `phase-1-record-truth` (`git merge --ff-only phase-1-record-truth`, clean since `65dd365` is an ancestor), and W1/W2 were redone against the real `evaluation` rule. `git diff 65dd365 96d14d7 -- policy/packs/gdpr/gdpr.rego policy/packs/hipaa/hipaa.rego policy/packs/soc2/soc2.rego policy/packs/finops/finops.rego` is empty - the four pack files are unaffected, only `policy/core/main.rego` differs, by the addition of `evaluation`. The report reflects the corrected branch throughout; see its "Git base correction" note in section 1.

The GDPR-13-not-12-deny-rules discrepancy (below) is unrelated to this and stands as originally found - it is a property of `gdpr.rego`'s content, unaffected by which branch/commit was checked out.

## Note on the GDPR rule count

The spike premise states 12 deny rules total (GDPR 2, HIPAA 3, SOC2 4, FinOps 3). `policy/packs/gdpr/gdpr.rego` actually contains 3 `deny contains msg if { ... }` blocks (the pci-dss region rule, the unclassified-data region rule, and a `query_database` purpose-limitation rule), making the true total 13. The golden corpus in W3 covers all 13.
