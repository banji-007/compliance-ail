# Phase 0: Truth pass

Start SHA: record `git rev-parse HEAD` before any change. End SHA: record after.
Inputs: `docs/audit/2026-08-16-verification.md`, `docs/plan/ail-v2-plan.md`.

## Purpose

Every claim the repo makes must be backed by something that runs. No new capability is built in this phase. This is the precondition for the v2 work, not part of it.

## Standing rules

- **No design changes.** If an acceptance criterion cannot be met without altering the architecture, adding a dependency, or changing a schema, **stop and escalate**. Do not implement around it. An escalation is a successful outcome; a criterion met by quietly redesigning is a failure even if the tests pass.
- **Never widen an assertion to make a test pass.** If narrowing or collecting a test reveals that it fails or that a vector does not fire, report that. Do not fix it in this phase.
- No new tools, no new Rego rules, no WASM, no Rekor, no hosted anything.
- Comments explain why, not what. No change-history narration. No em dashes anywhere, code or prose.
- Each item below is pre-registered. Report `MET`, `NOT MET`, or `ESCALATED` against the stated criterion, nothing else.

---

## P0-1. Recorded policy digest must be the policy that ran

The defect: `_compute_policy_hash` (`interceptor/middleware.py:154-188`) HEADs `/bundles/{AIL_TENANT_ID}` using the **interceptor's** env, which has no relationship to the bundle the OPA process actually loaded. The audit reproduced a ledger entry stamped with the `tenant_finance` digest for a decision OPA computed against `tenant_default`. On error the same function returns `bundle-hash-unavailable` and the write proceeds anyway.

**Design decision, not open for redesign:** the digest is sourced from the OPA instance that produced the decision, in the same evaluation cycle. If it cannot be obtained, the call **denies**. There is no placeholder value. Delete `_compute_policy_hash` and its control-plane round trip entirely.

Implementation route, in order of preference:

1. Control plane sets `revision` in the generated bundle `.manifest` to the same SHA-256 it already uses for the ETag. The interceptor reads the loaded revision back from the OPA instance it just queried. Check first whether `control_plane/bundle.py` already writes a revision; if it writes an empty one, that is the fix.
2. If the revision is not reachable from the decision path, a second read against the same OPA instance in the same cycle is acceptable.

If neither is achievable, escalate with what you found. Do not fall back to the control plane.

**Acceptance:**
- A test proves that when OPA has `tenant_default` loaded and the interceptor env says `tenant_finance`, the recorded digest is the one OPA loaded, or the call denies. This is the exact V2 scenario; reproduce it live.
- A test proves that when the digest cannot be established, the result is `DENIED` and **no ledger entry is written**.
- `grep -rn "bundle-hash-unavailable" .` returns nothing outside the audit report.

This closes V2 and V4 together. It is the only item in Phase 0 that touches enforcement behavior, so it gets the most careful review.

---

## P0-2. Section 4.5 must work as written

Two independent defects. Fix both.

First: the README's verbatim Step 2 prompt states no hourly cost, so the LLM emits `cost_per_hour: 0.0` and the call dies at Pydantic validation before OPA is queried. It prints `DENIED`, which is what the reader expects, for entirely the wrong reason. **Fix the prompt text, not the schema.**

Second: the documented procedure cannot switch tenants. `docker compose run -e AIL_TENANT_ID=tenant_finance langgraph-demo` sets the variable on the agent only; OPA resolves its bundle resource once at process start. Rewrite the procedure to recreate the OPA container against the finance bundle, then run the agent.

Also correct section 3.3 and the section 4.5 closing line. The truthful statement is that isolation is achieved by a dedicated OPA process per tenant, which is what the Helm chart already does. "The same OPA process, two isolated policy brains" is false and must go.

**Acceptance:** execute the corrected section 4.5 verbatim from a clean stack and paste the transcript. Step 2 must be denied by the FinOps cost-center rule, with that message, and the container log must show the request reaching OPA. Step 3 must be approved.

---

## P0-3. The demo must not report failures that did not happen

The audit observed the agent telling the operator the audit ledger had failed, on all four runs where `Ledger write verified: tx=N` appears in the logs and the entry is retrievable from `/audit`.

Root-cause it. Fix only if the fix is local and does not change the architecture. If the cause is structural, escalate with the diagnosis rather than patching the symptom.

**Acceptance:** an approved call produces an agent reply consistent with the ledger state, demonstrated on three consecutive runs. Or an escalation naming the mechanism.

---

## P0-4. The gate must collect what it claims

Five test methods across `tests/test_agent.py`, `tests/test_interceptor.py`, and `tests/test_ledger.py` are silently dropped because their classes define `__init__`. Restructure so pytest collects them. Do not alter what any of them asserts.

If a newly collected test fails, **report it and leave it failing.** Do not weaken it, skip it, or fix it in this phase.

**Acceptance:** collected item count rises from 29 to 34; record the new count and the pass/fail status of each of the five. Zero `PytestCollectionWarning` in the output.

---

## P0-5. The integration suite must pass on a machine with a root `.env`

Compose auto-loads the root `.env` regardless of which `-f` file is passed, so the test stack's control plane enforces the developer's real API key while the Makefile passes `test-api-key` to pytest. `test_cross_process` fails with 403 for every contributor who has an `.env`.

Pick the fix. One value must reach both the compose stack and pytest.

**Acceptance:** with a populated root `.env` containing a `CONTROL_PLANE_API_KEY` different from the test default, the full suite passes. State the command run and the summary line.

---

## P0-6. Tamper coverage claim scoped to reality

Of the five tests in `tests/test_verification.py`, one exercises a realistic tamper vector. `test_tamper_pubkey` overwrites `_vk` on a client object the test itself constructed, which models a key-rotation misconfiguration and not an attack.

Correct the claim in README section 3.4 and in ADR-001's References. Do not write a new tamper test in this phase; add it to `TODO.md` instead, with the vector it should cover.

**Acceptance:** no document claims more tamper coverage than exists; a TODO entry names the missing test.

---

## P0-7. Helm chart marked unsupported

The chart renders no verifier and injects pre-ADR-001 ImmuDB credentials into the agent pod. A charted deployment denies every call.

**Do not port the verifier.** The hosted direction may retire the chart entirely; porting it now is work we may throw away.

Add a prominent notice at the top of `charts/ail-gateway/README.md` and remove or qualify the "production-ready Helm chart" and "the production path" language in README section 4.7.

**Acceptance:** no document presents the chart as deployable.

---

## P0-8. Housekeeping

Low risk, reduces reviewer noise. Each is independent; do what is safe and report what you skipped.

- Six legacy `test_*.py` files at repo root, 543 lines, outside the gate. Before deleting, confirm each is stale or duplicated by `tests/`. If any covers something `tests/` does not, move it rather than delete it.
- Stray empty `policy;C` directory at repo root.
- ADR-002 is presented in the README's numbered ADR list but has no file in `docs/adr/`. Extract it to `docs/adr/0002-fastapi-immudb-proxy.md`.
- Em dashes in `interceptor/schemas.py` comments; double period at the end of README section 5's prompt-injection paragraph.
- `_SENSITIVE_KEYS` (`interceptor/middleware.py:50`) omits `tags`, so free text in `provision_cloud_server` tags is unredacted even in stdout. Add it. Note in the report that this affects logging only; the ledger still stores raw payloads until Phase 1.

**Acceptance:** `pytest tests/` from the repo root and `pytest` from the repo root collect the same set.

---

## Report

Write `docs/reports/phase-0.md`. Two reviewers read it alongside the diff, so keep it evidence-first.

Required sections:

1. **Start SHA, end SHA, environment.** Include anything you had to do beyond the documented setup.
2. **Verdict table.** One row per item P0-1 to P0-8: `MET` / `NOT MET` / `ESCALATED`, plus the evidence, which means a command and its output or a `path:line`.
3. **Could not verify.** Anything you asserted without directly observing, and what blocked observation. This section being empty is itself a claim; only write it if it is true.
4. **Worked around.** Anything you did to get past an obstacle that is not in the diff, and anything that felt like it was pushing toward a design change.
5. **Cumulative gate.** New collected item count, pass/fail, and the exact command.
6. **Discovered outside scope.** Anything found that P0-1 to P0-8 does not cover, especially further drift between README, ADRs, and code.

No remediation proposals for items outside scope. Findings only.
