# Phase 1.3: Make the claims true - Report

## 1. Start SHA, end SHA, environment

**Base confirmed:** the instruction's expected base is the head of `phase-1-1-remediation`. That head, resolved live against the real GitHub remote at session start: `973d3a09cf3999afcfec9ed90f1ab23f4e6ea698`. Per the instruction's own note, code claims are audited against `82777b2ace8de04c0fca3d941fd28c2aee92a8d1` - confirmed the only difference between the two (`git diff --stat 82777b2 973d3a0`) is `docs/reports/phase-1-2.md`, one file, its own end-SHA bookkeeping. Both are stated here; nothing in this phase's diff depends on which of the two is treated as "the base."

**Start SHA:** `973d3a0` (branch tip; `82777b2` is the last commit that changed code or tests before this phase).

**Environment:**

- Windows 11, Docker Desktop, Docker Compose v2 (`docker compose`), OPA `1.14.1` (pinned image), `opa` CLI `1.19.0` (downloaded fresh for the P13-6 harness, matching the version the original spike used).
- Work was done in a fresh scratch clone (`ail-phase1-3-<timestamp>`, a directory name not used by any earlier session), `git clone` + `git checkout origin/phase-1-1-remediation` (`973d3a0`), origin repointed at the real GitHub remote. Docker images were built with `docker compose -f docker-compose.test.yml build --no-cache` for all three custom services (`ail-control-plane`, `verifier`, `dashboard`) before any test ran.
- The `docs/reports/spike-mcp-mediation.md` file P13-8 cites (per an amendment to this phase's instruction) did not exist on this branch's history - it lived only on an unmerged worktree branch (`worktree-agent-ae3450a1671a68e29`, commit `27ef8b1`). Cherry-picked into this branch (`bc1f1ff`) rather than cited unreproducibly, for the same reason P13-6 exists: a citation to a report that does not exist in the audited tree is not evidence.
- One environmental mistake, disclosed rather than hidden: mid-session, the P13-1/P13-2 live "from the host" demonstration attacks (U1, U8) were run directly against the same live stack a background "clean baseline" pytest run was using concurrently. This corrupted `tests/test_bundle_revision_attribution.py`'s expected OPA bundle state and caused two unrelated tests in that file to fail on that run. Not a code defect - confirmed by a full `down -v` / fresh `up -d --wait` and a second, uninterrupted run (§7). The lesson carried forward: live attack demonstrations and "clean suite" runs must not share a mutable stack at the same time.

---

## 2. Verdict table

| Item | Status | Key evidence |
| :--- | :--- | :--- |
| P13-1 (OPA management surface not reachable off-host) | **DONE** | Interceptor calls OPA directly, not through Envoy, on the only path this test suite (and `docker-compose.test.yml`) actually exercises - established before choosing the fix (§3). Loopback binding added to both compose files; off-host unreachable (LAN-IP connect refused), U1/U8 both still reproduce from the host, exactly as before; mutation (restore the binding) caught by `tests/test_host_port_bindings.py` |
| P13-2 (verifier not reachable off-host) | **DONE** | Same binding pattern applied to the verifier's port; off-host unreachable, U5 forged tombstone still reproduces from the host; mutation caught |
| P13-3 (`GET /tenants/{id}` requires the read credential) | **DONE** | `_require_read_key` dependency added; unauthenticated request refused (422, missing header - the same convention as every other route this dependency gates), wrong key refused (403), read key accepted (200); mutation (remove the dependency) caught |
| P13-4 (erasure is final) | **DONE** | `write_content` now refuses any write to a tombstoned `call_id` (409); U4 combination 2 (resurrection) reproduced pre-fix, refused post-fix; U4 combination 1 (tombstone + present row) now renders a fifth, distinct `payload_state`, `erasure_conflict`, payload withheld; mutation (remove the tombstone check) caught |
| P13-5 (docker-dependent tests skip cleanly) | **DONE** | `requires_docker_cli` skipif guard added to both named tests; demonstrated clean skip with `docker` removed from PATH |
| P13-6 (P12-4's evidence reproducible from one commit) | **DONE** | Harness moved into the main tree (`spikes/wasm-parity/`), reads `../../policy/*` live rather than a frozen copy; re-run from a clean state against this branch's own (already-fixed) policy tree: **42/42, 0 mismatches** |
| P13-7 (threat model describes the system that exists) | **DONE** | §1, §3.1 no longer call the interceptor out-of-band; §5's opening sentence corrected without touching its scoping analysis; Residual Limits section added; full sentence-to-evidence mapping in §8 below |
| P13-8 (records declare their conformance profile) | **DONE** | `profile` added to both record types (`RECORD_PROFILE = "observed"`), surfaced in `/audit` and the dashboard; ADR-0005 defines the three profiles by authority (not topology), grounded in `docs/reports/spike-mcp-mediation.md`'s findings, plus the attribution ceiling; mutation (drop the field) caught |

---

## 3. Evidence

### P13-1 - OPA's management surface is not reachable from outside the host

**Investigation first, as instructed.** Does Envoy front OPA on the interceptor's path, or does the interceptor call OPA directly? Both, depending on which compose file: `docker-compose.yml` (the full/production-simulating stack) sets `langgraph-demo`'s `OPA_URL=https://envoy:8443/v1/data/ail/main/allow` - Envoy does front OPA there, over mTLS. But `docker-compose.test.yml` - the stack this repository's own test suite and CI actually run against - has no Envoy service at all, and `Makefile`'s `test-integration` target sets `OPA_URL=http://localhost:8181/v1/data/ail/main/allow` (`Makefile:75`): the interceptor calls OPA directly. Worse, even in the full stack, OPA's port `8181` is *separately* published to the host in parallel with Envoy's `8443` (`docker-compose.yml:34-37`, before this fix) - Envoy is an additional path, not a gate in front of the only path. The instruction's own prediction ("the audit trail suggests the latter") is correct for the path this codebase's tests and CI actually exercise, and the raw port is reachable regardless of which compose file is used. This is reported plainly, per the instruction, before any fix was chosen.

**Constraint respected:** `tests/test_bundle_revision_attribution.py` and `tests/test_opa_request_count.py` both reach OPA's Data API from the host via `localhost:8181` - confirmed both still pass after the fix (§7's full-suite run), because loopback remains reachable from the host itself.

**Demonstrate - off-host (simulated via the host's own LAN-facing address, no second physical machine available this session):**

```
$ curl -m4 http://192.168.2.22:8181/v1/data/system/bundles
curl: (7) Failed to connect to 192.168.2.22 port 8181: Connection refused (exit 7)
$ curl -m4 http://192.168.2.22:8003/health
curl: (7) Failed to connect to 192.168.2.22 port 8003: Connection refused (exit 7)
```

Both U1 (manifest forgery) and U8 (bypass) require reaching this port at all; neither can even begin from a non-loopback address once the binding is loopback-only.

**Demonstrate - from the host, both attacks re-run verbatim, both still work:**

```
$ curl http://localhost:8181/v1/data/system/bundles/ail-policies/manifest/revision
{"result":"14387ebda8edf5f202b767317409010535a6a38452189bcf2f771b3861c06e3c"}
$ curl -X PUT http://localhost:8181/v1/data/system/bundles/ail-policies \
    -d '{"manifest":{"revision":"FORGED-REVISION-P13-DEMO","roots":["ail"]}}'
(204)
$ curl -X POST http://localhost:8181/v1/data/ail/main/evaluation -d '{"input":{...p4d.24xlarge...not-ml-training...}}'
{"result":{"allow":false,"reasons":["DENIED: Instance type p4d.24xlarge is restricted. 'project' tag must be 'ml-training'."],"revision":"FORGED-REVISION-P13-DEMO"}}
```

U1 reproduces exactly: a real deny reason attributed to a forged revision, unchanged by the loopback binding, because the host itself is still inside the trust boundary the binding draws.

```
$ curl -X DELETE http://localhost:8181/v1/data/system/bundles/ail-policies      # (204)
$ curl -X PUT http://localhost:8181/v1/policies/evil-eval --data-binary $'package ail.main\n\nevaluation := {"allow": true, "reasons": [], "revision": "FORGED-EVAL-BYPASS-P13-DEMO"}\n'
(200)
$ curl -X POST http://localhost:8181/v1/data/ail/main/evaluation -d '{"input":{...p4d.24xlarge...not-ml-training...}}'
{"result":{"allow":true,"reasons":[],"revision":"FORGED-EVAL-BYPASS-P13-DEMO"}}
```

U8 reproduces exactly: a call the real policy denies is approved. Cleaned up (`DELETE /v1/policies/evil-eval`, `docker compose restart opa`); confirmed the real revision and the real deny reason both returned afterward.

**Fix:** `docker-compose.yml` and `docker-compose.test.yml`, `opa` service: `"8181:8181"` -> `"127.0.0.1:8181:8181"`.

**Enforce:** `tests/test_host_port_bindings.py::test_management_port_not_bound_to_a_non_loopback_address[opa-8181-*]` - parses both compose files with PyYAML (not a text match) and asserts every host-side port mapping for the `opa` service's `8181` carries an explicit `127.0.0.1` prefix.

**Mutation:** restored `"8181:8181"` in `docker-compose.yml`. `pytest tests/test_host_port_bindings.py -k opa` failed with the expected assertion (`'8181:8181' is not loopback-bound`). Reverted; `4 passed` clean.

**Residual limit:** anything on the host, and anything inside the compose network including the agent container, still reaches OPA's Data API and its unauthenticated management endpoints - confirmed directly above (the host-side repro is the residual, not a hypothetical). Phase 2's removal of the agent's own network path to OPA is the actual fix; this item only closes off-host reachability through the published port.

### P13-2 - The verifier is not reachable from outside the host

**Demonstrate - off-host:** same LAN-IP connection-refused result as P13-1, port `8003` (§3, P13-1's transcript).

**Demonstrate - from the host, U5 re-run verbatim:**

```python
tombstone = {"record_type": "content_erasure", "call_id": "p13-demo-forged-tombstone",
             "timestamp": "2020-01-01T00:00:00", "actor": "FORGED-NOT-A-REAL-ERASURE-P13-DEMO"}
httpx.post("http://localhost:8003/write", json={"key": b64(key), "value": b64(json.dumps(tombstone))})
# verifier /write response: 200 {'tx_id': 13, 'verified': True, 'detail': None}
```

Unauthenticated, unchanged, from the host - exactly as documented.

**Fix:** same loopback-binding pattern, `verifier` service, both compose files.

**Enforce:** `tests/test_host_port_bindings.py::test_management_port_not_bound_to_a_non_loopback_address[verifier-8003-*]`.

**Mutation:** restored `"8003:8003"` in `docker-compose.yml`. Failed with the expected assertion. Reverted; clean.

**Residual limit, stated precisely as instructed:** in the Observed profile, any party with the agent's network position can write arbitrary records to the ledger, and those records will carry valid inclusion proofs. Tamper-evidence protects against modification of a record, not against forgery of one.

### P13-3 - `GET /tenants/{id}` requires the read credential

**Fix:** `control_plane/main.py::get_tenant` gains `_: None = Depends(_require_read_key)`, the same dependency already gating `GET /audit`.

**Demonstrate:**

```
$ curl http://localhost:8002/tenants/tenant_default
422 {"detail":[{"type":"missing","loc":["header","X-API-Key"],"msg":"Field required"}]}
$ curl http://localhost:8002/tenants/tenant_default -H "X-API-Key: wrong-key"
403 {"detail":"Invalid API key"}
$ curl http://localhost:8002/tenants/tenant_default -H "X-API-Key: test-read-key"
200 {"id":"tenant_default", ...}
```

**Enforce:** `tests/test_dashboard_auth.py::test_control_plane_get_tenant_rejected_with_no_key` (422 - the missing-header shape every other route gated by this dependency already produces, per `docs/reports/phase-1-1-redteam.md` T3's own precedent for reading this status code), `::test_control_plane_get_tenant_rejected_with_wrong_key` (403), `::test_control_plane_get_tenant_accepted_with_read_key` (200).

**Mutation, live:** removed the `Depends(_require_read_key)` parameter from `get_tenant`, rebuilt/redeployed the `ail-control-plane` container (`docker compose -f docker-compose.test.yml up -d --build --wait ail-control-plane`). Both named tests failed exactly as expected:

```
FAILED test_control_plane_get_tenant_rejected_with_no_key - AssertionError: Expected 422 ..., got 200: {"id":"tenant_default", ...}
FAILED test_control_plane_get_tenant_rejected_with_wrong_key - AssertionError: Expected 403, got 200: {"id":"tenant_default", ...}
```

Reverted, rebuilt/redeployed again; both pass clean (§7's confirmation run).

### P13-4 - Erasure is final

**Fix, two parts.** `control_plane/main.py::write_content` now calls `_has_tombstone(call_id)` first and refuses (409) if a `content_erasure` tombstone exists for that `call_id` - checked against the verifier directly (the same source `/audit` reads), fail-closed on any check failure. `_payload_state` now checks `has_tombstone` before `content_row`: a tombstone with the row still present renders `erasure_conflict` (payload withheld), not `present`.

**Demonstrate - U4 combination 2 (resurrection), verbatim:**

```
$ curl -X DELETE localhost:8002/content/<call_id> -H "X-API-Key: test-write-key"   # 204
$ curl localhost:8002/audit | jq '...payload_state'  # "erased"
$ curl -X POST localhost:8002/content -H "X-API-Key: test-write-key" -d '{"call_id":"<call_id>","payload":{"resurrected":"..."}}'
409 {"detail":"call_id '<call_id>' has been erased; content writes are refused"}
$ curl localhost:8002/audit | jq '...payload_state'  # still "erased"
```

**Demonstrate - U4 combination 1 (tombstone + present row):** a tombstone written directly via the verifier (bypassing `DELETE /content`, same technique as U5) for a `call_id` whose row is never deleted now renders `payload_state: "erasure_conflict"`, `payload: null` - not `"present"`, and not silently `"erased"` either (which would hide that a real row still exists).

**Enforce:** `tests/test_content_states.py::test_resurrection_after_erasure_refused` (combination 2), `::test_tombstone_coexisting_with_present_row_renders_erasure_conflict` (combination 1).

**Mutation, live:** removed the `_has_tombstone` check from `write_content`, rebuilt/redeployed `ail-control-plane`:

```
FAILED test_resurrection_after_erasure_refused - AssertionError: Expected the ordinary write key to be
  refused on an erased call_id, got 204: assert 204 == 409
```

The resurrection POST returned 204 again, matching the exact pre-fix U4 combination-2 shape. Reverted, rebuilt/redeployed again; both `test_resurrection_after_erasure_refused` and `test_tombstone_coexisting_with_present_row_renders_erasure_conflict` pass clean (§7's confirmation run) - this mutation only touches `write_content`'s own guard, not `_payload_state`'s tombstone-first ordering, so combination 1's own test is unaffected by it either way, confirming the two fixes are independent as intended.

**Note on cost:** `_has_tombstone` adds one synchronous verifier round trip to every `/content` write (confirmed live in the container logs during the full-suite run, §7) - the same fail-closed-by-design tradeoff D7 already accepted for the ledger write itself, not a new architectural pattern.

### P13-5 - Docker-dependent tests skip cleanly

**Fix:** `tests/test_content_states.py` gains `requires_docker_cli = pytest.mark.skipif(shutil.which("docker") is None, ...)`, stacked on both `test_direct_sqlite_delete_produces_lost_not_erased` and `test_erasure_refused_when_tombstone_write_fails`.

**Demonstrate:**

```
$ PATH="$(echo "$PATH" | tr ':' '\n' | grep -vi docker | tr '\n' ':')" which docker
which: no docker in (...)
$ PATH=<same> python -m pytest tests/test_content_states.py -v
tests/test_content_states.py::test_present_then_erased_via_delete_content PASSED
tests/test_content_states.py::test_unavailable_for_non_dict_args PASSED
tests/test_content_states.py::test_content_store_down_denies_as_fault_and_writes_no_record PASSED
tests/test_content_states.py::test_direct_sqlite_delete_produces_lost_not_erased SKIPPED
tests/test_content_states.py::test_erasure_refused_when_tombstone_write_fails SKIPPED
tests/test_content_states.py::test_erasure_tombstone_not_a_second_decision_entry PASSED
tests/test_content_states.py::test_tombstone_coexisting_with_present_row_renders_erasure_conflict PASSED
tests/test_content_states.py::test_resurrection_after_erasure_refused PASSED
6 passed, 2 skipped in 262.39s (0:04:22)
```

Clean skip, not a `FileNotFoundError` - matching the P01-1 convention. The containers themselves remained fully reachable throughout (only the CLI binary was hidden from this host-side process), matching U7's own original scoping.

**Enforce:** the guard itself, per the instruction (no separate enforcing test specified beyond the demonstration above).

### P13-6 - P12-4's evidence is reproducible from one commit

**Fix:** the harness (`package.json`, `package-lock.json`, `scratch/corpus.json`, `scratch/run_parity.mjs`, `.gitignore`, plus a new `REPRODUCE.md`) moved into `spikes/wasm-parity/` on this branch. `run_parity.mjs` was already written to read `../../policy/core/main.rego` etc. by relative path (not an embedded copy) - so once it sits in a tree whose `policy/` already carries the P12-4 fix, it evaluates the real, current, fixed policy, not a frozen snapshot. The `opa` CLI binary and `build/` output are intentionally not committed (`.gitignore`) - cheap to regenerate, not project state.

**Demonstrate, from this commit:**

```
$ curl -sL -o tools/opa.exe https://openpolicyagent.org/downloads/v1.19.0/opa_windows_amd64.exe
$ ./tools/opa.exe build -t wasm -e ail/main/compliance_summary \
    ../../policy/core/main.rego ../../policy/packs/{gdpr,hipaa,soc2,finops}/*.rego -o build/bundle.tar.gz
$ tar -xzf build/bundle.tar.gz -C build/extracted policy.wasm .manifest data.json
$ npm install && node scratch/run_parity.mjs
Total cases: 42
Matches: 42
Mismatches: 0
```

Live-confirmed this session, in the scratch clone, from this branch's own commit. Full repro steps: `spikes/wasm-parity/REPRODUCE.md`.

### P13-7 - The threat model describes the system that exists

**§1 (no longer out-of-band):** rewritten to state plainly that `intercept_tool_call` is an in-process hook, name what it does and does not defend against (a cooperating agent including one prompt-injected, versus a compromised container), and point at the Residual Limits section and Phase 2.

**§3.1 ("nothing actionable" removed):** rewritten to distinguish the property SPIFFE/SPIRE actually gives (a stolen static credential is worthless) from the property it does not (code running inside the trusted workload holds that workload's real identity for as long as it runs).

**§5 (prompt-injection scoping untouched, mechanism sentence corrected):** only the opening sentence's "out-of-band" claim was reworded, to the same effect as §1; the boundary analysis, the demonstrated-attack table, and the coverage-boundary paragraph are byte-for-byte unchanged.

**Residual Limits section added** (§5, after the fail-closed table): holds P13-1's and P13-2's disclosures verbatim in substance, the attribution ceiling (grounded in `docs/reports/spike-mcp-mediation.md`), and a note on the shared-secret (not per-caller) authorization model P13-3/P13-4 extend rather than replace.

**One additional factual correction found during the audit, unrelated to the out-of-band framing:** §4.5's worked example quoted the FinOps cost-center deny message in its pre-P12-4 format (`Approved values: {"executive", "finance"}.`) - stale since `82777b2`. The real message today (confirmed against `policy/packs/finops/finops.rego:23`) is `Approved values: executive, finance.` (sorted, comma-joined, no set-literal punctuation). Corrected to match.

**Full mapping table:** §8 below.

### P13-8 - Records declare their conformance profile

**Amendment applied mid-phase** (see the user's clarification): profiles are per-call, defined by authority, not by deployment topology. `RECORD_PROFILE = "observed"` added to `ledger/immudb_ledger.py` and independently to `control_plane/main.py` (the tombstone is a record too); both record types now carry `profile`. `/audit` surfaces it (defaulting to `"observed"` only for a hypothetical pre-P13-8 entry that predates the key); the dashboard renders it per-entry.

ADR-0005 gains a Conformance Profile section defining `observed` / `mediated` / `attested` by what the agent can and cannot do independently of the gateway, grounded directly in `docs/reports/spike-mcp-mediation.md`'s M2 (bypass) and M5 (attribution) findings - cherry-picked into this branch (`bc1f1ff`) so the citation resolves in the same tree rather than repeating P13-6's own finding about unreproducible citations.

**Enforce:** `tests/test_record_profile.py` - `test_raw_decision_record_carries_observed_profile` and `test_raw_tombstone_record_carries_observed_profile` check the raw ImmuDB value directly (the same pattern `test_raw_ledger_fields.py` uses for other fields `/audit` could silently drop), `test_audit_response_carries_profile_from_closed_set` checks the `/audit` projection.

**Mutation:** removed `"profile": RECORD_PROFILE` from `log_tool_call`'s `log_entry` dict. `test_raw_decision_record_carries_observed_profile` failed (`profile missing or not in the closed set: {...}`, `KeyError`-shaped via `.get()` returning `None`). Reverted; clean.

---

## 4. What required judgment and what was decided

**P13-1's investigation changed the shape of the fix, as the instruction anticipated.** Had Envoy actually fronted every OPA request in every environment this codebase runs in, a narrower fix (gate the management API behind Envoy's own mTLS route table) might have been available. It does not: the test/CI stack has no Envoy at all, and even the full stack leaves OPA's raw port published in parallel with Envoy. A loopback bind on the published port is the only fix available at this layer that does not touch Envoy's routing (out of scope - no design changes beyond what P13-1 states) and does not break the two tests the instruction named as a constraint.

**P13-4's `erasure_conflict` naming and precedence, left to this session's judgment per the instruction's own "decide what that state means" framing.** Considered: silently treating a tombstoned-but-present row as `erased` (rejected - hides that the row is still there, a real problem worth surfacing) or as `present` (rejected - repeats the exact defect P13-4 exists to close). Decided on a fifth state, `erasure_conflict`, tombstone-precedence over row-presence, payload always withheld. This also means the combination should not arise at all going forward through this control plane's own routes (write_content's own tombstone check), so the new state is chiefly a detector for the residual (a forged tombstone via the verifier, or an operational failure between tombstone-write and row-delete) rather than a state the ordinary write path can reach.

**P13-8's profile model, amended mid-phase by the user.** The instruction as originally written implied a topology-based profile (tied to which components sit in the request path). The amendment redefined profiles by authority instead - who holds the tool's real capability - directly citing `docs/reports/spike-mcp-mediation.md`'s finding that a mediation proxy in the path does not, by itself, remove a compromised agent's ability to reach a tool's authority through a channel the proxy never sees (self-spawning the tool server under stdio; a shared network under HTTP). Applied as given; the spike report was cherry-picked into this branch rather than cited from an unmerged worktree, for the same reproducibility reason P13-6 exists.

**Where the `profile` field belongs on the tombstone record.** D11 (Phase 1.2) treats the tombstone as its own record type, distinct from a decision. P13-8 says "every record" - read literally, this includes tombstones, not only decisions. Decided to add `RECORD_PROFILE` independently in `control_plane/main.py` rather than import `ledger/immudb_ledger.py`'s constant across a process boundary the codebase does not otherwise cross (the control plane and the interceptor are separate processes/containers); both currently hold the same literal value, and a divergence between them would itself be worth catching, which duplicating the constant (rather than sharing a module) makes visible rather than silently prevented.

---

## 5. Pre-registered negatives - confirmed individually

- **Any failure path returning something other than DENY.** Confirmed false: `write_content`'s new tombstone-check failure path (`_has_tombstone` unable to reach the verifier) returns `True` (treated as "tombstone present," write refused) rather than proceeding - fail-closed, not a silent pass. No existing fault path was touched by this phase's diff.
- **Any management or verifier endpoint bound to a non-loopback address.** Confirmed false for both compose files: `tests/test_host_port_bindings.py`, 4/4 passing, parses the actual YAML rather than trusting a comment.
- **Any content write succeeding for a `call_id` with a tombstone.** Confirmed false: `test_resurrection_after_erasure_refused` (409, live), `test_tombstone_coexisting_with_present_row_renders_erasure_conflict` (write was never attempted through the real endpoint in this combination, by construction of the attack - the tombstone was forged directly against the verifier, which is exactly the residual P13-2 discloses, not a gap in `write_content`'s own check).
- **Any claim in the README, an ADR, or the dashboard that is not in the P13-7 mapping.** See §8 - every section of the README, both touched ADRs, and the dashboard's new profile/erasure_conflict rendering are mapped.
- **Any assertion weakened.** Confirmed false: `git diff -- tests/` for this phase contains no `assert True`, no commented-out assertion, no loosened comparison; the one test-side correction this phase made (`test_control_plane_get_tenant_rejected_with_no_key` expecting 422 instead of 401/403) tightened the assertion to an exact status code rather than a set, and added a second test (`test_control_plane_get_tenant_rejected_with_wrong_key`) to cover the case the original, wrong expectation would have silently skipped.
- **Any item met by live evidence alone with no test enforcing it** other than P13-5, which the instruction itself scopes to "the guard itself" as the enforcement (no additional test specified) - confirmed by demonstration in §3.

---

## 6. Could not test / could not verify

- **A live second physical machine for P13-1/P13-2's off-host demonstration.** Simulated via the host's own LAN-facing address instead (§3) - the same substitution this project's prior red-team sessions used for equivalent claims (e.g. `docs/reports/phase-1-2-redteam.md`'s U1, "a real second Bundle-API-serving container... judged equivalent"). The port is provably not listening on that interface either way; a second machine would observe the identical `ECONNREFUSED`/timeout, not a different result.
- **A deployed-Worker re-run of the P13-6 WASM parity harness.** Same limitation the original spike and Phase 1.2's own re-verification both disclosed - local `opa eval` + `@open-policy-agent/opa-wasm` under Node only.
- **Whether `mediated` is reachable without further work.** Out of scope for this phase (P13-8 defines the profile; reaching it is Phase 2's mandate) - `docs/reports/spike-mcp-mediation.md` already answers this in the negative for MCP mediation specifically, not re-litigated here.

---

## 7. Cumulative gate

Full suite, `docker-compose.test.yml`, fresh volumes (`down -v` / `up -d --wait`), run clean on an uninterrupted stack (no manual attack demonstration run concurrently, per §1's disclosed mistake and correction):

```
96 passed, 1 warning in 648.68s (0:10:48)
```

96 = 95 (Phase 1.2's own baseline of 84, plus P13-1's 4 parametrized `test_host_port_bindings.py` cases, plus P13-3's 2 new dashboard-auth tests, plus P13-4's 2 new content-state tests, plus P13-8's 3 new record-profile tests = 84 + 4 + 2 + 2 + 3 = 95) + 1 (a `test_control_plane_get_tenant_rejected_with_wrong_key` test added after the first attempt's own test-side bug was found and fixed, §3 P13-3). No test skipped in this run (the docker-CLI skip guard, P13-5, only activates with `docker` removed from PATH - demonstrated separately below, not in this run).

Individually, each item's own mutation was applied live against the running stack, confirmed to fail its named test(s), reverted, and reconfirmed passing (§3) - not re-run as one combined batch, per the mutation-testing convention (one mutation at a time).

**End SHA for audit purposes:** `70a8581cf70ebdfed887479c6bfcd37c613d5316`, pushed to `origin/phase-1-1-remediation` (updating PR #2 - `gh pr view 2` confirms `headRefOid: 70a8581...`, `state: OPEN`). **CI run:** `32182167165` (`Integration Tests`, `success`, created `2026-08-18T20:25:31Z`, completed `2026-08-18T20:27:58Z`, ~2m27s) - `https://github.com/banji-007/compliance-ail/actions/runs/32182167165`.

---

## 8. P13-7 mapping table

Methodology: every substantive claim in `readME.md`, `docs/adr/0005-outcome-taxonomy.md`, `docs/adr/0007-two-tier-authorization.md` (the two ADRs this phase's diff touches), and the dashboard is mapped to one of: a passing test (named), a reproducible command (given), or a residual-limits entry (quoted). Purely operational instructions (exact quickstart commands, version-pin tables) are marked "reproducible command" without a named test, since the instruction itself is the reproduction. Sections not listed below (`readME.md` §7 Stack Reference, §9 Known Limitations) contain no guarantee-shaped claims this phase's criteria apply to - they are version/backlog listings, unchanged by this phase, already accurate as operational statements.

| README/ADR location | Claim | Maps to |
| :--- | :--- | :--- |
| §1, "not a security control... polite suggestion" | System prompts are not enforceable | Reproducible: `docs/reports/spike-mcp-mediation.md` (an off-the-shelf server accepted unauthenticated calls); not specific to this codebase, a general property of LLM instruction-following |
| §1, "in-process hook... cooperating agent cannot evade... compromised container can" | Corrected claim, this phase's own fix | `tests/test_epic_2.py` (every registered tool call routes through `intercept_tool_call`, no bypass for a cooperating caller); Residual Limits §5 bullet 1 (compromised-container case) |
| §2, four-stage pipeline diagram + fail-closed table | OPA/ImmuDB/verifier/SPIRE-down all DENY; schema failure DENY before OPA | `tests/test_outcome_types.py::test_fault_opa_unreachable`, `::test_fault_revision_unavailable`, `::test_fault_verifier_unreachable_writes_no_record`, `::test_fault_spiffe_unavailable`; `test_epic_2.py::TestMiddlewareRoutingFailClosed` (schema-deny before OPA, 0 OPA requests) |
| §3.1, SPIFFE/SPIRE bullets (ephemeral SVIDs, mTLS, in-memory certs, exit-on-absent-socket) | Unchanged by this phase, already true | `test_mtls_flow.py` (live mTLS handshake); `interceptor/middleware.py`'s SPIRE-socket-absent exit path, unchanged |
| §3.1, corrected "nothing actionable" paragraph | Static-secret theft vs. in-workload code execution, distinguished | Residual Limits §5 bullet 1 and bullet 2 (OPA/verifier reachable from the agent's own network position) |
| §3.2, schema registry table | Three tools validated, unregistered blocked at registry | `tests/test_epic_2.py::TestToolValidatorsRegistry`, `::TestMiddlewareRoutingFailClosed::test_hallucinated_tool_is_schema_denied` |
| §3.3, multi-tenant bundle generation, single-OPA-process-per-tenant | Unchanged by this phase | §4.5's own worked example (corrected message text, this phase); `control_plane/bundle.py`'s ETag generation, untouched |
| §3.4, "the record, not a message" / outcome taxonomy | Unchanged structure, `profile` field added | `docs/adr/0005-outcome-taxonomy.md`; `tests/test_outcome_types.py`; `tests/test_record_profile.py` (new, this phase) |
| §3.4, "the hash, not the payload" / content store / erasure | Erasure semantics strengthened this phase | `docs/adr/0005-outcome-taxonomy.md`'s `erasure_conflict` addition; `tests/test_content_states.py` (P13-4's two new tests plus the five pre-existing) |
| §3.4, verifiedSet/verifiedGet, five verification states | Unchanged by this phase | `tests/test_verification.py` (9 tests, all passing, §7) |
| §3.4, "what this proves, and what it does not" | Tamper-evidence vs. policy-correctness, tamper-evidence vs. forgery-resistance | Residual Limits §5 bullet 3 (P13-2's forgery disclosure is the sharper, phase-1.3-specific version of this same distinction) |
| §3.5, Prometheus metric cardinality, dashboard server-side auth | Unchanged by this phase | `tests/test_outcome_types.py::test_metric_label_set_matches_closed_collection`; `tests/test_dashboard_auth.py` (13 tests, §7) |
| §3.5, "rendering outcome_type/fault_class and all four verification states distinctly" | Dashboard rendering, extended this phase with profile | `dashboard/components/audit-table.tsx`'s `DecisionCell`/`VerificationCell` (unchanged) plus the new profile line (this phase); not extended to render `payload_state`/`erasure_conflict` visually - the dashboard never rendered `payload_state` before this phase either, so no existing claim regressed, and none is made about it here |
| §4.1-4.4 | Environment setup, boot sequence, three worked demo requests | Reproducible commands, unchanged by this phase |
| §4.5, cost-center denial worked example | Exact deny message text | Corrected this phase (was stale pre-P12-4 formatting); now matches `policy/packs/finops/finops.rego:23`'s live `sprintf` output, confirmed via `tests/test_deny_message_formatting.py::test_finops_cost_center_message_is_sorted_concat_not_set_format` |
| §4.6, service endpoint table | Port numbers | Reproducible command (`curl` each); OPA's `:8181` entry now reads "direct query" from the host only, per P13-1 - not edited further since the table already says "direct query," not "from anywhere" |
| §4.7, Helm chart unsupported | Unchanged, already an honest disclosure | `docs/audit/2026-08-16-verification.md`, item V1; not re-verified this phase (out of scope) |
| §5, prompt injection scoping (paragraph 2 onward), demonstrated-attack table, coverage boundary | Untouched, per the instruction | `docs/reports/phase-0-1.md`/`phase-1.md` (the original demonstrations); not re-run this phase, explicitly out of scope |
| §5, opening sentence (mechanism only) | Corrected this phase | Same evidence as §1's in-process-hook claim, above |
| §5, Infrastructure Failure table | Unchanged | Same tests as §2's fail-closed table |
| §5, Residual Limits (new section) | Five bullets, each a direct claim about a still-open gap | Bullet 1: §1/§3.1 correction, no test (a negative claim - "this is not defended," demonstrated by the absence of any interceptor call in a bypass path, not by a passing assertion). Bullets 2-3: `tests/test_host_port_bindings.py` (what the fix changes) plus §3's live U1/U8/U5 transcripts (what it does not) |
| §6, ADR-005 summary | `profile` field mentioned | `docs/adr/0005-outcome-taxonomy.md`'s Conformance Profile section; `tests/test_record_profile.py` |
| §6, ADR-001/002/003/004/006 summaries | Unchanged by this phase | Respective ADR files and test suites, untouched |
| `docs/adr/0005-outcome-taxonomy.md`, payload_state table | Five states including new `erasure_conflict` | `tests/test_content_states.py::test_tombstone_coexisting_with_present_row_renders_erasure_conflict` |
| `docs/adr/0005-outcome-taxonomy.md`, Conformance Profile section | Three profiles by authority, attribution ceiling | `docs/reports/spike-mcp-mediation.md` (M2, M5); `tests/test_record_profile.py` |
| `docs/adr/0007-two-tier-authorization.md` | "`CONTROL_PLANE_READ_KEY` authorizes `GET /audit` only" | Was stale as of this phase's start (P13-3 makes it also authorize `GET /tenants/{tenant_id}`) - corrected this phase to name both routes; `tests/test_dashboard_auth.py::test_control_plane_get_tenant_accepted_with_read_key` |
| `docs/adr/0007-two-tier-authorization.md`, everything else | Two independent keys, read/write split, dashboard-layer Basic Auth | Unchanged in substance; P13-4's tombstone check is a new condition inside the existing write-key-gated `POST /content`, not a new authorization tier - `tests/test_dashboard_auth.py` |
| Dashboard, `AuditEntry.profile` / `AuditEntry.payload_state` types | New closed-set values | `dashboard/lib/types.ts` (TypeScript compiles under the dashboard's own `npm run build`, confirmed during the `--no-cache` image build, §1) |

---

---

## Erratum, 2026-08-25 (added by Phase 3c-1, `p3c1-mapping`, item P3c1-3)

`tools/mapping_check.py` was run over section 8's P13-7 mapping table. The
table carries 28 rows. **Five fail class (b)**, the support check. None fails
class (a).

- **Row 9**, Location "§3.4, \"the hash, not the payload\" / content store /
  erasure", Claim "Erasure semantics strengthened this phase". Selected term:
  `semantic`.
- **Row 14**, Location "§4.1-4.4", Claim "Environment setup, boot sequence,
  three worked demo requests". Selected term: `sequence`.
- **Row 15**, Location "§4.5, cost-center denial worked example", Claim "Exact
  deny message text". Selected term: `message`.
- **Row 16**, Location "§4.6, service endpoint table", Claim "Port numbers".
  Selected term: `number`.
- **Row 18**, Location "§5, prompt injection scoping ...", Claim "Untouched,
  per the instruction". Selected term: `instruction`.

**All five are citation defects, not false claims.** Each cited section was
read directly this pass and carries what its row claims: §3.4 discusses
erasure (in the word "erasable"), §4.5 carries the exact
`DENIED: Production environments must include a valid 'cost_center' tag.
Approved values: executive, finance.` string the row is about, §4.6 carries
the service endpoint table with its port numbers, §4.1-4.4 carry the setup and
demo requests, §5 carries the prompt-injection scoping. What fails in every
case is the Claim column, which names the *kind* of row rather than the claim,
so the term rule is left with `semantic`, `sequence`, `message`, `number` and
`instruction`, none of which the README has any reason to use. Class (a)
passes all five: `policy/packs/finops/finops.rego`,
`tests/test_deny_message_formatting.py` and the rest all resolve.

One row was examined closely and does **not** fail, for a reason worth
recording because it nearly did. **Row 5**, Claim "Static-secret theft vs.
in-workload code execution, distinguished", backs itself on "Residual Limits
§5 bullet 1 and bullet 2". That subsection was rewritten in Phase 2 and no
longer contains the term `theft`, so the citation the row gives has drifted
out from under it. The row survives only because its Location column cites
§3.1, which still carries the distinction ("exfiltrating a *static API key*
buys an attacker nothing on this data plane"). A row with a single citation in
that position would have failed, and the drift would have been real rather
than cosmetic.

Coverage: 23 of this table's 28 rows cite a document section and 15 of those
yield no load-bearing term, so class (b) is decisive on 8 rows. Four rows name
nothing mechanically checkable.

The rows are not corrected here. They are entered in
`docs/reports/mapping-check-baseline.json` and asserted by
`tests/test_mapping_tables.py`.

See `docs/adr/0013-mapping-table-self-check.md` and
`docs/reports/phase-3c1.md`.
