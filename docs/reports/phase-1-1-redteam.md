# Phase 1.1 Red-Team Report

## 1. Environment, branch/head confirmation, developer-state confirmation

Fresh CC session, no memory of building Phase 1.1. Confirmed via `gh run list --branch phase-1-1-remediation`: run `32054605848` ("Integration Tests"), `success`, matching the brief exactly. `git log --oneline main..origin/phase-1-1-remediation` showed six commits, head `e7e9607` ("fix(interceptor,ledger,control-plane,dashboard,verifier): Phase 1.1 remediation - D6-D8, P11-1..9"), matching the brief's stated PR head.

Work was done in a fresh scratch clone (`redteam-1-1`, a directory name not used by any earlier session), `git clone` + `git checkout phase-1-1-remediation` at `e7e9607`. Docker images were built with `docker compose build --no-cache` for all three custom services (`ail-control-plane`, `verifier`, `dashboard`) before any test ran.

**Pre-existing violation of the standing rule, found and left untouched.** Before starting my own stack, `docker ps -a` showed a five-container stack already running under the Compose project name `compliance-ail`, up ~43 minutes, with `com.docker.compose.project.config_files` and `.working_dir` pointing directly at the **primary working directory** (`C:\Users\banji\OneDrive\Documents\compliance-ail\docker-compose.test.yml`), holding host ports 8002/8003/3322/8080/8181/3001. This predates every action in this transcript — the primary directory's current branch (`spike-wasm-parity-report`, based on `main`) has no Phase 1.1 code, and `git status --short` there was clean throughout, so nothing in this session created it. It directly contradicts the brief's standing rule ("work in a scratch clone... do not touch named volumes there") and must have been started by an earlier, different session against the same working directory. I did not stop, inspect further, or otherwise touch it — I worked around the port collision by remapping only my own scratch clone's host-side ports (`docker-compose.test.yml`, edited and reverted via `git checkout --` at the end, same pattern as every other mutation in this report) and left the pre-existing stack running exactly as found. `docker compose ps -a` in the primary directory at the end of this session shows the same five `compliance-ail-*` containers, same uptime trajectory, untouched. See §5, finding 1.

Baseline: `78 tests collected` (confirmed via `pytest --collect-only`, exact match to the build report's own count). A full run produced `76 passed, 2 failed` on the first pass; both failures (`test_policy_digest.py::test_digest_unavailable_denies_and_writes_a_fault_record`, `test_verification.py::test_cross_process`) were `httpx.ReadTimeout` on `/audit` calls, and both passed cleanly when re-run in isolation immediately after. Root cause: `/audit` calls the verifier once per scanned entry, synchronously; this Windows Docker Desktop environment is measurably slower for that per-entry gRPC round trip than the Linux CI runner that produced the build report's clean `78 passed, 1 warning in 61.23s` (my from-scratch run took `242.20s` for the same suite). This is environmental, not a functional regression — noted here per precedent (prior phase reports disclosed comparable environment quirks) and not counted as evidence against any claim below.

---

## 2. Verdict table

| Claim | Verdict | Key evidence |
| :--- | :--- | :--- |
| T1 | **REFUTED** | The guard test is live and does fail loudly on a source-level string mutation — confirmed. But once the string doesn't match, the error reclassifies as `error_class: "unknown"`, which the control plane unconditionally promotes to `state: "failed"` — the tamper signal — for a condition (key never written) involving no tampering at all. A drift with no accompanying code diff (e.g. the ImmuDB *server* image changing its wording) has no mechanism to catch it short of someone re-running this exact test against the new server. |
| T2 | **REFUTED** | Exact test count (78) confirmed accurate — not padded. 76/78 items carry a real assertion. 2/78 (`test_bundle_ownership.py::test_single_correct_claimant_does_not_exit`, `::test_disjoint_roots_do_not_count_as_claiming_ail`) have zero assertions; live-demonstrated to pass even when the function under test (`_check_bundle_root_ownership`) is completely gutted to a no-op. |
| T3 | **HOLDS** | Unusual methods (OPTIONS/PATCH/DELETE/HEAD all 401; TRACE 500 — rejected by the framework before reaching any handler), `X-HTTP-Method-Override` header (ignored, still 401), GET+query-string mutation attempt (401), and direct cross-container access bypassing the dashboard (control-plane's own mutating routes: 422/403, never succeed) — no bypass found on any mutating route at either layer. |
| T4 | **HOLDS** | All 4 state-changing control-plane routes, enumerated from the live `/openapi.json` (`POST /tenants`, `PUT /tenants/{id}`, `POST /content`, `DELETE /content/{call_id}`) — including `POST /tenants`, which the existing test suite never exercises — reject the read-scoped key (403) and accept only the write-scoped key (201/200/204), confirmed live for each individually. |
| T5 | **REFUTED** | Live: content lost by direct SQLite manipulation (bypassing `DELETE /content` entirely — no auth, no erasure semantics, simulating an operational failure) renders in `/audit` byte-for-byte identical to a legitimate GDPR erasure through the real endpoint. No field distinguishes "erased on request" from "lost any other way." The `unavailable`-precedence sub-case (a stray content row for a call whose ledger entry says `unavailable`) correctly holds. |
| T6 | **HOLDS** | Exactly one OPA `/evaluation` request confirmed live for `policy_allow`, `policy_deny`, and the `opa_unreachable` fault; `schema_deny` confirmed at 0. The startup bundle-root check (`_check_bundle_root_ownership`) is called from exactly one place in each entry point (`base_agent.py`, `langgraph_demo.py`), at process start only — grep confirms no other call site, so it never fires per-call, though it can itself issue more than one GET during a slow boot (disclosed in the code's own docstring). |
| T7 | **REFUTED** | S2's exact original attack reproduces byte-for-byte, unmodified, live against `e7e9607`: a two-bundle OPA config still returns a real FinOps deny reason from `ail-policies` with `revision` attributed to an unrelated decoy bundle. Confirmed further: the real, unmutated P11-7 startup check, run fresh against this exact drifted environment, passes cleanly and never detects it — P11-7 only guards against two bundles claiming the *same* root, which was never the mechanism S2 exploited. All 7 of S1's named sub-mutations, S6, and S7 are independently confirmed fixed on re-test (see §3, "attacks attempted that failed"). |
| T8 | **HOLDS** | Full diff of every changed test file between `96d14d7` and `e7e9607` contains no `assert True`, no commented-out assertions, no loosened comparisons; every changed line strengthens or mechanically renames. `e7e9607` itself has zero uncommitted residue on a fresh checkout. Did not independently re-drive each of the report's 8 named mutations byte-for-byte as an inverse-exactness check (see §4). |

---

## 3. Evidence

### T1 — REFUTED

`tests/test_verification.py::test_not_found_state` is live against the real verifier and a real, never-written key (confirmed by reading the test and the module docstring: "All five tests run against a real ImmuDB container and the real verifier service (no mocks)" — true for this test specifically, live-confirmed below). `verifier/main.py:223` matches on `details.endswith("key not found")`.

**Attack — simulate an upstream message-text drift** by mutating the matched string in `verifier/main.py` (`"key not found"` → `"key absent from tree"`), rebuilding and redeploying only the `verifier` container:

```
$ pytest tests/test_verification.py::test_not_found_state -v
FAILED: AssertionError: Expected error_class 'not_found', got:
{'verified': False, ..., 'detail': '...status = StatusCode.UNKNOWN
   details = "tbtree: key not found"...', 'error_class': 'unknown'}
assert 'unknown' == 'not_found'
```

The guard **does** fail loudly — confirmed. This half of the claim holds.

**Then — check what the non-matching error is classified as, and whether that's safe** (per the brief's own instruction). `control_plane/main.py::_verification_from_200` (unaffected by the verifier mutation, re-tested separately and passed) has exactly three branches: `verified` → `verified`, `error_class == "not_found"` → `not_found`, else → `failed`. `"unknown"` falls into the third branch:

```python
return {"state": "failed", "state_id": vdata.get("state_id"),
        "detail": vdata.get("detail"), "error_class": vdata.get("error_class")}
```

So the moment the string stops matching, a key that was never written — no tampering, no rejected proof — is reported as `state: "failed"`, the highest-severity, tamper-implying signal in the taxonomy. This is precisely the conflation D8/ADR-0006 exists to eliminate, silently reintroduced in exactly the one failure mode ("the underlying condition drifts without an accompanying source diff," e.g. the ImmuDB *server* image being bumped in `docker-compose.yml` without anyone re-running this specific test against the new server) that "the build fails" cannot catch, because there is no build to fail. Reverted, rebuilt, redeployed; `pytest tests/test_verification.py` confirmed `7 passed` clean afterward.

**Attacks attempted that failed:** none — the guard test itself performed exactly as claimed (live, and it does fail on mutation). The finding is about what happens *after* it stops matching, which the claim's own text ("rather than silently reclassifying absence as something else") does not survive.

---

### T2 — REFUTED

```
$ pytest tests/ --collect-only -q | tail -1
78 tests collected in 7.02s
```

Exact match to the build report's own number — not inflated by collecting something trivial. Static AST scan of every `test_*` function in `tests/*.py` for at least one `assert` or `pytest.raises`:

```
total test functions (source-level, pre-parametrize): 75  (78 collected once parametrize expands)
functions with ZERO assert/pytest.raises:
  tests/test_bundle_ownership.py::test_single_correct_claimant_does_not_exit
  tests/test_bundle_ownership.py::test_disjoint_roots_do_not_count_as_claiming_ail
```

**Attack — gut the function these two are supposed to be testing.** `interceptor/middleware.py::_check_bundle_root_ownership`, mutated to `return` as its first line (a complete no-op, in-process, no rebuild needed):

```
$ pytest tests/test_bundle_ownership.py -v
test_single_correct_claimant_does_not_exit        PASSED   <- should mean nothing
test_two_claimants_of_ail_root_exits              FAILED: DID NOT RAISE
test_single_claimant_name_mismatch_exits          FAILED: DID NOT RAISE
test_zero_claimants_exits                         FAILED: DID NOT RAISE
test_unreachable_bundles_map_exits                FAILED: DID NOT RAISE
test_disjoint_roots_do_not_count_as_claiming_ail  PASSED   <- should mean nothing
4 failed, 2 passed
```

The 4 tests using `pytest.raises` correctly caught the deletion. The 2 with no assertion passed — because "the function ran and didn't raise" is exactly as true of a real, correct implementation as of a completely deleted one. Reverted; `6 passed` confirmed clean afterward.

**Live-vs-mocked classification, as requested.** `test_bundle_ownership.py` (6 items, P11-7) and `test_policy_response_shape.py` (5 items, P11-3) are both pure unit tests — `httpx`/the OPA fetch helpers are entirely monkeypatched, no live stack — by their own module docstrings ("Pure unit tests - no live stack"). The build report's own evidence section describes P11-7 as "6 table-driven **live** scenarios" — the word is doing real work there and could read as "against a live multi-bundle OPA," which it is not; the report's own §6 does separately and correctly disclose "P11-7's live second-bundle scenario, with two real OPA bundle servers... [not attempted]," so this specific gap is disclosed, just not where the evidence table itself makes the "live" claim. `test_verification.py::test_control_plane_maps_not_found_state_not_failed` (D8/S8's fifth gate test) is also a pure-function call against `_verification_from_200` directly — no ImmuDB, no verifier — despite living inside a file whose own module docstring states "All five tests run against a real ImmuDB container and the real verifier service (no mocks)," a blanket claim that was true of the file's original five tests and is no longer true of two of its current seven.

**Attacks attempted that failed:** searched the full test tree for `assert True`, bare `pass` where an assertion was expected, and always-true tautologies (`assert 1 == 1` style) — none found beyond the two zero-assertion items above.

---

### T3 — HOLDS

```
$ for M in OPTIONS PATCH DELETE HEAD; do curl -X $M .../api/tenants/tenant_default; done
401 401 401 401
$ curl -X TRACE .../api/tenants/tenant_default
500  (dashboard log: "TypeError: 'TRACE' HTTP method is unsupported" — rejected inside
      Next.js's own request construction, before middleware.ts or any route handler runs)
$ curl -X GET  .../api/tenants/tenant_default -H "X-HTTP-Method-Override: PUT"   -> 401
$ curl -X POST .../api/tenants/tenant_default -H "X-HTTP-Method-Override: GET"   -> 401
$ curl ".../api/tenants/tenant_default?enable_hipaa=false&_method=PUT"           -> 401
```

Cross-container, bypassing the dashboard entirely (from inside the `verifier` container, no host port involved):

```
$ docker exec redteam-1-1-verifier-1 python -c "urllib.request.urlopen(
    'http://ail-control-plane:8002/audit')"
rejected: HTTP Error 422: Unprocessable Entity
```

Direct, zero-credential hits on every mutating control-plane route, bypassing the dashboard entirely:

```
PUT /tenants (no creds):            422
POST /content (no creds):           422
DELETE /content (no creds):         422
POST /tenants create (no creds):    422
```
(422 = FastAPI rejecting the request for a missing required header, functionally equivalent to a rejection; confirmed no mutation occurred — `tenant_default`'s name was unchanged afterward.)

**Attacks attempted that failed:** TRACE (framework-level 500, not a bypass — reaches no handler); method-override headers (both directions, ignored); GET-as-mutation via query string; static-asset/`_next` path tricks and double-encoded path segments (`%2F`) — all rejected or 404.

---

### T4 — HOLDS

```
$ curl localhost:18002/openapi.json | ...
GET /health
GET /tenants/{tenant_id}          <- see §5, finding 2
PUT /tenants/{tenant_id}
POST /tenants
GET /bundles/{tenant_id}          <- intentionally open, OPA Bundle API
POST /content
DELETE /content/{call_id}
GET /audit
```

Every state-changing route, tried with the **read** key:

```
POST /tenants (read key):    403
PUT /tenants/{id} (read key): 403
POST /content (read key):    403
DELETE /content (read key):  403
sanity: POST /tenants (write key): 201
```

`POST /tenants` (tenant creation) is not exercised anywhere in `tests/test_dashboard_auth.py` — this was tested here for the first time and holds.

**Attacks attempted that failed:** none of the four state-changing routes accepted the read key under any credential presentation tried.

---

### T5 — REFUTED

Issued a real approved call (tx=100, call_id `9e05913...`), confirmed `payload_state: "present"` via `/audit`. Then bypassed `DELETE /content/{call_id}` entirely — no auth, no erasure semantics, no audit trail — with a raw SQL delete inside the control-plane container's own SQLite file:

```
$ docker exec ail-control-plane python -c "sqlite3... DELETE FROM call_content WHERE call_id=?"
after direct SQL delete: None
$ curl .../audit | jq '... | select(.tx_id==100)'
{
  "payload": null,
  "payload_state": "erased",
  ...
}
```

This is byte-for-byte the same shape `tests/test_content_states.py::test_present_then_erased_via_delete_content` asserts for a *legitimate* erasure through the real endpoint — same fields, same absence of any erasure-actor/timestamp/reason marker. There is no way, from `/audit` alone, to tell "a GDPR Article 17 request was honored" from "an operator ran a bad migration" from "a bug deleted a row."

**Supporting check — the one sub-attack that does not work.** Inserted a stray `call_content` row for a call whose ledger entry already recorded `content_state: "unavailable"` (a non-dict-args case):

```
$ curl .../audit | jq '... | select(.tx_id==21)'
{ "payload": null, "payload_state": "unavailable", ... }
```

`_payload_state`'s precedence (`unavailable` always wins, checked before the content-row lookup) correctly ignores the stray row. This one sub-case holds.

**Attacks attempted that failed:** "kill the content store between the content write and the ledger write" and "kill it after both" do not produce a *third*, confusable state as originally worried — in this architecture the content store and the audit-reading process are the same FastAPI app sharing one SQLite file, so killing it mid-window either fails the content write (already fail-closed, no ledger entry at all — confirmed via the existing `test_content_store_down_denies_as_fault_and_writes_no_record`) or makes `/audit` itself return 503 (a loud failure, not a silent misreport) rather than a misleading state.

---

### T6 — HOLDS

Spy-wrapped `httpx.Client.post`/`.get` (real calls still execute) and counted requests to `_OPA_EVAL_URL`, `_OPA_REVISION_URL`, `_OPA_BUNDLES_URL` across paths the existing `test_opa_request_count.py` does not cover:

```
schema_deny (unregistered tool):      eval_post delta = 0
fault (opa_unreachable, one attempt,
       logged exactly once, no retry): confirmed via single "OPA connection error" log line
startup check (bundle already loaded): 1 revision GET + 1 bundles GET = 2 total, once
```

```
$ grep -rn "verify_bundle_at_startup\|_check_bundle_root_ownership" --include=*.py | grep -v tests/
agent/base_agent.py:159:            verify_bundle_at_startup()
framework_integration/langgraph_demo.py:417:  verify_bundle_at_startup()
interceptor/middleware.py:484:      _check_bundle_root_ownership(ssl_context)   # called from within verify_bundle_at_startup only
```

Called from exactly one place in each of the two entry points, both at module/script level (process start), never inside the per-call path. The startup check's own revision-polling loop can issue more than one GET during a single boot if OPA is slow to activate the bundle (`poll_interval` up to `timeout_seconds`) — this is disclosed in the function's own docstring and does not contradict "boot-only": it is boot-only, just not always exactly-one-request-boot-only.

**Attacks attempted that failed:** a live "call arrives mid-reload" race was not forced (see §4) — reasoned safe from OPA's documented atomic bundle activation (a single HTTP request only ever observes one atomically-applied state) rather than confirmed by directly racing a poll cycle.

---

### T7 — REFUTED

**S2, re-run verbatim.** `git diff 96d14d7 e7e9607 -- policy/core/main.rego` is empty — the Rego rule S2 exploited is byte-for-byte unchanged. Rebuilt the exact Phase-1 attack: a decoy bundle (`{"revision": "DECOY-REVISION-1234-NOT-AIL-POLICIES", "roots": ["decoy"]}`) served from a throwaway container, added to OPA's live config, OPA restarted to pick it up (the config drift happens to a *running* environment, not at the interceptor's own boot):

```
$ curl -X POST .../v1/data/ail/main/evaluation -d '{"input":{...,"bundle_name":"decoy-bundle"}}'
{"result": {
  "allow": false,
  "reasons": ["DENIED: Instance type p4d.24xlarge is restricted. 'project' tag must be 'ml-training'."],
  "revision": "DECOY-REVISION-1234-NOT-AIL-POLICIES"
}}
```

Identical to Phase 1's own reproduction: a real FinOps deny reason (which exists nowhere but `ail-policies`) reported alongside a revision naming an unrelated bundle with no policy rules at all.

**Then — does P11-7's own fix catch this, right now, unmutated?**

```python
middleware.verify_bundle_at_startup(timeout_seconds=10, poll_interval=1)
# ...
# RESULT: startup check PASSED CLEANLY -- did not detect the decoy bundle at all
```

No. `_check_bundle_root_ownership` only flags a second bundle claiming the *same* `ail` root — it was never designed to catch a bundle claiming a disjoint root (confirmed by its own test, `test_disjoint_roots_do_not_count_as_claiming_ail`, which asserts this must *not* raise). The actual S2 mechanism — `revision` looked up from an attacker/caller-supplied `bundle_name` string, structurally decoupled from whichever bundle populated `data.ail.*` — is untouched by this phase. P11-7 also only ever runs once, at process start; a bundle added to OPA's live config after a real interceptor has already booted successfully would never be re-checked at all.

**Attacks attempted that failed — the rest of S1-S8, re-verified live:**

| Original S1 sub-mutation | Re-tested against `e7e9607` | Result |
| :-- | :-- | :-- |
| #2 `verified:true` self-assertion in ledger | live, rebuilt verifier n/a (in-process) | **caught** — `test_raw_ledger_entry_has_no_verification_field` |
| #3 metric label reshaped w/ message text (`"policy_deny:<word>"`) | live mutation, in-process | **caught** — `test_metric_label_set_matches_closed_collection` (not one of the report's own named "5 gate tests," catches it incidentally via the closed-set check) |
| #4 raw `tool_args` in ledger | (already covered by #2's sibling gate test) | **caught** — `test_raw_ledger_entry_has_no_raw_argument_content` |
| #6 `DELETE /content` auth dependency removed | live mutation, control-plane rebuilt | **caught** — `test_control_plane_read_key_rejected_on_delete_content` now fails (204 instead of the expected 403), confirmed via a direct zero-header probe returning `204` against the mutated code |
| #7 second OPA round trip for deny reasons | (already covered by P11-8's dedicated gate test) | **caught** — `test_exactly_one_opa_request_for_a_denied_call` |
| S3 non-dict `tool_args`, varied (nested dicts, unicode, keys colliding with `call_id`/`input_sha256`) | live | **safe** — Pydantic's own `extra="forbid"` schema rejects the colliding top-level keys; no crash, clean `schema_deny` with a real ledger record for every shape tried |
| S6 anonymous dashboard access | live (§T3 above) | **fixed** — 401 everywhere tried |
| S7 cardinality, varied (unusual casing/whitespace on registered names) | reasoned from code (same exact-match dict lookup governs both validity and the metric allowlist) | **safe by construction** — any variant that isn't an exact registry key collapses to `_unregistered` the same as any other hallucinated name |

All 7 of Phase 1's named S1 sub-mutations are individually caught on this head — a materially stronger result than the build report's own "5 gate tests" framing suggests (2 are caught incidentally by tests not purpose-built for them). This makes S2's unremediated status the clean, isolated finding it is, rather than one of several.

---

### T8 — HOLDS

```
$ git diff 96d14d7 e7e9607 --stat -- tests/
 9 files changed, 908 insertions(+), 7 deletions(-)
$ git diff 96d14d7 e7e9607 -- tests/ | grep -n "assert True\|# assert\|assert 1 =="
(no output)
```

The one non-additive change, `tests/test_policy_digest.py` (4 lines), is a mechanical rename (`API_KEY`/`CONTROL_PLANE_API_KEY` → `READ_API_KEY`/`CONTROL_PLANE_READ_KEY`) tracking the D6 key split — no strength change. `git status --short` on a fresh checkout of `e7e9607` was clean before any of my own testing began, confirming no residual mutation artifact ships in the commit itself.

**Could not fully verify:** did not independently re-drive each of the report's 8 named mutations byte-for-byte to confirm every individual revert is an *exact* inverse rather than merely equivalent — my own re-testing (§T7's table, T1, T2) covers 5 of the 8 through fresh, independently-authored mutations rather than replaying the report's own diffs, which is stronger evidence of the underlying property but does not confirm the report's literal edit-then-revert sequence left zero textual residue beyond the `git diff`/`git status` checks above.

---

## 4. Could not test, and what blocked it

- **T6's "call made while OPA is mid-reload."** Not forced live — would require winning a race against OPA's bundle-activation window (sub-millisecond, atomic per OPA's own documented behavior) from the host. Reasoned safe (a single HTTP request only ever observes one atomically-applied bundle state) rather than confirmed by direct reproduction.
- **T5's mass-data-loss variant** (wiping the control-plane's SQLite volume entirely while leaving ImmuDB/ledger data intact, so every previously-`present` entry becomes `erased` in bulk). Not run — the single-row direct-SQL-delete attack already establishes the core claim (indistinguishability), and the mass case is the same mechanism at scale; judged not to add new information for the time cost.
- **T8's byte-exact-inverse verification for all 8 named mutations.** See §3 above — partial coverage via independently-authored equivalents, not the report's own literal diffs replayed and reverted.
- **A live, real-time immudb-py/immudb-server version bump** (T1) — the drift was simulated by editing the matched string directly; an actual SDK or server version upgrade was not performed, since it would require pulling a different pinned dependency/image and was judged out of scope for confirming the mechanism itself.

---

## 5. Findings outside T1-T8

1. **A docker-compose stack was already running directly against the primary working directory's own `docker-compose.test.yml`** (project name `compliance-ail`, host ports 8002/8003/3322/8080/8181/3001, ~43 minutes old at discovery), predating this session and violating the standing rule that applies to this class of red-team session. Left untouched; worked around via alternate host ports in an isolated scratch clone. Flagged for the user/architect to investigate its origin — it is not explained by anything in this session's own actions or by the primary directory's checked-out branch (`spike-wasm-parity-report`, which has no Phase 1.1 code).

2. **`GET /tenants/{tenant_id}` on the control plane has no authentication at all** — not gated by `_require_read_key` or any dependency, confirmed live both from the host and from inside the Docker network (another container, zero credentials, `200` with full tenant config including which compliance frameworks are enabled and cost-center/region allowlists). This sits outside T3 (not mutating) and T4 (not state-changing), so neither claim's letter catches it, but it materially undercuts ADR-0007's "two independent layers, not one" framing: for this one route, the control-plane layer provides zero independent protection of its own and relies entirely on the dashboard's outer Basic Auth layer, which is trivially bypassed by reaching the control plane directly (as `docker-compose.test.yml`'s own host port mapping, and any network-adjacent container, both already do).

3. **`/audit`'s synchronous, one-verify-call-per-scanned-entry design does not scale**, independent of environment — confirmed by this session's own repeated `ReadTimeout`s under Windows Docker Desktop as the ledger grew past ~150-200 entries during a single test run (§1). Not a functional defect and not something CI's clean Linux run would surface, but worth the team's attention before the ledger holds a production-scale entry count: the same O(n) per-request-verify design will slow every `/audit` read as the ledger grows, on any platform, not just this one.

4. **Two of 78 collected test items carry no assertion of any kind** (`test_bundle_ownership.py::test_single_correct_claimant_does_not_exit`, `::test_disjoint_roots_do_not_count_as_claiming_ail`) — covered in depth under T2, flagged again here as a standalone test-suite-hygiene note since it's a general property of the suite, not only an attack-surface question.
