# phase-1-3-complete - Report

## 0. Run id, working directory, branch

**Run id:** p13-complete
**Working directory:** `C:/Users/banji/AppData/Local/Temp/claude/c--Users-banji-OneDrive-Documents-compliance-ail/28510ff8-b262-4fd8-a9b6-e42886db2535/scratchpad/phase-1-3-complete` (not the primary working directory, per the instruction and per `docs/process/review-protocol.md` section 1)
**Branch:** `phase-1-3-complete`, created off `phase-1-1-remediation` at `0cf0f92` (matched `origin/phase-1-1-remediation` at run start - confirmed via `git rev-parse HEAD` and `git rev-parse origin/phase-1-1-remediation` both returning `0cf0f92f76d8fd2e059d71dc77ac09658731edad`)

**Start SHA:** `0cf0f92f76d8fd2e059d71dc77ac09658731edad`

This run is a direct continuation of the red-team session's own findings (`docs/reports/phase-1-3-redteam.md`, run id `rt-p13-a`, audited the same `0cf0f92` tip). That report was present on the primary working directory's filesystem but not committed anywhere; it was copied into this worktree and is committed here (see section 8).

---

## 1. Verdict table

| Item | Status | Enforcing test | Mutation |
| :--- | :--- | :--- | :--- |
| R1 - unpublish management/record ports | **DONE** | `tests/test_host_port_bindings.py` (both test functions) | Confirmed fails when a port is added back |
| R2 - ADR-0002 ImmuDB claim matches compose | **DONE** | Same as R1 (the claim and the fix are the same port removal) | Same as R1 |
| R3 - profile-less record renders as unknown | **DONE** | `tests/test_record_profile.py::test_audit_forged_profile_less_record_renders_as_unknown_not_observed` | Confirmed fails when default reverted to `RECORD_PROFILE` |
| R4 - `GET /bundles/{tenant_id}` requires a credential | **DONE** | `tests/test_dashboard_auth.py` (four new tests) | Confirmed two tests fail when the dependency is removed |
| R5 - four false statements | **DONE** (all four) | See per-item evidence below | See per-item evidence below |
| R6 - docker guard fails cleanly | **DONE** | `tests/test_content_states.py::_docker_cli_usable` (guard itself, exercised via the two `@requires_docker_cli` tests) | Confirmed old guard crashes, new guard skips, same fake binary |
| R7 - Residual Limits states the real reach | **DONE** | N/A (prose correction) - verified against the live re-run evidence in R1 | N/A |
| R8 - mapping is complete | **DONE**, with stated gaps | N/A (this section) | N/A |

Pre-registered negatives: all five individually confirmed in section 7.

---

## 2. R1 - management and record surfaces are not published to the host

**Property asserted:** in `docker-compose.yml`, no port is published for opa (8181), verifier (8003), immudb (3322, 8080), envoy's admin API (9901), spire-server (8081), or the control plane (8002). `docker-compose.test.yml` keeps what the suite needs, documented as deliberately more permissive.

**Attack re-run (V2, `docs/reports/phase-1-3-redteam.md`):** `host.docker.internal` reaching a loopback-bound port from a container on an unrelated network, plus the control plane's own unbound 8002.

Before the fix, this attack worked (this is the red-team's own transcript, quoted, not re-run against the vulnerable state since the fix is already applied to this branch's working tree):

```
$ docker run --rm --network v2-isolated-test alpine sh -c 'curl http://host.docker.internal:8181/v1/data/system/bundles/ail-policies/manifest/revision'
{"result":"14387ebda8edf5f202b767317409010535a6a38452189bcf2f771b3861c06e3c"}
```

After the fix, re-run live against the real deployment compose (`docker-compose.yml`, not the test compose), a subset of it brought up under its own project (`prod-check`) with the test compose's competing loopback-bound ports on the same host stopped first, to isolate the check from cross-contamination:

```
$ docker ps --format "{{.Names}}\t{{.Ports}}"
prod-check-ail-control-plane-1   8002/tcp
prod-check-verifier-1            8003/tcp
prod-check-opa-1
prod-check-immudb-1              3322/tcp, 5432/tcp, 8080/tcp, 9497/tcp
```

No `0.0.0.0:PORT->` prefix on any of the four - nothing is published to the host at all (contrast with `phase-1-3-complete-immudb-1  0.0.0.0:3322->3322/tcp, [...], 0.0.0.0:8080->8080/tcp`, the test compose's own immudb, correctly still published there).

```
$ docker network create v2-final-check
$ docker run --rm --network v2-final-check curlimages/curl:latest sh -c '
curl -s -m 3 -o /dev/null -w "%{http_code}\n" http://host.docker.internal:8181/health
curl -s -m 3 -o /dev/null -w "%{http_code}\n" http://host.docker.internal:8003/health
curl -s -m 3 -o /dev/null -w "%{http_code}\n" http://host.docker.internal:8002/health
'
opa via host.docker.internal:8181:
000
CONNECTION FAILED
verifier via host.docker.internal:8003:
000
CONNECTION FAILED
control-plane via host.docker.internal:8002:
000
CONNECTION FAILED
```

All three connections fail. The named attack no longer works.

**First attempt produced a false positive, corrected before trusting the result:** the first run of this same check returned `200` for all three. Investigation (`docker inspect prod-check-ail-control-plane-1 --format '{{json .HostConfig.PortBindings}}'` returned a real binding) traced this to the still-running `docker-compose.test.yml` stack's own loopback-bound `opa`/`verifier` and host-bound `ail-control-plane` containers from earlier in this same session, not to `prod-check`. Stopping those three containers (`docker compose -f docker-compose.test.yml -p phase-1-3-complete stop opa verifier ail-control-plane`) and confirming via `docker ps` that only `prod-check-*` containers were live is what produced the clean `000`/`CONNECTION FAILED` result quoted above. Recorded here because the instruction requires the re-run attack and its actual result, and the first result was wrong for a reason worth naming rather than silently discarding.

**Enforcing test:** `tests/test_host_port_bindings.py`, extended with `test_deployment_compose_publishes_no_management_or_record_port` (9 cases: the full candidate set against `docker-compose.yml`) and `test_management_port_not_bound_to_a_non_loopback_address_on_test_compose` (scoped to `docker-compose.test.yml` only, since `docker-compose.yml` no longer has a binding to check).

```
$ python -m pytest tests/test_host_port_bindings.py -v
9 passed in 0.77s
```

**Mutation:** add back `"127.0.0.1:8181:8181"` to `opa` in `docker-compose.yml`.

```
$ python -m pytest tests/test_host_port_bindings.py -v -k opa-8181
FAILED tests/test_host_port_bindings.py::test_deployment_compose_publishes_no_management_or_record_port[opa-8181]
AssertionError: docker-compose.yml: opa:8181 must not be published to the host at all ... found: ['127.0.0.1:8181:8181']
1 failed, 1 passed in 0.49s
```

Reverted; re-ran; both pass again.

**Escalation check:** unpublishing 8002 does not break anything structural. The dashboard already reached the control plane by compose DNS name (`CONTROL_PLANE_URL=http://ail-control-plane:8002` was already the configured value; the host-published copy was only ever a debugging/documentation convenience). The one documented affordance that did break - `readME.md` section 4.5's `curl -s localhost:8181/...` bundle-load check, and section 4.6's endpoint table - is fixed in documentation (section 5 below), per the instruction's own escape hatch ("if that breaks a documented affordance, fix the documentation"). No escalation needed.

---

## 3. R2 - ADR-0002's ImmuDB claim matches the compose files

**Property asserted:** ADR-0002's claim ("ImmuDB is intentionally not exposed on the host network interface") is true of `docker-compose.yml`.

**Before this pass:** false. `docker-compose.yml`'s `immudb` service published `"3322:3322"` unrestricted, directly contradicting the ADR's own sentence.

**Fix:** removed from `docker-compose.yml` as part of R1 (immudb is in the same management/record-writing candidate set). ADR-0002's Context section rewritten to state the port removal explicitly, name both ports (3322 and 8080, not just the one that was actually published), and distinguish `docker-compose.test.yml`'s deliberate exception. `readME.md` section 6's ADR-002 summary paragraph updated to match, and its own separate stale claim ("one of four verification states") corrected to five in the same edit (folded into R5 below since it is the same class of bug, not a new one).

**Confirmed:** `tests/test_host_port_bindings.py::test_deployment_compose_publishes_no_management_or_record_port[immudb-3322]` and `[immudb-8080]`, both passing (section 2's test run above).

---

## 4. R3 - a record without a profile does not render as one with

**Property asserted:** a record with no `profile` field renders as explicitly unknown, distinctly, not as a genuine `"observed"` record.

**Attack re-run (V5):** forge a raw decision-shaped record directly against the verifier, omitting `profile` entirely, then read it back through `/audit`.

```
$ python -c "
key = 'tool_call:forged-no-profile-agent-r3check:...'
entry = {record_type: decision, agent_id: ..., outcome_type: policy_allow, ..., content_state: unavailable}  # no 'profile' key
httpx.post('http://localhost:8003/write', json={'key': b64(key), 'value': b64(json.dumps(entry))})
"
forged write: 200 {'tx_id': 1, 'verified': True, 'detail': None}

$ curl http://localhost:8002/audit ... | select agent_id == forged-no-profile-agent-r3check
{'profile': 'unknown', ...}
```

Before this fix (the red-team's own transcript, `docs/reports/phase-1-3-redteam.md`, V5), the identical forgery rendered `{"profile": "observed"}` - indistinguishable from a genuine record.

**Fix:** `control_plane/main.py::get_audit`, `log_entry.get("profile", RECORD_PROFILE)` -> `log_entry.get("profile", "unknown")`. `dashboard/lib/types.ts`'s `AuditEntry.profile` type widened to include `"unknown"`, deliberately outside the closed set `{observed, mediated, attested}` so it cannot be confused with a real profile value at the type level either.

`outcome_type` and `record_type` were checked for the same class of bug per the instruction ("check outcome_type and record_type while you are there"): `outcome_type` is read via `log_entry.get("outcome_type")` with no default (falls through to `None`, which already renders as explicitly absent, not as a valid-looking outcome); `record_type` is never projected into `/audit`'s response at all and its one read site (tombstone classification, `value.get("record_type") == "content_erasure"`) also has no default. Neither needed a fix.

**Enforcing test:** `tests/test_record_profile.py::test_audit_forged_profile_less_record_renders_as_unknown_not_observed` (new).

```
$ python -m pytest tests/test_record_profile.py -v
4 passed in 26.16s
```

**Mutation:** reverted `control_plane/main.py` to `log_entry.get("profile", RECORD_PROFILE)`, rebuilt and restarted the `ail-control-plane` container.

```
$ python -m pytest tests/test_record_profile.py::test_audit_forged_profile_less_record_renders_as_unknown_not_observed -v
AssertionError: Expected 'unknown' for a structurally profile-less record, got 'observed' - ...
1 failed in 7.09s
```

Reverted; rebuilt; re-ran; all 4 pass again.

---

## 5. R4 - `GET /bundles/{tenant_id}` requires a credential

**Property asserted:** the route requires the read-scoped credential; OPA (the only normal caller) is configured with it; OPA still loads its bundle.

**Attack re-run (V6):**

```
$ curl http://localhost:8002/bundles/tenant_finance -o bundle.tar.gz -w "%{http_code}"
200          # before the fix - zero credentials
```

After the fix, live against the running test stack:

```
--- unauthenticated ---
422
--- wrong key ---
403
--- correct read key ---
200
--- nonexistent tenant with correct key ---
404
```

**OPA still loads its bundle** (the fix's own risk - OPA is the caller it must not break):

```
$ curl -s http://localhost:8181/v1/data/system/bundles/ail-policies/manifest/revision
{"result":"14387ebda8edf5f202b767317409010535a6a38452189bcf2f771b3861c06e3c"}
$ curl -s http://localhost:8181/v1/data/ail/config
{"result":{"allowed_cost_centers":[...],"tenant_id":"tenant_default"}}
```

A real revision resolves and the tenant-scoped config is loaded - the credentialed poll works.

**Fix:** `control_plane/main.py::get_bundle` gains `_: None = Depends(_require_read_key)`. `opa-config.yaml`'s `services` entry gains `headers: {X-API-Key: ${CONTROL_PLANE_READ_KEY}}`. `docker-compose.yml` and `docker-compose.test.yml`'s `opa` service each gain `CONTROL_PLANE_READ_KEY` in `environment`, so OPA's own process can substitute it into the config file. The write key was deliberately not used - OPA only ever reads this route.

**Enforcing test:** `tests/test_dashboard_auth.py`, four new tests (`test_control_plane_get_bundle_rejected_with_no_key`, `::_rejected_with_wrong_key`, `::_accepted_with_read_key`, `test_opa_still_loads_bundle_through_the_now_credentialed_poll`).

```
$ python -m pytest tests/test_dashboard_auth.py -v
17 passed in 9.69s
```

**Mutation:** removed `_require_read_key` from `get_bundle`, rebuilt and restarted `ail-control-plane`.

```
$ python -m pytest tests/test_dashboard_auth.py -k bundle -v
FAILED test_control_plane_get_bundle_rejected_with_no_key - AssertionError: Expected 422, got 200
FAILED test_control_plane_get_bundle_rejected_with_wrong_key - AssertionError: Expected 403, got 200
2 failed, 2 passed in 7.03s
```

Reverted; rebuilt; re-ran; all 17 pass again.

---

## 6. R5 - the four false statements

### 5a. README section 3.1, Envoy mTLS claim

**Before:** "All traffic from the agent to the policy engine transits through an Envoy proxy enforcing strict mutual TLS." False: `docker-compose.test.yml` (what CI and the integration suite actually run) has no Envoy service at all, and OPA's own port is reachable directly in parallel even on the full stack.

**Fix:** rewritten to state precisely what is true - Envoy fronts the langgraph-demo agent's traffic on the full `docker-compose.yml` stack only, `docker-compose.test.yml` has none, and OPA's own listener is reachable directly regardless (cross-referenced to Residual Limits).

### 5b. README verification-state count (four in two places, five in a third)

**Before:** section 3.5 and section 6 (ADR-006 summary) both said "four" and omitted `not_found`; section 3.4 correctly said "five" and named it; `docs/adr/0006-verification-states.md`'s own title says "Five." Self-contradicted within the same document. `docs/adr/0002-fastapi-immudb-proxy.md` separately said "four" in its own body. `dashboard/components/audit-table.tsx`'s own comment above `VerificationCell` also said "four" (the code itself was already correct - only the comment was stale).

**Fix:** all four corrected to five, naming `not_found` where the others name states individually.

### 5c. Dashboard `FaultClass` type omission

**Before:** `dashboard/lib/types.ts`'s `FaultClass` union was `{opa_unreachable, revision_unavailable, verifier_unreachable, spiffe_unavailable}` - it included `verifier_unreachable`, which structurally can never reach `/audit` (ADR-0005's own Documented Boundary section), and omitted `malformed_policy_response`, which does.

**Attack re-run (V1, finding 3):** force a `malformed_policy_response` fault through the real interceptor and confirm it produces a ledger entry `/audit` actually surfaces.

```
$ python - <<'EOF'
# selectively fake only the OPA /evaluation response (missing "revision"),
# real content-store write, real ledger write
r = middleware.intercept_tool_call("provision_cloud_server", {...}, agent_id)
EOF
ERROR OPA /evaluation response missing or malformed field(s) - allow=True reasons=[] revision=None.
INFO Ledger write verified: tx=15
intercept result: {..., 'outcome_type': 'fault', 'fault_class': 'malformed_policy_response', 'ledger_tx_id': 15}

audit entry: [{'tx_id': 15, ..., 'outcome_type': 'fault', 'fault_class': 'malformed_policy_response', ...}]
```

Confirmed live and independently, reproducing the red-team's own finding: this fault class does reach `/audit`, and the dashboard's type did not previously allow it.

**Fix:** `FaultClass` corrected to `{opa_unreachable, revision_unavailable, spiffe_unavailable, malformed_policy_response}` - the four that ADR-0005's Documented Boundary section says can produce a ledger record, no more and no fewer.

**Enforcing test:** `tests/test_outcome_types.py::test_dashboard_fault_class_type_matches_reachable_set` (new) - parses the TS union directly (regex against the committed file, not a hand-maintained duplicate list) and compares it against `middleware.py`'s six `FAULT_*` constants minus the two the ADR documents as unreachable.

```
$ python -m pytest tests/test_outcome_types.py -k fault_class_type -v
1 passed in 4.01s
```

**Mutation:** swapped `"malformed_policy_response"` for `"verifier_unreachable"` in the actual union member (not the surrounding prose, which mentions both strings and produced a false pass on the first attempt - corrected by anchoring the mutation to the exact union block).

```
FAILED test_dashboard_fault_class_type_matches_reachable_set
AssertionError: ... missing: ['malformed_policy_response'], unreachable-but-present: ['verifier_unreachable']
1 failed in 4.45s
```

Reverted; re-ran; passes again.

### 5d. Whatever R2 settles

Covered in section 3 above - ADR-0002's ImmuDB claim now matches `docker-compose.yml`.

---

## 7. R6 - the docker guard fails cleanly

**Property asserted:** a `docker` on `PATH` that is not really Docker produces a clean skip or a clean failure with a named reason, not an uncaught crash.

**Attack re-run (V7, sub-attack 3), before the fix** (old guard, `shutil.which("docker") is None` only), same fake binary the red-team used:

```
$ cat fakebin/docker.exe
#!/bin/sh
echo "fake-docker: pretending to succeed" >&2
exit 0

$ PATH="fakebin:$PATH" python -m pytest tests/test_content_states.py::test_direct_sqlite_delete_produces_lost_not_erased -v
E       OSError: [WinError 216] This version of %1 is not compatible with the version of Windows you're running...
FAILED tests/test_content_states.py::test_direct_sqlite_delete_produces_lost_not_erased
1 failed in 34.50s
```

Reported as FAILED with a raw `OSError` traceback - exactly the crash the red-team found, reproduced here under pytest directly (the red-team's own reproduction called `subprocess.run` standalone; this run confirms the same shape inside the actual gated test).

**After the fix**, identical fake binary, same PATH:

```
$ PATH="fakebin:$PATH" python -m pytest tests/test_content_states.py::test_direct_sqlite_delete_produces_lost_not_erased tests/test_content_states.py::test_erasure_refused_when_tombstone_write_fails -v
tests/test_content_states.py::test_direct_sqlite_delete_produces_lost_not_erased SKIPPED
tests/test_content_states.py::test_erasure_refused_when_tombstone_write_fails SKIPPED
2 skipped in 4.55s
```

**Fix:** `requires_docker_cli`'s guard now actually invokes `docker version` (wrapped in `try`/`except OSError`) rather than only resolving the binary with `shutil.which`. The same `OSError` that used to reach the test body now reaches the guard itself, which turns it into a skip.

**Confirmed the normal case is unaffected** (real docker CLI on PATH):

```
$ python -c "import tests.test_content_states as tcs; print(tcs._docker_cli_usable())"
True
```

And both gated tests pass normally in the full suite run (section 8).

---

## 8. R7 - Residual Limits states the real reach

**Before:** stated the OPA/verifier reach as "the host, and any container on this compose network" - true as far as it went, but silent about `host.docker.internal`'s broader reach (any container on the Docker host, any network), which V2 demonstrated live.

**After R1's fix, the accurate statement is different in kind, not just in wording:** for the deployment compose, the host-published surface is now gone entirely (section 2), so there is no longer a loopback bind for `host.docker.internal` to exploit there. What remains true, unchanged by R1, is compose-network reachability - anything on the same compose network, including the agent container, still reaches OPA's and the verifier's unauthenticated endpoints directly. `docker-compose.test.yml` still publishes OPA and the verifier to the host, loopback-bound, deliberately, and understating that this is test-only (not the deployment posture) would itself be a form of understating the exposure - so the rewritten section says this explicitly rather than leaving it implied.

Understating an exposure is the dangerous direction per the instruction; the rewrite is deliberately more specific about both what closed (off-host and cross-container-on-host reach, for the deployment compose) and what remains (compose-network reach, unchanged; the test compose's own broader publish, named as test-only).

The rewritten section also folds in R3 (a forged profile-less record now renders as `"unknown"`, narrowing but not closing the forgery residual) and R4 (`/bundles/{tenant_id}` joins the shared-secret-gated set, with the added note that OPA itself now holds this credential).

---

## 9. R8 - the mapping is complete

**Methodology, same as the prior pass's own (`docs/reports/phase-1-3.md`, section 8), extended to the two areas that pass missed:** every substantive claim in `readME.md`, all seven ADRs (`0001`-`0007`, not just the two the prior diff touched), and the dashboard's type and component layer is mapped to a passing test, a reproducible command, or a Residual Limits entry. Historical phase reports (`docs/reports/phase-0*.md` through `phase-1-3.md`, `docs/reports/*-redteam.md`, `docs/plan/ail-v2-plan.md`) are point-in-time records of what was true when written and are explicitly out of scope for this mapping - they are not corrected retroactively, matching the project's own established convention (`docs/reports/cleanup-p13-b.md` established this for a different but related class of check).

| Location | Claim | Maps to |
| :--- | :--- | :--- |
| README §1 | In-process hook, not a network perimeter; compromised-container limit | Residual Limits §5 bullet 1; `tests/test_epic_2.py` (no bypass for a cooperating caller) |
| README §2 | Four-stage pipeline, fail-closed table | `tests/test_outcome_types.py` (all four fault-producing paths); `test_epic_2.py::TestMiddlewareRoutingFailClosed` |
| README §3.1, SPIFFE/SPIRE bullets | Ephemeral SVIDs, in-memory certs, exit-on-absent-socket | `test_mtls_flow.py`; `interceptor/middleware.py`'s SPIRE-absent exit path, unchanged this pass |
| README §3.1, Envoy mTLS bullet | **Corrected this pass (R5a)** - was an overclaim, now states the full-stack-only, non-universal reality | This report, section 6.5a; Residual Limits §5 bullet 2 |
| README §3.2 | Schema registry, three tools, fail-closed on unregistered | `test_epic_2.py::TestToolValidatorsRegistry` |
| README §3.3 | Multi-tenant bundle generation, single-OPA-process-per-tenant | Unchanged this pass; `control_plane/bundle.py` |
| README §3.4, outcome taxonomy / "the record, not a message" | Unchanged this pass | `tests/test_outcome_types.py`; `docs/adr/0005-outcome-taxonomy.md` |
| README §3.4, "five states" sentence | Already correct pre-existing text | `docs/adr/0006-verification-states.md` |
| README §3.4, ImmuDB test coverage paragraph | Five integration tests, one a real tamper vector | `tests/test_verification.py` (9 tests, unchanged this pass) |
| README §3.5, Prometheus cardinality | Closed-set labels | `tests/test_outcome_types.py::test_metric_label_set_matches_closed_collection` |
| README §3.5, "four verification states" | **Corrected this pass (R5b)** to five | `docs/adr/0006-verification-states.md`'s own title |
| README §3.5, dashboard server-side auth | Unchanged this pass | `tests/test_dashboard_auth.py` (17 tests, up from 13) |
| README §4.1-4.4 | Quickstart, worked demo requests | Reproducible commands, unchanged |
| README §4.5, bundle-load confirmation step | **Corrected this pass (R1)** - `curl localhost:8181` broke when OPA's port was unpublished; replaced with a compose-network command | Verified live in section 2 above |
| README §4.6, service endpoint table | **Corrected this pass (R1)** - Control Plane API and OPA rows removed (no longer published); replacement commands given and verified live | Same as §4.5 |
| README §4.7 | Helm chart unsupported | `docs/audit/2026-08-16-verification.md` V1; not re-verified this pass, out of scope |
| README §5, prompt injection / infra-failure tables | Unchanged this pass | Same tests as §2 |
| README §5, Residual Limits | **Rewritten this pass (R7)** | This report, section 8 |
| README §6, ADR-001 summary | Unchanged | `docs/adr/0001-immudb-rest-migration.md`, untouched |
| README §6, ADR-002 summary | **Corrected this pass (R2, R5b)** - port claim and state count | `docs/adr/0002-fastapi-immudb-proxy.md`; section 3 above |
| README §6, ADR-003 summary | Unchanged | `docs/adr/0003-opa-bundle-api.md`, untouched |
| README §6, ADR-004 summary | Unchanged | `docs/adr/0004-pydantic-preflight-validation.md`, untouched |
| README §6, ADR-005 summary | Unchanged | `docs/adr/0005-outcome-taxonomy.md`, untouched |
| README §6, ADR-006 summary | **Corrected this pass (R5b)** - title and state count | `docs/adr/0006-verification-states.md`'s own title |
| README §7 Stack Reference, §9 Known Limitations | No guarantee-shaped claims | Not enumerated further, same ground as the prior pass |
| `docs/adr/0001-immudb-rest-migration.md` | Verifier isolation rationale | Not touched this pass; no claim in this pass's scope references it differently |
| `docs/adr/0002-fastapi-immudb-proxy.md`, Context | **Corrected this pass (R2)** | Section 3 above; `tests/test_host_port_bindings.py` |
| `docs/adr/0002-fastapi-immudb-proxy.md`, Decision/Consequences | **Corrected in `p13-merge` (item 1)** - now describes the five verification states, `payload_state`, `profile`, and the `record_type` tombstone discriminator, matching `control_plane/main.py::get_audit`'s current docstring and return shape | `docs/reports/p13-merge.md`, item 1 |
| `docs/adr/0003-opa-bundle-api.md` | Bundle API mechanics | Not touched this pass |
| `docs/adr/0004-pydantic-preflight-validation.md` | Schema-before-OPA rationale | Not touched this pass |
| `docs/adr/0005-outcome-taxonomy.md`, fault class table and Documented Boundary | Six fault classes, four reach the ledger | `tests/test_outcome_types.py::test_dashboard_fault_class_type_matches_reachable_set` (new, this pass) directly enforces the dashboard side of this claim |
| `docs/adr/0006-verification-states.md` | Five states, title | Unchanged and already correct; this pass corrected every other document that had drifted from it |
| `docs/adr/0007-two-tier-authorization.md` | Read key authorizes the read routes | **Extended this pass (R4)**: `GET /bundles/{tenant_id}` added to the read-key-gated set, named explicitly - `tests/test_dashboard_auth.py` (four new tests) |
| Dashboard, `dashboard/lib/types.ts::FaultClass` | **Corrected this pass (R5c)** | `tests/test_outcome_types.py::test_dashboard_fault_class_type_matches_reachable_set` |
| Dashboard, `dashboard/lib/types.ts::AuditEntry.profile` | **Widened this pass (R3)** to include `"unknown"` | `tests/test_record_profile.py::test_audit_forged_profile_less_record_renders_as_unknown_not_observed` |
| Dashboard, `dashboard/components/audit-table.tsx`'s `VerificationCell` comment | **Corrected this pass (R5b)** - comment only, code was already correct | Comment now matches the code and the ADR |
| Dashboard, `dashboard/components/audit-table.tsx`'s `DecisionCell` comment ("four outcome_types") | Checked - correct, not touched (there really are four `OutcomeType` values) | No fix needed |
| Dashboard, route handlers (`dashboard/app/api/*/route.ts`), `dashboard/middleware.ts` | Server-side-only credentials, caller auth gate | Unchanged this pass; `tests/test_dashboard_auth.py` |

**What was enumerated:** every README section, all seven ADRs in full, `dashboard/lib/types.ts` in full, and the two dashboard components the prior pass's own mapping cited (`audit-table.tsx`, `settings` page's use of `Tenant`/`TenantUpdate`). `docker-compose.yml` and `docker-compose.test.yml` in full (both were themselves the object of R1/R2's fix).

**What was not reached:** `dashboard/app/settings/page.tsx` and `dashboard/lib/api.ts` beyond the type-level check above (their prose comments, if any, were not individually audited line-by-line the way `audit-table.tsx`'s were - no known-stale claim was found there, but the search was not as exhaustive as the two-per-comment sweep this report gave `audit-table.tsx`). `docs/adr/0001`, `0003`, `0004` were read for the "no fault_class/state-count" class of staleness this pass was hunting and found clean, but not audited claim-by-claim against every test the way `0005`/`0006`/`0007` were, since no red-team finding this pass named them.

---

## 10. Pre-registered negatives - individual confirmation

- **Any port publishing a management or record surface in the deployment compose.** Confirmed absent: `tests/test_host_port_bindings.py::test_deployment_compose_publishes_no_management_or_record_port`, 7 cases, all passing; live-confirmed via `docker inspect` and the `host.docker.internal` re-run (section 2).
- **Any field rendering a silent default where the value is absent.** Checked `profile` (fixed, R3), `outcome_type` and `record_type` (already correct, no default). No other `.get(key, non-None-default)` pattern exists in `control_plane/main.py`'s `get_audit` (confirmed by regex sweep, section on R3).
- **Any route returning tenant configuration without a credential.** `GET /bundles/{tenant_id}` fixed (R4); `GET /tenants/{tenant_id}` was already fixed in the prior phase and reconfirmed still gated in this run's full suite (`test_control_plane_get_tenant_*`, 3 tests, passing).
- **Any claim not in the mapping.** Section 9's table covers README in full, all seven ADRs, and the dashboard type/component layer; gaps in coverage are named explicitly in "what was not reached" rather than silently omitted.
- **Any assertion weakened.** No test was narrowed, no collector filtered, no criterion loosened to make a result pass. Where a claim was corrected (README/ADR prose), the correction states a stricter or more precise fact than the original in every case (four states became five, not "some states"; a universal Envoy claim became a scoped, accurate one; a "four" fault-class union became the four that are actually correct, not a wider or vaguer set).
- **Any item met by live evidence alone with no test enforcing it.** R1/R2 (`test_host_port_bindings.py`), R3 (`test_record_profile.py`), R4 (`test_dashboard_auth.py`), R5c (`test_outcome_types.py`) each have a dedicated, mutation-tested enforcing test. R5a, R5b, R5d, and R7 are prose corrections to README/ADR text with no code behavior to assert against; their evidence is the live re-run transcripts quoted in sections 6 and 8, not a bare claim.

---

## 11. Full suite run (regression check)

Run against the live `docker-compose.test.yml` stack after all fixes landed, before the final commit:

```
$ python -m pytest tests/ -v
... 107 passed, 1 failed in 559.80s (0:09:19)
FAILED tests/test_docs_references_resolve.py::test_every_referenced_docs_path_exists_in_this_commit
  docs/reports/phase-1-3-complete.md referenced by ['docs/adr/0002-fastapi-immudb-proxy.md', 'readME.md']
  docs/reports/phase-1-3-redteam.md referenced by ['tests/test_host_port_bindings.py']
```

The single failure is `cleanup-p13-b`'s own dangling-reference test, working exactly as designed: this report and the red-team report it is based on were not yet committed when the suite ran. Both are committed in the same commit as this report (section 12). Re-running this specific test after that commit, against the committed tree, is required before CI is trusted - see section 12.

---

## 12. CI

Pushed `ce38cd0` to `origin/phase-1-3-complete`, opened PR #5 against `phase-1-1-remediation` to trigger the `pull_request` CI trigger (the workflow only runs on push to `main` or on a pull request; a plain branch push does not trigger it).

```
$ git push -u origin phase-1-3-complete
$ gh pr create --base phase-1-1-remediation --head phase-1-3-complete ...
https://github.com/banji-007/compliance-ail/pull/5
$ gh run view 32271095759 --json databaseId,headSha,status,conclusion,workflowName,url
{"conclusion":"success","databaseId":32271095759,"headSha":"ce38cd0fc9756693060250291179792c03d9b6f6","status":"completed","workflowName":"Integration Tests","url":"https://github.com/banji-007/compliance-ail/actions/runs/32271095759"}
```

CI run id: **32271095759**, conclusion: **success**.

**End SHA:** `ce38cd0fc9756693060250291179792c03d9b6f6`.

---

## 13. Could not verify

- Whether `dashboard/app/settings/page.tsx` and `dashboard/lib/api.ts` contain any further stale prose comments beyond the type-level checks this pass performed - not individually audited line-by-line (see section 9, "what was not reached").
- ~~`docs/adr/0002-fastapi-immudb-proxy.md`'s Decision and Consequences sections describe `/audit`'s response shape as a single `verified: true|false` boolean~~ - **resolved in `p13-merge`, item 1**: rewritten to describe the current five-state `verification` object, `payload_state`, `profile`, and `record_type`. See `docs/reports/p13-merge.md`.
- Whether every historical commit between the incidents `cleanup-p13-b`'s dangling-reference test cites and now was itself clean - that test only guards the current and future state (inherited limitation, restated from `docs/reports/cleanup-p13-b.md` section 6, not re-investigated this run).
- A second physical machine or a genuine WSL2 user distribution for V2's off-host reachability - same gap the red-team itself disclosed as untestable in this environment (`docs/reports/phase-1-3-redteam.md`, section 5); not re-attempted since R1's fix (removing the publish) makes the vantage point moot for the deployment compose specifically.

---

## Erratum, 2026-08-25 (added by Phase 3c-1, `p3c1-mapping`, item P3c1-3)

`tools/mapping_check.py` was run over section 9's R8 mapping table. The table
carries 38 rows. **One fails class (b)**, the support check. None fails class
(a).

- **Row 15**, Location "README §4.6, service endpoint table", Claim
  "**Corrected this pass (R1)** - Control Plane API and OPA rows removed (no
  longer published); replacement commands given and verified live". Class (b).
  Section 4.6 of `readME.md` carries none of the claim's load-bearing terms;
  the rule selects `given` and `replacement`.

**Citation defect, not a false claim.** Section 4.6 was read directly. Its
endpoint table lists only the CISO Control Plane, Grafana and Prometheus, so
the Control Plane API and OPA rows are indeed gone, and the section does give
replacement commands (`docker compose exec ail-control-plane python -c ...`
for OPA, and a sibling command for the control plane, from a container on
`backend`). Everything the row claims is true of the section it cites. The row
fails because its Claim column describes the edit that was made rather than
the state that resulted, and `replacement` and `given` are the report's own
words for that edit.

Coverage: 25 of this table's 38 rows cite a document section and 17 of those
yield no load-bearing term, so class (b) is decisive on 8 rows. Twelve rows
name nothing mechanically checkable, the highest count of any table in
`docs/reports/`, which is consistent with this table's own stated methodology
of mapping some claims to "Reproducible commands, unchanged" as prose.

The row is not corrected here. It is entered in
`docs/reports/mapping-check-baseline.json` and asserted by
`tests/test_mapping_tables.py`.

See `docs/adr/0013-mapping-table-self-check.md` and
`docs/reports/phase-3c1.md`.

---

## Erratum, 2026-08-26 (added by the Phase 3c-1 completion pass, `p3c1-complete`)

Red team `rt-p3c1-a` read the claim and the cited backing for every row of
this table that neither check could decide. It found one defect, in two rows,
and neither check reports it.

- **Row 14**, Location "README §4.5, bundle-load confirmation step", Maps to
  "Verified live in section 2 above".
- **Row 15**, Location "README §4.6, service endpoint table", Claim
  "replacement commands given and verified live", Maps to "Same as §4.5",
  which resolves to the same section 2.

**Section 2 of this report does not contain that verification.** It is R1's
port-binding evidence: it demonstrates that OPA's port is no longer published,
which is what broke the `curl localhost:8181` step, and it does not run the
compose-network command that replaced it. The only occurrence of `docker
compose exec` anywhere in this report is inside the erratum above, which
quotes the README. Section 2's own escalation note says the affordance "is
fixed in documentation (section 5 below)", and section 5 of this report is R4,
`GET /bundles/{tenant_id}` requires a credential, while section 6 is R5, whose
subsections cover four other statements. Neither carries the section 4.5 or
4.6 edit.

**Citation defect, not a false claim.** What the rows say about `readME.md` is
true and was re-checked: section 4.6's endpoint table lists only the CISO
Control Plane, Grafana and Prometheus, and section 4.5 gives the replacement
command. What is unsupported is "verified live", for which the cited section
carries no transcript. Whether the command was run during that pass cannot be
established from this tree either way, so this is filed as an erratum rather
than escalated.

**Why neither check reports it.** Both rows cite this report's own section 2.
An unqualified section marker names no document and is deliberately not parsed
as a citation, so class (b) never looks at it; row 14 names nothing
mechanically checkable at all, and row 15's class (b) failure is against
`readME.md` section 4.6 on different terms. This is the report-internal
citation shape recorded as out of reach in
`docs/adr/0013-mapping-table-self-check.md` (D28) and in `readME.md` section 5.
It is deliberately not in `docs/reports/mapping-check-baseline.json`: a
baseline records what the check reports, not what a person found.

The rows are not corrected here.

See `docs/reports/phase-3c1-redteam.md` (Z1) and
`docs/reports/phase-3c1-complete.md`.
