# AIL v1.1.0 Backlog

Items explicitly deferred from the hardening sprints. Nothing is blocking.

---

## Blocking

Nothing is blocking. The current build is stable and production-hardened; everything below is deferred.

**Closed in Phase 3c-3b (`docs/reports/phase-3c3b.md`, ADR-0014).** `GET /audit` used to return the lexicographically-largest agent ids and call them recent, because `desc: true` walks keys and a `tool_call:` key leads with `agent_id` - so a record written seconds ago was absent once the ledger exceeded `limit` (observed during `p3c2-defer` at 211 entries, reproduced at 501 during 3c-3b). No read parameter could fix it: `scan` has no ordering option, `TxScan` is not routed over REST, and no key this project writes is temporal or monotonic. The page is now selected through a view index whose score is a position allocated under a compare-and-set the ledger enforces, committed in the same transaction as the record it indexes. The count and tombstone halves of this entry closed earlier, in Phase 3c-3a (`docs/reports/phase-3c3a.md`).

What that phase added to the deferred list rather than closing is recorded in README's Residual Limits: the CAS globally serialises the ledger write path, so concurrency stops buying throughput, and the retry budget is an availability parameter that can deny traffic if it is set too low.

**Closed in Phase 3c-3c (`docs/reports/phase-3c3c.md`, ADR-0014 D35/D36/D37).** The red-team pass against 3c-3b refuted eight of ten claims; that set is closed. What it added to the deferred list rather than closing is the entry immediately below, plus three Residual Limits entries in the README.

---

## Deferred (v1.1.0)

### `fault_class: verifier_unreachable` covers two materially different outcomes

Raised in review of Phase 3c-3c and deliberately **not** taken as a decision in that phase. Since D35 this one closed-set class covers both:

- the verifier could not be reached, or the write did not commit, so **no ledger entry exists** (the original meaning, and the structural limit ADR-0005's Documented Boundary describes: nothing can write a durable record of "the durable-record writer is down");
- the write **committed** and its proof did not check out, so the record is in the ledger at a real transaction and position, indexed, with the counter advanced, and a `ledger_fault:` record qualifies it.

Both return `outcome_type: fault, fault_class: verifier_unreachable` and the call denies either way. **This is the same collapse D1 exists to prevent, one level down**: D1's point was that a fault is distinguishable from a denial, and here two faults with opposite consequences for the audit record are not distinguishable from each other by the field a consumer switches on.

Why it is deferred rather than fixed in 3c-3c. The distinction is cheap to *compute* - the write response already carries `committed`, and `ledger/immudb_ledger.py` would need to raise a typed exception rather than a bare `RuntimeError` for `decision_service/main.py` to map it - but the change is not a rename. It alters ADR-0005's closed set, which is D1's own artifact; it changes the Prometheus label collection that `tests/test_outcome_types.py::test_metric_label_set_matches_closed_collection` asserts, so any alert or dashboard keyed on the class changes meaning; and the right shape is genuinely open, because a call whose record committed unproven may not belong under the same `outcome_type` at all rather than merely under a second `fault_class`. That is an ADR-0005 conversation, and running it inside a remediation phase already closing eight refutations would make the least-examined part of that phase the taxonomy.

What exists in the meantime: the distinction is available to a caller in the write response's `committed` field and on the `/audit` row's `ledger_fault`, and it is stated in ADR-0005's Documented Boundary amendment and README's Residual Limits. What is collapsed is the class name.

### ImmuDB TLS
ImmuDB's REST API communicates over plain HTTP on the internal Docker network (`http://immudb:8080`). Internal Docker traffic is isolated from the host, but TLS should be enforced for defence-in-depth and to satisfy stricter SOC2 transport encryption requirements.

**Scope:** Configure ImmuDB with a TLS certificate, update `IMMUDB_URL` to `https://`, add the CA to the control plane and interceptor HTTP clients.

### SQLite → PostgreSQL
The control plane uses SQLite (`/data/control_plane.db`) backed by a Docker volume. This is sufficient for a single-instance deployment but provides no HA, no WAL replication, and no connection pooling under concurrent load.

**Scope:** Add a `postgres` service to `docker-compose.yml`, update `DATABASE_URL`, replace the volume with a managed DB in production Kubernetes deployments.

---

## Low Priority (unscheduled)

### Rate Limiting on OPA Queries
The interceptor middleware has no rate limit on the OPA policy evaluation path. A compromised or runaway agent could flood the policy engine.

**Scope:** Add a token-bucket or sliding-window rate limiter in `interceptor/middleware.py` before the `query_opa_policy` call.

### Remove Stale `/policies/` Directory
An old `/policies/` directory exists alongside the canonical `/policy/` directory. It is not referenced by any active code path but adds confusion.

**Scope:** Delete `/policies/`, confirm no scripts reference it, commit.

### Single-Instance ImmuDB
ImmuDB runs as a single container with a local volume. There is no backup, no replication, and no HA. A volume failure loses the entire audit ledger.

**Scope:** For production Kubernetes, deploy ImmuDB with a persistent volume claim backed by a replicated storage class, and implement scheduled backup to object storage (S3/GCS).

### Attacker-Reachable Signing-Key Mismatch Test
`tests/test_verification.py::test_tamper_pubkey` overwrites the `_vk` attribute on an `ImmudbClient` object the test itself constructs, then confirms `verifiedGet` raises `BadSignatureError`. This proves the SDK detects a verifying-key mismatch, but the vector it exercises (patching a private attribute on an in-process object) is not reachable by an external attacker or by anything the verifier's own deployment surface exposes. It does not simulate an attack; see README section 3.4 and ADR-001's References.

**Scope:** Add a test that exercises the vector an attacker (or a misconfigured deployment) with disk access to the verifier's mounted `IMMUDB_SIGNING_PUBKEY` file could actually cause: swap the file the *running* verifier process reads its public key from (e.g. mount a different key file, or point `IMMUDB_SIGNING_PUBKEY` at a second, unrelated keypair's public half before the verifier starts), then confirm the real `/verify` HTTP endpoint on the running verifier container returns `verified: false` for an otherwise-legitimate entry, exercising the same failure through the actual deployed service rather than a hand-modified client object.

### Workload Registrar Retry Logic
The `workload-registrar` script currently runs exactly once at startup. If it executes and completes before the agent is fully attested, the `langgraph-demo` container may start with stale or missing SPIFFE identity entries, causing a race condition in local environments.

**Scope:** Update the registrar startup script to include a retry/backoff loop or a liveness probe that verifies SVID fetch succeeds before the script exits.

- SPIRE `insecure_bootstrap` and `trust_domain` (`spire/agent/agent.conf`, `spire/server/server.conf`) are documented only in an inline comment, with no project-docs claim and no test (found in the Phase 2 completion pass B config sweep, `docs/reports/phase-2-completion-b.md`).
- Vault tool round trip is ~15s (a fresh Python interpreter per call, no persistent MCP session); Envoy's route timeout was raised to 45s to accommodate it (`docs/reports/phase-2.md`).
### Every service mounts every writer's private key (D22 item)

Raised in review of the Phase 3c-3c completion pass. `./keys:/keys:ro` is mounted by `ail-control-plane`, `verifier`, `decision-service`, `anchor-service` and `immudb` in `docker-compose.yml`, so each of them holds **every** writer's private key. The services are separated only by which path their own `AIL_WRITER_SIGNING_KEY` points at, which is a configuration convention rather than a boundary.

**What this costs.** D22's stated purpose was that "a bundle's `writer_key_fingerprint` names which service wrote the record". It does not: any of those services can read `/keys/writer-decision.key` and produce a signature indistinguishable from the decision service's own. The fingerprint names a key, and the key does not name a component. That matters exactly when it would be relied on, which is after one of them is compromised: a compromised control plane can forge a record attributed to the decision service, and no check in this project distinguishes that from the real thing.

**What is unaffected.** Per-key revocation, because `tools/ail_verify_bundle.py`'s deny-list operates on key fingerprints rather than on services. And the refusal of an unsigned record.

**Scope.** Give each service a mount of only the key it is configured to use (`./keys/writer-decision.key:/keys/writer-decision.key:ro` and so on), which needs a decision about what `immudb` requires from that directory - it mounts it for `--signingKey=/keys/signing.key` and has no writer key of its own. The claim in `docs/adr/0012-writer-signing-and-external-anchoring.md` and `readME.md` §5 is corrected to what the mechanism actually supports in the meantime, rather than left standing until this is done.

### Corpus coupling in the mapping check

- Writing a new mapping row can retire a historical baseline entry by making a stem generic; instanced by `docs/reports/phase-1-3.md` row 16 during `p3c1-complete` (`docs/adr/0013-mapping-table-self-check.md`). The same coupling runs the other way and is easier to trip: ordinary prose added to a *cited* document can make a word distinctive that was previously absent from it, which rewrites the reason string of a historical baseline entry and fails the build on a row nobody touched. Instanced during `p3c2-defer`: one word in a new README bullet changed `docs/reports/phase-3a.md` row 8's baselined reason from one selected term to two. Resolved by rewording the new prose, not by editing the quarantine record, since the row itself had not changed (`docs/reports/phase-3c2.md`). Both directions fired again in Phase 3c-3c, three times in one phase, always resolved the same way.
- A third shape, and the one no run of the checker reports: **a row can cite a document that is itself wrong.** Class (b) asks whether a cited section contains a distinctive term from the claim, so a claim that is false and a cited section that repeats the same false thing agree perfectly and the row passes. Instanced in the Phase 3c-3c completion pass: `readME.md` §5 said a `writer_key_fingerprint` names which service wrote a record, citing `docs/adr/0012-writer-signing-and-external-anchoring.md`, which is where the claim originates and where it was equally wrong - and `readME.md` §3.4 said a proof failure produces no ledger entry, citing `docs/adr/0005-outcome-taxonomy.md`, same shape. Correcting only the citing document leaves the citation pointing at the uncorrected source, and correcting only the source leaves the citing document wrong; the checker is satisfied either way, and in both instances above it was satisfied while both documents were wrong. Nothing mechanical catches this. What it means in practice: when a phase changes behaviour, sweep for the old claim's *wording* across the corpus rather than fixing the sites a review happened to name, and fix the cited source as well as the citing row.

---

## Structural Expansions (v1.1.0+)

### ~~Phase 3: `/audit` O(n) Verification Cost~~ (closed, Phase 3c-2)
Per-entry synchronous verifier round trip on `GET /audit` was `O(min(limit, ledger))`, not O(n) against ledger size - the bound is the page size whenever the ledger is larger than it, which is the case this item was actually reporting. Confirmed to time out tests at ~200 ledger entries (`docs/reports/phase-1-3-redteam.md`). Closed by D29 (`docs/adr/0006-verification-states.md`): the default page defers verification and one record is checked on expand. `GET /audit?verify=true` still costs the full per-record scan, so the cost is opt-in rather than removed (`docs/reports/phase-3c2.md`).

### Framework Expansion (PCI-DSS, ISO 27001)
The current gateway ships with 4 baseline policy frameworks (GDPR, SOC2, FinOps, HIPAA). To expand enterprise commercial viability, the Rego policy library needs to cover additional major compliance standards.

**Scope:** Author, test, and integrate new Rego packs for PCI-DSS (targeting CDE scoping) and ISO 27001. Update the FastAPI control plane to serve these as selectable toggles in the UI.
