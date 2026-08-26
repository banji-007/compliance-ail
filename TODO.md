# AIL v1.1.0 Backlog

Items explicitly deferred from the hardening sprints. One item is blocking, in the section directly below; everything after it is deferred and the current build is stable and production-hardened.

---

## Blocking for Phase 3c-3

### `GET /audit` returns the wrong records once the ledger exceeds `limit`
`desc: true` sorts by key, `tool_call:` keys lead with `agent_id`, so a page returns the lexicographically-largest agent ids rather than the newest decisions, and a record written seconds ago can be absent once the ledger exceeds `limit`. Observed during `p3c2-defer` at 211 entries: the newest transaction was 573 and the page's first row was not it (`docs/reports/phase-3c2.md`).

---

## Deferred (v1.1.0)

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
- Writing a new mapping row can retire a historical baseline entry by making a stem generic; instanced by `docs/reports/phase-1-3.md` row 16 during `p3c1-complete` (`docs/adr/0013-mapping-table-self-check.md`). The same coupling runs the other way and is easier to trip: ordinary prose added to a *cited* document can make a word distinctive that was previously absent from it, which rewrites the reason string of a historical baseline entry and fails the build on a row nobody touched. Instanced during `p3c2-defer`: one word in a new README bullet changed `docs/reports/phase-3a.md` row 8's baselined reason from one selected term to two. Resolved by rewording the new prose, not by editing the quarantine record, since the row itself had not changed (`docs/reports/phase-3c2.md`).

---

## Structural Expansions (v1.1.0+)

### ~~Phase 3: `/audit` O(n) Verification Cost~~ (closed, Phase 3c-2)
Per-entry synchronous verifier round trip on `GET /audit` was `O(min(limit, ledger))`, not O(n) against ledger size - the bound is the page size whenever the ledger is larger than it, which is the case this item was actually reporting. Confirmed to time out tests at ~200 ledger entries (`docs/reports/phase-1-3-redteam.md`). Closed by D29 (`docs/adr/0006-verification-states.md`): the default page defers verification and one record is checked on expand. `GET /audit?verify=true` still costs the full per-record scan, so the cost is opt-in rather than removed (`docs/reports/phase-3c2.md`).

### Framework Expansion (PCI-DSS, ISO 27001)
The current gateway ships with 4 baseline policy frameworks (GDPR, SOC2, FinOps, HIPAA). To expand enterprise commercial viability, the Rego policy library needs to cover additional major compliance standards.

**Scope:** Author, test, and integrate new Rego packs for PCI-DSS (targeting CDE scoping) and ISO 27001. Update the FastAPI control plane to serve these as selectable toggles in the UI.
