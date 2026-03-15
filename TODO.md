# AIL v1.1.0 Backlog

Items explicitly deferred from the hardening sprints. Nothing here is blocking — the current build is stable and production-hardened.

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

### Workload Registrar Retry Logic
The `workload-registrar` script currently runs exactly once at startup. If it executes and completes before the agent is fully attested, the `langgraph-demo` container may start with stale or missing SPIFFE identity entries, causing a race condition in local environments.

**Scope:** Update the registrar startup script to include a retry/backoff loop or a liveness probe that verifies SVID fetch succeeds before the script exits.

---

## Structural Expansions (v1.1.0+)

### Framework Expansion (PCI-DSS, ISO 27001)
The current gateway ships with 4 baseline policy frameworks (GDPR, SOC2, FinOps, HIPAA). To expand enterprise commercial viability, the Rego policy library needs to cover additional major compliance standards.

**Scope:** Author, test, and integrate new Rego packs for PCI-DSS (targeting CDE scoping) and ISO 27001. Update the FastAPI control plane to serve these as selectable toggles in the UI.
