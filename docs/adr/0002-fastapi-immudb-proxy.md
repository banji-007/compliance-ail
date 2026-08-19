# ADR 0002: FastAPI as ImmuDB Proxy

## Status

Accepted

## Context

ImmuDB is intentionally not exposed on the host network interface. As of R1/R2 (Phase 1.3 completion pass), `docker-compose.yml`'s `immudb` service publishes neither the gRPC port (3322) nor the REST port (8080) to the host - both are a direct ledger read/write surface, independent of the verifier layer entirely, and a loopback-only bind was found not to hold (`host.docker.internal` reaches a loopback-bound port from any container on the Docker host - see `docs/reports/phase-1-3-complete.md`, R1). Before this fix, the gRPC port was published unrestricted (`"3322:3322"`), contradicting this ADR's own claim - that contradiction is what R2 closes. `docker-compose.test.yml` publishes both ports, deliberately, so the integration suite's own ImmuDB scans (`tests/test_verification.py`, `tests/test_record_profile.py`) can reach it directly from the host; it is never a deployment target. The CISO dashboard is a browser application and cannot reach an internal Docker-network-only service directly, and should not be given direct ImmuDB credentials regardless.

## Decision

The FastAPI control plane exposes `GET /audit`, which:

1. Scans ImmuDB via its REST API for `tool_call:` key listing (a plain scan needs no SDK-level proof).
2. For each entry found, calls the verifier service's `POST /verify` (which performs `verifiedGet` - see ADR-0001) to get a real, per-entry proof result.
3. Returns each entry with `verified: true|false` and the `state_id` it was checked against, appended to the response regardless of the verification outcome - an entry that fails verification is surfaced as an integrity warning, not dropped from the response. Only entries whose stored payload itself fails to decode are skipped, which is a malformed-record guard, not a verification-outcome filter.

CORS is restricted to `http://localhost:3001` (the dashboard's own origin) via `CORSMiddleware` in `control_plane/main.py`.

## Consequences

**Gained:**

- The dashboard never holds ImmuDB or verifier credentials; it only ever talks to the control plane over HTTP with its own restricted CORS origin.
- Every entry the dashboard displays carries a live proof result from the same verifier chain described in ADR-0001, not a cached or inferred flag.

**Constraints:**

- Per-entry `verifiedGet` on `/audit` is O(n) SDK calls against the verifier. At the default limit of 100 entries this is acceptable; consider lazy verification (verify on expand) if audit pages grow large.
- If the verifier becomes unreachable partway through a scan, the endpoint stops calling it for the remainder of that scan and defaults the remaining entries to `verified: false` rather than retrying per entry - a fail-safe default, not a fresh proof check, for whatever entries follow the failure in that response.

## References

- `control_plane/main.py` - `GET /audit` implementation
- `docs/adr/0001-immudb-rest-migration.md` - the verifier service `/audit` calls into
- `docs/audit/2026-08-16-verification.md` - V6, live confirmation of this behavior
