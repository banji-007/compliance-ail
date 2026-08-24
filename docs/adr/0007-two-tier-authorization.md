# ADR 0007: Two-Tier Authorization for the Dashboard and Control Plane

## Status

Accepted

## Context

Before Phase 1.1, `CONTROL_PLANE_API_KEY` was a single shared credential
gating every mutating control-plane route, and the dashboard's own Next.js
Route Handlers (`dashboard/app/api/*/route.ts`) held it server-side and
attached it to every outbound request - but never checked anything about the
*inbound* request first. Red-team S6 (`docs/reports/phase-1-redteam.md`)
showed the consequence directly: an anonymous `curl` with zero headers read
the full audit log, including other agents' raw payloads, and mutated tenant
policy (`enable_hipaa`) through the dashboard's own `/api/*` routes. D4
(Phase 0) achieved its literal goal - the control-plane key never reaches
client-side JavaScript - by turning the dashboard server itself into an
unauthenticated proxy for everything that key was gatekeeping. The security
property the key existed to provide was fully defeated for anyone who could
reach the dashboard's port, a strictly larger population than "anyone who
has the key" ever was.

## Decision

Authorization splits at both layers, independently.

**Dashboard layer** (`dashboard/middleware.ts`): every request under `/api/`
must authenticate before any route handler runs, over HTTP Basic Auth with
two independent credential pairs - `DASHBOARD_READ_USER`/`PASSWORD` and
`DASHBOARD_WRITE_USER`/`PASSWORD`. Read (GET/HEAD) accepts either pair;
every other method requires the write pair specifically - the read pair
never authorizes a write route, and there is no hierarchy where one implies
the other. HTTP Basic Auth was chosen over a custom header + client-side
credential store because it requires zero new client code: the browser's
native auth dialog collects and caches the credential per origin after the
first challenge, and `curl -u user:pass` exercises it directly. An anonymous
or wrongly-scoped request never reaches a route handler, so it never causes
a control-plane key to be attached at all.

**Control-plane layer** (`control_plane/main.py`): the single
`CONTROL_PLANE_API_KEY` splits into `CONTROL_PLANE_READ_KEY` (authorizes the
three read routes, `GET /audit`, `GET /tenants/{tenant_id}`, and
`GET /bundles/{tenant_id}`) and `CONTROL_PLANE_WRITE_KEY` (authorizes
`PUT`/`POST /tenants`, `POST /content`, `DELETE /content/{call_id}`).
`GET /tenants/{tenant_id}` had no dependency at all until P13-3 (Phase 1.3)
added one - named by Phase 1.1's red-team (finding #2) and reconfirmed
still open by Phase 1.2's red-team (finding 6.2) in the interim; full
tenant configuration was readable with zero credentials until then.
`GET /bundles/{tenant_id}` had the same gap, named by the Phase 1.3
red-team (V6) and closed by R4 (Phase 1.3 completion pass): it returned
the same tenant configuration `GET /tenants/{tenant_id}` is gated to
protect. OPA is the only caller of this route in normal operation, and
carries the read key in `opa-config.yaml` as a static header on every
poll. These are independent secrets, not a hierarchy -
the read key structurally cannot authorize a write route, checked by
`_require_read_key`/`_require_write_key`, two separate FastAPI dependencies
replacing the single `_require_api_key`. Either key being unset returns 503
on the routes it gates, matching the prior fail-closed behavior for a
missing key.

The dashboard's own route handlers hold both control-plane keys and forward
the one that matches the route: `GET /api/audit` and `GET /api/tenants/{id}`
forward `CONTROL_PLANE_READ_KEY`; `PUT /api/tenants/{id}` forwards
`CONTROL_PLANE_WRITE_KEY`. Neither key is ever a `NEXT_PUBLIC_*` variable or
reachable from a client component (D4 is unchanged by this ADR).

## Why two independent layers, not one

A caller reaching a control-plane mutating route needs to pass two separate
checks that fail differently: the dashboard's own caller-auth (D6) rejects
an unrecognized caller before any control-plane credential is even
considered, and the control plane's own key scoping (also D6) rejects a
mismatched credential regardless of which layer presented it - confirmed
directly in `tests/test_dashboard_auth.py` by testing the control plane
without going through the dashboard at all. A regression that drops the
caller check from one dashboard route handler (the named mutation for
P11-1) is caught by tests written against both layers independently, not
just the layer where the regression happened to land.

## Consequences

**Gained:**

- `curl` with zero headers against `/api/audit` or `/api/tenants/{id}` (GET
  or PUT), and against the control plane's `/tenants`/`/content` routes
  directly, is rejected everywhere red-team S6 found it wasn't.
- A caller holding only the read-scoped credential at either layer is
  rejected on every write-shaped route - confirmed as its own named test
  case (`tests/test_dashboard_auth.py::test_read_credentialed_put_tenant_rejected`,
  `::test_control_plane_read_key_rejected_on_put_tenants`), not just implied
  by the write case passing.
- No client-side authentication code was added - `dashboard/lib/api.ts` and
  every page component are unchanged; the browser's native Basic Auth
  handling and Next.js middleware do all of it.

**Constraints:**

- HTTP Basic Auth sends credentials on every request (base64-encoded, not
  encrypted) - this deployment already terminates TLS upstream of the
  dashboard in the Kubernetes/Helm path; a production deployment without TLS
  in front of the dashboard would need one before this credential exchange
  is meaningful. This is unchanged from every other credential this project
  already assumes travels over a TLS-terminated connection (e.g.
  `CONTROL_PLANE_API_KEY` before this phase).
- Four credential pairs now exist (`DASHBOARD_READ/WRITE_*`,
  `CONTROL_PLANE_READ/WRITE_KEY`) where one existed before - rotation and
  provisioning touch more configuration surface, tracked in
  `docker-compose.yml`, `docker-compose.test.yml`, `Makefile`, and
  `.github/workflows/ci.yml` together, deliberately not something a single
  file's change can do silently.
- `dashboard/middleware.ts`'s method-based read/write split (`GET`/`HEAD` vs
  everything else) means any future mutating route added under `/api/`
  is write-gated automatically, without needing a per-route allowlist - but
  also means a future *read-only* route using a non-GET method (unusual, but
  possible) would be write-gated too; none exists today.

## References

- `dashboard/middleware.ts`
- `control_plane/main.py::_require_read_key`, `_require_write_key`
- `dashboard/app/api/audit/route.ts`, `dashboard/app/api/tenants/[id]/route.ts`
- `docs/reports/phase-1-redteam.md`, S6 - the open-relay finding this closes
- `docs/reports/phase-1-1-redteam.md` and `docs/reports/phase-1-2-redteam.md` - `GET /tenants/{tenant_id}`'s missing dependency, closed by P13-3 (Phase 1.3)
- `docs/reports/phase-1-3-redteam.md`, V6 - `GET /bundles/{tenant_id}`'s missing dependency, closed by R4 (Phase 1.3 completion pass)
- D4 (Phase 3) - the server-side-only credential handling this ADR extends
  rather than replaces; referenced in `dashboard/lib/api.ts` and
  `dashboard/app/api/*/route.ts` comments, no dedicated ADR of its own
- `tests/test_dashboard_auth.py`, including
  `test_control_plane_get_tenant_rejected_with_no_key`,
  `::test_control_plane_get_tenant_rejected_with_wrong_key`,
  `::test_control_plane_get_tenant_accepted_with_read_key` (P13-3),
  `::test_control_plane_get_bundle_rejected_with_no_key`,
  `::test_control_plane_get_bundle_rejected_with_wrong_key`,
  `::test_control_plane_get_bundle_accepted_with_read_key`,
  `::test_opa_still_loads_bundle_through_the_now_credentialed_poll` (R4)
- `docs/adr/0011-verifier-authentication.md` (D21, Phase 3a completion) -
  extends this same two-tier pattern to a third service, `verifier/main.py`,
  with its own independent credential pair
