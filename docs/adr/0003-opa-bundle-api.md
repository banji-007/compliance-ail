# ADR 0003: OPA Bundle API over Direct Rego Push

## Status

Accepted

## Context

Policy changes (enabling/disabling a compliance framework, editing tenant
config like approved cost centers) need to take effect without restarting
OPA or the agent. Pushing Rego files directly to OPA's REST API on every
change, or baking policy into the OPA container image, both require a
restart or a manual sync step and give no natural cache-invalidation
signal.

## Decision

The control plane generates a spec-compliant bundle (tar.gz: `.manifest` +
`data.json` + the active Rego files) per tenant, keyed by a SHA-256 digest
of every file's content (`control_plane/bundle.py::generate_bundle`). OPA
is configured with the Bundle API (`opa-config.yaml`) and polls
`GET /bundles/{tenant_id}` on an interval, sending `If-None-Match` with the
last ETag it saw. Unchanged bundles return `304`; changed ones return the
new tar.gz with a new `ETag`.

`PUT /tenants/{tenant_id}` doesn't push anything to OPA directly - it just
changes what the next bundle generation will produce. OPA's own poll cycle
is what actually picks up the change, within the configured polling window.

## Consequences

**Gained:**

- No OPA restart on policy or tenant-config change.
- The bundle's own revision (its ETag) is exactly what Phase 1's
  `evaluation` rule reads back at `data.system.bundles.<name>.manifest.revision`
  - see `docs/adr/0005-outcome-taxonomy.md`. This is what lets the
  interceptor attribute a decision to the exact bundle content that
  produced it, not to a separately-computed hash that could disagree with
  what OPA actually loaded (`docs/reports/phase-0-redteam.md`, C2).

**Constraints:**

- Policy changes are not instantaneous - they take effect on OPA's next
  poll, bounded by `opa-config.yaml`'s `polling.min_delay_seconds` /
  `max_delay_seconds`.
- The bundle name (the map key under `bundles:` in `opa-config.yaml`) and
  `AIL_BUNDLE_NAME` (read by `interceptor/middleware.py`) must name the
  same bundle. See `docs/reports/phase-0-1.md`, P01-3, for the
  single-sourcing fix, and `interceptor/middleware.py::verify_bundle_at_startup`
  for the startup check that catches a mismatch before it can silently
  produce request-time denials.

## References

- `control_plane/bundle.py` - bundle generation and ETag computation
- `control_plane/main.py::get_bundle` - the Bundle API endpoint
- `opa-config.yaml` - OPA's bundle polling configuration
