# ADR 0006: Four Read-Time Verification States

## Status

Accepted

## Context

Before Phase 1, `/audit` reported a single boolean, `verified`, computed by
calling the verifier's `/verify` for each entry during the scan. `false`
collapsed three different situations into one: a genuine tamper detection
(a proof or signature actually failed), the verifier being unreachable for
that specific entry, and - because the handler stops calling the verifier
after the first failure in a scan ("stop hammering on every entry") - every
later entry in the same response that was never even attempted. Finding
#3 in `docs/reports/phase-0-1-redteam.md` names this directly:
`dashboard/lib/types.ts`'s own `AuditEntry.verified` comment already
documented the conflation without a fix.

## Decision

A ledger entry cannot assert its own verification status - that would be
self-certifying, and it says nothing about whether the check was even
attempted for *this* read. Verification state is computed by `/audit`
(`control_plane/main.py::get_audit`) at request time, per entry, and lives
only in the API response - never inside the immutable entry itself.

Four states, not one boolean:

| State | Meaning |
| :--- | :--- |
| `verified` | A `verifiedGet` ran and every proof passed. Carries `state_id`. |
| `failed` | A `verifiedGet` ran and a proof or signature was rejected - the tamper signal. Carries `error_class` (`consistency_failure` vs `signature_failure`, from `verifier/main.py`'s own exception handling) and `detail`. |
| `unverifiable` | A `verifiedGet` was attempted and could not complete (verifier unreachable, non-200, transport error). Carries `detail`. |
| `asserted` | No `verifiedGet` was attempted for this entry in producing this response. |

The distinction between `unverifiable` and `asserted` matters operationally:
in a single `/audit` scan, the *first* entry the verifier fails to reach is
`unverifiable` (we tried, it didn't work); every entry after it in that same
scan, for which the handler never even attempts a call once `verifier_up`
flips false, is `asserted` (we didn't try). `asserted` is deliberately not
treated as a problem by itself - it also covers the case of lazy
verification on an unexpanded row, which Phase 1 doesn't implement but
doesn't want to preclude either.

Write-time verification is unaffected by this ADR: `ledger/immudb_ledger.py`'s
write path stays binary and fail-closed - `verifiedSet` passes or the call
denies (see `docs/adr/0005-outcome-taxonomy.md`'s `verifier_unreachable`
fault class). These four states describe a *read*, not a write.

## Consequences

**Gained:**

- The dashboard (`dashboard/components/audit-table.tsx`) can render a real
  tamper detection, a verifier outage, and an unchecked row with three
  visually distinct treatments, instead of one red "UNVERIFIED" badge that
  meant all three.
- `error_class` lets an operator distinguish "someone tampered with the
  ledger content" (`consistency_failure`) from "the verifier's signing key
  doesn't match what it should" (`signature_failure`) - previously both
  surfaced as the same generic `detail` string.

**Constraints:**

- A large `/audit` scan where the verifier goes down early produces mostly
  `asserted` entries, not mostly `unverifiable` ones - by design, but worth
  knowing when reading a response where every entry after the first handful
  says "not checked" rather than "could not check".
- This ADR does not implement lazy/on-expand verification; `asserted` is
  currently only produced by the existing scan's circuit breaker, not by any
  new deferred-check mechanism.

## References

- `control_plane/main.py::get_audit` - where all four states are computed
- `verifier/main.py::verify` - `error_class` (`consistency_failure` /
  `signature_failure` / `unknown`)
- `dashboard/lib/types.ts::Verification`, `dashboard/components/audit-table.tsx::VerificationCell`
- `docs/reports/phase-0-1-redteam.md`, finding #3 - the conflation this closes
