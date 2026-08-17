# ADR 0006: Five Read-Time Verification States

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
(`control_plane/main.py::get_audit`, via the extracted pure function
`_verification_from_200`) at request time, per entry, and lives only in the
API response - never inside the immutable entry itself.

Five states, not one boolean:

| State | Meaning |
| :--- | :--- |
| `verified` | A `verifiedGet` ran and every proof passed. Carries `state_id`. |
| `failed` | A `verifiedGet` ran and a proof or signature was rejected - the tamper signal. Carries `error_class` (`consistency_failure` vs `signature_failure`, from `verifier/main.py`'s own exception handling) and `detail`. (D10, Phase 1.2: this is the *only* way into `failed` - see below.) |
| `unverifiable` | A `verifiedGet` was attempted and could not complete (verifier unreachable, non-200, transport error), **or** completed but returned an `error_class` this function does not positively recognize as tamper evidence (D10, Phase 1.2). Carries `detail`. |
| `asserted` | No `verifiedGet` was attempted for this entry in producing this response. |
| `not_found` | (Phase 1.1, D8) A `verifiedGet` was attempted against a key no entry was ever written for. Not a tamper signal - no proof was ever rejected, because there was never a proof to check - and not `unverifiable` either, since the check did complete cleanly. Carries `error_class: "not_found"` and `detail`. |

### `failed` requires positive identification, not a default (D10, Phase 1.2)

Red-team T1 (`docs/reports/phase-1-1-redteam.md`): `control_plane/main.py::
_verification_from_200` had exactly three branches - `verified`, `not_found`,
and an unconditional `else` that mapped everything else to `failed`. Live
testing showed the consequence directly: simulating an upstream message-text
drift (mutating the string `verifier/main.py`'s `not_found` detection
matches) reclassified a never-written key's `error_class` as `"unknown"`,
which the old default promoted straight to `failed` - the highest-severity,
tamper-implying state in this taxonomy, for a condition involving no
tampering and no rejected proof at all. Nothing about that drift touches
source code; there is no build for it to fail.

`failed` is now a positive claim, not a fallback: `error_class` must be
exactly `"consistency_failure"` or `"signature_failure"` - `verifier/main.py`'s
own two exception-derived classes, the only conditions where a proof or
signature was actually rejected. `not_found` keeps its own branch, checked
first (unchanged from D8). Everything else - `"unknown"`, or any
`error_class` this function has never seen at all - maps to `unverifiable`,
with `detail` preserved so the information isn't lost, only correctly
de-escalated from a tamper alarm to "could not positively verify this."

### `not_found` is not `failed`, and how it's actually detected

Red-team S8: a `verifiedGet` on a key that was never written returned
`verified: false, error_class: "unknown"` at HTTP 200 (caught by the
verifier's old blanket `except Exception`), which `get_audit` then promoted
to `state: "failed"` - the tamper signal - for a condition that involved no
tampering and no rejected proof at all. `not_found` fits none of the other
four states: the verifier answered cleanly at HTTP 200, so not
`unverifiable`; a `verifiedGet` was attempted, so not `asserted`. It is
operationally a bug or race signal, not a security signal, and folding it
under `failed` (as an `error_class`, rather than its own state) would leave
the dashboard badge wrong and put the conflation back in UI branching.

The original plan called for `verifier/main.py::verify` to detect this via
the gRPC status code `VerifiableGet` returns, on the theory that a status
code is a more stable contract than matching an exception's message text.
Live testing against immudb 1.9.5 disproved the premise: `VerifiableGet` on
a missing key returns `grpc.StatusCode.UNKNOWN`, not `NOT_FOUND` - the
server gives no status-code-level way to distinguish "key never written"
from any other failure at all. `immudb-py`'s own plain-`Get` handler
(`immudb/handler/get.py::call`) makes exactly this distinction the same way,
out of the same necessity: `e.details().endswith('key not found')`. D8
follows that established precedent for `VerifiableGet` rather than inventing
a different strategy the SDK itself doesn't use. This is still a real
fragility, just not the one originally assumed - `verifier/requirements.txt`
pins `immudb-py==1.5.0` specifically so this string match doesn't silently
break on an upgrade; re-verify it against `immudb/handler/get.py` in the
new version before bumping that pin.

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
fault class). These five states describe a *read*, not a write.

### Bundle revision attribution is no longer caller-suppliable (D9, Phase 1.2)

A related but distinct integrity gap sat next to this ADR's own subject:
`policy/core/main.rego`'s `evaluation` rule (the per-call source of
`policy_revision`, the field this ledger entry's own attribution
ultimately rests on) read `data.system.bundles[input.bundle_name].manifest
.revision` - `input.bundle_name` was part of the request the interceptor
itself sent, sourced from `AIL_BUNDLE_NAME`. Nothing stopped a caller who
could reach OPA directly (bypassing the interceptor, or on a compromised
interceptor) from naming a different loaded bundle instead - red-team T7
(`docs/reports/phase-1-1-redteam.md`) reproduced exactly this: a decoy
bundle, added to a running OPA, whose revision got attributed to a real
FinOps deny reason simply by naming it.

D9 removes `input.bundle_name` from the request document entirely. The
revision is now derived by `policy/core/main.rego` itself, from whichever
loaded bundle's manifest actually claims the `ail` root
(`data.system.bundles[name].manifest.roots`) - a caller supplies nothing
that influences this. Exactly one claimant resolves; zero or more than one
makes `evaluation` itself undefined, which `interceptor/middleware.py`
already treats as `FAULT_REVISION_UNAVAILABLE` (a fault, not a guess). This
runs on every evaluation, not once at boot - closing T7's second finding,
that a bundle added to OPA's live configuration after the interceptor had
already started was never rechecked - and it obsoletes P11-7's own
startup-only single-claimant check (`_check_bundle_root_ownership`), which
only ever flagged a second bundle claiming the *same* root and never the
mechanism T7 actually used (see `docs/reports/phase-1-1.md`'s erratum).

## Consequences

**Gained:**

- The dashboard (`dashboard/components/audit-table.tsx`) can render a real
  tamper detection, a verifier outage, an unchecked row, and a no-record
  condition with four visually distinct treatments, instead of one red
  "UNVERIFIED" badge that meant all of them.
- `error_class` lets an operator distinguish "someone tampered with the
  ledger content" (`consistency_failure`) from "the verifier's signing key
  doesn't match what it should" (`signature_failure`) from "this key
  reference doesn't point at anything" (`not_found`, Phase 1.1) - previously
  all three surfaced as the same generic `detail` string, or worse, the same
  `failed` badge.
- `control_plane/main.py::_verification_from_200` is a pure function,
  extracted from `get_audit`'s previously-inline logic specifically so
  `not_found`'s mapping is directly unit-testable (see
  `tests/test_verification.py::test_control_plane_maps_not_found_state_not_failed`)
  without needing a key that is both scanned by ImmuDB and simultaneously
  never written - a contradiction `/audit`'s own scan can't construct, since
  it only ever lists keys ImmuDB confirms exist.

**Constraints:**

- A large `/audit` scan where the verifier goes down early produces mostly
  `asserted` entries, not mostly `unverifiable` ones - by design, but worth
  knowing when reading a response where every entry after the first handful
  says "not checked" rather than "could not check".
- This ADR does not implement lazy/on-expand verification; `asserted` is
  currently only produced by the existing scan's circuit breaker, not by any
  new deferred-check mechanism.
- `not_found` is a live-testable state in isolation (a fabricated key
  against `verifier/main.py::verify` directly) but not end-to-end through
  `/audit`'s own scan+verify flow, for the structural reason above.

## References

- `control_plane/main.py::get_audit`, `_verification_from_200` - where all
  five states are computed
- `verifier/main.py::verify` - `error_class` (`consistency_failure` /
  `signature_failure` / `not_found` / `unknown`)
- `dashboard/lib/types.ts::Verification`, `dashboard/components/audit-table.tsx::VerificationCell`
- `docs/reports/phase-1-redteam.md`, S8 - the conflation this closes
- `tests/test_verification.py::test_not_found_state`,
  `::test_control_plane_maps_not_found_state_not_failed`,
  `::test_control_plane_maps_unknown_error_class_to_unverifiable_not_failed`,
  `::test_control_plane_maps_both_tamper_classes_to_failed` (D10, Phase 1.2)
- `docs/reports/phase-0-1-redteam.md`, finding #3 - the conflation this closes
- `docs/reports/phase-1-1-redteam.md`, T1 - the `unknown`-to-`failed` conflation D10 closes; T7 - the caller-suppliable revision D9 closes
- `policy/core/main.rego::_ail_root_owners`, `_ail_bundle_name`, `evaluation` (D9, Phase 1.2)
- `tests/test_bundle_revision_attribution.py` (D9, Phase 1.2)
