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

### Verification is deferred by default, and the reserved option is taken (D29, Phase 3c-2)

This ADR wrote `asserted` to cover two producers and implemented one. The
Decision section above says `asserted` "is deliberately not treated as a
problem by itself - it also covers the case of lazy verification on an
unexpanded row, which Phase 1 doesn't implement but doesn't want to preclude
either." Phase 3c-2 implements it.

`GET /audit` no longer verifies per record by default. Every row comes back
`asserted`, and a reader who wants a specific record checked expands it,
which calls `GET /audit/verify?key=` for that one record. **This is a change
to when verification runs, not to what the states mean.** No state is added,
none is redefined, and `asserted` covers the deferred row for the reason it
was written to: no `verifiedGet` was attempted for this entry in producing
this response, which is exactly true of a deferred one.

**Verification stays reachable: `GET /audit?verify=true`.** Deferral is the
default, not the only behaviour. Two things depend on this. The circuit
breaker that produced `asserted` before this phase lives on that path, and
under unconditional deferral it would be unreachable code, leaving the state
this ADR describes with one producer instead of the two it names. And two
existing assertions read a real verification state off `/audit`: without the
parameter, `tests/test_verification.py::test_cross_process` would fail, and
`tests/test_content_states.py`'s erasure test, which compares the state
before an erasure to the state after it, would compare `asserted` to
`asserted` and pass while proving nothing. A weakened assertion that goes
red is a nuisance; one that stays green is how a phase certifies itself.

**Deferral removes the only outage signal there was, so the response carries
one field.** Before this phase an unreachable verifier left a fingerprint on
the page: the first entry's attempt failed and rendered `unverifiable`, and
the circuit breaker then produced the run of `asserted` rows the Constraints
section below describes. Defer every attempt and there is no first attempt to
fail, so nothing is `unverifiable` and an outage renders exactly like a
healthy stack that simply did not look.

`/audit` therefore reports `verifier_reachable`, from a live `GET /health`
against the verifier on **every** path, including `?verify=true` where the
per-record calls would also answer the question. One field, established one
way, so it cannot mean two things depending on which path produced it. The
cost is one round trip against the up-to-`limit` this phase removed.

It is one field and not a pair. A `verification_mode` of `scanned` or
`deferred` would re-encode a distinction this ADR already draws: all rows
`asserted` with no `unverifiable` already means nothing was attempted. A
redundant summary of the rows can drift out of agreement with the rows.

**What `verifier_reachable` establishes, exactly.** The verifier answered a
health check at the moment this response was produced. It does not mean these
rows would verify. A probe that succeeds can be followed by an expand that
fails: they are separate calls at separate times, and no field closes that
gap. The field is named for the reachability it establishes rather than for
the verification it does not.

**`not_found` is now reachable end to end.** The third Constraints bullet
below said `not_found` was live-testable only against `verifier/main.py`
directly, because `/audit`'s own scan lists keys ImmuDB confirms exist and a
key that is simultaneously scanned and never written is not constructible.
`GET /audit/verify` takes a key from the caller rather than from a scan, so
that case is now the ordinary one:
`tests/test_deferred_verification.py::test_per_record_route_reports_not_found_for_an_unwritten_key`.

`failed` remains the one state with no live path through this control plane.
The two tamper tests corrupt a client-side `PersistentRootService` in the
test process and never reach the verifier service; producing a live `failed`
means corrupting the verifier's own persisted state and restarting it, which
leaves the stack inconsistent for everything after it. Its enforcing test is
therefore a mapping unit test against a fabricated verifier body, the same
treatment `not_found` already had and the same reason `_verification_from_200`
was extracted as a pure function.

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
- Lazy/on-expand verification **is** implemented, as of D29 (Phase 3c-2):
  `GET /audit` defers by default, `GET /audit/verify?key=` checks one record,
  and `asserted` now has the two producers this document always described -
  deferral, and the scan's circuit breaker on the `?verify=true` path. This
  bullet previously said the opposite, correctly, for every phase before
  3c-2. Bookkeeping on which of the reserved options was taken; the five
  states are unchanged.
- The bullet above still describes the `?verify=true` path exactly: a large
  scan whose verifier goes down early produces one `unverifiable` entry and a
  run of `asserted` ones behind it. On the deferred path the distinction that
  matters is a different one, and `verifier_reachable` carries it.
- `not_found` is reachable end to end as of D29, through
  `GET /audit/verify?key=` with a key that was never written
  (`tests/test_deferred_verification.py::test_per_record_route_reports_not_found_for_an_unwritten_key`).
  It remains unreachable through `/audit`'s own scan+verify flow, for the
  structural reason above: that scan only ever lists keys ImmuDB confirms
  exist. `failed` is now the one state with no live path through this control
  plane at all - see the D29 section for why, and what stands in for it.

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
