# Phase 3c-2: deferred verification

**Run id:** `p3c2-defer`
**Working directory:** `.../Temp/claude/<session>/scratchpad/ail-p3c2`
(a scratch clone, not the primary working directory)
**Branch:** `p3c2-defer`, based on `main` at `404d1a2`
**Compose project:** `ail-p3c2`, passed explicitly as `-p` on every invocation

---

## Objective

Make verification deferred by default, without removing the operator's ability
to see that verification did not happen, and without promoting an untested
state to the normal case.

---

## Challenges raised before building

Seven, all accepted. Three of them changed what was built rather than how it
was described, and the first changed the shape of five items.

**C1. Unconditional deferral would have broken one existing assertion and
silently gutted another.** `tests/test_verification.py::test_cross_process`
asserts a real `verified` off `/audit` and would have failed outright.
`tests/test_content_states.py::test_present_then_erased_via_delete_content`
compares the verification state before an erasure to the state after it: under
deferral both sides become `asserted`, so it would have passed while
establishing nothing about the proof surviving erasure. And with deferral
unconditional, the circuit breaker at the heart of P3c2-4 would have been
unreachable code, leaving `asserted` with one producer instead of the two the
item names. Resolved by `GET /audit?verify=` defaulting to false, authorized as
a design change. The honest cost is in Residual Limits: `verify=true` is still
`O(min(limit, ledger))`, so this phase makes the cost opt-in rather than
removing it.

**C2. P3c2-2 and P3c2-3 contradicted each other.** "Zero verifier calls" on the
default page against a mandated live health probe on that same page. Resolved
as zero per-record `POST /verify` and exactly one `GET /health`, and the
pre-registered negative reworded to match.

**C3. The dashboard has no JavaScript test harness.** `dashboard/package.json`
declares `dev`, `build`, `start`, `lint` and no runner; CI runs pytest only.
The project's precedent is a static parse of the component's own source
(`tests/test_dashboard_state_rendering.py`). The Claim cells for the dashboard
halves say what a static parse establishes and no more.

**C4. `failed` is not live-reachable through any route.** The two tamper tests
corrupt a client-side `PersistentRootService` in the test process and never
reach the verifier service. Its enforcing test is a mapping unit test against a
fabricated verifier body. The observation in the other direction is the more
useful half and is now true: `GET /audit/verify` makes `not_found` reachable
end to end for the first time.

**C5, C6, C7.** The probe runs on both paths so the field has one meaning; the
measurement table reports the after-column's constancy as the result rather
than as four measurements; the new decision is D29, recorded in
`docs/adr/0006-verification-states.md`, with no new ADR.

---

## Verdict per item

| Item | Verdict |
| :--- | :--- |
| P3c2-1. A record can be verified on demand | **Met.** `GET /audit/verify?key=` live for `verified` and `not_found`; `failed` by mapping unit test, disclosed. Mutation caught. |
| P3c2-2. The default page defers, and the dashboard can expand | **Met.** Zero per-record `/verify` on the default path, counted from the verifier's own access log. The dashboard half is a static parse, claimed at that strength. Both mutations caught. |
| P3c2-3. An outage is visible on a page that verified nothing | **Met.** `verifier_reachable` from a live probe, true and false both demonstrated live, banner rendered. Mutation caught. |
| P3c2-4. `asserted` is tested | **Met.** Both producers tested live, rendering tested statically. Mutation caught. |
| P3c2-5. One default page size, unchanged in value | **Met**, with a correction: three files carried the literal, not two. Mutation caught. |
| P3c2-6. Measurement | **Met.** Before and after at four sizes, per request and per minute. |
| P3c2-7. Documentation | **Met.** D29 in ADR-0006, two false claims corrected, TODO item closed with its bound fixed, README and Residual Limits. |

---

## 1. P3c2-1. A record can be verified on demand

`GET /audit/verify?key=` on the control plane, following `GET /audit/bundle`'s
precedent: the same base64 raw ImmuDB key, the same `Depends(_require_read_key)`
gate, the same base64 validation on the way in.

It returns a 200 carrying the verification object rather than mapping states
onto HTTP status codes. A key that was never written is a 200 with state
`not_found`; an unreachable verifier is a 200 with `unverifiable`. Collapsing
those into 404 and 503 would undo D2, D8 and D10 at the transport layer.
`/audit/bundle` does 404 for the same condition, and differently on purpose: a
bundle is evidence a record was committed, so there is no honest bundle for a
key that was never written, whereas "this key names nothing" is a perfectly
good answer to "verify this key".

### Demonstration

```
$ curl -s "localhost:8002/audit/verify?key=$KEY" -H "X-API-Key: $READ"
{"key":"dG9vbF9jYWxsOnRlc3QtYWdlbnQ6...","verification":{"state":"verified","state_id":177,"detail":null,"error_class":null}}

$ curl -s -o /dev/null -w '%{http_code}\n' "localhost:8002/audit/verify?key=$KEY"
422                      # no X-API-Key at all
$ curl -s -o /dev/null -w '%{http_code}\n' "localhost:8002/audit/verify?key=$KEY" -H "X-API-Key: wrong"
403                      # present but wrong
```

`not_found` and the malformed-key 400 are in the tests below rather than
transcribed here; both run live.

### Enforcing tests

- `tests/test_deferred_verification.py::test_per_record_route_verifies_a_written_record`
- `tests/test_deferred_verification.py::test_per_record_route_reports_not_found_for_an_unwritten_key`
- `tests/test_deferred_verification.py::test_per_record_route_requires_the_read_credential`
- `tests/test_deferred_verification.py::test_per_record_route_rejects_a_key_that_is_not_base64`
- `tests/test_deferred_verification.py::test_the_failed_state_maps_from_a_fabricated_verifier_body`

### Mutation

Removed `Depends(_require_read_key)` from the route, rebuilt the control plane,
re-ran the named test.

```
E       AssertionError: Route answered without any X-API-Key at all: HTTP 200
        {"key":"dG9vbF9jYWxsOnRlc3QtYWdlbnQ6MDI1MmNkNTE4YTcxNGU4NTg5NmRiYjI2ZWU3YmMyYjY6cDNjMl9hdXRo",
         "verification":{"state":"verified","state_id":177,"detail":null,"error_class":null}}
E       assert 200 == 422
FAILED tests/test_deferred_verification.py::test_per_record_route_requires_the_read_credential
1 failed in 12.28s
```

Reverted, rebuilt, `18 passed in 89.45s`.

The mutated route did not merely answer: it handed an unauthenticated caller a
complete, genuine verification of a real ledger record. That is what the gate
is for.

---

## 2. P3c2-2. The default page defers, and the dashboard can expand

`GET /audit` gains `verify: bool = False`. On the default path no verifier call
is made for any entry and every row returns `asserted` with `state_id`, `detail`
and `error_class` all null. The synthesized-intent pass (D16) defers with the
rest, deliberately: a default page that verified nothing must not have verified
those either, or the property would hold only for ledgers with no orphaned
intents in them, which is not a property at all.

### Demonstration

The states alone do not establish the item. A page could report every row
`asserted` and still have called the verifier for each of them and discarded
the answers. So the count is taken from the verifier's own uvicorn access log,
which is the only record of who called it:

```
$ docker compose -p ail-p3c2 -f docker-compose.test.yml logs --no-log-prefix verifier | grep -c 'POST /verify'
   ... before and after one default GET /audit: unchanged
   ... before and after one GET /audit?verify=true at 200 entries: +200
```

### Enforcing tests

- `::test_default_audit_page_returns_every_row_asserted`
- `::test_default_audit_page_issues_no_per_record_verify_call`
- `::test_verify_true_restores_per_record_verification`
- `::test_the_expand_handler_names_the_per_record_route_and_names_no_other`
- `::test_the_verify_proxy_route_exists_and_holds_the_key_server_side`

### Mutations

**Restore per-record verification on the default path** (`verify: bool = True`):

```
E       AssertionError: {'detail': None, 'error_class': None, 'state': 'verified', 'state_id': 187}
E       assert 'verified' == 'asserted'
FAILED ::test_default_audit_page_returns_every_row_asserted
FAILED ::test_default_audit_page_issues_no_per_record_verify_call
FAILED ::test_verifier_reachable_is_false_on_a_deferred_page_when_the_verifier_is_down
FAILED ::test_asserted_comes_from_deferral
4 failed, 14 passed in 174.40s
```

**Point the expand handler at the whole page instead of the record**
(`fetch("/api/audit")` in place of `fetchRecordVerification(ledgerKey)`):

```
FAILED ::test_the_expand_handler_names_the_per_record_route_and_names_no_other
1 failed in 7.68s
```

Both reverted; suite clean after each.

### What the dashboard half establishes, exactly

`dashboard/components/audit-table.tsx` gains a per-row expand control that
calls `fetchRecordVerification(entry.ledger_key)`, and the checked result
supersedes the deferred `asserted` in that row's verification cell. The
enforcing test is a static parse: it establishes that the expand handler names
the per-record route, names no other API path, and does not call `fetch()`
directly. **It does not establish that clicking the control fires the
request.** Closing that needs a JavaScript test runner and a CI job to run it,
which is a phase of its own and is not scheduled here.

---

## 3. P3c2-3. An outage is visible on a page that verified nothing

One field, `verifier_reachable`, from a live `GET /health` against the verifier
on every path including `verify=true`.

Not a pair. A `verification_mode` of `scanned` or `deferred` would re-encode a
distinction ADR-0006 already draws, since all rows `asserted` with no
`unverifiable` already means nothing was attempted, and a redundant summary of
the rows can drift out of agreement with the rows.

The probe rather than an inference, on both paths, so the field cannot mean two
things depending on which path produced it. Deriving it from the calls a
`verify=true` page happened to make is exactly the drift the pair was rejected
to avoid.

**What it establishes.** The verifier answered a health check at the moment the
response was produced. It does not mean these rows would verify. A probe that
succeeds can be followed by an expand that fails: separate calls at separate
times, and no field closes that gap. This is stated in the function's own
docstring, in ADR-0006's D29 section, in `dashboard/lib/types.ts`, and in
Residual Limits, because a boolean named for reachability invites being read as
a claim about the records.

### Demonstration

```
healthy stack:            {"verifier_reachable": true,  ...}   (0.76s, 200 entries)
docker compose stop verifier:
                          {"verifier_reachable": false, ...}   every row still asserted,
                                                               entries still returned
```

Deferral costs the reader the checks, not the records: the page is still a page
with the verifier down.

### Enforcing tests

- `::test_verifier_reachable_is_true_on_a_healthy_stack`
- `::test_verifier_reachable_is_false_on_a_deferred_page_when_the_verifier_is_down`
- `::test_default_audit_page_issues_exactly_one_health_call`
- `::test_the_dashboard_renders_an_unreachable_verifier`

The health count filters on client address. The verifier's own Docker
healthcheck calls `/health` every 5 seconds from inside the container, so its
access log always carries loopback-sourced lines; the control plane reaches it
across the compose network and never appears as `127.0.0.1`.

### Mutation

Replaced the probe body with `return True`:

```
E       AssertionError: Deferred page reported the verifier reachable while it was stopped: True
E       assert True is False
FAILED ::test_default_audit_page_issues_exactly_one_health_call
FAILED ::test_verifier_reachable_is_false_on_a_deferred_page_when_the_verifier_is_down
2 failed, 16 passed in 84.95s
```

Both halves caught it: the value test, and the test that counts whether a probe
was made at all. A static value fails the second even when it happens to be
right.

Reverted, rebuilt, clean.

---

## 4. P3c2-4. `asserted` is tested

Before this phase `asserted` carried zero assertions anywhere in `tests/`,
while being produced by one hard-to-reach branch and rendered as a muted badge.
This phase makes it the state most rows carry.

Both producers are now tested live:

- **Deferral.** `::test_asserted_comes_from_deferral`, which also asserts the
  deferred object is bare: no `state_id`, no `detail`, no `error_class`. A
  deferred row must not carry anything a reader could mistake for a diagnosis.
- **The circuit breaker.** `::test_asserted_comes_from_the_circuit_breaker_too`,
  on the `verify=true` path with the verifier stopped: the first scan entry is
  `unverifiable`, every scan entry behind it is `asserted`.

The breaker producer exists only because verification stayed reachable. Under
unconditional deferral this test could not have been written.

### Mutation

Rendered `asserted` identically to `verified` in `VerificationCell`:

```
E       AssertionError: the asserted branch no longer renders its own NOT CHECKED badge
FAILED ::test_asserted_renders_distinctly_from_verified
1 failed, 17 passed in 105.88s
```

Reverted, clean.

### A finding while testing the breaker, outside the items

`get_audit` builds its response in two passes: the `tool_call:` scan, which the
circuit breaker governs, and a second pass that synthesizes an entry for every
intent record with no matching completion (D16). **The second pass never
consults `verifier_up`.** With the verifier down and `verify=true`, it attempts
a verify for each orphaned intent and each returns `unverifiable`, so the
response carries one `unverifiable` per orphaned intent after the run of
`asserted`, and the breaker's own stop-hammering property does not reach them.

Found by an assertion that was too strong, then confirmed directly: the ledger
here holds exactly one `execution_state: "unknown"` entry, and it accounts for
exactly one extra `unverifiable`. This is pre-existing behaviour on the
`verify=true` path, unchanged by this phase and outside its items. Reported
rather than widened into it. The test now scopes its breaker assertion to the
scan-loop entries and says why.

---

## 5. P3c2-5. One default page size, unchanged in value

**A correction to the item: three files carried the literal, not two.**
`dashboard/app/audit/page.tsx` called `fetchAudit(200)` explicitly, alongside
the `route.ts` and `lib/api.ts` occurrences the instruction names. Three
independent numbers that had to agree, with nothing making them agree.

All three now take it from `dashboard/lib/constants.ts`, which holds the one
definition. The page calls `fetchAudit()` and takes the default.

**The value is unchanged, deliberately.** Showing a compliance operator fewer
rows on one screen is a product decision, not a performance fix. The reason to
lower it also went away in the same change that made it easy to: since D29 the
page size no longer governs a per-record scan cost.

**`refetchInterval: 30_000` is kept, and here is the decision rather than
silence.** It was the real multiplier on the old cost, not the page size: 200
verifier round trips every 30 seconds per open tab, indefinitely. Since D29 a
poll costs three ImmuDB scans and one health probe regardless of row count, so
30 seconds is now a cheap refresh on a live compliance view rather than a
standing load. Kept, and the reasoning is in the source beside it.

### Mutation

Restored `fetchAudit(limit = 200)`:

```
E       AssertionError: api.ts spells the page size literally (1 occurrence(s))
        instead of taking it from lib/constants.ts
FAILED ::test_the_audit_page_size_has_exactly_one_definition
1 failed in 7.88s
```

The test rejects the digits anywhere in those three files, comments included. A
comment carrying the number is how the next literal gets copied back in.

Reverted, clean.

---

## 6. P3c2-6. Measurement

Ledger seeded to 200 `tool_call:` records. Counts are `POST /verify` and
off-loopback `GET /health` lines in the verifier's uvicorn access log, taken
before and after a single request. Per-minute figures are per open dashboard
tab at `refetchInterval: 30_000`, so two requests per minute.

### Per request

| Entries | Before: `/verify` | Before: seconds | After: `/verify` | After: `/health` | After: seconds |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 10 | 10 | 1.77 | 0 | 1 | 0.54 |
| 50 | 50 | 6.69 | 0 | 1 | 0.65 |
| 100 | 100 | 11.22 | 0 | 1 | 0.65 |
| 200 | 200 | 22.24 | 0 | 1 | 0.76 |

### Per minute of an open dashboard tab

| Entries | Before: verifier round trips | After: verifier round trips |
| ---: | ---: | ---: |
| 10 | 20 | 2 |
| 50 | 100 | 2 |
| 100 | 200 | 2 |
| 200 | 400 | 2 |

**The after column is constant by construction, and that is the result.** It is
not four measurements that happened to agree: the deferred path makes exactly
one verifier call per request whatever the page holds, so the shape changed
from `O(min(limit, ledger))` to `O(1)` and the four rows are the evidence of
that rather than a sample of it. The elapsed time does still rise slightly with
size, from 0.54s to 0.76s, which is the three ImmuDB scans and the SQL join,
not verification.

### The cost is opt-in, not removed

| Request | `/verify` | seconds |
| :--- | ---: | ---: |
| `?verify=true`, 10 | 16 | 2.59 |
| `?verify=true`, 200 | 200 | 21.45 |

Essentially the old numbers, by request. At limit 10 the response carries 16
entries because `limit` bounds each of the three ImmuDB scans separately and
synthesized intent entries are added on top of the scan's own; pre-existing,
noted because it makes the 16 rather than 10 look like an error otherwise.

### Where the 10-second client timeout lands

`_VERIFIER_VERIFY_TIMEOUT` is 10 seconds **per verifier call**, and it never
bounded the request as a whole. At 200 entries the observed per-call latency is
21.45 / 200, about 0.107s, so the timeout sits at roughly 93 times the observed
call time and cannot fire in normal operation. It bounds one hung call, not the
scan. This is why the before-column's 22.24 seconds could exist under a
10-second timeout at all, and it is worth stating because "there is a 10s
timeout on /audit" would be the natural and wrong reading.

### The 90-second test-side timeout, revisited

Phase 2 raised several test clients from 30 to 90 seconds because a full suite
run pushed `/audit` past 30 (`docs/reports/phase-2.md`). Revisited as the item
asks, and the answer splits:

- **On deferred calls it should come down, and has.**
  `tests/test_content_states.py::_audit_entries` now uses 30 seconds when
  deferring. Measured worst case is 0.76 seconds; 90 seconds of headroom on a
  sub-second call hides a real hang for a minute and a half.
- **On `verify=true` calls it should stay at 90, and has.** The measured cost
  is 21.45 seconds at 200 entries on this host, the suite accumulates entries
  within a run, and CI runners are slower. `test_cross_process` and the erasure
  test keep it.

---

## 7. P3c2-7. Documentation

**`docs/adr/0006-verification-states.md`.** A D29 section recording that the
reserved option was taken, stated as bookkeeping on *when* verification runs
and not as an amendment to the five states. Its Constraints section had two
bullets that this phase makes false, and both are corrected rather than left:
the one saying lazy verification is not implemented, and the one saying
`not_found` is not reachable end to end. The second is now the other way round:
`not_found` is reachable through the new route, and `failed` is the one state
with no live path through this control plane.

**`docs/adr/0001-immudb-rest-migration.md`.** The acceptability claim named a
limit no caller sent. Corrected to what callers actually do, and the bound
corrected to `O(min(limit, ledger))`.

**`TODO.md`.** Same imprecision, same correction, and the item is closed with
its residual named: `?verify=true` still costs the full per-record scan.

**`readME.md`.** Section 4's description of `/audit` said it calls the verifier
per entry, which stopped being true; the dashboard feature bullet and the
ADR-006 summary likewise. A new Residual Limits bullet covers what a deferred
page proves, that the cost is opt-in rather than gone, what the probe
establishes and its gap, and the static-parse limit on the dashboard half.

---

## A second finding outside the items: `/audit` is not ordered by time

Found while diagnosing nine suite failures that appeared only after the
measurement seeded the ledger past the page size, and worth more than the
first finding.

`control_plane/main.py`'s ImmuDB scan passes `desc: true`. That orders by
**key** descending, and a `tool_call:` key is
`tool_call:<agent_id>:<uuid>:<tool_name>`, so the ordering is by agent id.
`GET /audit?limit=N` therefore returns the N lexicographically-largest keys,
not the N most recent decisions.

While the ledger holds fewer than `limit` matching keys this is invisible,
because every record is on the page whatever the order. Past that point a
record written seconds ago is simply absent. Observed directly:

```
entries: 211
tx range: 1 - 573
first 3 keys: tool_call:test_opa_agent:ff04bf53...:provision_cloud_server
              tool_call:test_opa_agent:e66878a7...:provision_cloud_server
              tool_call:test_opa_agent:c318c90f...:provision_cloud_server
tx sorted descending? False
```

The page leads with `test_opa_agent` because `t` sorts high, and the newest
transaction, 573, is not on it. This is what failed
`tests/test_intent_completion_visibility.py::test_real_mediated_call_surfaces_execution_state_completed`
with `tx_id 571 not found in /audit` once 200 seeded `measure-agent` records
crowded the page.

**Pre-existing, and untouched by this phase.** The scan is byte-for-byte what
it was; deferral changed what happens to each entry after the scan, not which
entries the scan returns. It surfaced here only because measuring the thing
this phase exists to fix required a ledger larger than the page.

**One consequence was in scope, because this phase was rewriting the line.**
`dashboard/components/audit-table.tsx`'s footer said "newest first". That was
already false, and this phase was editing that sentence for other reasons, so
the claim was removed rather than restated. Nothing else was changed: no
reordering, no new sort, no widening. The defect is recorded in `TODO.md` with
the evidence above.

**It also bounds what the measurement table means.** Section 6's figures are
per-request costs at a given page size and are unaffected. But "200 entries"
there means "a 200-row page", not "the 200 newest decisions", and the two are
the same thing only while the ledger fits in the page.

---

## Pre-registered negatives

All confirmed false, individually, each derived rather than asserted.

| Negative | Confirmed by |
| :--- | :--- |
| Any per-record `/verify` call on the default `/audit` path | `::test_default_audit_page_issues_no_per_record_verify_call`, counted from the verifier's access log |
| Any response-level field reporting a value it did not establish | `::test_default_audit_page_issues_exactly_one_health_call` shows the probe is made; the static-value mutation fails |
| Any new verification state | `dashboard/lib/types.ts::VerificationState` unchanged; every state in the response is one of the five |
| Any page-size default with more than one definition | `::test_the_audit_page_size_has_exactly_one_definition` |
| Any lowered page size without a stated product reason | `AUDIT_PAGE_SIZE` is 200, the prior value |
| Any Claim cell describing a goal rather than a behaviour | mapping table below, derived per row |
| Any assertion weakened | the two sites C1 identified now pass `verify=true`, and the erasure test additionally asserts the compared state is `verified` so a re-deferral cannot pass vacuously; mutation confirmed |
| Any item met by live evidence alone with no test enforcing it | every item above names its enforcing tests |

---

## Mapping

| Claim | Backed by | Kind |
| :--- | :--- | :--- |
| A record named by its ledger key returns a verification object with the same four fields a row carries | `tests/test_deferred_verification.py::test_per_record_route_verifies_a_written_record` | test |
| A key that was never written returns state `not_found` through the control plane | `tests/test_deferred_verification.py::test_per_record_route_reports_not_found_for_an_unwritten_key` | test |
| The per-record route answers 422 with no credential and 403 with a wrong one | `tests/test_deferred_verification.py::test_per_record_route_requires_the_read_credential` | test |
| A key that is not base64 is refused with 400 rather than reaching the verifier | `tests/test_deferred_verification.py::test_per_record_route_rejects_a_key_that_is_not_base64` | test |
| A verifier body carrying either tamper class maps to state `failed` | `tests/test_deferred_verification.py::test_the_failed_state_maps_from_a_fabricated_verifier_body` | test |
| Every row of a default page carries state `asserted` | `tests/test_deferred_verification.py::test_default_audit_page_returns_every_row_asserted` | test |
| A default page adds no `POST /verify` line to the verifier's access log | `tests/test_deferred_verification.py::test_default_audit_page_issues_no_per_record_verify_call` | test |
| A default page adds exactly one off-loopback `GET /health` line to that log | `tests/test_deferred_verification.py::test_default_audit_page_issues_exactly_one_health_call` | test |
| Requesting `verify=true` returns state `verified` for a written record | `tests/test_deferred_verification.py::test_verify_true_restores_per_record_verification` | test |
| The row-expand handler names the per-record route, names no other API path, and calls no `fetch` of its own | `tests/test_deferred_verification.py::test_the_expand_handler_names_the_per_record_route_and_names_no_other` | test |
| The browser's route to the per-record check reads its credential from the server environment and from no `NEXT_PUBLIC` variable | `tests/test_deferred_verification.py::test_the_verify_proxy_route_exists_and_holds_the_key_server_side` | test |
| The response reports the verifier reachable on a healthy stack | `tests/test_deferred_verification.py::test_verifier_reachable_is_true_on_a_healthy_stack` | test |
| A deferred page served while the verifier is stopped reports it unreachable and still returns its entries | `tests/test_deferred_verification.py::test_verifier_reachable_is_false_on_a_deferred_page_when_the_verifier_is_down` | test |
| The audit page reads the reachability field and renders a distinct treatment when it is false | `tests/test_deferred_verification.py::test_the_dashboard_renders_an_unreachable_verifier` | test |
| Deferral yields state `asserted` with no state id, no detail and no error class | `tests/test_deferred_verification.py::test_asserted_comes_from_deferral` | test |
| On a verified page with the verifier stopped, the first scan entry is `unverifiable` and every scan entry behind it is `asserted` | `tests/test_deferred_verification.py::test_asserted_comes_from_the_circuit_breaker_too` | test |
| The `asserted` branch renders its own badge text and neither the word nor the colour the verified branch uses | `tests/test_deferred_verification.py::test_asserted_renders_distinctly_from_verified` | test |
| The page size has one definition, and none of the three files that once carried it spells the digits | `tests/test_deferred_verification.py::test_the_audit_page_size_has_exactly_one_definition` | test |
| A verified page compared before and after an erasure reads `verified` on both sides, not `asserted` | `tests/test_content_states.py::test_present_then_erased_via_delete_content` | test |
| The control-plane process reads a real verification state without touching an interceptor-local file | `tests/test_verification.py::test_cross_process` | test |
| One default request costs zero verifier round trips at 10, 50, 100 and 200 entries, and one verified request at 200 costs 200 | `python tools/audit_roundtrip_measure.py` against a 200-entry ledger, transcribed in section 6 above | **command, marked: no test covers this** |
| A deferred page proves nothing about the records on it, and the reachability field establishes a health answer rather than a verification | `readME.md` §5, Residual Limits | residual limit |
| The dashboard expand affordance is held in place by a static source parse, which does not establish that clicking it fires the request | `readME.md` §5, Residual Limits | residual limit |

---

## Could not verify

- **That clicking the expand control fires the request.** No JavaScript test
  harness exists in this repository and adding one is out of scope here. The
  static parse establishes what the source names, not what a browser does with
  it. Stated in the mapping table, in the test's own docstring, and in Residual
  Limits.
- **A live `failed` through any control-plane route.** Producing one requires
  corrupting the verifier's persisted state and restarting it, which leaves the
  stack inconsistent for every test after it. Covered by a mapping unit test
  against a fabricated verifier body, which is what `not_found` had before this
  phase for the same class of reason.
- **The measurement table by a committed test.** The numbers come from a
  measurement script run against a seeded 200-entry ledger, not from an
  assertion. The properties the table exists to show, zero verify calls and
  exactly one health call on the default path, *are* committed tests; the
  timings are not, and no row claims otherwise.
- **The 14 pre-existing suite failures on this host.** All are
  `No module named 'sigstore'`. `sigstore` cannot be installed into this
  machine's Python without breaking `spiffe==0.2.5`'s `cryptography` pin, and
  it is present in `requirements-test.txt`, so CI covers them. The same 14
  failed before any change in this phase, on the same host, from the same
  clone.
- **Nine further failures on a ledger left oversized by the measurement.**
  `tests/test_content_states.py` (five) and
  `tests/test_intent_completion_visibility.py` (two) among them, all of the
  form "the record I just wrote is not in /audit". Diagnosed to the key-order
  finding above rather than to this phase's change, and confirmed by resetting
  the stack to an empty ledger, which is what `make test-integration` and CI
  both do, and re-running. The clean-ledger result is the one reported under
  CI below; the oversized-ledger run is recorded here rather than omitted,
  because "reset it and it passed" is exactly the shape a real regression also
  has, and the diagnosis rather than the re-run is what distinguishes them.

---

## CI

CI_RUN_ID
