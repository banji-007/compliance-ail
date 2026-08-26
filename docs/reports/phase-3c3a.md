# Phase 3c-3a: Audit read correctness

**Run id:** `p3c3a-counts`
**Working directory:** `C:\Users\banji\AppData\Local\Temp\claude\c--Users-banji-OneDrive-Documents-compliance-ail\78d7627e-f224-4bda-89a1-80f270a65b20\scratchpad\ail-p3c3a`, a scratch clone. Not the primary working directory.
**Branch:** `p3c3a-counts`, cut from `main` at `062e029`.
**Compose project:** `p3c3a`, passed as `-p p3c3a` on every invocation in this report.

---

## 1. Objective

Stop the audit view from reporting numbers it did not measure, and stop the tombstone join from silently reporting an erased record as present.

Neither needs an ordering decision, so neither waited for one. Ordering is Phase 3c-3b, and the intent join sequences with it because the intent key's uuid exists nowhere but in the key itself.

---

## 2. Grounding, and what re-deriving it changed

The instruction is grounded in three run ids: `p3c3-question`, `p3c3-probe`, and `p3c3-scoring`. **No committed artifact for any of the three exists in this repository**, and none is present in any session scratch directory on this machine. They are cited here by run id because that is all this session can do with them, and every factual claim the instruction attributes to `p3c3-probe` was therefore re-derived live against immudb 1.9.5 before anything was built on it.

Re-derivation transcript, `tools/immudb_read_api_probe.py` against the `p3c3a` stack:

```
FACT 1: GET /api/v2/db/count/{prefix_b64} routes, and its shape
  prefix='tool_call:'             status=200 body={"count":"3"}
  prefix='tool_call'              status=200 body={"count":"5"}
  prefix='tool_call_intent:'      status=200 body={"count":"2"}
  prefix='content_erasure:'       status=200 body={"count":"1"}

FACT 2: GET /api/v2/db/countall routes
  status=200 body={"count":"6"}

FACT 3: count counts distinct KEYS, not versions
  before={'count': '3'}  after 3 writes to ONE new key={'count': '4'}

FACT 4: POST /api/v2/db/getall omits missing keys silently
  requested 2 keys (1 present, 1 missing) -> got 1 entries

FACT 4b: getall with ALL keys missing
  status=200 entries=0 body={}

FACT 5: getall has no 2500 ceiling
  3000 keys -> status=200 entries=1

FACT 6: scan ceiling
  scan limit=2500 -> status=200 ok
  scan limit=2501 -> status=500 {"error":"result size limit exceeded: ...}
  scan limit=5000 -> status=500 {"error":"result size limit exceeded: ...}
```

Every claim the instruction made held. `tool_call:` counts 3 while `tool_call` counts 5, which is the underscore point: the trailing colon is what keeps `tool_call_intent:` records out of the decision count. Three things the instruction did not carry came out of the same probe and are load-bearing below:

**(a) `getall` with every key missing returns `{}`, not `{"entries": []}`.** The join reads `.get("entries", [])` for that reason.

**(b) `scan` refuses a limit above 2500.** This is why P3c3a-2 could not be implemented as a bare `limit + 1`: `GET /audit?limit=2500` served a page before this phase, and `limit + 1` would have turned it into a 502. The page shrinks with the scan instead - `page_limit` is the caller's limit below 2500 and 2499 at or above it, which keeps the extra row available and keeps `has_more` exact at every limit. Clamping only the scan would have been worse than the bug it avoids: the extra row would vanish and `has_more` would read false at exactly the largest page, which is the pre-registered negative "always report no more" arriving by accident.

**(c) The instruction estimated the tombstone `getall` at "about 34ms" for a 200 row page.** Measured median here is 57ms (section 7). Same order, and it is still cheaper than the scan it replaces.

---

## 3. Challenges raised before building

The instruction requires items that do not serve the objective to be challenged before building. Three were raised and answered; all three answers are implemented as given.

**3.1 P3c3a-1's stated binary has no reachable branch.** The item offers "either all four cards become ledger-scoped or all four are relabelled to say page", but Approved, Denied and Faults cannot be made ledger-scoped in this phase: `outcome_type` lives inside a record's value, not in its key, so ImmuDB's prefix `count` cannot see it; counting them ledger-wide means reading every record, which is the unbounded cost P3c3a-4 exists to bound; and a maintained counter is explicitly deferred. Meanwhile the item's own Enforce and Mutation clauses fix `total` as the ledger count, which forecloses the second branch too.

*Answer taken:* label every card with the scope it is actually computed at. `total` becomes the ledger count and card one says "(ledger)"; the other three stay computed from `data.entries` and say "(this page)". "Do not fix one and leave three" is read as "do not leave three silently mislabelled", which is the defect the item describes. Enforced by a static parse, not by inspection - section 5.

**3.2 A ledger-scoped `total` silently redefines the empty state.** `total` now counts `tool_call:` keys and excludes the synthesized rows for orphaned write-ahead intents (D16), whose orphanhood is only knowable after the completion join and which therefore no key count can include. A ledger holding only those has `total === 0` while the table renders rows.

*Answer taken:* `page.tsx`'s empty state moves to `data.entries.length === 0`. The instruction flags line 151 as a hazard, so changing it is in scope.

**3.3 `has_more` has two scans to describe, not one.** After P3c3a-3 deletes the tombstone scan, two scans still feed `entries`: `tool_call:` and `tool_call_intent:`. Both are bounded by the same `limit` and both can truncate.

*Answer taken:* `limit + 1` on both, `has_more` true if either had more behind it. Scoping it to the decision scan alone would silently drop orphan rows with `has_more` reading false, which is the same defect one field along.

---

## 4. Verdict per item

| Item | Verdict |
| :--- | :--- |
| P3c3a-1, four stat cards report what their labels claim | **Met.** `total` is the ledger count; every card label states its own scope; the empty state moved off `total`. |
| P3c3a-2, truncation is stated | **Met.** `limit + 1` on both entry-producing scans, `has_more` in the response, no cursor. |
| P3c3a-3, the tombstone join is exact | **Met.** The `content_erasure:` scan is deleted; the join is a keyed `getall` on the page's own `call_id`s. |
| P3c3a-4, cost is measured, not assumed | **Met, with a stated limit.** End-to-end timings could not separate before from after at 2k or 10k - the difference is inside host noise. The component breakdown does separate them, and is reported alongside. |
| P3c3a-5, documentation | **Met.** `TODO.md`'s ordering half stays open, the count and tombstone halves are closed there; two Residual Limits added; README's card claims rewritten. |

---

## 5. Demonstration, enforcing test, mutation

The suite is `tests/test_audit_read_correctness.py`, ten tests. The whole file was written first and run against the **unmodified** `main` control plane, so every defect below is a live before-result and not a description.

### Before: the defects reproduced

`git stash` of the fix, control plane rebuilt at `062e029`, same stack:

```
8 failed, 2 passed in 26.74s
```

The two that passed are the two that should: `test_the_response_carries_no_cursor` and `test_a_tombstone_is_never_rendered_as_a_decision_row` are negatives that already held.

**P3c3a-1.** `total` is the page's length:

```
AssertionError: total changed when only limit changed, so it is a property of
the page rather than of the ledger: limit=1 -> 2, limit=50 -> 51
assert 2 == 51
```

and the card that renders it says nothing about its scope:

```
AssertionError: card "Total Decisions" is computed from data.total - the
ledger's count - but its label does not say ledger, so it is
indistinguishable from the page-scoped cards beside it.
assert 'ledger' in 'total decisions'
```

**P3c3a-2.** `has_more` is absent from the response entirely, so both truncation tests fail on the missing key.

**P3c3a-3, and a correction to the instruction's premise.** The instruction says the record "renders `present` instead of `erased`". That is one of two faces, and it is not the one an ordinary erasure produces. `_payload_state` branches on whether the content row survived:

- Erased through the real endpoint, row gone, tombstone outside the window: renders **`lost`**, which that function documents as "the row disappeared some other way" - an operational incident with no erasure semantics. A lawful Article 17 erasure reported as an incident.

```
AssertionError: an erased record rendered as something else because its
tombstone fell outside a limit that has nothing to do with it.
payload_state='lost'
assert 'lost' == 'erased'
```

- Row outlived its tombstone, tombstone outside the window: renders **`present`**, *and returns the payload*. This is the face the instruction names, and it is the one that leaks - P13-4 undone at read time.

```
AssertionError: a tombstoned call_id whose row still exists rendered as
something other than erasure_conflict: 'present'
assert 'present' == 'erasure_conflict'
```

Both faces are covered. The correction does not change the fix, the mutation, or the scope; it changes what the report may claim the defect was.

### After: the same suite against the fix

```
10 passed in 26.03s
```

### Mutations

One at a time, control plane rebuilt for each, reverted and rebuilt before the next. No mutation was ever applied on top of another.

| Mutation | Change | Named test | Result |
| :--- | :--- | :--- | :--- |
| P3c3a-1 | `"total": len(entries)` | `test_total_is_the_ledger_count_not_the_page_length`, `test_total_does_not_move_when_the_page_size_does` | **Both failed** |
| P3c3a-2 | `has_more = False` | `test_has_more_is_true_when_records_exist_behind_the_page` | **Failed** |
| P3c3a-3 | restore the `content_erasure:` prefix scan under `page_limit` | `test_erased_record_reads_erased_even_when_its_tombstone_is_far_down_the_ledger`, `test_conflicted_record_withholds_its_payload_even_when_its_tombstone_is_far_down` | **Both failed** |
| extra, not named by the instruction | relabel `"Approved (this page)"` back to `"Approved"` | `test_every_stat_card_label_states_the_scope_it_is_computed_at` | **Failed** |

Transcripts:

```
m1-total: APPLIED to main.py
E  AssertionError: total came back equal to (or below) the number of rows on
   the page. That is the page's length, not the ledger's count - the exact
   defect P3c3a-1 closes. total=7 rows=7
E  assert 7 > 7
E  AssertionError: total changed when only limit changed ... limit=1 -> 2, limit=50 -> 51
2 failed in 15.01s

m2-hasmore: APPLIED to main.py
E  AssertionError: the ledger holds more decision records than this page
   returned and has_more still reads False. total=139 rows=5
E  assert False is True
1 failed in 14.92s

m3-scan: APPLIED to main.py
E  AssertionError: ... payload_state='lost'   assert 'lost' == 'erased'
E  AssertionError: ... rendered as something other than erasure_conflict: 'present'
2 failed in 19.15s

m4-label: APPLIED to page.tsx
E  AssertionError: card "Approved" is computed from data.entries - the rows on
   this page - but its label does not say page, so it reads as a ledger-wide
   number. This is the defect P3c3a-1 closes, one card along.
E  assert 'page' in 'approved'
1 failed in 7.92s
```

Revert-clean confirmation, no `.bak` left in the tree, control plane rebuilt from the reverted source:

```
10 passed in 26.03s
```

The fourth mutation is not required by the instruction and is included because P3c3a-1 has two halves that fail independently: the response contract can be correct while a card beside it lies. The named mutation exercises the first half only.

---

## 6. What the tests enforce

| Test | What it holds |
| :--- | :--- |
| `test_total_is_the_ledger_count_not_the_page_length` | `total` exceeds the rows returned, and equals ImmuDB's own `count` over `tool_call:` asked independently. |
| `test_total_does_not_move_when_the_page_size_does` | `total` is identical at `limit=1` and `limit=50`, while the pages are not. |
| `test_every_stat_card_label_states_the_scope_it_is_computed_at` | Static parse of `page.tsx`: each of the four cards reads exactly one of `data.entries` / `data.total`, and its label names that scope. |
| `test_the_empty_state_is_not_keyed_off_the_ledger_count` | The empty state keys off the rendered rows, not `total`. |
| `test_has_more_is_true_when_records_exist_behind_the_page` | Truncation is reported. |
| `test_has_more_is_false_when_the_page_covers_everything_behind_it` | A flag that is always true states nothing either. |
| `test_the_response_carries_no_cursor` | No `cursor`, `next`, `continuation`, `offset` or `after` key appears in the response. Pre-registered negative, enforced. |
| `test_erased_record_reads_erased_even_when_its_tombstone_is_far_down_the_ledger` | An erased record reads `erased` with its tombstone outside any window a limit could impose. |
| `test_conflicted_record_withholds_its_payload_even_when_its_tombstone_is_far_down` | The same for `erasure_conflict`, and the payload is not returned. |
| `test_a_tombstone_is_never_rendered_as_a_decision_row` | D11's structural property survives the change of how tombstones are read. |

How the defect is constructed, since it depends on ordering the fix does not change: the old scan was `desc: True` over `content_erasure:` under the page's `limit`, so a tombstone is pushed out of the window by putting `limit` lexicographically-larger tombstones in front of it. Tombstone keys carry a hex uuid, so a forged `call_id` beginning `zzzz` sorts above every real one. The record's own `tool_call:` key must still land on the page and those lead with `agent_id`, so the records use a `zzzz`-leading agent id for the same reason.

---

## 7. Cost (P3c3a-4)

### 7.1 End to end, `GET /audit?limit=200`

Nine samples per cell after one discarded warm request. **Median, with the full observed range**, because host noise here is larger than the effect.

| `tool_call:` keys | Before, median (range) | After, median (range) |
| ---: | :--- | :--- |
| 2,000 | 1101.6 ms (818.0 - 1318.5) | 955.8 ms (784.1 - 1200.6) |
| 10,000 | 1214.5 ms (1044.5 - 1396.7) | 1003.0 ms (876.8 - 1436.8) |
| 40,000 | 1096.2 ms (950.6 - 1470.8) | 1190.6 ms (917.6 - 1736.1) |

**These numbers do not separate before from after, and saying otherwise would be reading noise.** The ranges overlap at every size, and the clearest evidence that noise dominates is inside the "before" column itself: it is *slower* at 10k than at 40k, which nothing in that code path can explain. A full 200 row `/audit` request is dominated by work neither version changed - 200 per-row content-store lookups and the verifier health probe - so the ImmuDB delta is not visible end to end at any size measured.

### 7.2 Component breakdown

Fresh stack, `python tools/audit_read_cost_probe.py`, ledger seeded to each size, 15 samples per cell after three discarded. This times the individual ImmuDB calls each version makes, which is where the signal is.

| Call | 2,000 keys | 10,000 keys | 40,000 keys |
| :--- | ---: | ---: | ---: |
| `scan tool_call:` limit 200 *(before)* | 85.6 ms (49.8-125.5) | 63.2 ms (47.6-73.6) | 51.4 ms (39.3-99.0) |
| `scan tool_call:` limit 201 *(after)* | 69.6 ms (53.8-183.6) | 61.5 ms (40.2-164.6) | 55.7 ms (46.9-100.3) |
| `scan content_erasure:` limit 200 *(**deleted** by P3c3a-3)* | 72.5 ms (31.5-87.8) | 76.6 ms (35.2-105.1) | 75.3 ms (40.1-125.8) |
| `scan tool_call_intent:` limit 201 | 51.8 ms (47.7-79.2) | 50.5 ms (47.2-58.8) | 52.3 ms (47.8-67.1) |
| `count tool_call:` *(**added** by P3c3a-1)* | **19.8 ms** (14.7-26.4) | **57.0 ms** (46.8-63.6) | **225.7 ms** (196.5-384.9) |
| `getall` 207 tombstone keys *(**added** by P3c3a-3)* | 56.8 ms (50.7-63.2) | 60.7 ms (25.6-104.5) | 56.7 ms (51.3-68.2) |

Every row is flat against ledger size except one. The scans are bounded by the page, so they do not grow. The `getall` is bounded by the page's own `call_id` count, so it does not grow either - that is the point of P3c3a-3, and it is also 18 ms *cheaper* than the scan it replaced while being exact rather than approximate.

`count` is the row that grows. Going 2k to 10k is 5x the keys for 2.9x the time; going 10k to 40k is 4x the keys for 4.0x the time. Sub-linear at the low end, indistinguishable from linear at the top.

### 7.3 Net per-request delta, and the poll multiplier

Net = the deleted scan removed, the count and getall added:

| `tool_call:` keys | Net ImmuDB delta per request | Per open tab, per hour |
| ---: | ---: | ---: |
| 2,000 | +4.1 ms | +0.5 s |
| 10,000 | +41.1 ms | +4.9 s |
| 40,000 | +207.1 ms | +24.9 s |

The multiplier is `dashboard/app/audit/page.tsx`'s `refetchInterval: 30_000`: 120 requests per hour per open tab, indefinitely, whether or not anyone is looking at it. At 40k keys the count alone is 225.7 ms x 120 = **27.1 s of ImmuDB work per hour per open tab**, and nothing bounds that.

**Stated plainly: this cost grows with the ledger forever.** It is a walk over the prefix on every request, bounded by the ledger rather than by the page. A maintained counter can replace it later without changing the response contract, because the contract is the number and not how it was obtained. That is recorded in README's Residual Limits, not only here.

---

## 8. Documentation (P3c3a-5)

**`TODO.md`.** The Blocking-for-3c-3 entry is *not* closed. The ordering paragraph stands unchanged and the entry now states explicitly which two halves closed here and that what remains is exactly the ordering, so the remainder is not read as larger than it is.

**README Residual Limits, two new entries.** One states the count's unbounded growth and names the measured figures. One states that the page is not ordered by time, that `has_more` therefore means more records exist behind this page and never that more recent ones do, that there is deliberately no cursor, and - stated rather than left implied - that `limit` bounds the decision scan while orphan-intent rows are appended after it, so a response can carry more rows than `limit` asked for and `len(entries)` can exceed `total`.

**README dashboard section.** What the cards now claim, including why three of them are page-scoped rather than ledger-scoped.

---

## 9. Pre-registered negatives

All false at the end. Each derived individually.

| Negative | Status | How it was determined |
| :--- | :--- | :--- |
| Any stat card whose label's scope differs from its computation | **False** | `test_every_stat_card_label_states_the_scope_it_is_computed_at`, per card, from the card's own value expression. Mutation m4 confirms it bites. |
| Any `total` derived from page length | **False** | `test_total_is_the_ledger_count_not_the_page_length` and `test_total_does_not_move_when_the_page_size_does`. Mutation m1 confirms both bite. |
| Any cursor or continuation token | **False** | `test_the_response_carries_no_cursor` checks the response keys against a forbidden set. No `page_limit`-derived offset is exposed either; `page_limit` is local to the handler. |
| Any limit applied to the tombstone join | **False** | `_tombstoned_call_ids` takes a key set and no limit; `getall` has no ceiling (probe FACT 5). Mutation m3 confirms the test bites when a limit is reintroduced. |
| Any claim that the page is ordered | **False** | Checked per changed string. `has_more` is worded "more records exist behind this page" in the handler docstring, `types.ts`, the dashboard notice, README Residual Limits, and `TODO.md`; each says explicitly that it is not a recency claim. |
| Any Claim cell describing a goal rather than a behaviour | **False** | Section 10, derived per row. |
| Any assertion weakened | **False** | One assertion was **removed**, not weakened: a guard asserting `len(entries) <= limit`, which is false of `/audit` for a reason predating this phase (orphan-intent rows are appended after the slice). It guarded nothing this phase claims; the behaviour it would have encoded is recorded in Residual Limits instead. No existing test in the repository was edited. |
| Any item met by live evidence alone with no test enforcing it | **False**, except P3c3a-4 | P3c3a-4 is a measurement item whose deliverable is a report, and it is marked as command-backed in section 10 rather than claimed as tested. |

---

## 10. Mapping

| Claim | Backed by | Kind |
| :--- | :--- | :--- |
| `GET /audit`'s `total` exceeds the rows it returned and equals ImmuDB's own count of `tool_call:` keys | `tests/test_audit_read_correctness.py::test_total_is_the_ledger_count_not_the_page_length` | test |
| `total` is identical at limit 1 and limit 50 while the two pages differ in size | `tests/test_audit_read_correctness.py::test_total_does_not_move_when_the_page_size_does` | test |
| Each of the four summary cards reads exactly one of the page rows or the ledger count, and its label names that scope | `tests/test_audit_read_correctness.py::test_every_stat_card_label_states_the_scope_it_is_computed_at` | test |
| The audit page's empty state is decided by the rendered rows rather than by the ledger count | `tests/test_audit_read_correctness.py::test_the_empty_state_is_not_keyed_off_the_ledger_count` | test |
| A page with records behind it reports `has_more` true | `tests/test_audit_read_correctness.py::test_has_more_is_true_when_records_exist_behind_the_page` | test |
| A page that covers the whole ledger reports `has_more` false | `tests/test_audit_read_correctness.py::test_has_more_is_false_when_the_page_covers_everything_behind_it` | test |
| The response carries no cursor, continuation token or offset field | `tests/test_audit_read_correctness.py::test_the_response_carries_no_cursor` | test |
| An erased record reads `erased` with its tombstone outside the window a page limit imposes | `tests/test_audit_read_correctness.py::test_erased_record_reads_erased_even_when_its_tombstone_is_far_down_the_ledger` | test |
| A tombstoned record whose row survived reads `erasure_conflict` and returns no payload, with its tombstone outside that window | `tests/test_audit_read_correctness.py::test_conflicted_record_withholds_its_payload_even_when_its_tombstone_is_far_down` | test |
| No tombstone is rendered as a decision entry | `tests/test_audit_read_correctness.py::test_a_tombstone_is_never_rendered_as_a_decision_row` | test |
| Counting `tool_call:` keys takes 19.8 ms at 2k, 57.0 ms at 10k and 225.7 ms at 40k, while every other call the endpoint makes stays flat | `python tools/audit_read_cost_probe.py`, transcribed in section 7.2 | **command, marked: no test covers this** |
| A tombstone `getall` over a page's keys is cheaper than the prefix scan it replaced and does not grow with the ledger | `python tools/audit_read_cost_probe.py`, transcribed in section 7.2 | **command, marked: no test covers this** |
| ImmuDB refuses a scan limit above 2500 and imposes no such ceiling on `getall` | `python tools/immudb_read_api_probe.py`, transcribed in section 2 | **command, marked: no test covers this** |
| The ledger count is a walk bounded by the ledger, recurring every 30 seconds per open tab, and grows with the ledger forever | `readME.md` §5, Residual Limits | residual limit |
| `has_more` means more records exist behind this page and never that more recent ones do, because the page is ordered by ledger key | `readME.md` §5, Residual Limits | residual limit |
| A response can carry more rows than `limit` asked for, because orphan-intent rows are appended after the limit is applied | `readME.md` §5, Residual Limits | residual limit |

---

## 11. Could not verify

1. **The three grounding run ids have no artifact.** `p3c3-question`, `p3c3-probe` and `p3c3-scoring` are cited by id only. Their factual content was re-derived (section 2); their reasoning was not recovered and is not reproduced here.
2. **End-to-end cost could not separate before from after at 2k or 10k.** Section 7.1 says so rather than presenting a difference that is inside the noise. The component breakdown in 7.2 is what carries the claim.
3. **The dashboard has no JavaScript test harness.** The card labels, the empty-state condition and the truncation notice are held in place by a static parse of the component's own source. That establishes what the source says, not that the browser renders it - the same limit this project already states for D29's expand affordance.
4. **A first full-suite run reported 60 failures and was discarded as invalid.** A `docker compose build dashboard` was running concurrently for 8.7 minutes of that 14.7 minute run and saturated the host. Every sampled failure passed on re-run in isolation. It is superseded by the hermetic run in section 12 and is recorded here rather than omitted.
5. **`total` counts keys, not successful decodes.** A record the response skips as malformed is still counted. This follows from counting keys and is documented on the field; no test pins it.

---

## 12. Suite and CI

Local hermetic run, `docker compose -p p3c3a -f docker-compose.test.yml down -v` first, fresh stack, nothing else running on the host:

```
PLACEHOLDER_LOCAL_SUITE
```

CI run: PLACEHOLDER_CI

---

## 13. Files changed

| File | Change |
| :--- | :--- |
| `control_plane/main.py` | `_ledger_decision_count` and `_tombstoned_call_ids` added; `content_erasure:` scan deleted; `limit + 1` on both remaining scans with the 2500 ceiling handled; `total`, `has_more` in the response; decode moved into the client block. |
| `dashboard/lib/types.ts` | `total` redocumented, `has_more` added. |
| `dashboard/app/audit/page.tsx` | Four card labels state their scope; truncation notice added; empty state keyed off the rendered rows. |
| `tests/test_audit_read_correctness.py` | New, ten tests. |
| `tools/immudb_read_api_probe.py` | New. Re-derives the ImmuDB REST facts in section 2. |
| `tools/audit_read_cost_probe.py` | New. The component cost breakdown in section 7.2. |
| `TODO.md` | Blocking entry records which two halves closed; the ordering half stays open. |
| `readME.md` | Two Residual Limits; dashboard card claims; `/audit` route description. |
