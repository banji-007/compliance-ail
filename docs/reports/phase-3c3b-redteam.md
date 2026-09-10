# Red-team report: Phase 3c-3b, run `p3c3b-red`

**Target:** PR #14 at `b9f6a1d`, branch `p3c3b-order`. Not merged, nothing fixed.
**Environment:** scratch clone, Compose project `p3c3bred`.
**Baseline before attacking:** `tests/test_audit_ordering.py` 24 passed.

Eight of ten claims refuted (C1, C2, C3, C5, C6, C7, C8, C10); C4 and C9 held, as did C5's second attack. The two most serious: a write the verifier reports as not having happened has in fact committed, indexed, and advanced the counter; and the ordering fault is not permanent, it self-clears as newer traffic pushes the corruption off the page.

---

## C1 - Refuted (both halves), except the CAS case

Claim: "No path commits a record without its position... no rejected write leaves a record, a counter advance, or an index entry behind."

"No path commits a record without its position" is false. The plain `/write` route does exactly that, and a decision record can reach it (see C8): committed at tx 135, no position, no index entry, absent from `/audit`.

"No rejected write leaves a record, a counter advance, or an index entry behind" is false. See C7: a write rejected to the caller left all three.

The CAS-rejection case holds; see C9.

## C2 - Refuted

`indexed_keys()` (`tools/ail_backfill_index.py:133-143`) issues one un-paginated `zscan` at the 2500 cap, while `scan_all()` beside it pages properly. Once a view exceeds 2500 rows, records that are indexed become invisible to the snapshot and get indexed a second time.

Setup: 5 records written through the real `/write-ordered` (positions 1000000001..5), then a view padded past 2500 rows.

```
=== DRY RUN ===  "records": 20, "already_indexed": 5, "to_index": 15
=== REAL RUN (pass 1) ===  "total_indexed": 15, "assigned_range": [1.0, 15.0]

=== records holding MORE THAN ONE position ===
  live-0-8e5ace2117a0425f8   positions=[1.0, 1000000001.0]
  live-1-ce7f08b18d7d49679   positions=[2.0, 1000000002.0]
  live-2-b7d0001aad684c5db   positions=[3.0, 1000000003.0]
  live-3-e241c789f2194238b   positions=[4.0, 1000000004.0]
  live-4-53cc7e423157463c8   positions=[5.0, 1000000005.0]
```

On one page:

```
call_ids appearing more than once on ONE page: 7
  83db3b70d24c x2 at page rows [0, 2490] agent=live4 tx=5
  4c6423639aa9 x2 at page rows [1, 2496] agent=live3 tx=4
```

Precision on the claim as worded: passes 2 and 3 were idempotent (`to_index: 0`). The duplication comes from a single pass whose index snapshot truncated, not from re-running. A production view reaches 2500 rows after 2500 decisions.

Related, untriggered: `indexed_keys()` returns an empty set on any non-200 (lines 139-140), so one transient `zscan` error makes the backfill believe nothing is indexed and re-index everything.

## C3 - Refuted, along the tool's own documented remediation

The backfill refuses to run if history reaches the reserve and instructs: "Raise AIL_RESERVED_POSITIONS... on every service, and re-run." Doing exactly that puts already-allocated CAS positions inside the new reserve.

```
before:  {"state":"clean","allocated":5,"indexed":5,"backfilled":0}
seed:    {"seeded":true,"from":1000000005,"value":2000000000}
after:   {"state":"clean","allocated":0,"indexed":0,"backfilled":5}
  view positions: [1000000005.0 ... 1000000001.0]   counter now: 2000000000
```

Five committed CAS allocations are reclassified as backfilled history. They are no longer reconciled (`allocated: 0`, so a hole among them is now undetectable) and no longer order-checked, since D33 is scoped to `s >= reserve+1` (`control_plane/main.py:871`). `seed_counter_above_reserve` prevents future overlap only; the existing overlap is permanent.

## C4 - Not refuted

Both wire facts the design cites are real, measured:

```
zscan desc=True : [(5,'pos'), ('<OMITTED>','zero')]      # negative silently omitted
zscan desc=False: [('<OMITTED>','zero'), (5,'pos'), (-1,'neg')]
scan entry keys : ['key','revision','tx','value'] | tx present: True
```

Live positions start at `reserve+1`; backfill scores at `entry.tx` and `scan` does return `tx`, so the `.get("tx", 0)` default is unreachable. No path to a score at or below 0 found.

Named: nothing validates `AIL_RESERVED_POSITIONS` in any of its four copies. A zero or negative value is accepted silently, and that is the one input that would put every position at or below zero.

## C5 - Refuted (first attack); second attack not refuted

The check's window is the page, and the page is always the top-of-index.

Same corrupt index, one injected disagreement (position 1000000030.5 to tx 1):

```
limit=1    -> HTTP 200   (clean page served)
limit=2    -> HTTP 500   audit_ordering_fault
limit=200  -> HTTP 500
limit=2500 -> HTTP 500
```

Then 2510 newer clean rows added, nothing withdrawn, the disagreement still in the index:

```
/audit?limit=1:    HTTP 200 rows=1
/audit?limit=200:  HTTP 200 rows=200
/audit?limit=2500: HTTP 200 rows=2499
zscan top-2500 window: scores 1000003509.0 .. 1000001010.0
injected row 1000000030.5 inside that window: False
```

No limit reaches it: `scan_limit` caps at 2500 and there is no cursor or offset.

Second attack (one position, two transactions, and its inverse) is caught: `not (score_a > score_b and tx_a > tx_b)` raises on equal scores and on equal transactions alike.

## C6 - Refuted, three ways

**Wrong view reads clean.** A decision record allocated a position but indexed into the intent view:

```
wrote decision record into the INTENT view -> {"tx_id":38,"seq":1000000032,"verified":true}
AFTER reconcile : {"state":"clean","allocated":32,"indexed":32,"backfilled":0,"missing_count":0}
in DECISION view: False
on /audit page  : False
```

`collect_positions` unions scores across every view, so a record absent from every `/audit` page reconciles clean.

**Extra positions are never checked.** On the corrupt index, reconciliation reported `{"state":"clean","allocated":32,"indexed":2542,"backfilled":1}`: 2510 positions the counter never handed out, and the verdict is clean. `anchor_service/main.py:368` computes `missing` in one direction only. This matters because the fault body's own remediation tells the operator to run this reconciliation to find what else is affected.

**A missing score kills the detector.** `anchor_service/main.py:324` does `min_score = float(rows[-1]["score"])` two lines after a correct `.get("score", 0.0)`:

```
collect_positions   : RAISED KeyError 'score'
```

Swallowed by `run_forever`'s except, so the detector goes permanently dark, one log line per interval. (No production write path producing score 0 was found.)

## C7 - Refuted. The most serious finding.

`ExecAll` commits, then `verifier/main.py:695` runs `verifiedGet`. The read is against the record key; that half of the claim is fine. But the guarantee did weaken: it moved from before the commit to after it.

Fault injected by corrupting the verifier's persisted trust anchor (ADR-0006 `consistency_failure`, one byte of `txHash`):

```
verifier response   : {"tx_id": null, "seq": null, "verified": false, "detail": "proof verification failed"}
counter before/after: 1000000129 -> 1000000130
record in ledger    : True
indexed in view     : True at [1000000130.0]
```

The response is the exact contract `ledger/immudb_ledger.py` reads as "the write did not happen". It happened.

End to end:

```
DECIDE -> {"status":"DENIED","fault_class":"verifier_unreachable"}
LEDGER row score 1000000132 tx 139 agent c7-allow outcome policy_allow
```

The tool call did not execute. The audit ledger holds a `policy_allow` record for it at a CAS position, as the newest row on the page. Fail-closed holds for execution; it does not hold for the ledger.

Minor: `attempts` is reported as 0 on this path though the commit took 1.

## C8 - Refuted

The parse reads two files and counts substrings. First, it can fail: diverting the decision write the obvious way gives `assert 1 == 2`. Then, appending a caller to `ledger/immudb_ledger.py` itself that holds the route in a variable (`ledger.verifier_url + _PLAIN_ROUTE`):

```
test_each_record_kind_is_written_through_the_route_that_matches_it  1 passed
```

Live, that path is not cosmetic:

```
tx committed        : 135
counter before/after: 1000000128 -> 1000000128
in decision view    : False
record in ledger    : True
on /audit page      : False (page rows: 129)
```

A decision record in the ledger, no position, no index entry, absent from every ordered page, permanently, since `/audit` now selects through the index. The parse also walks only two files, so any third module is invisible to it.

## C9 - Not refuted

`AIL_SEQUENCE_MAX_ATTEMPTS=1`, 60 writers at 12 threads:

```
counter: None -> 1000000031
verified ok: 31  not verified: 29
   [29] sequence allocation gave up after 1 rejected attempts; the ledger write did not happen
--- of the FAILED writes ---
  records present in ledger : 0 / 29
  of those, indexed in view : 0
--- of the OK writes ---
  all indexed: True (31)
  seq unique: True  range: 1000000001 1000000031  gapless: True
```

Exhaustion is a clean DENY. No partial write, no reused position.

## C10 - Refuted

"Permanently and for every page" is false; see C5. The same disagreement that 500'd every page returned to 200 at every limit once newer traffic pushed it below the window. `transient: false` is wrong in the worst direction: the fault is transient, the corruption is not.

Read paths during an active fault:

```
GET /audit?limit=200      -> 500  audit_ordering_fault
GET /audit/verify?key=... -> 200  {"verification":{"state":"verified"...
GET /audit/bundle?key=... -> 200  {"bundle_format":"ail-evidence-bundle/2"...
GET /anchors/latest       -> 200
```

Keyed diagnosis survives, but it needs a key, and the paging path that yields keys is the one denied. And the remediation the body prints points at the reconciliation, which reports this index clean (C6).

---

## The unexplained failure: not reproduced, bounded further

- 2 cold-start runs of the full ordering suite: 24 passed each.
- 1 run under concurrent `docker compose build --no-cache` (the condition the report names): 24 passed in 80.11s.
- Ruled out the leading hypothesis, ImmuDB index-visibility lag: 120 write-then-immediate-getall trials at 8 concurrent on a cold stack, 0 anomalies.
- Measured `/write` latency p50 574ms, p95 2988ms, max 3115ms on a cold stack, well inside the client's 60s timeout.

Still unexplained. Bounded a little tighter than before.

## Not on the list

**`total` and the page no longer describe the same thing.** `/audit?limit=2500` served 2499 rows while reporting `total: 20`. Phase 3c-3a's `total` counts ledger records; the page is now a count of index rows. Duplicate index rows (C2) make the page larger than the ledger it pages.

**Two stale comments at HEAD contradict the shipped design.** `control_plane/main.py:896` ("History is therefore scored in (0, 1), never at or below zero") and `:1233` ("backfilled positions are fractional, so int() would collapse every one of them to 0"). The backfill assigns `float(tx)`, integers at or above 1. Both survive from the pre-`f4944b0` ranking design and would mislead the next reader about the seam.

**`AIL_RESERVED_POSITIONS` is declared by no service** in `docker-compose.test.yml` or `docker-compose.yml`, while four modules read it independently and nothing checks agreement at runtime. `anchor_service`, which owns reconciliation, is absent from the test compose file entirely, so its copy of the reserve is never exercised by the suite. (This confirms and extends could-not-verify item 3.)

## Reproduction

Every refutation above was reproduced independently on clean stacks built from `b9f6a1d`,
Compose project `p3c3brepro`, host ports remapped (18080/18003/18002/18010) so an unrelated
`p3c3c` stack could keep its own. Baseline on each fresh stack: `tests/test_audit_ordering.py`
24 passed. The poisoned `p3c3bred` ledger was destroyed, not reused.

Identical to the original run: C2 (five records at two positions each after one pass; passes
2 and 3 idempotent), C3 (`allocated: 5, indexed: 5` becomes `allocated: 0, backfilled: 5`,
verdict clean), C5a (limit=1 serves a clean 200, limit>=2 faults), C5b/C10 (every limit
returns to 200 with the disagreement still indexed and outside the top-2500 window), C6c
(`KeyError: 'score'`), C7 (`verified: false, tx_id: null` with record, counter advance and
index entry all present; `/decide` DENIED while the ledger holds `policy_allow`), C8
(tx committed, counter unmoved, absent from the view and from `/audit`).

Three deviations, none affecting a verdict:

- **C6 needs a virgin ledger.** Running the suite first leaves a deliberate hole from
  `test_a_consumed_position_with_no_index_entry_is_detected` (`missing_count: 1`), which
  offsets the arithmetic and hides the point. On a virgin ledger the numbers are
  unambiguous: a decision record indexed into the intent view leaves the verdict `clean`,
  and an unallocated position gives `allocated: 6, indexed: 7` - still `clean`.
- **C9 gave up 42 of 60 rather than 29 of 60.** Contention differs run to run. The
  conclusion is unchanged: zero leaked records, zero index entries, positions unique and
  gapless.
- **C2 duplicated four records on one page rather than two.** Where the seam falls inside
  the page depends on row counts. The mechanism is the same.

The `total`-versus-page-rows mismatch reproduced as well: `HTTP 200 rows=2499 total=10`.

## Environment cleanup: partly blocked

The Docker daemon began returning 500 Internal Server Error on every API call during teardown, after the interrupted background build, and has not recovered.

Removed: the scratch clone contents, including the generated `keys/*.key`, `*.pub` and `vault_api_token.txt`, and all temporary probe scripts.

Could not remove (needs the daemon back):

- Compose project `p3c3bred`, containers and volumes (`test-immudb-data`, `test-verifier-state`, `test-control-plane-data`). Its last `down -v` is the call that hit the 500.
- Images built by project `p3c3bredload`, from the interrupted `--no-cache` build.
- The now-empty directory `.../scratchpad/p3c3b-red/repo`, held by a stale bind mount (Device or resource busy).

After restarting Docker Desktop:

```
docker rm -f $(docker ps -aq --filter label=com.docker.compose.project=p3c3bred)
docker volume rm p3c3bred_test-immudb-data p3c3bred_test-verifier-state p3c3bred_test-control-plane-data
rm -rf ".../scratchpad/p3c3b-red"
```

The primary working directory is untouched: still on `main`, `git status` clean.
