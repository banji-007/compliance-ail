# Order dependence and isolation: how much of green is collection order

**Run id:** `p3c3d-sweep`. **Head:** `c7b29d0` on `p3c3b-order`, the same commit
the red-team pass `p3c3d-red` reported against. **Compose project:**
`p3c3dsweep`, stated explicitly on every invocation. Scratch clone, not the
primary working directory.

Written because the red-team report's "not on the list" finding named one pair
of contradictory tests and attributed their green to alphabetical collection.
That is correct, and it is not the whole of it. This measures the whole of it.

## Method

Five full-suite runs, each preceded by `docker compose down -v`, so the only
variable is the order modules are collected in. Module granularity, not
test-within-module: the finding under investigation is cross-module.

Orders: alphabetical (what CI does), reverse, and three shuffles of the sorted
module list under `random.Random(seed).shuffle` for seeds 1, 2 and 3. The
seeds are recorded so any run is reproducible.

**Host-broken tests cancel by construction.** This machine cannot install
`sigstore`, so `test_external_anchor`, `test_offline_verify` and
`test_writer_signing` fail here in every order. Rather than filter them by
hand, each order's failing **set** is diffed against the alphabetical
baseline's. Anything host-broken appears in both and cancels.

**The baseline validates the method.** Alphabetical: 14 failed, 428 passed,
9 skipped. All 14 are that known `sigstore` set and nothing else, and
428 + 14 = 442, exactly CI's `442 passed` at this commit
(run `33477596287`). The local sweep is a faithful proxy for CI.

## Result

| Order | Failed | Passed | Order-dependent |
| :--- | ---: | ---: | ---: |
| alphabetical (CI) | 14 | 428 | baseline |
| reverse | 18 | 424 | 4 |
| shuffle-1 | 16 | 426 | 2 |
| shuffle-2 | 16 | 426 | 2 |
| shuffle-3 | 17 | 425 | 3 |

**Four distinct tests are order-dependent, out of 442.** Union across all four
non-alphabetical orders; no order produced a fifth.

**Nothing in the other direction.** In all four orders, the set of tests
passing here and failing alphabetically is **empty**. Alphabetical collection
is not concealing a real defect. The suite's green is **fragile, not false** -
which is the single most useful thing in this document, because it bounds what
has to be re-established rather than re-derived.

## The causal map

Each victim was correlated against the position of each suspect module in all
five orders. Three of the four correlate perfectly with one polluter; the
fourth has two independent ones.

**Polluter A: `tests/test_backfill_index.py::_pad_view_past_the_ceiling`.**
Pads the decision view to 2600 rows and never removes them.

| Victim | Fails exactly when |
| :--- | :--- |
| `test_audit_read_correctness.py::test_has_more_is_false_when_the_page_covers_everything_behind_it` | backfill ran first (4/4 orders) |
| `test_audit_ordering.py::test_a_record_written_before_the_index_appears_in_the_ordered_page_after_backfill` | backfill ran first (4/4 orders) |

`has_more` can never be false once the view exceeds any page limit, so the
test asserts a property the ledger no longer has.

**Polluter B: `tests/test_reconciliation.py`, two permanent injections.**

- `:325` `_zadd(VIEW_DECISION, _counter() + 0.5, key)` - a fractional position
  above the reserve.
- `test_a_second_position_below_the_reserve_for_an_indexed_record_is_a_finding`
  `_zadd(VIEW_DECISION, 42.0, key)` - a record at two positions, and a history
  score that is not its record's transaction id. **This one was added in Phase
  3c-3d, by the same session that wrote the fixes it tests.**

| Victim | Fails exactly when |
| :--- | :--- |
| `test_backfill_index.py::test_one_pass_over_a_view_past_the_ceiling_leaves_no_record_at_two_positions` | reconciliation ran first (4/4 orders) |

**Both polluters, one victim.**
`test_audit_ordering.py::test_the_seam_is_monotone_across_the_boundary` fails
whenever **either** module runs before it, and passes only when neither does.
It makes three ledger-wide assertions and each polluter breaks a different
one:

- `all(float(x).is_integer() for x in live)` - broken by the `counter + 0.5`
  injection.
- a backfilled position is its record's transaction id - broken by the `42.0`
  injection and by the padder's synthetic scores.
- `max(history) < min(live)` - holds throughout.

## What this says

**The scope is bounded and the cluster is coherent.** Four tests, two
polluters, three polluting actions, and every one of them is about the view
index and a global assertion over it. This is not a scattering of unrelated
state leaks; it is one design surface where several tests each assert a
ledger-wide invariant while several others deliberately violate one to prove a
detector fires.

**That is the actual tension, and it is not a test-hygiene problem.** A test
that proves the reconciler finds a fractional position has to create one. A
test that proves the seam is monotone has to assert none exists. Both are
correct tests. What is missing is that the second states its precondition as a
ledger-wide fact when it is not one.

**One of the three polluting actions is mine**, added in the phase that was
supposed to be closing this class of defect. The Phase 3c-3d report already
records two of my tests failing in CI for shared-ledger reasons; this is a
third instance of the same misjudgement in the same phase, found only because
the order was permuted.

## Isolation: the other failure class, measured

The permutation sweep cannot see a test that passes in every order because
some earlier module seeded state it silently depends on. Such a test passes
every permutation and fails run alone. The two want different fixes:
interference wants the assertion scoped or the polluter cleaned up, hidden
dependence wants the test to build its own preconditions.

Eleven modules run alone, each against a ledger destroyed and rebuilt first:
the nine this phase changed, plus `test_audit_ordering.py`,
`test_audit_read_correctness.py` and `test_backfill_index.py`, which are the
victims and polluters the permutation sweep named.

**The comparison is exact rather than filtered.** All fourteen failures in the
alphabetical baseline are in `test_external_anchor`, `test_offline_verify` and
`test_writer_signing`, none of which is in this scope, so the baseline
restricted to these eleven modules is empty. Any failure here is hidden
dependence by construction, with no host noise to subtract.

```
test_committed_is_a_fact          4 passed   60.47s
test_fault_key_and_page_read     12 passed   68.34s
test_image_contents               5 passed   94.73s
test_ledger_faults               20 passed   78.72s
test_ledger_vocabulary            7 passed   11.60s
test_ordered_route_refusals       6 passed   45.28s
test_reconciliation               7 passed   40.32s
test_reserve_binding             20 passed   59.35s
test_audit_ordering              24 passed   61.74s
test_audit_read_correctness      10 passed   26.74s
test_backfill_index               3 passed   19.96s
```

**118 tests, zero failures. No hidden dependence in scope.**

That is the result that bounds the remediation. This suite's failure mode is
**interference only**: every one of the four order-dependent tests has an
identified polluter, and no test in the phase's blast radius needs state some
other module happened to leave. The fix is one decision about assertion scope,
not a suite-wide rewrite of preconditions.

Two residuals, stated rather than implied. The thirty-five modules outside
this scope were not isolated; nothing in the data points at them, but nothing
excludes them either. And isolation here is per **module**, not per test, so a
dependence that one test in a module satisfies for a later test in the same
module is invisible to it. Per-test isolation is 442 runs and is not
indicated by anything measured here.

## Reproducing

`sweep.sh` at this commit's scratch clone, removed with it. It is forty lines:
for each order, `down -v`, `up -d --wait`, sleep 15, `pytest <files> -q
--tb=no -rf`, then `comm` the failing sets. The five orders are alphabetical,
reverse, and `random.Random(seed).shuffle(sorted(modules))` for seeds 1, 2, 3.

`isolation.sh` beside it, same shape: for each module, `down -v`, `up -d
--wait`, `pytest <module>`, then `comm` against the alphabetical baseline.
