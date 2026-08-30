# ADR-0014: An ordered audit view, selected by a CAS-allocated sequence

**Status:** Accepted (Phase 3c-3b)
**Decisions:** D32, D33, D34
**Supersedes nothing. Extends:** ADR-0002 (the `/audit` proxy), ADR-0006 (verification states), ADR-0009 (write-ahead intents)

---

## Context

`GET /audit` paged the ledger with `scan` over the `tool_call:` prefix under
`desc: true`. That walks keys, and a decision key is
`tool_call:{agent_id}:{uuid}:{tool_name}`, so the page returned the
lexicographically-largest agent ids and presented them as the most recent
decisions. A record written seconds ago was absent once the ledger exceeded
`limit`. Observed during `p3c2-defer` at 211 entries: the newest transaction
was 573 and the page's first row was not it. Reproduced during this phase at
501 entries, where the newest transaction was 638 and the page's highest was
630, in an order that was not descending by transaction at all.

No read parameter fixes this. `scan` has no ordering option, `TxScan` is not
routed over the REST API the control plane uses, and no key this project
writes is temporal or monotonic. The ordering has to be put somewhere the
ledger enforces, at write time.

## D32. A zset index selects; a CAS-allocated sequence scores it

`zscan` is routed and orders by a caller-supplied score. The question is
where the score comes from.

**Not a clock.** A timestamp is globally comparable and wrong under skew, and
the thing being ordered is commits, not wall time.

**Not a per-writer counter.** `p3c3-scoring` had four writers each claim
positions 1 to 15. Signing the claim does not help: it proves the writer
*said* position 3, not that position 3 is where the record belongs. A
per-writer sequence is not an ordering.

**A single counter, allocated under a compare-and-set the ledger enforces.**
One `ExecAll` carries three operations - the record, the advanced counter,
and the `zAdd` into the view index - gated by a `KeyNotModifiedAfterTX`
precondition on the counter. A writer that read a stale counter is rejected
outright, so any position that commits is the unique next one from the state
that writer read. All three operations land in one transaction or none do.

Verified live against immudb 1.9.5 during this phase: a three-operation
`ExecAll` commits with `nentries=3` under one transaction id, and repeating
it against the now-stale precondition is refused with `precondition failed:
KeyNotModifiedAfterTxID`. Under 8 concurrent writers, 64 writes produced 142
rejected attempts, a gapless block of positions, and score order equal to
commit order.

**The index is a view index, not the ordering.** The ledger's ordering is its
transaction sequence; this is one view over it. Hence the naming:
`ail_view:decision:v1` and `ail_view:intent:v1`, scored from one shared
`ail_seq:commit`. A second view - incident-first, say - is a new zset over
the same positions and needs no second backfill. `p3c3-question` established
that no scan can filter on outcome, because `outcome_type` lives in the
record's value and not in its key, so such a view would need its own index;
adopting the shape now is nearly free and cannot be adopted cheaply later.

The counter key sits outside `tool_call:`, `tool_call_intent:` and
`content_erasure:`, or it would be counted as a decision by the ledger count
Phase 3c-3a added.

### What the write path gave up, and got back

`immudb-py` 1.5.0 has no `verifiedExecAll`, and its `execAll()` wrapper
cannot express a precondition at all - the handler builds
`ExecAllRequest(Operations=..., noWait=...)` with no preconditions field, so
the whole mechanism is unreachable through it. Two consequences, both
deliberate:

**The request goes to the generated gRPC stub rather than the wrapper.** No
verification code is reimplemented; only a request the wrapper cannot
express. This is a much narrower thing than the hand-rolled `Alh()` ADR-001
exists as a warning about.

**The proof check moved from inside the write call to immediately after it.**
`verifiedSet` ran the inclusion and consistency proofs as part of writing.
`ExecAll` does not, so the ordered write issues a `verifiedGet` on the record
key straight afterwards. It is the same SDK verification code over the same
proofs, and it raises on the same conditions, so the fail-closed rule is
unchanged: an unverifiable write raises, `ledger/immudb_ledger.py` turns that
into an exception, and the decision service denies the call. Confirmed live
that a `verifiedGet` on an `ExecAll`-written key succeeds and that the
consistency proof keeps advancing across `ExecAll` transactions. **The
guarantee moved; it did not weaken.** Measured cost of the move: none
distinguishable from noise (see the report).

### Scores are positive and fractional below 1

Two measured constraints, both discovered by trying the obvious thing first:

- `zscan` under `desc: true` **silently omits negatively-scored members**,
  and an explicit `minScore` does not bring them back. A backfill that placed
  history below zero would produce records that are indexed and still absent
  from every page, which is this ADR's own defect reintroduced by the
  migration meant to fix it.
- A score of exactly `0` comes back with **no `score` field at all**, because
  protobuf's JSON mapping omits zero-valued fields.

So the CAS allocates integers from 1 up, and `tools/ail_backfill_index.py`
places history in the open interval (0, 1). History sorts below live traffic,
which is correct: it is older, and the page is newest-first.

## D33. The index selects, the record proves

`zscan` returns the caller's score and the resolved `entry.tx` in the same
response, so comparing them costs no extra call.

Under the CAS this is no longer a defence against a writer that can misorder;
the ledger refuses to commit an out-of-order position at all. It is a cheap
assertion that the enforcement is still in place, and it is what would catch
the precondition having been dropped. That is not hypothetical: applying this
phase's own "drop the precondition" mutation left 48 writes sharing 10
positions, and the resulting duplicate scores made every sufficiently deep
page fault.

**A disagreement is a fault, not a sort order.** `/audit` answers 500.
Reordering the page to match the transaction ids would hide precisely the
condition worth reporting - an index that no longer describes the ledger it
indexes - and would show a reader a page that looks fine.

**What the check covers, stated precisely.** Only positions the CAS
allocated, which are the integers from 1 up. Backfilled history was ordered
by an offline pass from transaction ids of records already committed, and
was never subject to the CAS, so a pre-index record can legitimately carry a
higher transaction id than a record indexed after it. Comparing those two
would report a fault about a rule that never applied to either. The check is
scoped to the rows the CAS produced and is not weakened for them.

## D34. The serialisation ceiling is accepted, documented, and measured

The CAS globally serialises the ledger write path: every write contends on
one counter key.

**Concurrency stops buying anything, and this deployment reproduces that.**
Measured here: one writer sustained about 8.7 writes per second; eight
concurrent writers sustained 5.9 to 8.0, with 142 of 206 attempts rejected
and retried. Adding writers moved no more traffic and made tail latency
much worse (median 325 to 657 ms against 115 ms for one writer). This is a
property of the design, not a defect in it: the ordering is what is being
bought, and a total order over commits is inherently serialised.

**Caching the counter is worth paying for.** A writer that caches
`(seq, tx)` from its own last successful commit measured indistinguishable
from the pre-ordering write path; reading the counter from the ledger on
every write cost noticeably more. `AIL_SEQUENCE_CACHE=0` turns the cache off,
so both figures are reproducible rather than asserted. Correctness does not
depend on the cache either way - the CAS rejects a stale read whichever
place it came from.

**One decision writer exists today.** `docker-compose.yml`'s
`decision-service` has no `replicas` or `deploy` stanza, and the Helm chart
deploys no decision service at all. The ceiling is therefore not currently
reached; it is documented because it is what would be hit first if it were.

**The retry budget is an availability parameter, not a correctness one.**
`AIL_SEQUENCE_MAX_ATTEMPTS` defaults to 300. An exhausted budget is a failed
ledger write, which the existing rule turns into a denied call - so lowering
it can deny traffic and raising it trades latency for availability. Zero
writers gave up at 8 concurrent in either this phase's measurements or
`p3c3-scoring`'s.

## Consequences

- A record with no index entry is absent from every ordered page, not merely
  unordered. That is why `tools/ail_backfill_index.py` ships in the same
  phase as the index rather than after it: on an append-only ledger the set
  of unreadable records would only grow.
- Gaplessness makes reconciliation arithmetic over the index alone rather
  than a full key scan, because a rejected precondition consumes no position.
  A hole is therefore evidence that a committed record is missing from its
  view, not an unremarkable crash artifact. `anchor_service` runs the check:
  it is already a periodic loop that observes and reports and never gates a
  write, which is exactly what a detector should be.
- `has_more` now means more *recent* records exist behind the page, which is
  a stronger claim than the one Phase 3c-3a shipped. README's Residual Limits
  states the new meaning rather than leaving both alive.
- A position is a float64 score, so positions stay exact to 2^53. At one
  write per second that is about 285 million years.

## References

- `docs/reports/phase-3c3b.md` - the measurements, the mutation transcripts,
  and the before/after demonstration
- `docs/reports/phase-3c2.md` - where the defect was first observed
- `tools/ail_backfill_index.py`, `tools/ail_ordering_cost_probe.py`
- `tests/test_audit_ordering.py`
