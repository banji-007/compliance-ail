# Probe brief: D38 fault key shape

**Run id:** `p3c3d-keyprobe`. Fresh session. Scratch clone, not the primary working directory. Explicit Compose project name on every invocation. Remove your scratch directory before reporting and say what you removed or could not remove.

**Base:** `p3c3b-order` at its current head.

## This is a probe. Do not build.

Answer the questions. Do not implement D38, do not fix anything you find, do not open a PR. Every answer is a command and its output. "This is not routed" and "I could not test this" are useful answers; an inference from the SDK source or from how it ought to work is not.

The reason this exists: D35's single fault key was locked off a probe that answered the question asked rather than the question that mattered. It confirmed prior versions were readable and nobody asked what a second version does to a page. The instruction to keep asking past the first satisfying answer is the point of this pass.

**Precedent:** `p3c3-question`, `p3c3-probe` and `p3c3-scoring` established that this REST route does not expose everything the SDK has. `TxScan` is not routed. Assume nothing is routed until you have driven it.

## Context

D38 replaces `ledger_fault:{call_id}` with a composite key carrying the transaction. The reason is shadowing: a second write to the single key replaces the first on the page, the genuine fault survives only as a prior version invisible to every consumer that exists, and `/write-ordered` refuses nothing, so a caller can author that write. Composite keys turn erasure of a fault into noise beside it.

What is not settled is the key's shape and the page-side read. Two requirements, and the second is the one most likely to be met wrongly and silently:

- One bounded read per page, whose bound is derived from the page itself.
- No second key holding the same fact. An existence marker alongside the fault is rejected; that is the duplication class Phase 3c-3c just swept.

The failure mode to avoid: a single bounded scan over `ledger_fault:` filtered client-side. Fault keys sort by `call_id`, `call_id`s are random hex, so a bounded prefix scan returns an arbitrary lexicographic slice and can exclude a record's fault by a bound that was never about it. That is P3c3a-3's finding re-manufactured, and it fails silently.

---

## Q1. Is a range scan routed at all?

Ask this first; if the answer is no, Q2 and Q3 are moot and cost nothing.

`scan` takes `seekKey`, `endKey`, `inclusiveSeek` and `inclusiveEnd`. Establish which of these the REST route actually honours, as opposed to accepting and ignoring. An accepted-and-ignored parameter is the dangerous answer, so drive each one to a result you can check rather than reading the response shape.

**Report:** routed, not routed, or accepted-and-ignored, per parameter, with the call and the result.

## Q2. Does the 2500 ceiling apply to a range result?

If a page's transaction window contains more than 2500 fault keys, one read is not enough. That is still a page-derived bound if it paginates, but "one paginated read per page" needs stating rather than discovering.

The reconciler's `minScore` cursor is the pattern already in the tree; establish whether the equivalent works here.

**Report:** the ceiling's behaviour on a range result, and whether a cursor over it is available.

## Q3. What is the zero-pad width, and what happens past it?

A composite key carrying a transaction sorts numerically only while the transaction fits the pad width. Past it the keys stop sorting numerically and a range quietly returns the wrong set.

Fix a width in the probe. Then exceed it deliberately and show what the range returns.

**Report:** the width, and the measured behaviour at and past the boundary.

## Q4. Both orderings, both consumers

`{tx}:{call_id}` makes the page read cheap and turns "every fault for this record" into a full-prefix scan. `{call_id}:{tx}` does the reverse.

The per-record direction has real consumers: the evidence bundle exporter and `GET /audit/verify?key=` both start from a key, not from a page. Optimising the page alone and discovering later what it cost the exporter is the same mistake this decision is correcting.

Measure both orderings against both consumers. Report round trips and wall time for each of the four combinations, with the ledger size stated. Say which figures are inside host noise; this project's measurements have been wrong in that direction before.

## Q5. Does a record with no `call_id` reach a page?

The fallback's justification is that such a record never reaches a page. Nothing has tested it, and the page is built from the view index, which `/write-ordered` will populate with any value handed to it.

Write one and look.

This decides the question rather than informing it. If such a record does reach a page, both options in the standing lean are wrong: the row carries `ledger_key`, `_tombstones_and_faults` already returns it, so `sha256(record_key)` is derivable from a page row today and the fallback is joinable with no format change at all.

**Report:** whether it reaches a page, and if so, whether the digest is derivable from what the row already carries.

## Q6. What happens to the faults already committed?

ImmuDB is append-only and a key cannot be renamed, so every `ledger_fault:{call_id}` already written keeps that shape permanently. After D38 the page reads the new shape and old faults stop rendering unless it reads both.

This is C3's class: raising the reserve reclassified committed positions as history and nothing anywhere said so.

Establish the cost of the page reading both shapes: extra round trips per page, and whether the old shape's exact `getall` can be kept alongside the new read rather than replaced. If reading both is not cheap, say what it costs, because the alternative is a stated limit in `readME.md` and I would rather choose that knowingly.

---

## Report

Inline, no file. Per question: the answer, the command, the output. Name anything you found that these six questions did not ask about, particularly anything suggesting the composite key is the wrong shape entirely.

Recommend a key format and a page-side read shape, with the measurements behind it. If the evidence points somewhere other than a composite key, say so; reversing this decision a second time is cheaper than building on a bad one.
