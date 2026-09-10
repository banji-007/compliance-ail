# Red-team brief: Phase 3c-3b (audit ordering)

**Run id:** `p3c3b-red`. Fresh session, clean context. Scratch clone, not the primary working directory. Explicit Compose project name on every invocation. Remove the scratch directory before reporting and say what you removed or could not remove.

**Target:** PR #14 at `b9f6a1d`, branch `p3c3b-order`. Do not merge. Do not fix anything you find; report it.

## What you are doing

The build session made the claims below. Each is stated as a behaviour that could be false. Your job is to make one of them false, not to confirm them. A refutation is a command and its output. "I could not refute this" is a valid and useful verdict; a confirmation you did not test is not.

Two standing cautions from this project's history. Controls here have twice reported success while not running, so for any check you exercise, first establish that it can fail. And mutation `m1` poisons the ledger it runs against, so a test failing after a mutation may be failing for `m1`'s reason; wipe between attempts.

## Claims

**C1. A record and its index entry cannot exist without each other.** No path commits a record without its position in the same transaction, and no rejected write leaves a record, a counter advance, or an index entry behind.

**C2. Re-running the backfill does not duplicate a record on the page.** ImmuDB's `zAdd` appends rather than replaces. Establish what a second backfill pass, or a backfill overlapping live traffic, does to the page. If the same record can appear twice at two positions, say so.

**C3. The seam is monotone by construction and stable across runs.** Historical positions are `entry.tx` under the reserve, live positions above it. Attack the boundary: a ledger whose `tx` approaches `RESERVED_POSITIONS`, a backfill run twice against different denominators, a live counter that already exists below the reserve when the backfill starts, a fresh verifier against a ledger that already has history.

**C4. No score is zero or negative.** `zscan` under `desc` silently omits negatively-scored members, so an omitted record is indexed and invisible rather than absent. Find any path that can produce a score at or below zero, including defaults on a missing or malformed score.

**C5. A score-versus-transaction disagreement is always surfaced as a fault.** Two specific attacks. First: a disagreement between rows that no single page's comparison window spans. Second: the inverse of the demonstrated case, one position carrying two transactions rather than two positions carrying one.

**C6. Reconciliation reports a committed record missing from the index.** `collect_positions` unions scores across every view. Determine whether a record indexed into the wrong view reads as clean. Determine what a row with a missing or unparseable score contributes.

**C7. Write-time verification was moved, not dropped.** `ExecAll` then `verifiedGet` is claimed to run the same inclusion and consistency proofs as `verifiedSet` and to raise to DENY. Confirm the read is against the record key just written and not an index or cached key. Then: the record commits before the verification runs, so make the verification fail and establish what is in the ledger afterwards and whether the tool call executed.

**C8. The `/write` versus `/write-ordered` split is enforced.** A static parse of production callers is claimed to catch a record kind changing routes. Add a caller the parse does not see: indirection, an alias, a route held in a variable, a call from a module the parse does not walk.

**C9. Retry exhaustion denies rather than corrupts.** The retry budget is an availability parameter. Drive it to exhaustion and establish that the failure is a clean DENY with nothing written, not a partial write or a reused position.

**C10. The audit fault response is the only face of a fault.** A fault returns 500 with `page_served: false` and `transient: false`, permanently and for every page. Establish whether any read path remains that could diagnose the ledger once it fires, and whether a single bad row denies every audit read including the ones needed to investigate it.

## Also

Attempt reproduction of the unexplained failure recorded in could-not-verify: one run, two tests, no server-side trace, ImmuDB healthy. Bound it or leave it bounded.

## Report

Inline. Per claim: refuted, not refuted, or could not test, with the command and output. Name anything you found that is not on this list.
