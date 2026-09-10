# Phase 3c-3e: Enumerated guarantees

**Run id:** `p3c3e-fix`. State run id, working directory, branch first. Not the primary working directory. Explicit Compose project name on every invocation. Remove your scratch directory before reporting and say what you removed or could not remove.

**Base:** `p3c3b-order` at its current head, continuing PR #14. No rebase, no second PR, no merge. Prefer a new commit over amending anything already pushed; this branch is shared.

**Session closure:** this session is not closed until its report is committed and pushed.

## Objective

Every guarantee this system claims holds at every site where it applies, and the enumeration of those sites is derived from the code rather than from memory.

The 3c-3d red-team pass (`docs/reports/phase-3c3d-redteam.md`) refuted six of ten claims. Read it before building. The pattern underneath the six is one thing: a rule that must hold at N sites, with nothing enumerating the sites. Two routes covered at one. Four or more read functions covered at two. N key encodings covered at one. N inspection surfaces covered at one. Earlier passes: five modules compared at four, four copies of a validator, two copies of a compose rule.

## The shape of a fix in this phase

**The enumeration is written first and is expected to fail. The fix follows.**

This is not stylistic. In 3c-3d the fix was applied to one route and the enforcing test was written alongside it, pointing at the route that was already correct. A4 survived a full phase and a red-team brief that named the route by name. An enumeration derived from the code fails until every site is covered, so the test produces the fix rather than ratifying it.

Where an enumeration can be derived from the code, derive it. A hand-listed registry carries the same defect one level up. Where it cannot be derived, hand-list it and say in the test that this instance is weaker.

## Standing rules

Escalate rather than substitute. Never widen or weaken an assertion. No em dashes. Each item has a **demonstrate** half, an **enforce** half, and a named **mutation** that must fail the suite. Reproduce each defect before fixing it.

Challenge any item that does not serve the objective, or whose Claim cell would describe a goal rather than a behaviour. Raise it before building.

---

## Decisions

### D43. A guarantee holds at every site, enumerated from the code

Routes are the first instance, not the rule. The rule is that any property the system claims is asserted against a site list the test derives, so a new site fails the suite until it is covered.

The project built this control once and scoped it to constants (`test_ledger_vocabulary.py`). This generalises it to guarantees.

**The route list is derived, and the discriminator is named.** `app.routes` carries POST `/write`, `/write-ordered` and `/verify`, and the last is a read. The write routes are those whose dependency is `_require_write_key`; `/verify` takes `_require_read_key`. Hand-listing which are writes would sweep `/verify` in or out by judgement, which is this decision failing on its own terms at the first step.

**Three states per cell, not two: holds, does not apply, or missing.** A property that does not apply to a route is recorded as such **with its reason, in the test**, so a new route forces a decision rather than defaulting silently to either state.

That distinction is load-bearing rather than tidy. `KeyMustNotExist` does not belong on `POST /write`: D39's reason for it is that a second write gives the key a second entry in the view index at a second position, and the plain route allocates no position. Applying it there would refuse a second erasure attempt after a partial failure, on the GDPR path, which is the harm P3c3e-3 exists to close. An earlier draft of this decision said "each against every write route" without checking that each property's justification survives on both routes, which is the shape of the rule substituted for the rule.

**Properties in scope as of now**, per route: the refusals, `KeyMustNotExist`, and `committed` as a fact about the ledger.

**The no-proof path guard is not one of them.** `_set_without_verification` is module-level and no route reaches it, so "route by no-proof guard" has no meaning as a cell. The assertable property is that **no route reaches the unverified path**, which is one assertion rather than a matrix column. P3c3e-9 carries what does and does not enforce the rest of it.

### D44. A test's assertions are scoped to the records that test wrote

A test proving the reconciler finds a fractional position has to create one. A test proving the seam is monotone has to assert none exists. Both are correct; the defect is the second stating its precondition as a ledger-wide fact when it is not one.

Four tests, two polluters, measured in `docs/reports/phase-3c3d-order-sweep.md`. The sweeps also established what this decision does not need to cover: hidden dependence came back zero across 11 modules and 118 tests, so tests already build their own preconditions. Scoping assertions is the whole of it.

---

## Items

### P3c3e-1. The route parity test

Implement D43. Enumerate the verifier's registered POST routes from the application object, select the write routes by their `_require_write_key` dependency, and assert each property against each route in the three states D43 names.

**Authoring order, not commit order.** The test is written before A4 is touched and its failing output is recorded in the report; it then lands in the same commit as the fix it produces. Nothing is gained by pushing a knowingly-red commit to a branch the red team also works on. P3c3d-1 landed separately for a different reason: it was an independent fix closing live paths, not a test and the fix it forces.

**Demonstrate:** the test failing on unmodified head, naming `/write-ordered` for the `committed` property. Record that output in the report; it is the evidence that the enumeration produces the fix rather than ratifying it.

**Enforce:** the parity test itself.

**Mutation:** add a third write route with none of the properties. The parity test must fail without being edited.

### P3c3e-2. `committed` is a fact on the ordered route

`verifier/main.py:1545-1549` returns `committed: false` from a generic handler with no ledger read. A relay dropping the ExecAll's own response left the record at tx 55, counter advanced, zAdd at position 1000000017, the row reading `policy_allow` on `/audit`, and the response saying nothing happened.

The comment three lines above it says everything before that line can fail without anything having been written. That is false and it is the sentence that would have caught this.

**Demonstrate:** the red team's relay case on `/write-ordered`, with the response, the ledger, the counter and the index agreeing afterwards. The `POST /write` cut that also takes out the confirmation read, reproducing the GDPR `erasure_conflict`: DELETE 503, tombstone at tx 121, payload still in `call_content`, writes frozen at 409.

**Enforce:** P3c3e-1's parity test covers the property. Add the relay cases as tests against both routes.

**Mutation:** restore the generic handler's `committed: false`. Parity test must fail.

Correct the false comment.

### P3c3e-3. A retry the caller was wrongly told to make

D39's `KeyMustNotExist` turns a write the caller was wrongly told had failed into one they can never retry: 409 forever. Neither decision produces this alone.

D40 removes the cause. This item establishes the interaction is closed and that no legitimate retry path is permanently denied.

**Demonstrate:** the sequence end to end, with the retry succeeding or being correctly told the write already exists.

**Enforce:** a test for it.

**Mutation:** revert P3c3e-2. Named test must fail.

### P3c3e-4. Bounded reads, enumerated

D42's assertions cover some reads. `indexed_keys` and `scan_all` in `tools/ail_backfill_index.py` assert nothing, and both decide what gets zAdded into a view.

**Enumeration first:** derive the list of bounded reads from the code and assert each one asserts its bound. Expect it to fail on at least the two named.

**Demonstrate:** the enumeration failing before the fix.

**Mutation:** remove a bound assertion from any one read. The enumeration must fail without being edited.

### P3c3e-5. Key material in images, enumerated

A DER key rode into the real image with the test at 5 passed. A PEM deleted by a later layer came back byte-identical from `docker save`.

Two enumerations, both hand-listed and both weaker for it; say so in the test. Encodings: PEM, DER, PKCS8, OpenSSH, base64 with no header. Inspection surfaces: the running filesystem and every layer in `docker save`.

**Demonstrate:** both red-team cases caught.

**Mutation:** drop one encoding from the detector. Named test must fail.

### P3c3e-6. Fault keys are bounded and validated

Nothing validates `call_id`. Past roughly 1000 characters the fault key exceeds ImmuDB's max key length and no fault record is written: the record is committed, unverified, on the page, with `ledger_fault: null`.

Validate `call_id` at key construction. A fault that cannot be written fails loudly; a qualification that silently does not exist is the defect the fault record was built to prevent.

**Demonstrate:** an over-long `call_id` refused at construction, and an unwritable fault failing loudly rather than silently.

**Mutation:** remove the validation. Named test must fail.

### P3c3e-7. A fault key's transaction is not caller-supplied

A fault keyed at a transaction the record does not occupy is invisible at HTTP 200, and nothing compares the key's transaction against the body's own `committed_tx_id`.

Derive the key's transaction from the committed record, or cross-check the two and fail on disagreement. Derivation is preferable; if it is not available on both fault-producing paths, say so and cross-check instead.

**Demonstrate:** a mismatched fault refused or surfaced rather than silently invisible.

**Mutation:** accept the caller's transaction. Named test must fail.

### P3c3e-8. Delete the legacy fault-key read path

P3c3d-4 exists so pre-D38 `ledger_fault:{call_id}` records still render, and it is the source of A7's `count: 2` for one fault, because its key derives from a caller-authored `call_id`.

**The condition is answered and does not need re-deciding: there is no deployment outside CI.** Every ledger that has ever held a fault record is a CI or scratch stack destroyed by `down -v`. The path protects nothing and costs a caller-influenced code path.

What the session verifies is the half it can: that no volume in either compose file survives `down -v`, so no ledger persists between runs. It does not verify deployments, and it should not try; that fact is recorded here rather than derived.

Delete the path, state the migration, and remove its tests.

**Demonstrate:** the volume check, then the deletion, with A7's `count: 2` case no longer constructible.

**Mutation:** restore the legacy read. A7's case must become constructible again.

### P3c3e-9. Retire the source parse

Defeated three times: a plainly-named second caller, an alias binding, and `globals()[...]` / `getattr(sys.modules[__name__], ...)`.

A source parse is not a control against anything that can write Python, and keeping it invites the belief that it is a second line. The runtime guard held; that is the control. Remove the parse and its tests.

**State what replaces the half the parse was carrying, or state that nothing does.** The guard covers what gets *written*: it reads the bytes it is about to commit and refuses anything that is not a fault record. It does not bound *how many callers exist*, which is what the parse counted. The two are not the same property and the deletion must not quietly merge them.

The expected answer is that nothing replaces it. The AST reference walk written in 3c-3d is itself a source parse, and `globals()[...]` carries the name only as a string literal, so no reference walk sees it; catching that means flagging dynamic lookup, which is defeatable in turn. If that is the answer, it is a Residual Limits entry rather than something lost in the deletion.

### P3c3e-10. Scope the four order-dependent tests

Implement D44. The four tests, two polluters and one shared victim are named in `docs/reports/phase-3c3d-order-sweep.md`.

**Demonstrate:** the suite passing in alphabetical, reverse and at least two shuffled orders, with the seeds recorded.

**Enforce:** the scoped assertions, plus whatever makes order-dependence loud rather than silent.

**Mutation:** restore one ledger-wide assertion. Reverse-order run must fail.

---

## Residual limits to state, not to schedule

- 35 modules were not isolated. Nothing in the sweep data points at them; nothing excludes them.
- Isolation was per module, not per test. A dependence one test satisfies for a later test in the same module is invisible to it. Per-test isolation is 442 runs and nothing measured indicates it.
- The unverified-write path's caller count is no longer enforced once the source parse is retired. The runtime guard bounds what that path writes; nothing bounds how many callers reach it. See P3c3e-9.
- `/write-ordered` accepts a key of any shape into a view. Closing it would refuse the deliberately-mismatched writes `tests/test_reconciliation.py` uses to prove D37 finds a record in the wrong view. Carried, not taken.

## Pre-registered negatives

All false at the end, each confirmed individually and derived per row.

- Any property that holds on one write route and is, on another, neither held nor recorded as inapplicable with its reason.
- Any enumeration hand-listed where it could have been derived from the code. **This one is a stated judgement, not a confirmed negative**: it cannot be checked mechanically. The report names which enumerations were derived, which were hand-listed, and why each hand-listed one could not be derived.
- Any bounded read that does not assert its bound.
- Any response reporting `committed: false` for a write that committed, on either route.
- Any legitimate retry permanently denied.
- Any fault key accepted whose transaction the caller supplied.
- Any unwritable fault failing silently.
- Any test asserting ledger-wide what it can only assert about records it wrote.
- Any Claim cell describing a goal rather than a behaviour.
- Any assertion weakened, or any refutation closed by narrowing the claim without saying so.

## Report

`docs/reports/phase-3c3e.md`, committed and pushed before this session closes. Verdict per item, the reproduction before the fix, the enumeration's failing output before each fix that has one, demonstration, enforcing test, mutation result, mapping, could-not-verify, CI run id. Verdict by the red team's own A1 to A10 labels alongside the item verdicts, and say explicitly which claims were not refuted.
