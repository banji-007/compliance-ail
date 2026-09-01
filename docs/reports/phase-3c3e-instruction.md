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

Properties in scope as of now, each against every write route: the refusals, `KeyMustNotExist`, `committed` as a fact about the ledger, and the no-proof path guard. The route list is enumerated from the verifier's registered POST routes, not hand-listed.

### D44. A test's assertions are scoped to the records that test wrote

A test proving the reconciler finds a fractional position has to create one. A test proving the seam is monotone has to assert none exists. Both are correct; the defect is the second stating its precondition as a ledger-wide fact when it is not one.

Four tests, two polluters, measured in `docs/reports/phase-3c3d-order-sweep.md`. The sweeps also established what this decision does not need to cover: hidden dependence came back zero across 11 modules and 118 tests, so tests already build their own preconditions. Scoping assertions is the whole of it.

---

## Items

### P3c3e-1. The route parity test

**Lands first, separately, before A4 is touched.**

Implement D43. Enumerate the verifier's registered POST write routes from the application object. Assert each property against each route.

**Demonstrate:** the test failing on unmodified head, naming `/write-ordered` for the `committed` property. Record that output in the report; it is the evidence that the enumeration works.

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

**Check the condition first:** whether any ledger outside CI holds pre-D38 fault records, given every CI ledger dies on `down -v`. If none does, the path protects nothing and costs a caller-influenced code path.

If the condition holds, delete it, state the migration, and remove its tests. If it does not hold, say so and fix A7 in place instead.

**Demonstrate:** the check, then whichever branch follows.

### P3c3e-9. Retire the source parse

Defeated three times: a plainly-named second caller, an alias binding, and `globals()[...]` / `getattr(sys.modules[__name__], ...)`.

A source parse is not a control against anything that can write Python, and keeping it invites the belief that it is a second line. The runtime guard held; that is the control. Remove the parse and its tests, and state in the report and in Residual Limits that the runtime guard is the only control on that path.

### P3c3e-10. Scope the four order-dependent tests

Implement D44. The four tests, two polluters and one shared victim are named in `docs/reports/phase-3c3d-order-sweep.md`.

**Demonstrate:** the suite passing in alphabetical, reverse and at least two shuffled orders, with the seeds recorded.

**Enforce:** the scoped assertions, plus whatever makes order-dependence loud rather than silent.

**Mutation:** restore one ledger-wide assertion. Reverse-order run must fail.

---

## Residual limits to state, not to schedule

- 35 modules were not isolated. Nothing in the sweep data points at them; nothing excludes them.
- Isolation was per module, not per test. A dependence one test satisfies for a later test in the same module is invisible to it. Per-test isolation is 442 runs and nothing measured indicates it.
- `/write-ordered` accepts a key of any shape into a view. Closing it would refuse the deliberately-mismatched writes `tests/test_reconciliation.py` uses to prove D37 finds a record in the wrong view. Carried, not taken.

## Pre-registered negatives

All false at the end, each confirmed individually and derived per row.

- Any property enumerated by the parity test that holds on one write route and not another.
- Any enumeration hand-listed where it could have been derived from the code.
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
