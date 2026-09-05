# Phase 3c-3g: Falsifiers that can fail

**Run id:** `p3c3g-fix`. State run id, working directory, branch first. Not the primary working directory. Explicit Compose project name on every invocation. Remove your scratch directory before reporting and say what you removed or could not remove.

**Base:** `p3c3b-order` at its current head, **after the R6 fix has landed**. Continuing PR #14. No rebase, no second PR, no merge. Prefer a new commit over amending anything already pushed.

**Session closure:** this session is not closed until its report is committed and pushed.

## Objective

Every falsifier this phase covers can fail, demonstrated by breaking the thing it tests. What "covers" means is bounded in D48 and stated as a limit, not left as a quantifier.

The 3c-3f red-team pass (`docs/reports/phase-3c3f-redteam.md`) refuted six of ten. R6 is fixed out of band. Four of the remaining five are one class: a check that cannot fail, or an exemption that matches more than it names.

Read that report before building. R1, R3 and R5 are one class even though they look like three items.

## What the count does not mean

Refutation counts across this phase are eight, nine, a wrong clean, six, six, six. That is not a measurement of the code. The last pass returned six partly because it stopped: C7, C8 and C9 were never attacked and are recorded as untested, not as holding. The number is a function of brief scope and reviewer budget.

The thing worth weighing instead: R6 was an ordinary correctness defect on the auditor-facing read path, and three phases of enumeration discipline did not catch it. A reviewer reading a diff did. Keep that in view while building enumeration machinery; it is not the only thing that finds defects and it may not be the best one.

## Standing rules

Escalate rather than substitute. Never widen or weaken an assertion. No em dashes. Each item has a **demonstrate** half, an **enforce** half, and a named **mutation** that must fail the suite. Reproduce each defect before fixing it.

Challenge any item that does not serve the objective, or whose Claim cell would describe a goal rather than a behaviour. Raise it before building. The last three sessions each found a framing in the instruction that was wrong; this one had six, found before handoff, and it should be assumed to have more.

---

## Decision

### D48. A falsifier must fail when its own selector is deliberately broken

D43 generalised constants to guarantees. D46 generalised guarantees to selectors. Neither checks that a falsifier can fail, and R1 shows why that matters: `test_a_write_route_is_selected_under_any_verb` builds `SimpleNamespace(__name__=_handler.__module__)`, which agrees with the discriminator by construction and never calls the real selector. A falsifier built out of the thing it falsifies is not a falsifier.

**The rule is mutation-driven, not structural.** An earlier draft said each falsifier must be "constructed independently of the selector it tests". That is a data-flow property: R1's falsifier fails it by one hop, the next will fail it by two, and it cannot be checked mechanically. Worse, enumerating "every selector in the tree" requires a selector, so the regress does not terminate.

The checkable form: **break the selector, require the falsifier to fail.** For R1, make `_service_routes` return `[]` and require `test_a_write_route_is_selected_under_any_verb` to fail. It does not today, because it never calls the real one.

**D48's coverage is bounded, and the bound is a hand-list (corrected).** An earlier draft said "every falsifier in the tree", which has no completion criterion and makes the pre-registered negative below unfalsifiable at the quantifier. Enumerating every falsifier requires a selector, which is the D46 defect one level up, inside the phase that exists to close it.

This phase's D48 coverage is **the falsifiers in `tests/test_route_parity.py` and `tests/test_bounded_reads.py`**, the two files that implement D46, hand-listed in the D48 check itself. A falsifier elsewhere in the tree is outside this phase. The hand-list and its limit go to Residual Limits, stated, not implied. A hand-list with a stated limit is honest; an unbounded "every" that covers two files is not.

The falsifiers the R6 fix introduces are **outside** this bound. R6 landed out of band with its own hand-list and its own stated limit; the two documents are consistent in what they admit rather than one of them quietly claiming more.

**D48's own failure condition, stated as part of the decision:** D48 has this same defect if its own coverage check is derived rather than mutation-driven. If the thing that finds the falsifiers in those two files is itself a selector nobody broke on purpose, level four is built out of level three's material. Say in the report how D48's coverage is established and whether that establishment was itself mutation-driven.

**Pre-committed response if the failure condition fires:** if a later pass finds a recursive item this failure condition predicted and D48 did not catch, the response is not a further generalisation. The claim is scoped down to what the tests demonstrate and the enumeration limits go to Residual Limits. Written here so it is decided now, not re-litigated under the pressure of the finding.

---

## Items

### P3c3g-1. The route selector, and D48's first instance

`_service_routes` discriminates on `route.endpoint.__module__`, so a write route whose handler lives in another module and arrives via `app.include_router` is invisible to the site list, the matrix, and both falsifiers. A router gated by `_require_write_key` holding none of the four properties: `13 passed`, identical to baseline. The same handler in `main.py`: `3 failed`.

**Demonstrate:** the included-router case caught. Then D48 on this selector: `_service_routes` returning `[]` and the falsifier failing.

**Enforce:** the falsifier calling the real selector, plus the D48 check on it.

**Mutation:** restore the `SimpleNamespace` construction. The D48 check must fail.

### P3c3g-2. Bounded-read assertions that have never run

16 of 16 `assert_at_or_above_min_score` calls compared zero rows in a green run. Every walk passes `None` on the only page it reads. No mutation was needed to show this.

**The obvious fix is wrong.** Making the check run on page one checks nothing, because page one carries no bound. Non-vacuity requires the walks to actually page, which today happens only because one unrelated module pads to 2600 rows. A shared fixture driving each walk against a stub returning a full page is what makes the second-page path run deterministically. Moving the `min_score` update alone produces assertions that are no longer vacuous and still never execute.

**The zero-row rule is over a walk's whole life, not per call (corrected).** An earlier draft said "an assertion comparing zero rows is a failure rather than a pass". That breaks every first page in the tree: `min_score` is `None` on the first iteration of every walk, forever, and that is correct, because page one carries no bound. `assert_under_prefix` over an empty scan also legitimately compares zero. As drafted the item mandated something implementable only by weakening it back, which is a pre-registered negative of its own.

The failure condition is: **a walk that never compares a row, in any call, across its whole life.** One vacuous call is not a defect. A walk with no non-vacuous call is.

**Demonstrate:** each walk's second-page path executing, with the assertion comparing real rows. The count of rows actually compared, per walk, recorded in the report.

**Enforce:** the shared fixture, plus the whole-life check above.

**Mutation:** move the `min_score` update above the check. Named test must fail, not pass vacuously.

### P3c3g-3. Exemptions that match more than they name

R4 and R5 are one fix. Both are `explains()` matching a substring of a caller-supplied key segment.

- R4: a real record through `/write-ordered` with agent id `p3c3c-padded-batch-7` inherits the `p3c3c-pad` exemption.
- R5: `test_the_registered_violations_are_the_only_exemptions_in_use` is order dependent. Alphabetical `23 passed`; reconciliation first, `1 failed`. Both on fresh ledgers. CI is green because `b` sorts before `r`. That is D44's class, in a test this phase added.

Key the registry on an explicit marker the polluting test writes into the record value. Fixing them separately produces two mechanisms where one is needed.

**Where the marker is read, and at what cost (decided).** The invariant walk keeps `(key, score, tx)` from zscan and never reads record values, so a marker in the value is not free. It is read **only for rows already violating an invariant**, by an exact `getAll` over that handful of keys, never per row over the view. A view of 2600 rows yields a violating set in the single digits, so the cost is one bounded read per pass. This is a design constraint stated here, not a discovery for the implementing session to make after choosing a shape.

**Demonstrate:** the `p3c3c-padded-batch-7` record not inheriting the exemption, and the order-dependent test passing in both orders.

**Enforce:** a test for each half of the one fix.

**Mutation:** restore substring matching. Both named tests must fail.

**Also:** the order sweep's method cannot see R5, because it only compares failing sets and a skip is never in one. Say whether the sweep can be made to see this class, or state that it cannot.

### P3c3g-4. The count read

`_ledger_decision_count`'s `GET /api/v2/db/count/{prefix}` is a prefix-bounded production read deciding every `/audit` total, invisible to all three selectors and unchecked. Dropping the prefix returns HTTP 200 with a larger count.

**The specific numbers in the red-team report, 2631 against 2624, are incidental.** They came off a polluted ledger at one moment in that session and are not reproducible criteria. What reproduces is the shape: a dropped bound answers 200 with a different and larger number, and nothing checks it.

It is not one of the three limits the module states, which is the part that matters: the module's stated scope is wrong, not just incomplete.

This is a missing site, not a missing mechanism. It is the cheapest item here and it should not grow.

**Demonstrate:** the read enumerated and its bound asserted. The module's stated limits corrected.

**Mutation:** drop the prefix. Named test must fail.

### P3c3g-5. The untested claims

C7, C8 and C9 were recorded as untested rather than holding. They carry forward to the next red-team brief unchanged. Nothing to build; stated here so they are not lost.

`docker-compose.override.yml` and the exact-match stateful-path list also remain undemonstrated.

---

## Residual limits to state, not to schedule

- **D48's coverage is a hand-list of the falsifiers in two files.** A falsifier elsewhere in the tree is not covered by this phase, and nothing enumerates falsifiers tree-wide. Stated per D48 above.
- The unverified-write path's caller count is not enforced.
- `/write-ordered` accepts a key of any shape into a view.
- 35 test modules were never isolated; isolation was per module, not per test.
- The 16 KiB detector head bound stays, with its measured cost and the dependency test key that dropping it would hit.

## Pre-registered negatives

All false at the end, each confirmed individually and derived per row.

- Any falsifier **within D48's stated coverage** that passes when its selector is broken.
- Any walk that never compares a row in any call and reports a pass.
- Any exemption matched by substring rather than by an explicit marker.
- Any bounded read outside the enumerated site list.
- Any Claim cell describing a goal rather than a behaviour.
- Any assertion weakened, or any refutation closed by narrowing the claim without saying so.

## Report

`docs/reports/phase-3c3g.md`, committed and pushed before this session closes. Verdict per item, the reproduction before the fix, the broken-selector output for each falsifier, demonstration, enforcing test, mutation result, mapping, could-not-verify, CI run id. Verdict by the red team's own labels: R1 through R5 (R6 is closed out of band; cite `docs/reports/r6-headstate.md` rather than re-verdicting it), and C1 to C10, saying explicitly which were untested rather than holding.

State how D48's own coverage is established and whether that establishment was mutation-driven.
