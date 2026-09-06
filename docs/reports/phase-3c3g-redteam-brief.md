# Red-team brief: Phase 3c-3g (narrow), and the merge decision

**Run id:** `p3c3g-red`. Fresh session, clean context. Scratch clone, not the primary working directory. Explicit Compose project name on every invocation.

**Target:** PR #14 at the current head of `p3c3b-order`. Do not merge. Do not fix anything you find; report it.

**Read first:** `docs/reports/phase-3c3g.md`, `docs/reports/r6-headstate.md`, and `docs/reports/phase-3c3f-redteam.md` for the labels this brief carries forward.

**This session is not closed until its report is committed and pushed** to `phase-3c3g-redteam.md`, under `docs/reports/`.

**A note on how this file names the report it commissions.** The report filename above is written without its `docs/reports/` path prefix, deliberately. `tests/test_docs_references_resolve.py` requires every literal `docs/` path in a committed file to resolve in that same commit, it scans `docs/reports/` like everywhere else, and this brief is committed before the report it asks for exists. That test is right and is not being weakened: its subject is a pointer to a file that was present locally and never committed, a real defect it has caught three times. A forward reference to a document this brief commissions is a different thing. Naming the file without a resolvable path keeps both true. Do not helpfully restore the prefix; it turns CI red on a docs-only commit.

## Why this brief is narrow

Six prior passes ran ten-claim briefs and returned budget-limited counts. This one decides the merge of PR #14, so it spends its budget on the few places most likely to move that decision, plus the claims no pass has ever tested. Depth over coverage: fewer targets, driven further.

## The merge criterion, pre-committed

Three cells, not two. Classify every finding into exactly one:

1. **Application.** A missed site, a wrong clause, an unasserted bound; the kind of thing D46, D47 or D48 exists to catch and can be fixed under them. Applications do not block the merge.
2. **Recursive gap.** A finding in the shape D48's own failure condition predicts, which D48 did not catch. One of these triggers the pre-committed response: no further generalisation; the claim is scoped down, the limits go to Residual Limits, and the project shares a smaller claim.
3. **Carried.** A finding that predates D46/D47/D48 and is not closed by them; known, recorded, unfixed. R7 is one (`COMPOSE_FILES` still omits the override at the current head), the `test_record_profile.py` interaction is another, and the P3c3e-2 diagnosis below may become a third. Carried findings do not block the merge: they were known and unfixed when the earlier passes on this PR were judged, and elevating them at the decision would be a moving target. Rediscovering a carried finding is worth one line and its label, not a re-demonstration.

Your report says, per finding, which cell it is in. That classification, not severity, is what the decision turns on.

## Targets, in order of expected yield

### T1. D48's hand-lists, and whether the listed clauses are the clauses that matter

D48's coverage is two hand-typed lists that must agree with each other, both typed by the same person in the same commit. The build session measured the hole: a third conjunct added to `_service_routes` and recorded in neither list reads `2 passed`. The lists disagree when someone updates one and forgets the other; they agree silently when someone updates neither, which is the likelier mistake.

The deeper question is not list completeness. Attack whether the six listed clauses are the clauses that matter: a discrimination that lives outside any listed clause, or a clause whose replacement (not removal) changes the selector's output with no falsifier failing. The build session found one coincidental equivalence (gate versus path) with a replacement mutation.

**The floor for this target:** if you find no second instance, the report states which clauses you enumerated and which replacement mutations you attempted against each. "Enumerated and no replacement changed the output unseen" is evidence; "did not enumerate" is not, and the two must be distinguishable in the report.

### T2. The exemption marker through a production path

`ail_deliberate_violation` is a value anyone who can write a record value can write. The build session believes a real record cannot claim an exemption from a ledger-wide invariant, because `registered_for` also requires the invariant and the view to match, and did not drive it. Drive it: write the marker through `/write-ordered` and establish whether any production record can exempt itself from any invariant.

### T3. `state_read`, the new `/audit` field

R6 added a sibling field nobody has attacked: `state_read{source,status,detail}`, vocabulary `ok/unchecked/unavailable`, carried through the `/audit` branches. Attack the contract: a value outside the vocabulary, the field's behaviour when the head read fails in each branch, whether `unchecked` and `unavailable` are distinguishable by a consumer in the cases that matter, and whether any path still renders a null `state_id` with no sibling explaining it.

**Concrete starting point:** three `/audit` branches render `"state_read": None` outright, at `control_plane/main.py:817`, `:829` and `:850`. The docstring at `:845` claims the null is "for the same reason and not by omission". That claim is the attackable surface; start there.

### T4. C9: the digest-collision identity

Promoted from the untested set because it is ready to drive: the 3c-3f red team left a written, concrete, undriven hypothesis. A `call_id` set to the sha256 digest of a different record's key passes both checks and collides with that record's fallback identity. Drive it and establish whether one record's fault can be made to join as another's.

### T5. The count read, between the guard and the wire

The guard checks that the request carried its bound, because a count has no rows to check. Both in-process spellings are covered: dropping the segment fails the enumeration, removing the guard fails the driver. The residual space is the path itself, and in the deployed topology the control plane talks to ImmuDB directly over httpx, with Envoy on the agent path, so the expected answer is that nothing sits between them.

**A null result here is a finding, not an untested claim.** Enumerate what is actually between the call and ImmuDB in the deployed compose topology. If nothing is, report "no instance today" with the enumeration; that is a different verdict from "could not test" and the report must use the right one.

### T6. The remaining untested set

C7 and C8 from the 3c-3f brief, never attacked across two passes, and the exact-match stateful-path list, undemonstrated. (R7, the override file, is already a carried finding; one line and its label if you touch it.)

**Drop order, explicit:** if budget runs out, drop from the bottom: T6 first, then T5. A third consecutive "untested" on C7/C8 is acceptable as a decision; it is not acceptable as an accident. Say in the report which targets were dropped and that the drop was by this order.

## Diagnosis task, not a claim

`test_committed_is_a_fact::test_a_retry_after_a_dropped_response_is_told_the_record_already_exists` failed once during `r6-headstate` on write-path code its diff did not touch, and passed on re-run. What the failure showed is D45's lie on a branch D45's four states do not cover: relay dropped the response, key landed, caller told `committed: false`. The green re-run says the timing moved, not that the branch is sound.

Keep-alive standard: reproduce, find the window, demonstrate causally by moving something and watching the failure move with it. If the cause is that the branch is real, that is a refutation of a claim closed in 3c-3e (P3c3e-2), and it should be reported as one, then classified into the criterion's three cells like everything else: it predates D46/D47/D48, so if they do not close it, it is carried, and the report says so rather than letting it stall the decision.

**Not in this brief:** the `test_record_profile.py` order interaction. It is pre-existing, its two-module reproduction failed, and it is a bisection job with a recorded starting order, not an attack. Spending review budget on debugging is the misallocation this phase's own count section is about.

## Report

`phase-3c3g-redteam.md`, under `docs/reports/`, committed and pushed before you close. Per target: refuted, not refuted, no instance today (with the enumeration), or could not test, with the command and output. Per finding: application, recursive gap, or carried; stated explicitly, since the merge turns on it. Say which of your own checks you established could fail before trusting them. Enumerate anything you could not remove, by name, with the commands.
