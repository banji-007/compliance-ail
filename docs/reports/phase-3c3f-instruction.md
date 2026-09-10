# Phase 3c-3f: Selectors and the trust anchor

**Run id:** `p3c3f-fix`. State run id, working directory, branch first. Not the primary working directory. Explicit Compose project name on every invocation. Remove your scratch directory before reporting and say what you removed or could not remove.

**Base:** `p3c3b-order` at its current head, continuing PR #14. No rebase, no second PR, no merge. Prefer a new commit over amending anything already pushed; three sessions work this branch.

**Session closure:** this session is not closed until its report is committed and pushed.

## Objective

Every enumeration this system relies on states the property it covers, selects the sites that property applies to, and falsifies the selector in both directions. And no anchor is written or seeded from a state nothing verified.

The 3c-3e red-team pass (`docs/reports/phase-3c3e-redteam.md`) refuted six of ten. Read it before building. Two results underneath the six:

- The enumerate-first shape from 3c-3e is right, and both enumerations were built on selectors narrower than the property they claim. A selector is itself a claim and had no falsifier.
- A test's retry predicate contained its assertion, so the test retried until the property happened to hold. That is why one intermittent local failure was green in CI: the retry usually hid it.

## Standing rules

Escalate rather than substitute. Never widen or weaken an assertion. No em dashes. Each item has a **demonstrate** half, an **enforce** half, and a named **mutation** that must fail the suite. Reproduce each defect before fixing it.

Challenge any item that does not serve the objective, or whose Claim cell would describe a goal rather than a behaviour. Raise it before building.

---

## Decisions

### D46. A property is stated, and its selector is falsified in both directions

**The property comes first, and it is stated independently of the selector.** This is the clause the rest of the decision rests on, and it is where 3c-3e went wrong. `tests/test_route_parity.py` claims "every property this service claims about a write" and implements "takes the write key". Those are different sets, and nothing in the file says which one it means. A property defined as whatever its selector picks up makes both falsifiers below vacuous by construction: neither can ever fail. So the property is written down in the module in its own words, before the selector, and the selector is then a claim about covering it.

**Then two falsifiers, because one direction validates only against being too narrow.**

- **A case that satisfies the property and not the selector.** The same handler under `@app.put` gated by `_require_write_key`, holding none of the four properties, passed at `10 passed`; under `@app.post` it failed at `2 failed`. A bounded read in `verifier/main.py`, which the REST call-site matcher produces zero sites for because the verifier is gRPC only. **`POST /verify` is also this direction and not the other one:** it mutates the persisted anchor and the selector does not pick it up. An earlier draft of this decision called it the converse; that was wrong, and the correction matters because building a selector-not-property test out of `/verify` produces something incoherent.

- **A case that satisfies the selector and not the property.** There is no route today that `_require_write_key` selects and that fails the write property, so for that selector this direction is currently uninstantiated and the test says so rather than being omitted. It is not hypothetical in general: the bounded-read table's four `does_not_apply` entries are exactly selector-true, property-false cases, and the three-state design already in that file (holds / does not apply with a recorded reason / missing) is this direction's falsifier. That is the worked precedent to build against.

Every enumeration in the tree carries both falsifiers as tests. Where a selector cannot be validated in one direction, say so in the test rather than omitting it.

`tests/` is excluded by `_module_files()`. That exclusion is a selector and inherits this decision.

### D47. The persisted anchor is never written or seeded from an unverified state

Two call sites, same shape, different credential tiers. Named by function, because line numbers move on the first edit:

- `verifier/main.py::verify`, the `client.currentState()` call on the unanchored path, read-key gated.
- `verifier/main.py::write`, the D40 state read outside the `try`, write-key gated.

Both are "report the head" calls. `currentState()` reaches `currentRoot.call`, which takes no verifying key, never verifies, and calls `rs.set(state)` unconditionally: no signature check, no monotonicity check, no comparison against what it overwrites. The SDK's own `# IMPROVEMENT: we could check here, if state is valid` sits on that line. It runs last, so it overwrites the verified state that `verifiedSet.call` or `verifiedGet.call` set moments earlier under `newstate.Verify(verifying_key)`.

Reporting the head does not require persisting it. `_PinnedRootService` already records rather than persists and the anchored path uses it; the precedent is in the tree.

**Seeding is covered, not only writing, and there are two seeding paths.** `PersistentRootService.init` sets its cache from `CurrentState` when the state file is absent or unreadable, and `get()` does the same when the cache is `None`. Neither is a `set`, so neither is caught by a rule about writes, and both make the in-memory anchor a state nothing checked. The first proof after a fresh boot with no state file runs from that source. `_PinnedRootService` implements `init`, `get` and `set`, so one class covers the two seeds and the write together.

What was intended in Phase 1.3 was reporting the head. Overwriting a verified anchor with an unverified one is a consequence of how the SDK reports it, not a decision anyone made. `GET /state` reached the opposite conclusion about the same mutation in the same credential tier and wrote the argument down.

---

## Items

### P3c3f-1. A retry never retries an assertion

`cut_until_it_lands`'s docstring states in bold that it retries the fixture and never the assertion. The call site in `test_an_ordered_write_that_committed_is_reported_as_committed_when_its_response_is_dropped` puts `r[0].json().get("committed") is True` into the `landed` predicate.

The red team injected A4.1 in intermittent form and the test went green while the route answered `committed=false` for a record present at tx 8. Made deterministic, the same injection fails, so the test can fail.

The correction is the one this phase already found on a different line: `is not False`, not `is True`. `null` is honest; `false` is the only lie.

**Demonstrate:** the red team's intermittent injection, failing after the fix. Sweep every call site of every retry helper for an assertion inside a predicate.

**Enforce: the behavioural form, not a source parse.** The enforcing test drives a route that answers `committed: false` once and then correctly, and asserts the helper does not retry past it. `tests/test_route_parity.py`'s stub clients already make that buildable in-process, with no stack and no container. A parse over `tests/` that looks for an assertion inside a predicate is acceptable **only** as a declared second line, with its limits stated in the module the way the static Dockerfile check states its own; it is not the criterion. P3c3e-9 retired exactly that kind of check after it was defeated three times, and a check retired for cause does not come back as an acceptance criterion.

**Mutation:** restore `is True`. Named test must fail under the intermittent injection.

This is the diagnosis task from the previous brief, answered. Record it as such: the one-in-three local failure was the property genuinely failing, and CI's timing hit the retry more often.

### P3c3f-2. The write-route selector

Implement D46 on `write_routes()`. `"POST" in route.methods` is a hand-list wearing a derivation's clothes.

State the property first, in the module, in its own words. It is not "takes the write key". If the honest answer is that no single derivable discriminator matches it, say so and hand-list with the reason in the test, per D43's own rule for underivable enumerations.

**Demonstrate:** both falsifiers, per D46. Direction one: the PUT handler covered, and `POST /verify` classified correctly against the property as stated, since it is this direction too. Direction two: no instance exists for this selector today, so the test records that rather than omitting it.

**Mutation:** narrow the selector back to POST. The direction-one falsifier test must fail. That mutation does not touch direction two, and the report says so rather than claiming both.

### P3c3f-3. The bounded-read selector

Implement D46 on the bounded-read walk. It matches ImmuDB REST call sites, the verifier is gRPC only, and it therefore produces zero sites in the file carrying the route parity work.

`tests/` is excluded by `_module_files()`, and `tests/test_view_invariants.py::_view_rows` is an unasserted bounded read that decides how many rows all four ledger-wide invariants see. That is a D46 question about the exclusion, not a separate item.

**Demonstrate:** both falsifiers. Direction one: the gRPC sites enumerated; the four REST spellings the AST walk cannot attribute, either attributed or stated as underivable with the reason. Direction two: the four `does_not_apply` probe entries, which are already this direction and whose three-state handling is the precedent D46 points at.

**Mutation:** restore the REST-only matcher. Direction-one falsifier test must fail.

### P3c3f-4. `_committed_position_for` reads what it asserts on

A bounded zScan added this phase under D45 that never reads `entry.score` and returns the score it asked for.

**On a disagreement it returns `None`, and does not raise.** Pre-decided here so the item does not stall on it: `None` is what D45 already means by `seq: null` beside `committed: true`, which is "the record is in the ledger and its position could not be confirmed". Raising would change the response contract on a path that exists to report uncertainty honestly. Log the disagreement at error with both scores.

**Demonstrate:** the returned position derived from what came back, and a disagreement surfaced.

**Mutation:** return the requested score. Named test must fail.

### P3c3f-5. `scan_all`'s bound is driven

Marked covered with its `seekKey` bound undriven: 225 identical pages in 8 seconds, no refusal.

**Demonstrate:** the bound driven, and the runaway case refused.

**Mutation:** drop the bound assertion. Named test must fail.

### P3c3f-6. The anchor

Implement D47: both call sites and both seeding paths.

**Demonstrate:** the red team's `POST /verify` case, anchor unmoved. The same on `POST /write` under the write key. A fresh boot with no state file, with the first proof running from a verified source.

**Enforce:** a test per call site, plus one for the cold-boot seed.

**Mutation:** restore the unconditional `rs.set` at either site. Named test must fail.

**Escalate** if declining to persist the head breaks a caller that depends on the anchor advancing; that is a D21 or D23 question I have not decided.

**Expect this item to move a known flake, and check rather than be surprised.** `tests/test_committed_is_a_fact.py::test_a_write_that_committed_is_reported_as_committed_when_the_state_call_fails` asserts `str(ledger_tx) in after` against the persisted anchor, and this item changes what writes that anchor. The verified `verifiedSet` set should still carry the write's transaction, so it should hold, but if it moves, this item is why. See the handed-over hypothesis below.

### P3c3f-7. Key material detection

Three shapes of the live `keys/writer-decision.key` shipped in the real decision-service image at `18 passed` and came back byte-identical.

**These are not three of the same thing, and the item does not treat them as one fix.**

- **base64-of-a-PEM is a detector gap and a real bug.** `key_material()` looks for PEM armour only in the raw head; a base64 body is decoded and offered to the binary rule alone, so base64 of a PEM decodes to PEM text, fails the DER prefix test, and is not key material to it. That is the shape a Kubernetes Secret, a Helm value, a JSON config and a `.env` line all use. Close it.
- **gzip and past-16-KiB are bound decisions with a measured cost**, not detector gaps. Catching gzip means decompressing candidate files. Abandoning the 16 KiB head bound means reading whole files across four images totalling about 1.2 GB, where one check pass already measures 3.5 minutes.
- **`_B64RUN.findall(head)[:20]`** decodes only the first twenty base64 runs: a DER key behind 21 decoy runs is not detected, behind 19 it is. The module states the 16 KiB bound and the offset-zero anchor and not this one.

**Demonstrate:** base64-of-a-PEM caught. For each of the other three bounds, either the shape caught, or the bound stated in the module docstring as a limit **with its measured cost recorded as the reason it was kept**. A bound kept without its cost measured is not a decision, and that is what makes this an escape rather than a pass.

**Escalate** if closing gzip or the head bound turns out to cost more than the measurement suggests; buying those bounds is a scope call and it is mine.

**Mutation:** restore the head-only PEM check. Named test must fail.

### P3c3f-8. A `call_id` that cannot be encoded

A lone-surrogate `call_id` fits both length checks and cannot be encoded at the write, so no fault record is written.

**The defect is not loudness, and the item does not accept loudness as its criterion.** It already fails loudly on unmodified head: `fault_record_error` carries the `UnicodeEncodeError` and `_fault_failure_detail`'s sentence is in `detail`. So "or failing loudly" would be closed by running the existing code. The defect is that `_fault_identity` judges the `call_id` on length alone, so an unencodable identity is never judged unusable, the digest fallback never fires, and no fault record is written where one could have been. P3c3e-6's own argument is that refusing to write the fault is the defect the fault exists to prevent.

**Demonstrate:** the surrogate `call_id` refused **as an identity**, the digest fallback used, and the fault record written, which is exactly what the over-long `call_id` case already does.

**Mutation:** remove the encodability check. Named test must fail.

### P3c3f-9. Compose mount spellings

The compose parse sees neither a long-form `type: bind` of `/var/lib/immudb` nor `external: True`.

**Demonstrate:** both spellings caught.

**Mutation, one per defect, not one for both.** Restore the short-form-only mount parse: the bind-mount test must fail. Restore the case-sensitive `external:\s*true` regex: the external-volume test must fail.

### P3c3f-10. Ledger-wide invariants over both views and over non-empty ledgers

Two separate defects in `tests/test_view_invariants.py`.

`_view_rows` walks one of two views, so all four invariants are unenforced on the intent view.

`test_the_seam_between_history_and_allocation_holds` is the only one of the four that does not call `_seed_one_decision()`. It calls `pytest.skip` when either side of the seam is empty, which is `1 skipped` on every clean-ledger run. Whether it asserts anything depends on whether `test_backfill_index.py` or `test_reconciliation.py` ran first, and a skip is never in a failing set, so the order sweep's method cannot see it. That is D44's own stated shape, a check over zero rows asserting nothing, left in the test that guards against it.

**Demonstrate:** all four invariants over both views. The seam test seeding rather than skipping, and failing when the invariant is violated.

**Mutation:** restore the skip. Named test must fail. Second mutation: restore the single-view walk. An invariant violated in the intent view must fail.

### P3c3f-11. The tier and anchor claims

Correct at their sources, not only in the README.

ADR-0011 validates the tier split with "the read key does not open `/write` and the write key does not open `/verify`". That is route separation. Nothing in it says the read tier is side-effect-free, and the natural reading of "read-scoped" is the false one.

README §3.4 says the anchor sits on a volume separate from the ledger-writing identity so the process that records entries cannot rewrite the anchor. Literally true, and it invites the inference that reaching the verifier does not move the anchor.

D23's motivation is untouched; it rests on the local anchor being inside the operator's control, which holds either way. Say so, so the correction is not read as wider than it is.

---

## Handed over as a hypothesis, not scheduled

`docs/reports/phase-3c3e.md` §16 item 2 records an anchor advancing "for a reason nobody has named", behind an intermittent failure of `test_a_write_that_committed_is_reported_as_committed_when_the_state_call_fails`.

There is now a named path: `control_plane/main.py::_has_tombstone` calls `POST /verify` on every `POST /content`, and `POST /verify` advances the persisted anchor. The red team did not investigate this and should not have; it is a mechanism with a path, not a diagnosis.

**Test it to the standard the keep-alive race was tested to: move something and watch the window move.** That is what made the uvicorn `--timeout-keep-alive` finding causal rather than plausible. P3c3f-6 changes this path, so measure before the change as well as after, or the two will not be separable.

---

## Not in scope

`_set_without_verification` has no key guard, and a well-formed fault record writes under `ail_seq:commit`. The only assertion that looks at the key iterates `sorted(write_routes(verifier))`, so fixing the selector fixes the site list. That is the whole of what is reachable without reopening the retired caller count. Do not add an item for it.

## Residual limits to state, not to schedule

- The unverified-write path's caller count is not enforced. The runtime guard bounds what it writes; nothing bounds how many callers reach it.
- `/write-ordered` accepts a key of any shape into a view.
- 35 test modules were never isolated; isolation was per module, not per test.

## Pre-registered negatives

All false at the end, each confirmed individually and derived per row.

- Any enumeration whose property is stated only as what its selector selects.
- Any enumeration whose selector lacks a falsifier in either direction, or whose uninstantiated direction is omitted rather than recorded.
- Any assertion inside a retry predicate, established behaviourally rather than by a parse.
- Any anchor written or seeded from a state nothing verified.
- Any bounded read whose bound is asserted but never driven.
- Any position returned that was not read from what came back.
- Any ledger-wide invariant enforced over one view, or over zero rows.
- Any detector bound kept without its cost measured and recorded.
- Any Claim cell describing a goal rather than a behaviour.
- Any assertion weakened, or any refutation closed by narrowing the claim without saying so.

## Report

`docs/reports/phase-3c3f.md`, committed and pushed before this session closes. Verdict per item, the reproduction before the fix, both falsifier outputs for each selector, demonstration, enforcing test, mutation result, mapping, could-not-verify, CI run id. Verdict by the red team's own B1 to B10 labels alongside the item verdicts, and say explicitly which claims were not refuted.
