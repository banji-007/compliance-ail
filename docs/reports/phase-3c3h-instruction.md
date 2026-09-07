# Phase 3c-3h: Scope to what is demonstrated

**Run id:** `p3c3h-scope`. State run id, working directory, branch first. Not the primary working directory. Explicit Compose project name on every invocation. Remove your scratch directory before reporting and say what you removed or could not remove.

**Base:** `p3c3b-order` at its current head, continuing PR #14. No rebase, no second PR. **This is the last sub-phase of 3c. PR #14 merges when it closes green.**

**Before your baseline run:** a fresh clone has no keys, and `tests/test_route_parity.py` reads `1 failed` without them, on the fault-record write path. Generate the writer keys with the openssl commands `make keygen` runs, since `make` is not on PATH. Both P3c3h-3 and P3c3h-6 work in that file and in `verifier/main.py`, so without the keys you will meet a failure in the first ten minutes that reads exactly like a regression in the thing you are changing, and it is not one.

**Session closure:** this session is not closed until its report is committed and pushed.

## Why this phase exists, and why it is last

The 3c-3g red-team pass (`docs/reports/phase-3c3g-redteam.md`) found eleven findings: one recursive gap (F1), seven applications (F2 through F8), three carried. The merge criterion pre-committed the response to a recursive gap: no further generalisation; claims are scoped to what the tests demonstrate; the limits go to Residual Limits; the project shares a smaller claim.

This phase is that response. It builds no new enumeration machinery. It narrows claims, fixes the ordinary defects the pass demonstrated, and records the limits honestly. There is no red-team pass after it, and the argument is stated precisely because it has one exception: for P3c3h-1, -2 and -7 the narrowed claims assert less than what the last pass already tested; P3c3h-5 and -6 are test-side only; P3c3h-8 records carried findings and changes no code. **P3c3h-4 is the exception**: it changes `POST /write-ordered`'s behaviour on the central write path after the last adversarial pass. It is validated by its own drivers, its mutations and CI, and by nothing adversarial; that sentence goes in Residual Limits beside the fix, and the closing paragraph must not claim otherwise. P3c3h-3 also touches production code but is not an exception, for a reason stated rather than assumed: the `Literal` is behaviour-preserving on every input reachable at this head, since all five constructions use the three constants and nothing else can reach them; what it changes is the failure mode of a future programming error, recorded in the item as a consequence. The loop terminates here by design.

Challenge any item that does not serve that objective. But the bar for adding mechanism in this phase is: none, unless a demonstrated defect cannot be fixed without it, in which case escalate.

## Standing rules

Escalate rather than substitute. Never widen or weaken an assertion (narrowing a *claim* to match its test is the subject of this phase and is stated per site; weakening a *test* is still forbidden). No em dashes. Fixes get a demonstrate half, an enforce half, and a named mutation. Claim edits get the old text, the new text, and the reason, per site, in the report.

---

## Items

### P3c3h-1. Scope the route-parity claim (F1)

The claim becomes what the tests demonstrate: route parity covers routes registered directly on the verifier application and selected by the enumerated clauses. Discrimination via `app.mount`, composite `Depends` gates deeper than one level, and path-keyed collapsing is outside it. D48's clause coverage is the hand-listed `if`-conjuncts of two selectors; the other three discrimination places F1 measured are named as uncovered.

Residual Limits carries all of it, with F1's mutation table cited as the measurement. No production route today arrives by any of the three uncovered paths **on the verifier application**, which is the only application `test_route_parity.py`'s selector reads; the control plane and decision service are not covered by it at all. Say exactly that, with the enumeration, because it is why the scoped claim is still worth having and no more than it checked.

**Enforce:** nothing new. The existing falsifiers stay. The claim text in `readME.md`, the ADRs and the test docstrings is corrected wherever it asserts more than this.

### P3c3h-2. The exemption marker: scope the claim, build nothing (T2)

The fix an earlier draft of this item specified is a no-op: `explains()` already requires the marker AND a `registered_for` entry matching the invariant and the view (`tests/ledger_pollution.py`), and the T2 attack satisfied all three conjuncts by copying `p3c3d-dup`, whose entry already names both broken invariants and the view. Matching costs the attacker nothing. Building it again would match the English of the fix and not stop the attack, which is the P11-7 pattern.

Closing it for real requires binding the exemption to something the caller does not supply (test-written keys or a writer signature), which is new mechanism and forbidden this phase. The governing response decides it: **scope the claim.** The measured claim is 3c-3g's own: an ordinary record cannot drift into an exemption by resembling one. A caller who deliberately writes `ail_deliberate_violation` with a matching invariant and view is outside the registry's scope. State exactly that in Residual Limits beside the existing forgeability entry, with T2's demonstration cited, and correct any claim text asserting more.

**Demonstrate/enforce/mutation:** none; this item is a claim edit and its report row says so.

### P3c3h-3. `state_read` vocabulary, constrained at the type (T3)

Three constructions on the anchored path asserted nowhere, one able to report `status: "failed"`, the word the design forbids. What exists on the head branch is weaker than a vocabulary constraint: one driven case pinning `STATE_READ_UNAVAILABLE`, plus a check that "failed" is not among three module constants.

The fix is the type: `Literal["ok","unchecked","unavailable"]` on `StateRead.status` and `Literal["head","anchor"]` on `source`. One line, closes all five construction sites and the type at once.

This closes the **verifier end only**: `_verification_from_200` still passes `state_read` through as an untyped dict and `/audit` has no `response_model`, so F5's `/audit` half stays open and goes to P3c3h-8 as carried.

**Demonstrate:** the red team's anchored case, refused at construction.

**Enforce:** the `Literal` types, plus a driven test that **pins the expected member, not the set**: anchored path with `_rs.get()` working and a verifying key configured, asserting `source == "anchor"` and `status == "ok"`. Vocabulary membership alone cannot catch the mutation, because all five constructions sit inside `_state_read`'s `try` and a `ValidationError` from the mutated site is caught by `except Exception` and rendered as a well-formed `unavailable`: the forbidden word never reaches the wire, which is the property working, and a set-membership test reads green.

**Mutation:** `status="failed"` at the anchored OK construction. The pinned-member test must fail on the value moving to `unavailable`. Must target one of the **three anchored constructions**, not the head branch, for the reason stated in R6's history.

**Record as a consequence:** the `Literal` turns a future programming error on this path into a silent `unavailable` carrying a `ValidationError` string in the operator-facing detail. Defensible on the post-proof path, where nothing may change the verdict; recorded rather than discovered.

### P3c3h-4. The committed-false branch (the diagnosis finding)

The branch is real: a record in the ledger answered with `committed: false` and `StatusCode.UNAVAILABLE`. It refutes P3c3e-2. Classified carried, fixed anyway, because it is the write path's central guarantee.

**Fix the property, not the read.** The window has two independent halves: `_record_key_present` swallowing, and `_read_bound_reserve` unguarded on the next attempt. Fixing the named read leaves the second half open for any other reason the channel dies between attempts. The property is one flag: once an `ExecAll` has been issued in this call, `committed: false` is unreachable from `_ordered_commit`'s callers. That is the structure R6 used on the read path, and it is not growth.

**The answer is pinned as: not `committed: false`.** On the driven branch the record-key read is exactly what cannot run, so the service has no evidence for a 409's "already committed" claim; asserting it would be the same lie pointed the other way, plus a permanent refusal. The honest answers are D45's existing states, both reachable through the flag alone: `committed: true` when `_committed_tx_for_value` finds the record, `committed: null` when it cannot. The 409 stays the answer on the branch where the read works, which is unbroken today (the red team's control exercised it). **One change: the flag. No second change**; an earlier draft added `_record_key_present` propagation, which under the flag reaches the same uncertain path and changes nothing.

**Demonstrate:** the red team's driven case answering `true` or `null` (never `false`) after the fix, the second half's case (channel dies between attempts for a different reason) likewise, and the control still answering 409.

**Enforce:** a test on each driven half, plus one pinning the control's 409.

**Mutation:** remove the flag. Named test must fail. Second mutation: set `issued` after `stub.ExecAll` returns instead of before it; on a precondition refusal the call raises, `issued` is never set, and the branch falls back to `committed: false`. Its named test must fail.

If the property fix is more than the flag described, stop and escalate rather than growing it.

### P3c3h-5. Detector and list corrections (T6)

- C8: `base64(gzip(key))` and the two other undetected shapes, each one step from a detected one. Extend detection one step or state the bound with the measured gap, per the R6 hand-list convention. Given the pre-commitment, prefer the stated bound unless the extension is trivial.
- C7: the one declared bound undriven gets driven, with the control's cross-coverage noted.
- The stateful-path list: exact-match means `/var/lib/immudb/data` passes where `/var/lib/immudb` fails. Prefix-match **with a segment boundary**: `target == root or target.startswith(root + "/")`. A bare `startswith` matches `/database-config` for root `/data`, turning the fix into a false positive. Test both the sub-path case and the boundary case.

**Mutations:** one per fix, named.

### P3c3h-6. A stale property cell fails (F2)

The worst of the four replacement mutations: `write_routes` gaining `and route.path != "/write"` removes `POST /write` from the site list, three of its four property cells vanish from collection (16 to 13), and the run reads green. A vanished cell is indistinguishable from a passed one.

The fix is not new machinery; it is the assertion the same file already applies to `UNGATED_BY_DESIGN` at `tests/test_route_parity.py:693`, which `PROPERTIES` lacks: a recorded cell naming a route no longer in the site list is stale and fails. **Diff the site list against the union of both cell dicts**, `holds_on` and `does_not_apply_to`, since `state()` reads both; written against `holds_on` alone, a departed route recorded as does-not-apply stays invisible, the same silence one level in. Three lines, symmetric with existing code.

**Demonstrate:** the F2 mutation, now failing.

**Enforce:** the staleness assertion on `PROPERTIES`.

**Mutation:** the F2 edit itself. The staleness assertion must fail.

### P3c3h-7. The claims sweep

Every claim touched by this phase's narrowings, corrected at source: `readME.md`, the ADRs that state parity or enumeration coverage, and test docstrings that name a stronger property than their body asserts, including `_service_routes`'s own docstring, which asserts "Every route this service registers, under any verb" and is false at the head; it is the source a README-level claim would cite. The citing-document-and-cited-source rule applies: fix the source the README cites, not only the README.

The report lists every site changed, old text and new.

### P3c3h-8. Carried findings, recorded as carried

R7 (the override file), the `test_record_profile.py` order interaction, F5's `/audit` half (`_verification_from_200` passing `state_read` through untyped, `/audit` without a `response_model`), F8 (the five-constructor shape test is itself a hand-list), and anything else from the pass classified carried and not fixed above: each gets a `TODO.md` entry with its reproduction pointer if it lacks one. Carried means recorded, not lost.

---

## Pre-registered negatives

- Any claim, anywhere, asserting coverage the tests do not demonstrate.
- Any test weakened.
- Any new enumeration machinery.
- Any `state_read` construction that can emit a word outside the vocabulary.
- Any response reporting `committed: false` **for the record this write carried**, on the driven branches. (`_committed_tx_for_value` answering ABSENT for a key holding different bytes is honest and stays.)
- Any property cell that can vanish from collection and read as green.

## Report

**A note on how this file names the report it commissions.** The report filename below is written without its `docs/reports/` path prefix, deliberately. `tests/test_docs_references_resolve.py` requires every literal `docs/` path in a committed file to resolve in that same commit, and this instruction is committed before the report it asks for exists. That test is right and is not being weakened: its subject is a pointer to a file that was present locally and never committed, a real defect it has caught three times. A forward reference to a document this instruction commissions is a different thing. Naming the file without a resolvable path keeps both true. Do not helpfully restore the prefix; it turns CI red on a docs-only commit.

`phase-3c3h.md`, under `docs/reports/`, committed and pushed before this session closes. Per item: verdict, demonstration, enforcing test, mutation result. Per claim edit: site, old text, new text, reason. Mapping check clean. CI run id.

Close with one paragraph stating what the system now claims, in full, at the end of phase 3c. That paragraph is what Phase 3d packages and what gets shared.
