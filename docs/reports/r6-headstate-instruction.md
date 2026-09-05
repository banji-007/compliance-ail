# Out of band: R6, a false tamper claim on the audit read path

**Run id:** `r6-headstate`. State run id, working directory, branch first. Not the primary working directory. Explicit Compose project name on every invocation. Remove your scratch directory before reporting and say what you removed or could not remove.

**Base:** `p3c3b-order` at its current head. This lands on its own, before Phase 3c-3g. It is not queued behind a design decision.

**Session closure:** this session is not closed until its report is committed and pushed.

## Why this is out of band

`head_state` runs after the record proof succeeds, inside the `try` that decides `verified`. Any failure of it turns `verified=True` into `signature_failure`, which `/audit` renders as `state: "failed"`. That is a positive tamper claim, on every record of a sound page, on the read path an auditor uses.

The system asserting tampering it has not detected is worse than the system failing to detect tampering. It was introduced in Phase 3c-3f and it is a regression, not a gap in a decision. Full detail in `docs/reports/phase-3c3f-redteam.md`, finding R6.

## The fix

The head read has no bearing on whether the record's proof succeeded, so it does not belong inside the `try` that decides `verified`.

### The fix is the property, not the line (corrected)

An earlier draft of this instruction said "move `head_state` out of the `try`". That closes R6 at one site and leaves it open at five.

`head_state` is not the only thing inside that `try` that runs after `sdk_verified_get.call` has returned a verified entry. Also reachable only once `resp.verified` is in hand:

    client._rs.get()                      # the anchored path's state_id
    base64.b64encode(resp.value)          # and three more encodes
    ventry.SerializeToString()
    signing_key_fingerprint()             # reads and parses the configured public key

Any of these raising produces exactly R6, and a `BadSignatureError` out of `signing_key_fingerprint` renders as `state: "failed"` again.

**So the item is the property: no code that runs after a successful proof can turn `verified=True` into a failure response.** The enforcing test drives the property, at every post-proof site, not the one line the red team happened to name.

This correction matters beyond its own scope. `tests/test_route_parity.py`'s docstring records D40 landing on `POST /write` while `POST /write-ordered` answered from a generic handler, "because the enforcing test was written pointing at the route that was already correct." Fixing R6 by moving one line would reproduce D40's failure mode inside the fix for a finding about D40's failure mode.

**Stated limit.** The five post-proof sites above are a hand-list. Nothing derives them, and a sixth added later is outside this test until someone adds it. That is accepted here rather than hidden: this is a regression fix landing out of band, not a mechanism phase, and building a derivation for it would be the substitution this project's rules exist to prevent. Record it in the report's residual limits so that it and Phase 3c-3g's own hand-list (D48's bounded coverage) are consistent in what they admit.

### Reporting, decided (corrected)

`state_id` keeps its current meaning: the head. It is not redefined.

An earlier draft of this instruction redefined `state_id` to hold the state the proof ran against, on the false premise that it already did. It never held that on either path: unanchored reports the head, anchored reports the persisted anchor, and the proof state is already on the response twice, in `proof_material.source_state.tx_id` and `prove_since_tx`. Redefining it would add a third copy of a reported number and break two falsifiers that use `state_id` as their observable: `tests/test_trust_anchor.py:204`, which is D47's own falsifier (`state_id > before` becomes false and the natural repair relaxes the assertion, passing for the wrong reason), and `tests/test_anchored_export.py:453`, whose cross-path comparison dissolves rather than failing cleanly.

The head read's outcome goes in a **new sibling field** carrying its result and detail. On a failed head read, `state_id` is null and the sibling states why, so the null is never bare.

A failed head read is **not** a tamper claim and must not enter D2's four verification states. Unchanged, and the half that matters.

If `state_id` should be retired as a duplicate of `prove_since_tx`, that is its own deliberate item in a later phase, not a side effect of this one.

`/audit` carries the sibling field through. It passes `state_id` through in all four branches today; without the sibling, an operator sees verified rows with a null `state_id` and the explanation stranded at the verifier. This is an `/audit` contract change; say so.

**`dashboard/` explicitly does not render the sibling field in this phase.** It does not render `ledger_fault` either, and growing the dashboard is not this item's job. Stated rather than implied, so a later reader does not read the omission as an oversight.

### The `_vk is None` asymmetry

`head_state` and `_VerifiedRootService._checked` disagree on what to do when no verifying key is configured.

**The shared rule, stated as a behaviour rather than as a goal (corrected).** An earlier draft said the two must "behave identically". They cannot: one reports and one gates a persist, and they have different return contracts, so "identically" is a goal cell rather than a behaviour cell and this instruction's own pre-registered negatives forbid it.

The rule is: **with no verifying key configured, neither function presents an unchecked state as a checked one.** `_checked` refuses the persist. `head_state` reports the head as unchecked, in the sibling field. One rule, two correct expressions. State it in the code and the report in those terms.

**Ordering inside this change is not free.** The asymmetry can only resolve to fail-closed **after** the head read leaves the `try` that decides `verified`. Resolved first, every `/verify` on a stack with no `IMMUDB_SIGNING_PUBKEY` becomes a failure, which is R6 with a different trigger. Same commit is fine; the order of the two edits is not.

## Items

### R6-1. A sound proof is never reported as failed, at any post-proof site

**Demonstrate:** the red team's case reproduced on unmodified head, then the same case with the fix in place. Repeat for each of the five post-proof sites, not only the head read.

**The demonstration is in process, and that is pre-authorised rather than a substitution.** Making only the head read fail on a live stack while `VerifiableGet` still answers is not reachable with the existing fixture: corrupting `IMMUDB_SIGNING_PUBKEY` fails `sdk_verified_get.call` first, so the page is not sound, and the cut proxy arms on a byte marker in the request while `CurrentState` takes an `Empty` request carrying no marker. Aiming the relay per RPC means matching the `:path` pseudo-header, which is new fixture mechanism; per-method aiming is B2's standing untested territory and belongs to a red-team pass, not a fix session. **It is not required for this item and must not be built inside it.** A session that wants the live form may attempt it as optional work that never blocks the item.

The `/audit` half is demonstrated by composition: the verifier route driven in process, and the body it returns fed to `control_plane/main.py::_verification_from_200`. That is how the red team established the rendering and it is sufficient here. Standing up a live `/audit` page for it is not required.

**Enforce:** a test asserting that a failure injected at any post-proof site leaves every record's verification state unchanged.

**Mutation:** move the head read back inside the `try`. Named test must fail. Then, separately, make `signing_key_fingerprint` raise inside the `try`. The same test must fail, which is what shows the test drives the property rather than the line.

### R6-2. A failed head read is reported, not swallowed

The opposite failure is equally wrong. Taking the head read out of the `try` must not make its failure invisible.

**Demonstrate:** a failing head read surfaced in its own field on a page whose records verify.

**Enforce:** a test for it.

**Mutation:** drop the field. Named test must fail.

### R6-3. The unconfigured-key rule is one rule

**Demonstrate:** with no verifying key configured, `_checked` refusing the persist and `head_state` reporting the head as unchecked. Neither presenting an unchecked state as a checked one.

**Enforce:** a test asserting that rule across both functions, in those terms.

**Mutation:** restore the asymmetry, so `head_state` reports an unchecked state as checked. Named test must fail.

## Pre-registered negatives

- **Any post-proof failure that changes a record's verification state.** Widened from the head read to the class, per the corrected fix above.
- Any failing head read that leaves no trace on the response.
- Any tamper claim on a page where nothing was detected as tampered.
- Any change to what `state_id` means on either path.
- Any Claim cell describing a goal rather than a behaviour.

## Report

**A note on how this file names the report it commissions.** The report filename below is written without its `docs/reports/` path prefix, deliberately. `tests/test_docs_references_resolve.py` requires every literal `docs/` path in a committed file to resolve in that same commit, and this instruction is committed before the report it asks for exists. That test is right and is not being weakened: its subject is a pointer to a file that was present locally and never committed, which is a real defect it has caught three times. A forward reference to a document this instruction commissions is a different thing, and the sibling test's own docstring already recognises the category ("an instruction about a report not yet written"). Naming the file without a resolvable path keeps both true. Do not helpfully restore the prefix; it turns CI red on a docs-only commit.

`r6-headstate.md`, under `docs/reports/`, committed and pushed before this session closes. The reproduction before the fix, demonstration, enforcing test, mutation result, the `/audit` contract change stated explicitly, the `dashboard/` decision stated explicitly, the five-site hand-list recorded as a residual limit, CI run id.
