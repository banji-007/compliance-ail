# R6: a false tamper claim on the audit read path

**Run id:** `r6-headstate`. Branch `r6-headstate`, based on `p3c3b-order` at
`f5385b6`. Scratch clone `C:\Users\banji\ail-r6-headstate`, Compose project
`r6headstate`. Not the primary working directory.

Out of band, landing on its own before Phase 3c-3g. Closes finding R6 of
`docs/reports/phase-3c3f-redteam.md`, which is a regression introduced in
Phase 3c-3f rather than a gap in a design decision.

**A note on the base.** The session was opened at `a14d559` and rebased onto
`f5385b6` before any work: `a14d559` is a direct ancestor, nothing had to be
replayed, and `git diff origin/p3c3b-order..r6-headstate` was empty after it.
Recorded because the base was named from before the cleanup commit landed, and
a base divergence is how an earlier phase collected a rejected push.

## What was wrong

`POST /verify` decided `verified` inside a `try` that also contained
everything which reports the verdict. Six things ran in that block **after**
`sdk_verified_get.call` had already returned a verified entry:

    head_state(client)                    # the unanchored path's state_id
    client._rs.get()                      # the anchored path's state_id
    base64.b64encode(resp.value)          # and three more encodes
    ventry.SerializeToString()
    signing_key_fingerprint()             # reads and parses the public key

None of them has any bearing on whether the proof ran, and all of them shared
that block's handlers. A `BadSignatureError` out of any one was reported as
`error_class="signature_failure"`, which `control_plane/main.py` renders as
`state: "failed"` - a positive tamper claim, on every record of a sound page,
on the read path an auditor uses. A system asserting tampering it has not
detected is worse than one failing to detect tampering.

## The fix is the property, not the line

The red team named the head read. Moving the head read alone would have closed
R6 at one site and left it open at five, and would have reproduced D40's own
failure mode - an enforcing test written pointing at the site that was already
correct - inside the fix for a finding about D40.

So the proof's `try` now ends where the verdict is decided, and everything
that reports the verdict runs after it, in a region whose single handler has
one possible verdict:

    state_id, state_read = _state_read(client, payload.anchor)
    try:
        return _verified_response(source_state, ventry, resp, state_id, state_read)
    except Exception as exc:
        return VerifyResponse(verified=True, ...)

**The guarantee is structural, not a list of six.** The region cannot reach a
handler that answers `verified=False`, because no such handler is in scope. A
seventh thing added to it inherits the guarantee rather than needing its own
guard.

This is D40's argument applied to the read path. D40 moved the state read out
of `POST /write`'s proof `try` in Phase 3c-3d for exactly this reason, and left
this route alone.

**Ordering.** The head read left the `try` before the `_vk is None` asymmetry
was resolved, in that order, as the instruction requires. Resolved first, every
`/verify` on a stack with no `IMMUDB_SIGNING_PUBKEY` would have become a
failure, which is R6 with a different trigger.

## Reporting: `state_id` keeps its meaning

`state_id` is not redefined. The unanchored path reports the head; the anchored
path reports the persisted anchor. The state the proof ran against is already
on the response twice, as `proof_material.source_state.tx_id` and
`prove_since_tx`, and a third copy would have broken two falsifiers that use
`state_id` as their observable (`tests/test_trust_anchor.py:204`, D47's own
falsifier, and `tests/test_anchored_export.py:453`).

What is new is the sibling field `state_read`, carrying the outcome of the read
that produced `state_id`:

| field | meaning |
| --- | --- |
| `source` | `"head"` (unanchored) or `"anchor"` (anchored) |
| `status` | `"ok"`, `"unchecked"`, or `"unavailable"` |
| `detail` | why, when the status is not `"ok"` |

On a failed read, `state_id` is null and `state_read.detail` says why, so the
null is never bare. The vocabulary deliberately does not contain the word
`"failed"`: `/audit` renders D2's four verification states and one of them is
`"failed"`, a positive tamper claim about a record. A state read that could not
run is not a claim about the record at all, and giving the two the same word is
how they get conflated. A failed state read does not enter D2's four states.

`source` is a third field beyond the instruction's "result and detail". It is
there because the two paths read different things, and without it a reader
cannot tell whether a status refers to a head or to an anchor.

### The `/audit` contract change, stated

`control_plane/main.py::_verification_from_200` carries `state_read` through in
**all four branches**, so every `/audit` row now carries a fifth key. It is
`null` for rows the verifier answered without reading a state (every failure
path returns before the read is attempted) and for a verifier too old to send
it. Carried rather than dropped because `state_id` can now be null on an
otherwise sound row; without it an operator would see that null with the
explanation stranded at the verifier.

`state_read` is not a verification state and must never be read as one.

**The shape is uniform across all five constructors.** `/audit` builds this
object in five places: the four branches of `_verification_from_200`, the two
literals in `_verify_one_key` (verifier unreachable, verifier answering
non-200), and `_deferred_verification`. All of them carry `state_read`, null
where no state was read. A row where the key is absent rather than null would
be a second row shape that a reader has to know about.

The first push got this wrong and CI caught it. Only
`_verification_from_200` had been updated, and
`tests/test_deferred_verification.py:211` asserts the key set of a verified
row **exactly** - which is the assertion doing its job, on a live stack this
host cannot run. Its expected set now names `state_read` and is still an exact
set equality, not a relaxed one. The property it caught is now enforced in
process as well, over all five constructors, so the next field added to this
object is caught before CI rather than by it.

### `dashboard/`, stated

`dashboard/` deliberately does **not** render `state_read` in this phase. It
does not render `ledger_fault` either, and growing the dashboard is not this
item's job. Stated rather than implied, so a later reader does not read the
omission as an oversight.

## The unconfigured-key rule is one rule

`head_state` and `_VerifiedRootService._checked` are the two places a state
reaches this service from `CurrentState`. They cannot behave identically: one
reports and one gates a persist, and they have different return contracts. The
rule they share is a behaviour.

**With no verifying key configured, neither presents an unchecked state as a
checked one.** `_checked` refuses the persist, because a state nothing verified
must not become the thing every later proof is measured against. `head_state`
has nothing to refuse - it reports - so it reports the head and reports that
the head was not checked. One rule, two correct expressions.

`head_state` now returns `HeadRead(state, checked)`. The fact is returned
rather than left to be re-derived from `client._vk` at each call site: a caller
that forgets to ask is the asymmetry coming back at a third site. Three call
sites updated (`POST /write`, `GET /state`, `POST /verify`), plus the in-image
script at `tests/test_trust_anchor.py:364`.

## Evidence

### Before: R6 reproduced at all five post-proof sites

`tests/test_post_proof_reporting.py` run verbatim against unmodified
`f5385b6`, source parked with `git stash`:

    10 failed, 1 passed

    FAILED test_a_failure_after_the_proof_does_not_change_the_verification_state[anchored_rs_get]
    FAILED test_a_failure_after_the_proof_does_not_change_the_verification_state[head_state]
    FAILED test_a_failure_after_the_proof_does_not_change_the_verification_state[signing_key_fingerprint]
    FAILED test_a_failure_after_the_proof_does_not_change_the_verification_state[value_b64encode]
    FAILED test_a_failure_after_the_proof_does_not_change_the_verification_state[ventry_serialize]
    FAILED test_a_failed_head_read_is_reported_rather_than_swallowed
    FAILED test_the_sibling_field_is_carried_by_every_audit_branch
    FAILED test_a_failed_head_read_is_not_a_verification_state
    FAILED test_with_no_verifying_key_neither_function_presents_unchecked_as_checked
    FAILED test_an_unchecked_head_is_reported_as_unchecked_on_the_response

The one that passed is `test_the_control_verifies`, which is the control: it
passes before and after, so the assertions above are not holding against a
driver that cannot produce a verified response at all.

The head-read case, in full:

    AssertionError: a failure at the post-proof site 'head_state' turned a
    record whose proof succeeded into verified=False
    error_class='signature_failure'. The proof ran and returned a verified
    entry; nothing that runs after it may say otherwise. Response:
    {'verified': False, 'tx_id': None, 'value': None, 'timestamp': None,
     'state_id': None, 'detail': 'state signature verification failed',
     'error_class': 'signature_failure', 'proof_material': None}

The `/audit` half is by composition, exactly as the red team established it:
the verifier route driven in process, its body fed to
`_verification_from_200`. Before the fix, all five sites rendered as
`state: "failed"`.

### After

    12 passed

### Mutations, one at a time

| Item | Mutation | Result |
| --- | --- | --- |
| R6-1 | move the head read back inside the `try` | 3 failed, 8 passed: `[head_state]`, `[anchored_rs_get]`, `test_a_failed_head_read_is_reported_rather_than_swallowed` |
| R6-1 | make `signing_key_fingerprint` raise inside the `try` | 1 failed, 10 passed: `[signing_key_fingerprint]` |
| R6-2 | drop the sibling field | 2 failed, 9 passed: `test_a_failed_head_read_is_reported_rather_than_swallowed`, `test_an_unchecked_head_is_reported_as_unchecked_on_the_response` |
| R6-3 | restore the asymmetry, so `head_state` reports an unchecked state as checked | 2 failed, 9 passed: `test_with_no_verifying_key_neither_function_presents_unchecked_as_checked`, `test_an_unchecked_head_is_reported_as_unchecked_on_the_response` |
| R6-2 | drop `state_read` from one of the five constructors (the deferred one) | 1 failed, 11 passed: `test_every_constructor_of_a_verification_object_agrees_on_its_shape` |

Each reverted before the next; `12 passed` after every revert.

The two R6-1 mutations are the point of the pair. The first is the line the red
team named. The second is a different site entirely, and the same test file
catches it - which is what shows the test drives the property rather than the
line.

### The rest of the suite

Full suite run twice on this host, once with the fix and once with the source
stashed back to `f5385b6`, both with `-p no:randomly`:

    before: 24 failed        after: 24 failed
    only in AFTER  (regressions): none
    only in BEFORE (fixed):       none

Identical sets. The 24 are this host's standing failures and are not a
regression signal (see the local-environment notes: sigstore cannot be
installed into the host Python, the tests that need a live stack cannot
resolve Compose service names, and this scratch clone has no `keys/`). CI is
the signal; run id below.

One of the 24 is
`tests/test_route_parity.py::test_no_write_route_reaches_the_unverified_path_with_anything_but_a_fault_record`,
confirmed failing on unmodified `f5385b6` before any change here. It is
pre-existing and is not touched by this work.

## Residual limits

1. **`POST_PROOF_SITES` is a hand-list.** Nothing derives it, and a seventh
   site added to the post-proof region later is outside the test until someone
   adds it there. The *fix* does not share the limit - the region has no
   handler in scope that can answer `verified=False`, so a new site inherits
   the guarantee - but the test's coverage of it does. Accepted rather than
   hidden: this is a regression fix landing out of band, not a mechanism
   phase, and building a derivation for it would be the substitution this
   project's rules exist to prevent. Consistent with Phase 3c-3g's own
   hand-list under D48's bounded coverage.

2. **The demonstration is in process, not on a live stack.** Pre-authorised by
   the instruction and not a substitution: making only the head read fail while
   `VerifiableGet` still answers is not reachable with the existing fixtures.
   Corrupting `IMMUDB_SIGNING_PUBKEY` fails `sdk_verified_get.call` first, so
   the page is not sound; the cut proxy arms on a byte marker in the request
   while `CurrentState` takes an `Empty` carrying no marker. Aiming the relay
   per RPC means matching the `:path` pseudo-header, which is new fixture
   mechanism and is B2's standing untested territory. Not attempted here.

3. **An assembly failure's detail does not reach `/audit`.** If one of the four
   encodes, the serialisation or the fingerprint fails, the response is
   `verified: true` with the reason in `detail` - and
   `_verification_from_200`'s verified branch hardcodes `"detail": None`, so
   the reason stops at the verifier. The record is correctly reported as
   verified, and the bundle path already refuses loudly when `proof_material`
   is missing from a verified record (503, "predates D18"). Widening the
   verified branch to carry `detail` is an `/audit` contract change beyond what
   this item authorises, so it is recorded rather than taken.

4. **`head_state`'s `checked` is reported, not enforced, on the read path.** An
   unchecked head still populates `state_id`, marked `"unchecked"`. That is the
   instruction's decision - `_checked` gates, `head_state` reports - and is
   noted so the asymmetry is not rediscovered as a defect.
