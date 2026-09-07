# Phase 3c-3h: Scope to what is demonstrated

**Run id:** `p3c3h-scope`.
**Working directory:** a fresh clone at
`AppData\Local\Temp\ail-p3c3h-scope`, never the primary working directory.
Compose project `p3c3hscope`, named explicitly on every invocation that needed
one.
**Branch:** `p3c3b-order`, continuing PR #14. No rebase, no second PR.
**Base:** `4d402a8`, the head of `p3c3b-order` when this session opened. The
instruction names `9eca2cb`; `4d402a8` is one commit later and is the dated
residue note the 3c-3g red team appended to its own report after the
instruction was written. Nothing in it touches code, and this session worked
at the branch head rather than behind it.
**Keys** generated in the clone with the openssl commands `make keygen` runs,
because `make` is not on PATH here, before anything was measured.

**Baseline before anything was touched**, on the fresh clone at `4d402a8` with
the keys in place:

```
tests/test_route_parity.py                             16 passed
tests/test_bounded_reads.py                            24 passed
tests/test_post_proof_reporting.py                     12 passed
tests/test_ledger_state_does_not_survive_teardown.py    6 passed
tests/test_image_contents.py                           15 passed, 8 skipped
```

The first four match the 3c-3g red team's baseline figures exactly.

**This is the last sub-phase of 3c.** There is no red-team pass after it.

---

## What this phase is, and the one exception in it

The 3c-3g pass (`docs/reports/phase-3c3g-redteam.md`) returned eleven
findings: one recursive gap (F1), seven applications, three carried. The merge
criterion pre-committed the response to a recursive gap, and this phase is
that response: **no further generalisation.** No new enumeration machinery was
built. Claims were narrowed to what the tests demonstrate, the ordinary
defects the pass showed were fixed, and the limits were written down.

The argument for stopping here is stated precisely because it has one
exception.

For **P3c3h-1, P3c3h-2 and P3c3h-7** the narrowed claims assert strictly less
than what the last adversarial pass already tested. **P3c3h-5 and P3c3h-6** are
test-side only. **P3c3h-8** records carried findings and changes no code.
**P3c3h-3** touches production code and is not an exception, for a reason
stated rather than assumed: the `Literal` is behaviour-preserving on every
input reachable at this head, because all five constructions use the three
module constants and `grep -rn "StateRead(" verifier/ control_plane/` returns
nothing else. What it changes is the failure mode of a future programming
error, and that is recorded as a consequence in the item.

**P3c3h-4 is the exception, and it stays one.** It changes
`POST /write-ordered`'s behaviour on the central write path, after the last
adversarial pass. It is validated by its own drivers, its two named mutations
and CI, **and by nothing adversarial.** That sentence is in Residual Limits
below and in `readME.md` beside the fix, and the closing paragraph does not
claim otherwise.

---

## Items

| # | Verdict | Demonstration | Enforcing test | Mutation |
|---|---|---|---|---|
| P3c3h-1 | claim narrowed | F1's three instances, red team | none added, by design | none |
| P3c3h-2 | claim narrowed | T2, driven through `POST /write-ordered` | none, claim edit | none |
| P3c3h-3 | closed at the verifier | anchored mutation at `12 passed`, reproduced | 3 driven cases + the type | 3 anchored, all fail |
| P3c3h-4 | closed, and a second branch found open | both halves at `committed: false`, reproduced with control | 5 tests | 2 named, both fail |
| P3c3h-5 | 2 closed, 1 bounded | maxscore, stateful path, detector table | 3 | 4, all fail |
| P3c3h-6 | closed | F2 at 16 node ids to 13, green | staleness on `PROPERTIES` | F2 itself, fails |
| P3c3h-7 | done | n/a | n/a | n/a |
| P3c3h-8 | recorded | n/a | n/a | n/a |

**One finding arrived after the work was done and is escalated rather than
fixed:** the intermittent CI failure this branch has been carrying is a
*second* `committed: false` branch that P3c3h-4 does not touch, demonstrated
in the CI section below and recorded in `TODO.md`.

---

### P3c3h-1. Scope the route-parity claim (F1)

**Verdict: the claim is narrowed at every site that stated it. Nothing was
added to close the gap, and that is the decision.**

**The claim, as it now reads:** route parity covers routes registered directly
on the verifier application and selected by the enumerated clauses.
Discrimination via `app.mount`, composite `Depends` gates deeper than one
level, and path-keyed collapsing are outside it. D48's clause coverage is the
hand-listed `if`-conjuncts of two selectors, and the other three
discrimination places F1 measured are named as uncovered.

**The measurement is the red team's**, cited rather than re-run: T1's mutation
table in `docs/reports/phase-3c3g-redteam.md`, with the three live instances,
each carrying a control that produced the other outcome.

| position | attack | control |
|---|---|---|
| `app.mount` (the traversal) | `16 passed`, byte-identical to baseline | same handler through `app.include_router`: `3 failed` |
| composite `Depends` (the helper) | `write_routes` `[]`, route answers 403 on a wrong key | gate declared directly: `['/write-express']` |
| two verbs at one path (the dict key) | `16 passed` | same handler at a non-colliding path: `3 failed` |

**Enforce: nothing new.** The existing falsifiers stay. No falsifier was added
for any of the three, deliberately: each is fixable as R1 was, by widening the
selector and adding a falsifier, and the reason not to is that there are three
at once with one cause. The enumeration reads a comprehension's `if` and a
selector discriminates in four places, so the count of missing falsifiers is
not a property of how carefully the list was typed. That is the recursive-gap
cell and the pre-committed response is to scope the claim.

**Why the smaller claim is still worth having, enumerated because that is what
makes it worth having and no more than it checked.** Measured on this head:

```
APIRoutes on verifier.app : /health /state /verify /write /write-ordered
Mounts on verifier.app    : []
routes whose gate is more than one Depends deep : []
grep app.mount / app.include_router in verifier/main.py : 0 hits
```

Five routes, all registered directly on `app`, each declaring its gate
directly, each at a distinct path. **That is a measurement taken in this
phase, not a check this suite runs.** A sixth route arriving by a mount,
behind a composite gate, or colliding on a path would be outside the site list
and `tests/test_route_parity.py` would stay green.

**And which application.** `_service_routes` reads `verifier.app` only. The
control plane and the decision service register routes of their own and are
not covered by that file at all. This was not stated anywhere before.

---

### P3c3h-2. The exemption marker: scope the claim, build nothing (T2)

**Verdict: claim edit only. No mechanism, no test, no mutation, and the report
row says so.**

The fix an earlier draft specified is a no-op. `explains()` already requires
the marker, and `registered_for()` already requires the invariant and the view
to match (`tests/ledger_pollution.py`). The T2 attack satisfied all three
conjuncts by copying `p3c3d-dup`, whose entry already names both
`ONE_POSITION_PER_KEY` and `HISTORY_SCORE_IS_ITS_TRANSACTION` and the decision
view. Matching costs the attacker one copied string. Building the same check
again would match the English of a fix and not stop the attack, which is the
P11-7 pattern this project has a standing rule against.

Closing it for real means binding the exemption to something the caller does
not supply (a marker written by the test process into a place a request body
cannot reach, or a writer signature), which is new mechanism and forbidden
this phase.

**The measured claim, which is 3c-3g's own:** an ordinary record cannot drift
into an exemption by *resembling* one. That is what the exact-marker match
bought (P3c3g-3, closing R4, where `p3c3c-padded-batch-7` inherited
`p3c3c-pad`'s exemption and a genuine violation on it went unreported). A
caller who deliberately writes `ail_deliberate_violation` with a matching
invariant and view is outside the registry's scope, and reaches a ledger-wide
invariant on a record the production write path accepted: the 3c-3g pass drove
two verified records with ordinary agent ids differing in exactly one field of
the value, gave each a second position at score 42.0, and
`tests/test_view_invariants.py` reported the control on both invariants and
the attack on neither.

Stated in Residual Limits beside the existing forgeability entry, and at the
source (`tests/ledger_pollution.py`, `MARKER_FIELD`).

---

### P3c3h-3. `state_read` vocabulary, constrained at the type (T3)

**Verdict: closed at the verifier end. The `/audit` half is carried.**

**Demonstrate.** The red team's anchored case, reproduced on this head before
anything was changed: `status="failed"` at the anchored OK construction
(`verifier/main.py`, the `return state.txId, StateRead(...)` after the `_vk`
check) read `12 passed`. `"failed"` is the one word R6's design excludes,
because `/audit` renders it as a positive tamper claim about a record.
`test_a_failed_head_read_is_not_a_verification_state` does not catch it: it
asserts that `"failed"` is not among three module constants, which is a
statement about the constants.

**Fix.** `Literal["ok","unchecked","unavailable"]` on `StateRead.status` and
`Literal["head","anchor"]` on `StateRead.source`. Two lines, closing all five
construction sites and the type at once.

**Enforce.** Three driven cases and the type.

* `test_the_anchored_state_read_reports_the_anchor_and_reports_it_as_ok`
  pins the expected member, not the set: the anchored path with `_rs.get()`
  working and a verifying key configured, asserting `source == "anchor"` and
  `status == "ok"`. Membership alone cannot catch the mutation, and this was
  measured rather than argued: all five constructions sit inside
  `_state_read`'s `try`, a `ValidationError` from a mutated site is caught by
  its `except Exception` and rendered as a well-formed `unavailable`, and with
  only a membership test present the run read `14 passed`. The forbidden word
  never reaches the wire, which is the property working, and a set-membership
  test reads green through exactly that.
* `test_the_anchored_state_read_names_its_source_on_every_outcome` drives the
  other two anchored constructions, which the type would otherwise absorb
  silently.
* `test_the_state_read_vocabulary_is_closed_by_the_type` asserts the refusal
  at construction, which is the assertion that does not have to enumerate the
  sites.

**Mutation.** All three anchored constructions, one at a time, whole file each
time, reverted between:

| mutation | before the fix | after |
|---|---|---|
| anchored OK reports `status="failed"` | 12 passed | **1 failed** (the pinned-member test) |
| anchored unchecked reports `status="failed"` | 12 passed | **1 failed** |
| the unavailable branch reports `source="head"` on the anchored path | 12 passed | **1 failed** |

The named mutation in the instruction is the first, and it fails on the value
moving to `unavailable`, which is what the pinned member is for.

**One thing found while writing the test, recorded because it is a fact about
the code and not about the test.** The anchored *unchecked* construction is
**unreachable through `POST /verify`**. The route refuses a supplied anchor
outright when `client._vk is None` (`error_class="anchor_signature_failure"`,
"no ImmuDB signing key is configured, so a supplied anchor cannot be checked
and will not be used"), and `_state_read` has exactly one call site,
`_state_read(client, payload.anchor)`, below that refusal. The first draft of
the test drove it through the route and got the refusal instead, which would
have been an assertion quietly measuring something else. It is driven at the
function now, and the test also asserts that the route still refuses that
combination, so the unreachability is measured rather than read off the
source.

**Recorded as a consequence.** The `Literal` turns a future programming error
on this path into a silent `unavailable` carrying a `ValidationError` string
in the operator-facing `detail`, rather than a 500. Defensible on the
post-proof path, where nothing may change a verdict that has already been
established, and recorded here rather than discovered.

**What stays open.** `control_plane/main.py::_verification_from_200` passes
`state_read` through as an untyped dict and `/audit` has no `response_model`,
so F5's `/audit` half is untouched. Carried to `TODO.md`.

---

### P3c3h-4. The committed-false branch (the diagnosis finding)

**Verdict: closed at the property, with one flag and no second change.**

**Demonstrate.** `write_ordered` driven in process against a stub whose
`ExecAll` is refused on a precondition and whose channel dies after a chosen
number of reads. The reads in one attempt are, in order, the bound reserve,
the counter, and then, after the refusal, the record key, so the only thing
that moves between runs is that number. Reproduced on this head before the
fix, at the red team's figures:

```
ATTACK  (dies_after=2)   HTTP 200  committed: False  attempts: 0
                         reads attempted 4   ExecAlls issued 1
                         detail: StatusCode.UNAVAILABLE ... "Socket closed"
CONTROL (dies_after=3)   HTTP 409  "a record is already committed under this key"
                         reads attempted 3   ExecAlls issued 1
```

One read's worth of difference turns the honest 409 that D39 exists to give
into `committed: false` on a record that can be in the ledger, with
`attempts: 0` understating the one attempt the ledger did serve. It refutes
P3c3e-2, whose rule was that the exception type carries whether the request
reached the wire.

**The second half was reproduced too**, and it is why the fix is not the named
read. With the record-key read *working* and honestly answering "no record"
(one of the two retryable preconditions), the loop continues and the next
attempt's unguarded `_read_bound_reserve` meets the dead channel:

```
HALF TWO (dies_after=3, record absent)  HTTP 200  committed: False  attempts: 0
                                        ExecAlls issued 1
```

Nothing about `_record_key_present` is involved. Guarding the named read would
have closed half one and left this open for any other reason the channel dies
between attempts.

**Fix: one flag.** `issued`, set in `_ordered_commit` immediately before
`stub.ExecAll(request)`. The loop is wrapped so that anything escaping it
while `issued` is true becomes `OrderedCommitUncertain`, so once an `ExecAll`
has been issued in a call, `committed: false` is unreachable from
`_ordered_commit`'s callers. `RecordKeyExists` passes through unconverted on
purpose: that is the branch where the record-key read ran and answered yes, so
the 409 is established rather than guessed. **No second change** was made; an
earlier draft added `_record_key_present` propagation, which under the flag
reaches the same uncertain path and changes nothing.

**After the fix:**

```
HALF ONE  committed: None (null)  attempts: 2   ExecAlls issued 1
HALF TWO  committed: None (null)  attempts: 2   ExecAlls issued 1
CHANNEL BACK FOR THE READ-BACK    committed: True  tx_id 2
CONTROL   HTTP 409, unchanged
```

Never `false` on either driven half, which is what the answer is pinned as. On
those branches the record-key read is exactly what cannot run, so the service
has no evidence for a 409's "already committed" claim either; asserting it
would be the same lie pointed the other way, plus a permanent refusal. The
honest answers are D45's existing states, both reachable through the flag
alone.

**Enforce.** Five tests in `tests/test_committed_is_a_fact.py`:

* `test_an_ordered_write_whose_execall_reached_the_wire_never_says_committed_false` (half one)
* `test_the_second_half_of_the_window_is_closed_too` (half two)
* `test_the_ordered_route_still_refuses_a_key_it_can_see_is_committed` (the 409 control)
* `test_a_write_that_never_reached_the_wire_still_says_committed_false` (the
  other control: a reserve disagreement raises before any `ExecAll`, and
  `committed: false` stays a real state there, so the fix is not "never answer
  false")
* `test_an_exhausted_retry_budget_reports_committed_false_from_the_ledger`

**Mutation.**

| mutation | result |
|---|---|
| remove the flag (the guard never converts) | **2 failed**: both half tests |
| set `issued` after `stub.ExecAll` returns instead of before it | **2 failed**: both half tests |

The second is the one the branch turns on: on a precondition refusal the call
raises, so a flag set on the return path is never set on exactly the branch it
exists for. Both controls pass under both mutations, which is correct - they
do not depend on the flag.

**One behaviour change the flag brings, pinned rather than left to be found.**
When the CAS retry budget runs out, every attempt was refused whole and
nothing was written, so `committed: false` is the right answer and stays the
answer. What changes is how it is reached: an `ExecAll` has been issued, so the
route now asks the ledger, finds the record genuinely absent, and reports
`false` established from a read instead of assumed. Two things move with it,
both honest: one extra read on a path that has already made `MAX_CAS_ATTEMPTS`
round trips, and `attempts` reported as what it was rather than as 0. The
phase's pre-registered negatives name exactly this case as the one that stays
(`_committed_tx_for_value` answering ABSENT is an answer, not a guess), and
the fifth test above pins it.

**What validated this item, in full.** Its own drivers, its two named
mutations, the two controls, and CI. **Nothing adversarial.** It is the one
item in this phase that changes production behaviour after the last red-team
pass, and there is no pass after it.

**And what it does not close.** The intermittent CI failure on
`test_a_retry_after_a_dropped_response_is_told_the_record_already_exists` is a
different branch of the same route, identified by `attempts: 1` and
demonstrated to survive this fix. See the CI section below. This item closes
the branch the 3c-3g pass diagnosed and drove; it does not close the one CI
has been failing on, and the two were easy to conflate.

---

### P3c3h-5. Detector and list corrections (T6)

**Verdict: two closed, one bounded with its measured gap.**

#### C7, the undriven declared bound

`COVERAGE`'s entry for `verifier/main.py::_committed_position_for` declares
`("minscore", "maxscore")` and its driver asserted `minscore` only.
Reproduced: `maxscore=float(attempted_seq) + 1e9` with the kwarg kept read
`24 passed`. Removing the kwarg is caught by the derivation
(`test_every_bound_at_a_driven_read_has_a_driver`); keeping the name and
destroying the value was not.

**Fix and enforce:** one assertion in `_drive_committed_position_for`, that the
call asked for `maxscore == 1000000042.0`. **Mutation:** the same
`+ 1e9`, kwarg kept, now **1 failed**
(`test_the_bounded_read_asserts_its_bound[verifier/main.py::_committed_position_for[0]]`).

**The control's cross-coverage, noted because it decides the shape of the
fix.** The same class of mutation on another multi-bound entry - widening
`_faults_in_tx_window`'s `endKey` by 1,000,000 transactions - *is* caught. So
this was one entry's gap, not the table's shape, and one assertion is the
right size of fix. What limited the harm meanwhile, stated because it is not
what makes this safe: `_committed_position_for` compares the returned score
against `attempted_seq` itself, so the code refused what the test did not
check.

#### The stateful-path list

`STATEFUL_CONTAINER_PATHS` was matched with `target not in
STATEFUL_CONTAINER_PATHS: continue`. Reproduced with the control, by mutating
`docker-compose.test.yml`:

```
ATTACK  ./ledger-on-the-host mounted at /var/lib/immudb/data   -> 6 passed
CONTROL ./ledger-on-the-host mounted at /var/lib/immudb        -> 1 failed
```

`/var/lib/immudb/data` is where ImmuDB actually writes.

**Fix:** `is_stateful(target)`, a prefix match **with a segment boundary** -
`target == root or target.startswith(root + "/")`. The boundary is not
decoration: a bare `startswith` makes `/database-config` a stateful mount
under the root `/data`, which trades a missed ledger for a refused config
file.

**Enforce:** `test_a_stateful_mount_one_directory_deeper_is_seen`, driving
both the sub-path case and the boundary case through the same check the
compose files go through, with controls in both directions (the root itself
and a real path under it still match; the config bind does not).

**Mutations:**

| mutation | result |
|---|---|
| revert `is_stateful` to the exact match | **1 failed** |
| bare `startswith`, no segment boundary | **1 failed** |

And the original attack, re-run verbatim against the fix: the compose mutation
now reads **1 failed** on
`test_every_stateful_mount_is_a_named_volume_that_down_v_removes[docker-compose.test.yml]`,
where it read `6 passed` before.

#### C8, the detector's composition bound

Reproduced against the live `keys/writer-decision.key`:

```
raw PEM              232 -> 'pem'              base64(gzip(PEM))   284 -> None
base64(PEM)          312 -> 'base64-pem'       gzip(base64(PEM))   269 -> None
gzip(PEM)            212 -> 'gzip-pem'         base64(base64(PEM)) 416 -> None
raw DER              121 -> 'sec1-der'         base64(gzip(DER))   192 -> None
base64(DER)          164 -> 'base64-sec1-der'
```

Every undetected shape is one composition step from a detected one in the same
table.

**Bounded rather than extended, per the instruction's pre-commitment, and here
is the triviality judgement it asked for.** The extension is not one conjunct.
`key_material` tries armour and binary on the raw head, then offers a
decompressed gzip member to those same two rules, then offers each decoded
base64 run to those same two rules. Closing the composition means recursion
with a depth budget, and its cost falls on the base64 loop, which would then
re-scan every decoded body for base64 runs. This file's existing bounds were
each bought with a measurement on the real four-image surface (17.7s to 18.5s
for dropping the twenty-run cap, against 57.5s for dropping the head bound),
and a depth-2 detector cannot be justified on this head without the same
measurement on the same surface. That is not trivial, so the bound is stated.

**Fix:** the one-step composition bound written into the module docstring
beside the head bound and the twenty-run measurement it already carries, with
the table above.

**Enforce:** `UNDETECTED_COMPOSITIONS`, a hand-list of four twice-wrapped
shapes with its limit written down, per the R6 convention, driven in both
directions.
`test_a_twice_wrapped_key_is_outside_the_stated_composition_bound` asserts per
row that the one-step neighbour is still detected (the control, which is what
makes the second assertion a statement about depth rather than about a broken
detector) and that the twice-wrapped shape is not.

**Mutations:**

| mutation | result |
|---|---|
| drop the gzip branch from the detector | **2 failed**: the bound's control row and `gzipped-pem` |
| close the gap (offer a decoded base64 body to the gzip rule) | **1 failed**: the bound row, which is the good direction |

The second is the one that matters for a stated bound: if someone closes the
gap, this test says so and names what to do (move the row into
`KEY_ENCODINGS`, correct the docstring, and record what the second step costs
on the four-image surface).

---

### P3c3h-6. A stale property cell fails (F2)

**Verdict: closed.**

**Demonstrate.** F2's mutation, `and route.path != "/write"` added to
`write_routes`'s comprehension, reproduced on this head:

```
baseline: 16 collected, 16 passed
mutated : 13 collected, 13 passed          # green
```

`POST /write` leaves the site list, three of its four property cells vanish
from collection, and the run is green and three shorter in its count. A
vanished cell and a passed cell are the same green.

**Fix.** The assertion `tests/test_route_parity.py` already applies to
`UNGATED_BY_DESIGN` a few lines up, applied to `PROPERTIES`, which lacked it:
a recorded cell naming a route no longer in the site list is stale and fails.
Read against the **union of `holds_on` and `does_not_apply_to`**, since
`state()` reads both. Written against `holds_on` alone, a departed route
recorded as does-not-apply stays invisible, which is the same silence one
level in; no route in the tree today is recorded only as does-not-apply, so
the union direction is written for the general case rather than for an
instance.

**Mutation:** the F2 edit itself, and the sibling that removes
`/write-ordered`:

| mutation | result |
|---|---|
| `and route.path != "/write"` | **1 failed**: `test_every_write_route_has_a_recorded_state_for_every_property` |
| `and route.path != "/write-ordered"` | **1 failed**: the same test |

---

### P3c3h-7. The claims sweep

Every claim this phase narrowed, corrected at source. The citing-document-and-
cited-source rule applies throughout: where a README bullet would cite a
source, the source is fixed too.

| # | site | old text | new text | reason |
|---|---|---|---|---|
| 1 | `tests/test_route_parity.py`, `_service_routes` docstring, first line | "Every route this service registers, under any verb." | "Every `APIRoute` registered directly on `verifier.app`, under any verb." plus the three uncovered positions and which application is read | False at this head: `app.routes` is walked non-recursively, so a mounted sub-application's routes are not returned. This is the source a README-level claim would cite. |
| 2 | `tests/test_route_parity.py`, `write_routes` docstring, first line | "Every route gated by `_require_write_key`, under any verb, by path." | "The routes `_service_routes` returns whose **declared** dependencies name `_require_write_key`, under any verb, keyed by path", plus the composite-gate and path-collision limits | Not every one: a gate composed behind another `Depends` is enforced and unseen, and the path key collapses two verbs at one path. |
| 3 | `tests/test_route_parity.py`, module docstring | "Every property this service claims about a write is asserted against every write route, and the list of write routes is derived from the application object rather than typed here." | the same, with "every write route **this file's selector can see**", the three positions with their measured attack/control figures, the five-route enumeration marked as a measurement and not a check, and the note that only `verifier.app` is read | The unqualified sentence claims coverage the tests do not demonstrate. |
| 4 | `tests/test_selector_clauses.py`, module docstring | coverage stated as the falsifiers of two files, with the regress bounded and no statement of what a "clause" excludes | adds P3c3h-1's paragraph: the four discriminating places, the three that are not clauses of the covered kind, and the explicit claim "for the hand-listed `if`-conjuncts of the covered selectors, a falsifier fails when the conjunct is broken" - not "the selectors are checked" | No faithful application of D48 puts the traversal, the helper or the dict key in either hand-list, so the file's coverage had to say which unit it is about. |
| 5 | `docs/adr/0014-ordered-audit-view-index.md`, D43, "What this does not reach" | named only the bounded-read helper limit and "no enumeration here can see a property nobody stated" | adds the three route-parity positions with their figures, the corrected claim, the scoping of D48's clause coverage, and why nothing was added | The ADR is where the derivation claim originates, so correcting only the README would leave the citation pointing at an uncorrected source. |
| 6 | `readME.md` §5 Residual Limits | no entry | new bullet: route parity covers what its selector can see, the three positions with attack and control figures, the five-route measurement marked as a measurement, and the control plane and decision service being uncovered | The project-level statement of the narrowed claim. |
| 7 | `tests/ledger_pollution.py`, `MARKER_FIELD` comment | "A record arriving through the production write path does not carry it unless someone put it there deliberately, which is a weaker claim than 'unforgeable' and the right one" (correct, and silent on what "deliberately" costs) | adds T2's demonstration and its control, the exact claim ("cannot drift into an exemption by *resembling* one"), and why re-implementing the three-conjunct check would be the P11-7 pattern | The sentence was right and the belief around it was not; the belief is what T2 refuted. |
| 8 | `readME.md` §5 Residual Limits | no entry | new bullet: the exemption is forgeable through the production write path, with T2's demonstration and control, the measured claim, and what closing it would take | Stated beside the existing forgeability entries. |
| 9 | `readME.md` §5 Residual Limits | no entry | new bullet for P3c3h-3: closed at the verifier, open at `/audit`, with the consequence | The type is a behaviour claim and the `/audit` half is a limit. |
| 10 | `readME.md` §5 Residual Limits | no entry | new bullet for P3c3h-4, ending "**What validated it:** its own drivers, its two named mutations and CI. Nothing adversarial" | The exception, stated where a reader of the project's claims will meet it. |
| 11 | `verifier/main.py`, `write_ordered`'s bottom handler comment | "Nothing reached the wire: the client could not be built, the reserve disagreed, the ceiling was reached, **or the retry budget ran out**. `committed: false` is a fact on this branch and on no other." | the same first sentence without the retry-budget clause, plus the paragraph saying the sentence is now enforced by the flag rather than resting on the exception type | The sentence was false in two ways: an `ExecAll` could reach here having been issued, and the retry-budget path no longer arrives here at all. |
| 12 | `verifier/main.py`, `StateRead` docstring | the three-word set described in prose, fields typed `str` | adds the P3c3h-3 paragraph: the type is the constraint, what the red team measured, the `/audit` half being open, and the `ValidationError`-becomes-`unavailable` consequence | A naming convention that nothing enforced was described as if it were one. |

`TODO.md` also gains a phase-closure paragraph in the same series as the
3c-3b through 3c-3e entries.

**Mapping check:** clean. `0 new, 12 known, 0 stale`, `34 heading pins, 0
unpinned, 0 retitled, 0 stale`. It took one correction to get there, and it is
the corpus-coupling class `TODO.md` already documents: the word "vocabulary"
in a new README bullet made that term distinctive for
`docs/reports/phase-3a.md` row 13, whose cited section (`readME.md` §3.4.1)
does not contain it, and the historical row went red without having changed.
Resolved by rewording the new prose ("word set", "three-word closed set"),
which is the documented resolution for this direction, rather than by editing
the quarantine record.

---

### P3c3h-8. Carried findings, recorded as carried

Four entries added to `TODO.md`'s Deferred list, each with a reproduction
pointer:

* **R7, `COMPOSE_FILES` does not read `docker-compose.override.yml`.** One
  line at `tests/test_ledger_state_does_not_survive_teardown.py:33`. There is
  no override file in the tree today, so it is a hole rather than an instance.
  P3c3h-5 changed how a mount target is matched in that module and did not
  change which files it reads.
* **F5's `/audit` half.** `_verification_from_200` passes `state_read` through
  untyped and `/audit` has no `response_model`; the red team's rendering
  measurements are the reproduction.
* **F8, the five-constructor shape test is itself a hand-list.** With the two
  ways out named, and the observation that stating the limit is the R6
  convention and one paragraph.
* **`tests/test_record_profile.py` in one recorded collection order.** Carried
  from 3c-3g, mechanism unestablished, with `docs/reports/phase-3c3d-order-sweep.md`
  named as the instrument for the class.

---

## Pre-registered negatives, checked

* **Any claim asserting coverage the tests do not demonstrate.** The twelve
  sites in P3c3h-7 are the sweep. The route-parity enumeration is explicitly
  marked as a measurement rather than a check, in all three places it appears.
* **Any test weakened.** None. Every change to a test file adds an assertion
  or a case: the `maxscore` assertion, the `PROPERTIES` staleness assertion,
  three `state_read` tests, five `committed` tests, the stateful-path test,
  the composition-bound test. `is_stateful` widens what the stateful-mount
  check *catches*, which is the opposite direction.
* **Any new enumeration machinery.** None. `UNDETECTED_COMPOSITIONS` is a
  hand-list stating a bound, not a derivation, and it says so.
* **Any `state_read` construction that can emit a word outside the
  vocabulary.** Closed at the type for all five sites; the `/audit` boundary
  is carried and stated.
* **Any response reporting `committed: false` for the record this write
  carried, on the driven branches.** Both halves answer `null`. The two places
  `false` survives are the branch where nothing reached the wire and the
  branch where the ledger was read and answered ABSENT, and both are pinned by
  tests.
* **Any property cell that can vanish from collection and read as green.**
  Closed for `PROPERTIES` by P3c3h-6, against both F2 variants.

---

## Residual Limits

**Route parity is scoped, and three discrimination positions are outside it.**
`app.mount`, composite `Depends` gates deeper than one level, and path-keyed
collapsing. No falsifier was added for any of them; the measurement that no
production route arrives by any of them today is a measurement of today's tree
and not a check. D48's clause coverage is the hand-listed `if`-conjuncts of
two selectors. The control plane's and the decision service's routes are not
covered by `tests/test_route_parity.py` at all. F1's mutation table in
`docs/reports/phase-3c3g-redteam.md` is the measurement.

**The deliberate-violation exemption is forgeable through the production write
path.** The registry stops an ordinary record drifting into an exemption by
resembling one, and nothing more. Closing it needs mechanism this phase did
not add.

**P3c3h-4 changed `POST /write-ordered` after the last adversarial pass, and
is validated by its own drivers, its mutations and CI, and by nothing
adversarial.** It is the only item in this phase that changes production
behaviour on a path a caller reaches, and there is no red-team pass after this
one. Its two named mutations both fail their tests, its two controls hold, and
that is the whole of what stands behind it.

**`state_read` is typed at the verifier and untyped at `/audit`**, and a
future programming error on that path renders as `unavailable` with a
`ValidationError` string in `detail` rather than as a 500.

**The image detector composes exactly one step**, with four twice-wrapped
shapes measured as undetected, each one step from a detected one. The bound is
stated and pinned rather than bought, because buying it needs a measurement on
the four-image surface that this head did not take.

**A second `committed: false` branch is open and is the one CI intermittently
fails on.** `_committed_tx_for_value` answering ABSENT because the ledger
returned not-found, on a record that is in the ledger. P3c3h-4 does not touch
it, which is demonstrated rather than argued, and the mechanism is not
established. It is the only finding in this phase that arrived after the work
was done, and it is escalated rather than fixed.

**Carried and unfixed:** R7, F5's `/audit` half, F8,
`tests/test_record_profile.py`'s order interaction, and the branch above. All
five in `TODO.md` with reproduction pointers.

**And the standing ones this phase did not touch:** the fault record is the
one write that succeeds without write-time proof; an evidence bundle does not
name a record's ledger fault; external anchoring is the only fail-open
subsystem; every service mounts every writer's private key, so a writer
signature attributes a record to a key and not to a service.

---

## What could not be removed from the machine

Every source mutation was reverted, and `git checkout --` or a byte copy from
a backup was used after each one rather than trusting a hand restore, because
writing a repo file from Python rewrites its line endings. One trap cost time
and is worth recording: `git checkout -- verifier/main.py` after a mutation
also reverts an **uncommitted fix** in the same file, and two mutation results
were measured against a file that had silently lost the `Literal` before that
was noticed. Both were re-run against a byte copy of the fixed file, and the
corrected results are the ones in P3c3h-3.

Mutated and reverted: `tests/test_route_parity.py` (two selector conjuncts),
`verifier/main.py` (three `_state_read` constructions, one head-branch
control, one `maxscore` widening, the flag removed, the flag moved),
`tests/test_ledger_state_does_not_survive_teardown.py` (two `is_stateful`
rules), `tests/test_image_contents.py` (two detector edits),
`docker-compose.test.yml` (two mount mutations).

No Docker stack was started in this session. Every item was driven in process,
which is why `docker compose ls` has nothing from this run to tear down;
`tests/test_image_contents.py`'s docker-dependent cases report as skipped
throughout, as they do at baseline on this host.

Probe scripts are outside the repository, in the session scratchpad under
`AppData\Local\Temp\claude\...\scratchpad\`.

---

## CI

Every run this phase produced on `p3c3b-order`, in order:

| run | head | what the head is | conclusion |
|---|---|---|---|
| `34160511188` | `9eca2cb` | before this phase | success |
| `34160811148` | `4d402a8` | before this phase, docs-only above `9eca2cb` | **failure** |
| `34165919599` | `d5793e4` | all code changes and the first report | success |
| `34166518989` | `39decad` | plus the CI section and its `TODO.md` entry | success |
| `34166913958` | `a0c2e6e` | plus this table | success |
| `34167332033` | `6949bb1` | plus the table's own commit, docs-only | **failure**, the same defect |

A commit that records a run id cannot contain the id of its own run, so each
row after `d5793e4` is a docs-only commit named by the run of the one before
it. The tree is unchanged outside `docs/` and `TODO.md` from `d5793e4` onward,
so `34165919599` is the run that exercises this phase's code, and it is green.

**`34167332033` is the second firing of the defect above, on a docs-only
commit**, and it is stronger evidence than the first because it names the
record's transaction:

```
FAILED tests/test_committed_is_a_fact.py::
       test_an_ordered_write_that_committed_is_reported_as_committed_when_its_response_is_dropped
AssertionError: the record is in the ledger at transaction 255 and the ordered
route says the write never happened:
{'tx_id': None, 'seq': None, ..., 'committed': False, 'attempts': 1, ...}
```

A different test in the same module, the same `attempts: 1`, the same detail
shape, the same branch. Two tests are exposed to it, so the defect is in the
route and not in either fixture.

### This phase does not close green on a re-run basis, and that is stated rather than averaged away

The merge criterion for PR #14 was "closes green". The phase's own code is
green (`34165919599`, and two docs-only runs after it). The branch is not
reliably green, and it was not before this phase either: four failures in the
last twenty five runs, of which **two are this defect, both on 2026-09-07**
(`4d402a8` and `6949bb1`), and two are unrelated tests on 2026-09-05
(`6f5f51b`, `5ed4779`).

Re-running until it passes would produce a green that means nothing, since a
green is the common outcome. So the position this phase takes is: the work
commissioned is complete and green; a pre-existing intermittent defect on the
central write path is now characterised precisely, reproduced in process,
demonstrated not to be the one P3c3h-4 fixes, and recorded with its
reproduction. **Whether that blocks the merge is the owner's call, and this
report does not make it by choosing which run to quote.**

**The base was already red, and what it was red about matters more than the
green.** Run `34160811148`, head `4d402a8` - the commit this session started
from - failed:

```
FAILED tests/test_committed_is_a_fact.py::
       test_a_retry_after_a_dropped_response_is_told_the_record_already_exists
AssertionError: the caller is being told a write that committed did not
happen, which is the retry D39 refuses forever:
{'tx_id': None, 'seq': None, 'verified': False, 'committed': False,
 'attempts': 1, ..., 'detail': '<_InactiveRpcError ...
 StatusCode.UNAVAILABLE ... "Stream removed (Socket closed)">'}
1 failed, 562 passed, 10 skipped
```

Run `34160511188` on `9eca2cb` was green, and `9eca2cb` and `4d402a8` differ
by seven lines of a report. So the failure is intermittent and predates
everything in this phase.

### The failure is NOT the branch P3c3h-4 closes, and it is escalated rather than folded in

This is worth stating plainly because the opposite reading is the natural one:
P3c3h-4 fixes a `committed: false` on a record that committed, CI fails with
`committed: false` on a record that committed, so the fix must be the fix. It
is not.

**`attempts: 1` identifies the branch.** `write_ordered`'s bottom handler -
the one the flag makes unreachable after an `ExecAll` - passes no `attempts`,
and `OrderedWriteResponse.attempts` defaults to 0. Every driven reproduction
of P3c3h-4's branch in this phase carried `attempts: 0` before the fix. The
CI body carries 1, which only the `OrderedCommitUncertain` handler produces,
via `attempts=exc.attempts`, on the `state == ABSENT` path.

**Demonstrated rather than inferred.** Driven in process **with the P3c3h-4
flag in place**, against a stub whose `ExecAll` response is cut (the
`cutresponse` relay's shape) and whose record-key read then runs and answers
not-found:

```
committed: False  attempts: 1  tx_id: None  seq: None
ExecAlls issued: 1
detail: <_InactiveRpcError ... StatusCode.UNAVAILABLE ... >
```

That is the CI body, field for field, on a head that carries the fix.

**What is established:** the read ran, because a read that raises answers
`null`; it answered not-found; and the test then read the key directly out of
ImmuDB and found it present, in an assertion that runs *before* the one that
failed. **What is not established:** why. An ImmuDB index that has not caught
up with a commit that just happened produces exactly this, and so would other
things, and nothing here measured it. The 3c-3g red team said it could not
establish that the branch it diagnosed was what CI hit; this is evidence that
it was not.

**Why D45 does not already cover it.** D45 separates "the read could not run"
(`null`) from "the read ran and answered" (`false`). This is a third case: the
read ran, answered not-found, and was wrong. This phase's pre-registered
negatives preserve `_committed_tx_for_value` answering ABSENT **for a key
holding different bytes**, which is honest; here the key holds the same bytes
and `client.get(key)` returned `None`.

**Not fixed here.** P3c3h-4's instruction scoped the item to one change and
said to escalate rather than grow it, and this is a different branch. Deciding
it means deciding what a not-found read licenses immediately after an
`ExecAll` whose response was lost - a bounded re-read, a fourth state, or
`null` on that branch - which is a D45-level decision. Recorded in `TODO.md`
with the run id, the body, the probe shape and the enforcing test that already
exists.

**So the two greens here are two green runs on an intermittent failure, and
they are reported as that rather than as a fix.** The base failed once in
the three runs this branch has on record around this work (`9eca2cb` green,
`4d402a8` red, `d5793e4` and `39decad` green), and nothing in this phase
changed the branch that failed.

---

## What the system claims, in full, at the end of phase 3c

Every tool call an agent makes is intercepted, validated against a schema,
decided by policy, and written to a tamper-evident ledger before it executes,
and a failure anywhere in that chain denies the call. What phase 3c added is
that the ledger's own account of itself is now ordered, bounded and honest
about what it does not know: `/audit` is commit-ordered through a view index
whose positions are allocated under a compare-and-set the ledger enforces in
the same transaction as the record; a write reports `committed` as a fact read
back from the ledger, or reports that it does not know, and since this
sub-phase a write that reached the ledger can no longer be reported as never
having happened **on the branch where the confirming read could not run** -
one further branch, where that read runs and answers not-found about a record
that is there, is open, measured and recorded; a proof that fails after a record has committed
produces a durable, separately-signed fault record rather than a repairable
silence; and the reserve those positions are allocated against is bound into
the ledger itself, where four independent readers refuse to proceed on
disagreement. Beneath that sits the control the last four sub-phases were
really about: a guarantee this system claims is asserted against a list of
sites the tests derive from the code, so a new site fails the suite until a
decision is recorded about it, and where a list cannot be derived it is
hand-written with its limit stated and driven. **What the system does not
claim is now written down at the same level of detail as what it does**, and
that is the part of this phase worth sharing: the route-parity derivation
covers routes registered directly on the verifier application and selected by
its enumerated clauses, and three ways a route can hide from it are named,
measured and left open; the deliberate-violation registry stops an ordinary
record resembling an exemption and not a caller writing one; the image
detector composes one step and four twice-wrapped shapes are measured as
undetected; a bundle is evidence of a record and not of its truth; a writer
signature names a key and not a service; and external anchoring is the one
fail-open subsystem in an otherwise fail-closed design. One fix in this
sub-phase changed production behaviour after the last adversarial pass and is
backed by its own drivers, its mutations and CI alone, and the intermittent
CI failure it would have been natural to credit it with is a different branch
that it demonstrably does not close. The claim the project shares at the end
of 3c is smaller than the one it could have written four sub-phases ago, and
every sentence of it has a test or a measurement behind it.
