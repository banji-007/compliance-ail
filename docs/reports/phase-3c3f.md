# Phase 3c-3f: Selectors and the trust anchor

**Run id:** `p3c3f-fix`. Working directory `C:\Users\banji\ail-p3c3f-fix`, a
scratch clone, never the primary working directory. Branch `p3c3b-order` at
`be73c4c`, continuing PR #14: no rebase, no second PR, no merge. Compose
project `p3c3ffix`, stated with `-p` on every invocation. All five images
built `--no-cache` at the start of the run. Keys generated in the clone with
the openssl commands `make keygen` runs, because `make` is not on PATH here.

**Baselines, before anything was changed.**

| | |
| :--- | :--- |
| `tests/test_route_parity.py` + `tests/test_bounded_reads.py` | **18 passed** |
| `tests/test_view_invariants.py` | **7 passed, 1 skipped** |
| `tests/test_committed_is_a_fact.py -k ordered_write_that_committed` | **1 passed** |
| `tests/test_image_contents.py -k detector` | **10 passed** |

**Six corrections raised against the instruction, four of them changing what
an item delivers.** They are in section 2, before the items, because two of
them change a stated mutation and one changes a stated fix.

---

## 1. Verdict per item

| Item | Verdict | In one line |
| :--- | :--- | :--- |
| P3c3f-1 | **Met, with a corrected condition** | The predicate is a named function both the call site and three enforcing tests drive. `is not None`, not the `is not False` the instruction named - see correction 1. |
| P3c3f-2 | **Met** | Property stated first; selector is the gate under any verb; both directions carry a test and direction two records that it has no instance. |
| P3c3f-3 | **Met** | gRPC sites enumerated, four REST spellings attributed, `tests/` walked. Nine reads in `tests/` carry the assertion through one shared check. |
| P3c3f-4 | **Met** | The position is read from `entry.score`; a disagreement answers `None` and logs both scores. |
| P3c3f-5 | **Met** | `seekKey` asserted and driven; coverage is per bound now. |
| P3c3f-6 | **Met** | Both call sites, both seeding paths, one class. One of the three mutations is caught in process rather than live - see correction 3. |
| P3c3f-7 | **Met** | Three shapes closed (base64-of-a-PEM, gzip, the twenty-run cap). The 16 KiB bound kept, with its cost measured and a second reason the measurement found. |
| P3c3f-8 | **Met** | The identity is judged on encodability as well as length; the digest fallback fires and the fault is written. |
| P3c3f-9 | **Met** | Both spellings caught, one mutation each, and the external check extracted so its own test drives it. |
| P3c3f-10 | **Met, one mutation unreachable as specified** | Four invariants over both views; the seam test seeds both sides. Restoring the skip produces a skip, which is never a failure - see correction 4. |
| P3c3f-11 | **Met** | ADR-0011 and README section 3.4 corrected at their sources, with D23's motivation explicitly left alone. |

**Verdict against the red team's own labels.**

| Claim | 3c-3e verdict | This phase |
| :--- | :--- | :--- |
| B1 | Refuted, twice | **Closed.** B1.1 by the selector (P3c3f-2), B1.2 by D47 (P3c3f-6). |
| B2 | **Not refuted** | Untouched. No cut was found where a committed write reports `committed: false`. |
| B3 | **Not refuted** | Untouched. The `require_transaction=False` narrowing still rests on `_has_tombstone`'s 409 in a different module, which is recorded in that report and is not an item here. |
| B4 | Refuted, three times | **Closed.** B4.1 by P3c3f-3 and P3c3f-4, B4.2 by the four spellings, B4.3 by per-bound coverage (P3c3f-5). |
| B5 | Refuted | **Closed for the detector gaps** (P3c3f-7). The 16 KiB and gzip-past-the-head bounds are kept and stated with their measured cost. |
| B6 | Refuted | **Closed** (P3c3f-8). |
| B7 | **Not refuted** | Untouched. |
| B8 | Refuted, twice | **Closed** (P3c3f-9). Two shapes the red team recorded without demonstrating - `docker-compose.override.yml` and the exact-match `STATEFUL_CONTAINER_PATHS` list - are **not** closed and are in section 8. |
| B9 | **Not refuted** | Untouched, and explicitly out of scope per the instruction. |
| B10 | Refuted, twice | **Closed** (P3c3f-10). |
| Also (the retry predicate) | Refuted | **Closed** (P3c3f-1). |

**Not refuted, and therefore not closed here: B2, B3, B7, B9.** Nothing in
this phase touches them and nothing here should be read as strengthening them.

---

## 2. Corrections raised against the instruction

Raised before building, per the standing rule. Four of the six change what an
item delivers.

### Correction 1. `is not False` is the wrong condition for a retry predicate

P3c3f-1 says the correction is "`is not False`, not `is True`", on the
argument that null is honest and false is the only lie. That is right about
the **assertion** and backwards about the **predicate**, because a predicate
answering `False` is what causes a retry:

| the route answered | what it means | what must happen | `is True` | `is not False` | `is not None` |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `true` | the fixture worked | stop, assert | stop | stop | stop |
| `false` | the fixture worked, the route lied | **stop, assert** | retry | **retry** | stop |
| `null` | the confirming read could not run | **retry** | retry | **stop** | retry |

`is not False` is wrong in both rows that matter: it retries exactly the
answer the test exists to catch, and it stops on the fixture miss and then
fails an assertion about the route on a fact about the fixture. The
implemented condition is `is not None`, and the table above is in
`confirming_read_could_not_run`'s docstring.

### Correction 2. P3c3f-6 dissolves P3c3f-2's `/verify` falsifier

The instruction is right that `POST /verify` is direction one
(property-and-not-selector) and not the converse. But D47 removes the anchor
mutation, so after this phase `/verify` is **property-false** and correctly
excluded, and a static test asserting "`/verify` is property-true and
uncovered" would fail on a correct head.

Implemented as a behavioural falsifier instead:
`test_no_route_outside_the_site_list_durably_changes_state` drives a route and
asserts the anchor does not move. Reintroducing the mutation makes the route
property-true while the selector still excludes it, and the test fails. That
is the same direction, checked by driving rather than by classification.

### Correction 3. P3c3f-6's `/write` mutation is not catchable live

The mutation is "restore the unconditional `rs.set` at either site". At
`POST /verify` a live test catches it. At `POST /write` it cannot: telling
"the anchor moved to the head" from "the anchor moved to this write's
transaction" requires the head to move between the write's commit and its own
state read, which is a race no external driver can aim at - the write is the
newest transaction at the moment it commits, so the two are the same number.

**Measured: the mutation left `tests/test_trust_anchor.py` at `4 passed`.**
The discriminating test is in process
(`tests/test_route_parity.py::test_no_route_outside_the_site_list_durably_changes_state`,
head 4242, write at 77), and it fails at `[77, 4242]`. Both tests are kept and
each says what it cannot discriminate.

### Correction 4. P3c3f-10's skip mutation cannot produce a failure

"Restore the skip. Named test must fail." A restored `pytest.skip` produces a
skip, and a skip is never in a failing set - which is the defect's own
signature and the reason the order sweep could not see it. Measured on a clean
ledger: `13 passed` becomes **`11 passed, 2 skipped`**.

Recorded as a count difference rather than converted into a failure. The
alternatives are a source parse for `pytest.skip` in that module, which is the
kind of check P3c3e-9 retired for cause, or a conftest hook turning skips into
failures suite-wide, which changes the meaning of every other skip in the
suite. Neither is bought here.

### Correction 5. The seam assertion was a tautology

`test_the_seam_between_history_and_allocation_holds` partitions rows BY the
reserve and then asserts `max(history) < min(live)`. Every history score is at
or below the reserve and every live score is above it by the definition of the
two lists, so once both are non-empty that assertion cannot fail. Seeding
instead of skipping would have turned a check that asserts nothing into a
check that asserts a tautology.

Rewritten so the falsifiable content is asserted over this test's own two
rows: the position the **ordered route** allocated is above the reserve, and
the position the **backfill shape** carries is at or below it and equals its
record's transaction. A writer that allocated inside the reserve fails the
first, which is what raising `AIL_RESERVED_POSITIONS` after allocation used to
do (D36). The ledger-wide sentence is kept, and the docstring says which half
follows from the partition.

### Correction 6. The 16 KiB bound has a second reason, and the measurement found it

P3c3f-7 offers "the bound stated as a limit with its measured cost recorded".
The cost is in section 7. The measurement also turned up something the
instruction did not anticipate: a whole-file walk of `decision-service`
returns **one hit**, a published test vector inside
`ecdsa/__pycache__/test_keys.cpython-311.pyc` at 62047 bytes. It is real
private key material by every rule in that module. Abandoning the bound
therefore means an exemption list keyed by path - name matching standing in
front of a content check, which is exactly what the Phase 3c-3d red team got
past and what the current detector exists to replace. Both reasons are in the
module docstring.

---

## 3. P3c3f-1. A retry never retries an assertion

**Reproduced, two ways.**

In process, against the real helper and the predicate exactly as the call site
spelled it. A route answers the A4.1 shape once and then correctly:

```
=== the predicate as the call site spells it: `committed is True` ===
  attempts driven          : 2
  what attempt 1 answered  : {'tx_id': None, 'seq': None, 'verified': False,
                              'committed': False, 'attempts': 1}
  what the test then asserts on: {'tx_id': 8, ..., 'committed': True}
  -> the A4.1 answer was retried past, and the assertion below it never saw
     it: True
```

And live, the red team's own injection: A4.1 put back into `verifier/main.py`
in intermittent form, the verifier rebuilt `--no-cache`, and the test run
against the stack.

```
$ python -m pytest tests/test_committed_is_a_fact.py -q -k ordered_write_that_committed
.                                                                        [100%]
1 passed, 8 deselected in 127.86s (0:02:07)

$ docker compose -p p3c3ffix ... exec -T verifier cat /data/verifier-state/a41_transcript
call 1: route ANSWERED committed=false tx_id=null; ledger state=present tx=21
        key=tool_call:p3c3e-ZZORDZZ:7c966ea0eabc4b0caa7c3e63e14617b8:query_database
call 2: route told the truth; tx=22
```

A record present in the ledger at transaction 21, reported as never having
happened, and the suite green.

**The sweep.** Every call site of every retry helper in `tests/`, read for an
assertion inside a predicate:

| site | predicate | verdict |
| :--- | :--- | :--- |
| `test_committed_is_a_fact.py::cut_until_it_lands` x4 call sites | see below | one of four held an assertion |
| `...ordered_write_that_committed...` | log + ledger + `committed is True` | **the defect** |
| `...plain_write...blackhole` | log + ledger | fixture conditions only |
| `...erasure...blackhole` | log + tombstone in ledger | fixture conditions only |
| `...retry_after_a_dropped_response...` | log + ledger | fixture conditions only |
| `compose_helpers.py::wait_for_health` | HTTP 200 from `/health` | a readiness poll, not an assertion |
| `test_content_states.py:436`, `test_deferred_verification.py::_verifier_healthy` | the same health poll | the same |
| `test_reconciliation.py::_wait_for_report` | a report file newer than the one on disk | a fixture condition; raises rather than returning on timeout |
| `test_anchored_export.py:345`, `test_audit_ordering.py` x6 | `for _ in range(N)` seed loops | not retries |

One site, and it is the one the red team found.

**Fix.** The third conjunct is `confirming_read_could_not_run(response)`, a
named module-level function, and the condition is `is not None` (correction
1). The call site reads
`not confirming_read_could_not_run(r[0])`.

**Enforcing, behavioural.** Three tests, no stack, no containers, no relay,
driving the real `cut_until_it_lands` with the real predicate against a route
that answers from a scripted list:

- `test_the_retry_helper_does_not_retry_past_a_route_that_says_committed_false`
- `test_the_retry_helper_still_retries_when_the_confirming_read_could_not_run`
- `test_the_retry_helper_stops_on_an_honest_answer`

The second and third exist so the first cannot be satisfied by a helper that
never retries.

**No source parse was added, in any form.** P3c3e-9 retired that check for
cause and it does not come back, not even as a declared second line.

**Mutation** (`p1-retry-predicate`): the predicate function returns
`is not True`, which is the call site's old condition.

```
FAILED tests/test_committed_is_a_fact.py::test_the_retry_helper_does_not_retry_past_a_route_that_says_committed_false
E  AssertionError: the helper drove 2 attempts. The route answered
   {'tx_id': None, ..., 'committed': False} on the first one, which is a
   record in the ledger reported as never written, and the predicate treated
   that as a fixture miss and retried past it.
1 failed, 2 passed, 9 deselected
```

Reverted: `3 passed`.

**The diagnosis task from the previous brief, answered.** The one-in-three
local failure was the property genuinely failing. CI's timing hit the retry
more often, so the retry hid it more often there.

---

## 4. P3c3f-2. The write-route selector

**The property, stated first and independently of the selector**
(`WRITE_ROUTE_PROPERTY`, in the module):

> A route of this service is a write route when calling it durably changes
> what this service holds - a record written into the ledger on the caller's
> behalf, or the persisted trust anchor every later proof is measured against.

The anchor clause is load-bearing rather than decoration: it is what makes
`POST /verify` a member of the property's set before D47 and not after.

**Reproduced.**

```
=== after: the identical handler under PUT, gated by the write key ===
  ['POST']    /write           gates=['_require_write_key']
  ['POST']    /write-ordered   gates=['_require_write_key']
  ['GET']     /state           gates=['_require_read_key']
  ['POST']    /verify          gates=['_require_read_key']
  ['PUT']     /write-express   gates=['_require_write_key']
  write_routes() derives: ['/write', '/write-ordered']
  /write-express in the site list? False
```

**Fix.** `write_routes()` selects on the dependency alone, over
`_service_routes()` - every route whose endpoint is defined in the verifier
module, under any verb, with FastAPI's own `/docs` and `/openapi.json`
excluded by where their endpoint lives rather than by a path list. The
"which gate does this route declare" check is widened the same way, with
`GET /health` recorded in `UNGATED_BY_DESIGN` with its reason, so a second
ungated route is no longer indistinguishable from it.

**Both falsifiers.**

*Direction one, property-true and selector-false.*
`test_a_write_route_is_selected_under_any_verb` builds a stand-in app with
write-gated routes under PUT, PATCH and DELETE and requires all three in the
site list. Three verbs rather than PUT alone, because "any verb but POST" is
the claim and one verb would be a second hand-list.

The `/verify` half of the same direction is
`test_no_route_outside_the_site_list_durably_changes_state`, driven rather
than classified (correction 2), plus `tests/test_trust_anchor.py` live.

*Direction two, selector-true and property-false.*
`test_every_selected_route_durably_changes_state` drives every selected route
and requires it to ask the ledger to write something. **There is no instance
in the tree today** and the test says so in its docstring rather than the
direction being omitted; the worked precedent for the other outcome is
`tests/test_bounded_reads.py`'s four `does_not_apply` entries.

**Mutation** (`p2-post-only-selector`): `and "POST" in route.methods` restored.

```
FAILED tests/test_route_parity.py::test_a_write_route_is_selected_under_any_verb
1 failed, 12 passed
```

**Exactly one test failed, and it is the direction-one falsifier.** The
mutation does not touch direction two, and this report says so rather than
claiming both, as the item requires.

Reverted: `13 passed`.

---

## 5. P3c3f-3. The bounded-read selector

**The property, stated first** (`BOUNDED_READ_PROPERTY`):

> A read is bounded when it asks the ledger for less than everything - a
> prefix, a key range, a score range. Every bounded read checks that what came
> back is inside the bound it asked for, because a bound that did not survive
> turns the read into an unbounded one with nothing saying so.

No transport in it. The Phase 3c-3e selector was about how a read asked.

**Reproduced.**

```
  any verifier/main.py site at all? []
  verifier/main.py::_committed_position_for in the enumeration? False
  any tests/ site at all? []
  tests/test_view_invariants.py walked by _module_files()? False
```

**Fix, three parts.**

1. **gRPC.** A call to `scan`, `zScan` or `zscan` carrying one of the SDK's
   own bound keywords (`prefix`, `seekKey`, `seekScore`, `minscore`,
   `maxscore`) is a site.
2. **The four REST spellings.** The URL is read from the first positional
   argument or from `url=`, through f-strings, `+` concatenation and one level
   of name resolution; bound keys resolve through names too, so
   `body[_BOUND]` is attributed.
3. **`tests/` is walked.** The exclusion was a selector and D46 says it
   inherits the decision.

**Both falsifiers.**

*Direction one.* `test_the_derivation_finds_the_reads_no_route_literal_names`
asserts the gRPC site and the `tests/` site by name, and runs the derivation
over the four spellings as source written in the test rather than added to the
tree - putting them in the tree to test for them would be putting them in the
tree.

*Direction two.* The `does_not_apply` entries in `COVERAGE`: four probe
scripts that read rows and discard them, one of which has the bound's own
behaviour as its subject. `test_a_read_recorded_as_not_applying_says_why`
enforces that each carries an argument.

**What the widened walk found, and what was done about it.**

| site | bounds | state |
| :--- | :--- | :--- |
| `verifier/main.py::_committed_position_for` | minscore, maxscore | driven (gRPC) |
| `control_plane/main.py::_faults_in_tx_window` | endKey, seekKey | driven |
| `anchor_service/main.py::collect_positions` | minScore | driven |
| `tools/ail_backfill_index.py::indexed_keys` | minScore | driven |
| `tools/ail_backfill_index.py::scan_all` | prefix, seekKey | driven, one driver per bound |
| `tests/test_view_invariants.py::_view_rows` | minScore | assertion added, driven |
| `tests/test_backfill_index.py::_view_rows` | minScore | assertion added, driven |
| `tests/test_audit_ordering.py::_view_rows_paged` | minScore | assertion added, driven |
| `tests/test_audit_ordering.py::_keys_under_prefix` | prefix | extracted from a test body, assertion added, driven |
| `tests/test_audit_read_correctness.py::_view_row_count` | minScore | assertion added, driven |
| `tests/test_reconciliation.py::_positions_for_key` | minScore | assertion added, driven |
| `tests/test_committed_is_a_fact.py::_members_at_position` | minScore, maxScore | assertion added, driven |
| `tests/test_raw_ledger_fields.py::_raw_scan` | prefix | assertion added, driven |
| `tests/test_record_profile.py::_raw_scan` | prefix | assertion added, driven |
| four probe scripts under `tools/` | various | `does_not_apply`, with reasons |

The nine reads in `tests/` share one copy of each check
(`tests/bounded_read_checks.py`) rather than nine near-identical assertions:
this repository has paid twice for a rule with two copies and nothing
comparing them.

**Mutations.** Two, one per half of the selector.

```
p3-rest-only-matcher  (the gRPC branch disabled)
  FAILED ...::test_the_derivation_finds_the_reads_no_route_literal_names
  FAILED ...::test_every_bound_at_a_driven_read_has_a_driver
  FAILED ...::test_no_entry_in_the_table_names_a_read_that_no_longer_exists
  3 failed, 18 passed

p3-exclude-tests      (`tests` back in the skip set)
  the same three, 3 failed, 18 passed
```

Reverted after each: `21 passed`.

---

## 6. P3c3f-4 and P3c3f-5. The two reads

### P3c3f-4. `_committed_position_for` reads what it asserts on

**Reproduced.**

```
  asked for      : minscore=1000000042.0 maxscore=1000000042.0
  ledger answered: this key at score 1000000007.0
  function returns: 1000000042
  -> the position it reports is the one it ASKED for: True
  control, the key absent from the answer: None
```

**Fix.** The score is read from the returned entry and compared with the one
asked for. On a disagreement the function answers `None` and logs at error
with both scores. `None` is what D45 already means by `seq: null` beside
`committed: true`; raising would change the response contract of the one
branch that exists to report uncertainty honestly. Pre-decided in the
instruction, and implemented as decided.

**Demonstration after the fix**, same probe: `function returns: None`.

**Enforcing.**
`tests/test_bounded_reads.py::COVERAGE["verifier/main.py::_committed_position_for"]`,
which drives the disagreement and a control where the index agrees, so a
function that always answers `None` fails.

**Mutation** (`p4-return-the-requested-score`): return `attempted_seq` on a
key match.

```
FAILED tests/test_bounded_reads.py::test_the_bounded_read_asserts_its_bound[verifier/main.py::_committed_position_for[0]]
1 failed, 33 passed
```

Recorded because it cost a round: mutating only the `return` expression is a
**no-op**, because on the path that reaches it the returned score and the
requested one are equal by construction. The mutation has to remove the
comparison.

### P3c3f-5. `scan_all`'s bound is driven

**Reproduced.**

```
  after 8 seconds against a client that ignores seekKey:
    scan_all has NOT returned and has NOT refused.
    pages requested so far: 767
  control, the bound the coverage table DOES drive (prefix):
    refused, as recorded
```

**Fix.** `seekKey` is exclusive and this scan is ascending, so every key on a
page after the first must sort strictly above the key that page seeked from.

**Enforcing.** A second driver on the same site, whose stub client gives up
after 50 pages - the page budget is the difference between the mutation
failing this test and hanging it - and which asserts the refusal arrives on
page two, the first page that carries a `seekKey` at all.

**And the enumeration changed shape**, which is the half that stops this
recurring: `COVERAGE` pairs each driver with the bounds it drives, and
`test_every_bound_at_a_driven_read_has_a_driver` compares that against the
bounds the derivation attributes to the site, in both directions.

**Mutation** (`p5-drop-the-seek-key-bound`):

```
FAILED tests/test_bounded_reads.py::test_the_bounded_read_asserts_its_bound[tools/ail_backfill_index.py::scan_all[1]]
1 failed, 1 passed, 19 deselected
```

---

## 7. P3c3f-6. The anchor (D47)

**Reproduced live, the red team's B1.2 verbatim, against this session's
stack:**

```
1. one write through the verifier            200 {'tx_id': 1, 'verified': True, 'committed': True}
2. the persisted trust anchor now            {"immudb:3322/b'defaultdb'": 1}
3. four writes straight to ImmuDB            ledger head is now tx 5
4. the anchor, unchanged                     {"immudb:3322/b'defaultdb'": 1}   unchanged: True
5. POST /verify, READ key only               200 {'verified': True, 'tx_id': 1, 'state_id': 5}
6. the anchor AFTER the read                 {"immudb:3322/b'defaultdb'": 5}
   the read-gated route changed durable state: True
```

**After the fix, the same probe:**

```
5. POST /verify, READ key only               200 {'verified': True, 'tx_id': 29, 'state_id': 33}
6. the anchor AFTER the read                 {"immudb:3322/b'defaultdb'": 29}
   the read-gated route changed durable state: False
```

`state_id` still reports the head. The response contract is unchanged; what
changed is that reporting it no longer persists it.

**Fix, one helper and one class.**

`head_state(client)` makes the `CurrentState` RPC directly, checks the
signature when a key is configured, and writes nothing. Three call sites use
it: `POST /verify`'s unanchored path, `POST /write`'s D40 state read, and
`GET /state`, which had made the same argument in Phase 3b and held its own
copy of the code.

`_VerifiedRootService` replaces the SDK's `PersistentRootService` and covers
all three ways a state reaches the anchor:

- `init`'s seed, when the state file is absent or unreadable - the first boot
  of any deployment, and the source of its first proof.
- `get`'s seed, when the cache is `None`.
- `set`.

Each is checked: the ImmuDB signature must verify, and the anchor never moves
backwards, because an anchor that can go backwards can be replayed to a point
before a record was written. A `txId` of 0 is accepted unsigned - an empty
ledger has no history to be lied about, and refusing there would mean a stack
with no signing key cannot start rather than cannot anchor.

**The state FILE is read exactly as before, deliberately.** D47 names the two
`CurrentState` seeds, not the file. That file is the operator's own volume and
corrupting it is the ADR-0006 `consistency_failure` vector
`tests/anchor_helpers.py` drives; verifying its signature here would discard
the corruption and re-seed from the server, deleting a detection rather than
adding one.

**Enforcing:** `tests/test_trust_anchor.py`, four tests - one per call site,
one for the cold boot, and one driving `_VerifiedRootService`'s three
entry points inside the running image against states that do not check out,
each with its own control.

**Mutations, three.**

| mutation | result |
| :--- | :--- |
| `p6-verify-current-state` | `FAILED test_a_read_does_not_move_the_persisted_trust_anchor`, 1 failed 3 passed |
| `p6-unchecked-seed` | `FAILED test_both_seeds_and_the_write_refuse_a_state_nothing_verified`, 1 failed 3 passed |
| `p6-write-current-state` | `tests/test_trust_anchor.py`: **4 passed** (correction 3). Against the in-process driver: `FAILED tests/test_route_parity.py::test_no_route_outside_the_site_list_durably_changes_state`, `AssertionError: ... [77, 4242]` |

Each rebuilt `--no-cache` and reverted; the clean head is `4 passed`.

**Nothing was escalated.** No caller depends on the anchor advancing past the
transaction a proof ran to: the anchored path already used `_PinnedRootService`,
`GET /state` already made the direct RPC, and `state_id` is unchanged in the
response.

**The known flake this item was expected to move** is section 9.

---

## 8. P3c3f-7, P3c3f-8, P3c3f-9

### P3c3f-7. Key material detection

**Reproduced**, against the same detector:

```
  raw base64 of the PEM text                     None
  a Kubernetes Secret manifest carrying it       None
  a .env line carrying it                        None
  PEM inside a .gz                               None
  PEM after 16 KiB of padding                    None
  base64 DER behind 21 decoy base64 runs         None
    control, the same behind 19 decoys           base64-sec1-der
  --- controls: the shapes the module enumerates ---
  bare PEM / bare DER / base64 of DER            pem / sec1-der / base64-sec1-der
```

**Three closed, one kept.**

- **base64-of-a-PEM: a detector gap, closed.** A decoded base64 body is
  offered to the PEM armour rule as well as to the binary rule. A `.env` line
  needed one thing more: `=` is base64 padding and is only valid at the end,
  so a run holding `NAME_B64=<body>` is a name, an assignment and then a body.
  The run is offered whole and then in the pieces the padding cuts it into,
  each re-padded.
- **The twenty-run cap: closed.** Measured cost of removing it, inside
  `decision-service` over 6800 files: `17.7s, 16.5s` capped against
  `18.5s, 18.3s` uncapped.
- **gzip: closed rather than bounded.** A failed `gzip.decompress` on a 16 KiB
  head measures 0.010 ms and the four-image pass did not move. Anchored at
  offset zero by the magic, output bounded to 16 KiB so a crafted member costs
  no more than an ordinary file. What is still not caught, and is stated: a
  member whose compressed form runs past the head, which raises `EOFError`.
- **The 16 KiB head bound: kept, with its cost, and with a second reason.**

```
  16 KiB head, first 20 base64 runs (the old detector)   17.7s, 16.5s
  16 KiB head, every base64 run (this phase)             18.5s, 18.3s
  whole files, every base64 run                          57.5s, 57.4s
```

3.1 times the work on the running-filesystem surface, four images and two
surfaces, against a pass that already measures about three and a half minutes.
And the whole-file walk returns a hit on
`ecdsa/__pycache__/test_keys.cpython-311.pyc`, a published test vector in a
dependency's bytecode, which would need an exemption list keyed by path -
correction 6. Both reasons are in the module docstring.

**Enforcing.** Five new rows in `KEY_ENCODINGS`, each built from a real
in-process P-256 key: `base64-of-a-pem`, `kubernetes-secret`, `dotenv-line`,
`gzipped-pem`, `base64-behind-21-decoy-runs`.

**Mutation** (`p7-head-only-pem`):

```
FAILED ...[base64-of-a-pem]   FAILED ...[dotenv-line]   FAILED ...[kubernetes-secret]
3 failed, 10 passed
```

### P3c3f-8. A `call_id` that cannot be encoded

**Reproduced** through the real `POST /write` route function against a client
whose proof fails:

```
=== control: an ordinary 32-character call_id ===
    fault_record     : ledger_fault:00000000000000000077:c8c3623f...:04ff7562
    unverified writes the route actually made: 1
=== control: a 1200-character call_id, which P3c3e-6 closed ===
    fault_record     : ledger_fault:00000000000000000077:key:b8d2ac60...:ddd7abb9
=== ATTACK: 300 lone surrogates ===
    committed        : True   tx_id: 77
    fault_record     : None
    fault_record_err : UnicodeEncodeError: 'utf-8' codec can't encode
                       characters in position 34-333: surrogates not allowed
    unverified writes the route actually made: 0
```

**The item's own framing, honoured.** The defect is not loudness: on unmodified
head `fault_record_error` carried the exception and `_fault_failure_detail`'s
sentence was already in `detail`. The defect is that `_fault_identity` judged
the call_id on length alone, so an identity that could never be written was
never judged unusable and the digest fallback never fired.

**After the fix**, same probe: `fault_record:
ledger_fault:00000000000000000077:key:4ce4a56d...`, `fault_record_err: None`,
`unverified writes: 1`.

**Enforcing.**
`test_a_call_id_that_cannot_be_encoded_is_refused_as_an_identity_too`, beside
the over-long sibling it mirrors, with a control that an ordinary
300-character call_id is still accepted so the refusal is about encodability
rather than length.

**Mutation** (`p8-no-encodability-check`): `FAILED
tests/test_fault_key_and_page_read.py::test_a_call_id_that_cannot_be_encoded_is_refused_as_an_identity_too`,
1 failed 18 passed.

### P3c3f-9. Compose mount spellings

**Reproduced:**

```
  mounts the parse produced : [('immudb', 'type', ' bind'),
                               ('verifier', 'verifier-state', '/data/verifier-state')]
  stateful mounts it will examine: [('verifier', 'verifier-state', '/data/verifier-state')]
  external volumes it will report: []
```

**Verified against Compose itself**, `docker compose -p p3c3ffixb9 config` on
the same file: the long form resolves to `type: bind` with an absolute host
`source`, and `external: True` resolves to `external: true`.

**Enforcing.** `test_a_long_form_bind_mount_of_the_ledger_is_seen` (with the
short-form mount in the same file asserted as a control, so a parse returning
nothing cannot pass it) and
`test_an_external_volume_is_seen_whatever_case_yaml_spells_true_in` over
`true`, `True` and `TRUE`, with a no-external control.

**Mutations, one per defect, as the item requires.**

```
p9-short-form-only-mounts      FAILED ...::test_a_long_form_bind_mount_of_the_ledger_is_seen
p9-case-sensitive-external     FAILED ...::test_an_external_volume_is_seen_whatever_case_yaml_spells_true_in
```

**One thing this cost, recorded because it is the phase's own subject.** The
second mutation first came back **`6 passed`**: the enforcing test spelled the
`re.search(...)` inline instead of calling the check the production test uses,
so mutating one left the other passing. Extracted to `external_volumes()`,
which both now call, and the mutation fails.

**Not closed, and stated:** `COMPOSE_FILES` does not include
`docker-compose.override.yml`, which `docker compose` loads by default when
present, and `STATEFUL_CONTAINER_PATHS` is an exact-match hand list. The red
team recorded both without demonstrating them; neither is an item here and
neither is fixed.

---

## 9. P3c3f-10. Ledger-wide invariants over both views

**Reproduced.** The identical fractional position above the reserve, injected
into the intent view:

```
   injected  tool_call_intent:p3c3f-red-intent:e2f11bc5...:query_database
   at        1000000000.5 in ail_view:intent:v1
     7 passed, 1 skipped in 12.94s
```

Plus the skip itself, on every clean-ledger run:

```
SKIPPED [1] tests\test_view_invariants.py:253: this ledger has no records on
one side of the seam yet
```

**Fix.** `VIEWS` is `(decision, intent)`, every invariant is parameterised over
it, and `test_this_module_walks_every_view_the_verifier_writes` checks that
list against `verifier/main.py::_VIEW_SETS` read from source - so a third view
is this module's failure rather than its blind spot. The seam test seeds both
sides through `_seed_one` and a new `_seed_one_history`, which writes a record
and zAdds it at its own transaction, the shape the backfill produces.

Correction 5 applies here: the ledger-wide seam assertion follows from the
partition, and what the test now establishes that can fail is the pair of
writers.

**Demonstration after the fix**, the same injection:

```
FAILED tests/test_view_invariants.py::test_every_allocated_position_is_an_integer_or_a_registered_violation[ail_view:intent:v1]
E  AssertionError: position(s) in ail_view:intent:v1 above the reserve that
   are not integers and are not registered in tests/ledger_pollution.py:
   [('tool_call_intent:p3c3f-red-intent:a08ada29...:query_database', 1000000000.5)]
1 failed, 12 passed
```

The stack was torn down with `-v` and brought back afterwards, because
ImmuDB's zset has no remove and the injection is permanent for a ledger's
lifetime.

**Clean head:** `13 passed` where it was `7 passed, 1 skipped`.

**Mutations.**

```
p10-single-view-walk    FAILED ...::test_this_module_walks_every_view_the_verifier_writes
                        1 failed, 8 passed
p10-restore-the-skip    11 passed, 2 skipped   (correction 4: not a failure,
                        and cannot be made one without a check retired for cause)
```

---

## 10. P3c3f-11. The tier and anchor claims

Corrected at their sources, not only in the README.

**`docs/adr/0011-verifier-authentication.md`** gains a paragraph under the
cross-tier bullet: what that bullet validates is route separation, and it says
nothing about side effects. The natural reading of "read tier" was false here
for two phases, with the red team's transcript. It records that D47 makes the
read tier side-effect free on the routes that exist and that the property has
a test behind it now rather than being an inference from the bullet.

**`readME.md` section 3.4** keeps the volume-separation sentence, narrowed to
what it actually says ("cannot rewrite the anchor by writing to that volume"),
and adds the paragraph that the natural inference was false, with the
transcript and the pointer to `tests/test_trust_anchor.py`.

**D23's motivation is untouched, and both corrections say so explicitly**, so
neither reads as wider than it is: external anchoring rests on the local
anchor being inside the operator's control, which held either way. What
changed is which callers could move it.

---

## 11. The handed-over hypothesis

`docs/reports/phase-3c3e.md` section 16 item 2: an anchor advancing "for a
reason nobody has named", behind an intermittent failure of
`test_a_write_that_committed_is_reported_as_committed_when_the_state_call_fails`.
The named path is `control_plane/main.py::_has_tombstone`, which calls
`POST /verify` on every `POST /content`, and `POST /verify` advanced the
anchor.

That test's flaking assertion is `if body["verified"]: assert str(ledger_tx) in
after` - the persisted anchor must carry the write's own transaction. Before
D47 the anchor was whatever the head was at the moment of the last
`currentState()`, from this route or from any concurrent `/verify`.

See section 12 for what was measured and what that does and does not
establish.

---

## 12. Measurements

_(filled in below)_

---

## 13. Mapping

| Item | Decision | Changed | Enforced by |
| :--- | :--- | :--- | :--- |
| P3c3f-1 | - | `tests/test_committed_is_a_fact.py` | `test_the_retry_helper_does_not_retry_past_a_route_that_says_committed_false` + two controls |
| P3c3f-2 | D46 | `tests/test_route_parity.py` | `test_a_write_route_is_selected_under_any_verb`, `test_every_selected_route_durably_changes_state`, `test_no_route_outside_the_site_list_durably_changes_state` |
| P3c3f-3 | D46 | `tests/test_bounded_reads.py`, `tests/bounded_read_checks.py`, nine test modules | `test_the_derivation_finds_the_reads_no_route_literal_names`, `test_every_bounded_read_has_a_recorded_state`, `test_a_read_recorded_as_not_applying_says_why` |
| P3c3f-4 | - | `verifier/main.py::_committed_position_for` | `COVERAGE["verifier/main.py::_committed_position_for"]` |
| P3c3f-5 | - | `tools/ail_backfill_index.py::scan_all` | `COVERAGE[...scan_all]` driver 1, `test_every_bound_at_a_driven_read_has_a_driver` |
| P3c3f-6 | D47 | `verifier/main.py`: `head_state`, `_VerifiedRootService`, `_state_verifying_key`, three call sites | `tests/test_trust_anchor.py` (4), `test_no_route_outside_the_site_list_durably_changes_state` |
| P3c3f-7 | - | `tests/test_image_contents.py` detector and docstring | five new `KEY_ENCODINGS` rows |
| P3c3f-8 | - | `verifier/main.py::_fault_identity` | `test_a_call_id_that_cannot_be_encoded_is_refused_as_an_identity_too` |
| P3c3f-9 | - | `tests/test_ledger_state_does_not_survive_teardown.py` | `test_a_long_form_bind_mount_of_the_ledger_is_seen`, `test_an_external_volume_is_seen_whatever_case_yaml_spells_true_in` |
| P3c3f-10 | - | `tests/test_view_invariants.py` | four invariants x two views, `test_this_module_walks_every_view_the_verifier_writes` |
| P3c3f-11 | D46/D47 | `docs/adr/0011-verifier-authentication.md`, `readME.md` | prose; the behaviour is enforced by `tests/test_trust_anchor.py` |

---

## 14. Pre-registered negatives

Each derived per row, individually, at the end.

| Negative | Result | How it was established |
| :--- | :--- | :--- |
| Any enumeration whose property is stated only as what its selector selects | **False** | Both files carry a `*_PROPERTY` constant written before the selector, and both are quoted in failure messages. |
| Any enumeration whose selector lacks a falsifier in either direction, or whose uninstantiated direction is omitted rather than recorded | **False** | Four falsifier tests across the two files; direction two of the write-route selector is recorded as uninstantiated in `test_every_selected_route_durably_changes_state`'s docstring and still driven positively. |
| Any assertion inside a retry predicate, established behaviourally rather than by a parse | **False** | The sweep table in section 3; the one site is fixed and the enforcing tests drive the real helper. |
| Any anchor written or seeded from a state nothing verified | **False** | `_VerifiedRootService` covers `init`, `get` and `set`; driven inside the image with controls, and three mutations. |
| Any bounded read whose bound is asserted but never driven | **False** | `test_every_bound_at_a_driven_read_has_a_driver`, in both directions. |
| Any position returned that was not read from what came back | **False** | `_committed_position_for` reads `entry.score`; the mutation fails. |
| Any ledger-wide invariant enforced over one view, or over zero rows | **False** | Four invariants x two views; every one seeds; `test_this_module_walks_every_view_the_verifier_writes`. |
| Any detector bound kept without its cost measured and recorded | **False** | The 16 KiB bound is the only one kept; its cost and its second reason are in the module docstring. |
| Any Claim cell describing a goal rather than a behaviour | **False** | The four `PROPERTIES` claims are unchanged from 3c-3e and each names an observable; correction 5 removed the one assertion that could not fail. |
| Any assertion weakened, or any refutation closed by narrowing the claim without saying so | **False** | Section 2 records every place the delivered fix differs from the instruction. |

---

## 15. Residual limits, restated

Unchanged by this phase and stated so they are not read as closed:

- The unverified-write path's caller count is not enforced. The runtime guard
  bounds what it writes; nothing bounds how many callers reach it.
- `/write-ordered` accepts a key of any shape into a view.
- 35 test modules were never isolated; isolation was per module, not per test.
- `COMPOSE_FILES` does not include `docker-compose.override.yml`, and
  `STATEFUL_CONTAINER_PATHS` is an exact-match hand list (section 8).
- The bounded-read derivation reads call sites, so a read behind an
  argument-taking helper is invisible; a gRPC bound passed positionally is
  invisible; name resolution is one level. All three are in the module
  docstring.
- The 16 KiB head bound and gzip-past-the-head, with their measured cost.

---

## 16. Could not verify

1. **The `/write` anchor mutation, live.** Correction 3: not catchable from
   outside the process. Caught in process instead, and both tests say so.
2. **The skip mutation as a failure.** Correction 4.
3. **The full local suite.** This host has a standing ~50-failure baseline from
   two causes that are not about the code (`sigstore` cannot be installed into
   the host Python, and the in-process decision-service tests cannot resolve
   compose service names). CI is the signal; what was checked locally is that
   no test this phase owns is among the failures.
