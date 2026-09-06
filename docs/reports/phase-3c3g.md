# Phase 3c-3g: falsifiers that can fail

**Run id:** `p3c3g-fix`.
**Working directory:** `C:\Users\banji\OneDrive\Documents\p3c3g-fix`, a scratch
clone, never the primary working directory.
**Branch:** `p3c3b-order`, continuing PR #14. Not `p3c3g-fix`: the run id names
the run, and PR #14's head is `p3c3b-order`. A branch named after the run id
was created and pushed early in this session by mistake and would have needed
a second PR, which this phase's instruction forbids. It was moved onto
`p3c3b-order` and deleted from the remote before any further commit. No PR was
ever opened for it.

**Base:** `2cdcec3`, the branch head, after the R6 fix landed out of band
(`6f5f51b`, `81efc24`). No rebase, no merge, no second PR.

**Keys** were generated in the clone with the openssl commands `make keygen`
runs, because `make` is not on PATH here. Without them
`tests/test_route_parity.py` reads `1 failed` at baseline, on the fault-record
write path, which is an environment fact and not a regression.

**Baseline before anything was touched:** `tests/test_route_parity.py` =
**13 passed**, identical to the figure the Phase 3c-3f red team recorded.
`bounded_read_sites()` = **19 sites**.

---

## What this phase changed about D48 before building it

D48 as handed over said "break the selector, require the falsifier to fail",
and gave one worked instance: make `_service_routes` return `[]` and require
`test_a_write_route_is_selected_under_any_verb` to fail, which it "does not
today, because it never calls the real one".

**Both halves of that instance are wrong, measured.** The falsifier does call
the real selector: `write_routes()` at `tests/test_route_parity.py:218` calls
`_service_routes(verifier)`, and the falsifier reaches it through
`write_routes(stand_in)`. And with the selector gutted, it fails.

| mutation of `_service_routes` | the falsifier | whole file |
|---|---|---|
| A. `return []`, the instance D48 prescribed | **failed** | 2 failed, 5 passed, 1 skipped |
| B. drop the `__module__` conjunct, keep `isinstance` | passed | **13 passed**, identical to baseline |
| C. invert the discriminator to `!=` | failed | 2 failed, 5 passed, 1 skipped |

Mutation A was already satisfied before this phase began. B is the mutation
nothing saw, and B is one clause, not the whole selector.

**So the checkable form is per clause:** each discriminating clause of a
covered selector is mutated individually, and a named falsifier must fail for
each. A clause whose removal changes nothing on the real app is dead, and the
finding for a dead clause is deletion rather than a falsifier.

Two further things row A settled, and both shaped the check:

  * The whole-file total under A is **eight outcomes against a baseline of
    thirteen**. Five parametrised cases were never generated, because they
    parametrise over an empty `write_routes()`. A broken selector can delete
    the tests that would catch it rather than fail them, and a failure count
    cannot tell those apart. The check therefore pins a node id and requires
    it to **run and fail**; a vanished id reports as "no tests ran", which is
    a failure of the check.
  * One of A's two failures is
    `test_the_write_routes_are_selected_by_their_gate_and_not_by_their_path`
    failing on its `assert gates`, which is **not a falsifier**. A check
    phrased as "break it and require some failure" is satisfiable with no
    falsifier in existence.

### Three dispositions, not two

Rows two and three below read identically under a green suite. Only the
selector's output set separates them, which is why deadness is measured as a
set comparison and the suite result is corroboration.

| removing the clause | disposition | finding |
|---|---|---|
| changes the selector's output, named falsifier fails | live, checked | none |
| changes the output, no falsifier fails | live, **unchecked** | write the falsifier |
| leaves the output identical | dead | delete, if it also has a cost |

**Deadness is a fact about a selector against one app, so the app is
recorded.** The measurement for `_service_routes` was taken against the
verifier application as registered at `2cdcec3`:

```
  Route     /openapi.json          fastapi.applications
  Route     /docs                  fastapi.applications
  Route     /docs/oauth2-redirect  fastapi.applications
  Route     /redoc                 fastapi.applications
  APIRoute  /health                the verifier module
  APIRoute  /write                 the verifier module
  APIRoute  /write-ordered         the verifier module
  APIRoute  /state                 the verifier module
  APIRoute  /verify                the verifier module
```

Five `APIRoute`s with the conjunct, five without. And deletion is not
justified by deadness alone: the `__module__` conjunct is deleted because it
is dead **and** costly, excluding every route mounted from a router. A dead
clause with no cost is a tidying job, not a finding.

### How D48's own coverage is established

Not by anything derived. `D48_CLAUSES` in `tests/test_selector_clauses.py` is
typed out by hand, and `test_every_clause_of_a_covered_selector_has_a_recorded_state`
compares it against a second hand-typed list,
`CLAUSES_IN_THE_COVERED_SELECTORS`. Two hand-lists that must agree is weaker
than a derivation and stronger than one hand-list. Nothing parses a selector
to find its conjuncts, because deriving them needs a selector over selectors,
which is the regress D48 is bounded against.

**The establishment was mutation-driven, and one mutation refuted the file's
own first classification.** The `isinstance(route, APIRoute)` clause was
first recorded as not falsifiable, on the measurement that breaking it errors
during collection: two tests parametrise over `write_routes()`, so a
source-level edit is live before any test runs. The plugin rebinds the
selector **after** collection, where the same break reads `7 failed, 8 passed`
and is perfectly falsifiable. D48's own check caught that stale exemption on
its first run, and it became a real falsifier.

The `does_not_apply` state consequently has no members today. It is kept, and
reported as `1 skipped` rather than removed, because a three-state design
whose third state is deleted the moment it is empty is a two-state design.

---

## Verdicts

| finding | verdict | where |
|---|---|---|
| R1 write-route enumeration | **closed** | P3c3g-1 |
| R2 the unenumerated bounded read | **closed** | P3c3g-4 |
| R3 the vacuous bound assertions | see P3c3g-2 | P3c3g-2 |
| R4 the substring exemption | see P3c3g-3 | P3c3g-3 |
| R5 the order-dependent registry test | see P3c3g-3 | P3c3g-3 |
| R6 sound proof reported as tamper evidence | closed out of band | `r6-headstate.md` |
| R7 the teardown check and the default override file | **refuted, demonstrated, not closed here** | below |

**R7 is given a verdict line although the instruction's list stops at R5.**
The red team refuted seven things and the report's verdict list covers R1 to
R5 plus R6 out of band, so R7 had no slot. It is recorded rather than lost.
The instruction's P3c3g-5 says `docker-compose.override.yml` "remains
undemonstrated"; that is wrong. The Phase 3c-3f red team demonstrated it with
a control: the suite reads `6 passed` with the mount line in
`docker-compose.override.yml` and `1 failed` with the identical line in
`docker-compose.yml`. It is still unfixed at `2cdcec3`, where `COMPOSE_FILES`
is `("docker-compose.yml", "docker-compose.test.yml")` and no override is
loaded. Not built this phase: it is out of every item's scope and building it
would grow the phase. It carries forward as demonstrated and unfixed, not as
undemonstrated.

---

## P3c3g-1. The route selector, and D48's first instance

**Verdict: R1 closed.**

### Reproduced before the fix

A new module holding an `APIRouter` with one `POST /write-express` handler
gated by `_require_write_key`, mounted with `app.include_router`. The handler
does an unverified `client.set()` under a caller-supplied key: it allocates no
position, carries no `KeyMustNotExist`, refuses no fault record, and answers a
hardcoded `committed: true`. It holds none of the four write properties.

```
$ python -m pytest tests/test_route_parity.py -q
13 passed, 1 warning in 9.51s
```

Identical to baseline. What the selectors saw with it present:

```
ALL APIRoutes registered on the app:
  ['POST']     /write-express   module=verifier.extra_routes  gates=['_require_write_key']
  ['GET']      /health          module=parity_verifier_<uuid>  gates=[]
  ['POST']     /write           module=parity_verifier_<uuid>  gates=['_require_write_key']
  ['POST']     /write-ordered   module=parity_verifier_<uuid>  gates=['_require_write_key']
  ['GET']      /state           module=parity_verifier_<uuid>  gates=['_require_read_key']
  ['POST']     /verify          module=parity_verifier_<uuid>  gates=['_require_read_key']

_service_routes() sees : ['/health', '/state', '/verify', '/write', '/write-ordered']
write_routes()   sees : ['/write', '/write-ordered']
```

**Control**, the same handler under the same verb, path, gate and body defined
in the verifier module so only `endpoint.__module__` differs:

```
3 failed, 10 passed, 1 warning in 13.67s
  test_every_selected_route_durably_changes_state
  test_every_write_route_has_a_recorded_state_for_every_property
  test_no_write_route_reaches_the_unverified_path_with_anything_but_a_fault_record
```

### The fix is a deletion

The conjunct's stated justification was false. FastAPI's four framework routes
are `starlette.routing.Route`, not `fastapi.routing.APIRoute`, so
`isinstance(route, APIRoute)` already excluded all four on its own and the
`__module__` comparison excluded nothing. The docstring at
`tests/test_route_parity.py:185-190` claimed otherwise and is corrected at
source. `docs/reports/phase-3c3f-redteam.md` carried the same claim and has a
dated erratum.

### Demonstrated after the fix

The same included router, unchanged:

```
3 failed, 10 passed, 1 warning in 5.33s
```

The same three tests as the control. The attack, re-run verbatim, no longer
works.

### Enforced

`test_a_route_from_an_included_router_is_selected`, a permanent falsifier
rather than a probe. The handler's `__module__` is assigned rather than the
handler living in a committed module: a real second module under `verifier/`
would ship an ungated unverified write route into the image to make a test
fail.

### Mutation, substituted and recorded

The instruction's mutation is "restore the `SimpleNamespace` construction".
After the deletion nothing reads `verifier.__name__`, so restoring that field
mutates something nothing looks at and cannot fail. A named mutation that
cannot fail is the class D48 exists to find, arriving through D48's own
instruction.

**The mutation is restoring the `__module__` conjunct.** Both falsifiers fail,
each by its own `AssertionError` rather than by an `AttributeError`:

```
2 failed, 12 passed
  test_a_write_route_is_selected_under_any_verb
  test_a_route_from_an_included_router_is_selected
```

The stand-ins carry a `__name__` that deliberately differs from the handlers'
module. Dropping the field entirely, which the deletion first invited, made
this mutation fail with `AttributeError: 'types.SimpleNamespace' object has no
attribute '__name__'`, which is a test failing for the wrong reason.

### A second defect, found by mutating the other clause

`write_routes` discriminates on `"_require_write_key" in _gate_names(route)`.
Replacing that with `"write" in route.path`:

```
14 passed
```

`test_the_write_routes_are_selected_by_their_gate_and_not_by_their_path` is
named for exactly this property and its body never checks it. It asserts that
every route declares a gate, that `UNGATED_BY_DESIGN` is neither stale nor
thin, that something is selected, and that `/verify` is not selected.
`/verify` carries no "write" in its path, so a path rule satisfies every one
of those. The other two falsifiers use `/write-express`, `/write-amend` and
`/write-retract`, all of which carry the substring.

This is not deadness. Dropping the gate conjunct entirely sweeps in all five
routes and fails. The two rules merely **coincide on the app as it stands**,
which only a replacement mutation shows, and which is the concrete argument
for per-clause over per-selector.

`test_the_selector_is_the_gate_and_not_the_path` falsifies both directions: a
route gated by the write key with no "write" in its path must be selected, and
a route carrying "write" gated by the read key must not. Under the
substitution it is the only failure, `1 failed, 14 passed`.


### D48's check, and what it cost

`tests/test_selector_clauses.py` plus a `tests/d48_break.py` plugin. The
plugin rebinds the selector as a module attribute after collection rather than
rewriting source: a mutated copy written beside the original is collectable by
a concurrent run, and written elsewhere it computes the wrong `REPO_ROOT` from
its own `__file__`. Rebinding reaches the caller because every selector in
scope is resolved as a module global at call time.

Six clauses, two files, one subprocess each: `8 passed, 1 skipped in 227.44s`.
Run twice independently with the same result. Nearly four minutes of CI for
six clauses is the honest cost of this shape, and it grows linearly with the
hand-list.

**The check was demonstrated to fail, two ways.** Pinned to
`test_the_write_routes_are_selected_by_their_gate_and_not_by_their_path`,
which cannot fail under its clause's break, it fails on the outcome
assertion. Pinned to a node id that does not exist, it fails on the
did-not-run assertion rather than reading green.

**One piece of the plugin's own machinery had to be fixed for the same
reason.** `bounded_read_sites()` is `lru_cache`d. A break installed after
something had already walked the tree would have been invisible, and the
falsifier would have passed against a cached answer the unbroken selector
produced. The plugin clears it.

---

## P3c3g-4. The count read

**Verdict: R2 closed.** Built as one pass with the D48 clauses for
`tests/test_bounded_reads.py`, because they meet on the same read.

### Reproduced

`bounded_read_sites()` returned **19 sites** and
`control_plane/main.py::_ledger_decision_count` was not among them. It is
invisible three times over: the route is not one of the two scan routes, the
bound is a URL path segment rather than a JSON body field, and the call is
`client.get` where the body walk reads `json=`.

### The three clauses that hid one read

This is the concrete argument for per-clause over per-selector, and the code
makes it rather than anyone's judgement. R2's read is missed by
`BOUNDED_ROUTES`, by `_bound_keys` reading only a JSON body, and by the REST
detection looking at a `post`. Mutating the selector as a whole says only that
something is wrong. Mutating each clause says which.

### The derivation invented a site, immediately

The first thing the widened derivation did was attribute a bounded read to the
`raise BoundedReadFault(f"...{IMMUDB_URL}/api/v2/db/count/ ...")` that this
item adds, because a `raise` is an `ast.Call` whose first argument is a string
naming the route. Two `print` headings in `tools/immudb_read_api_probe.py` do
the same. Audited, every call in the tree whose target names the route:

```
  control_plane/main.py:1378                call='get'   kept
  control_plane/main.py:1371                call=None    dropped  (the raise)
  tests/test_audit_read_correctness.py:195  call='get'   kept
  tools/audit_read_cost_probe.py:70         call='get'   kept
  tools/audit_read_cost_probe.py:123        call='get'   kept
  tools/immudb_read_api_probe.py:67         call=None    dropped  (a print)
  tools/immudb_read_api_probe.py:70         call='get'   kept
  tools/immudb_read_api_probe.py:74         call=None    dropped  (a print)
  tools/immudb_read_api_probe.py:75         call='get'   kept
  tools/immudb_read_api_probe.py:82         call='get'   kept
  tools/immudb_read_api_probe.py:86         call='get'   kept
```

The verb guard drops three, all of them sentences about a read rather than
reads. An invented site is not harmless: each needs a `COVERAGE` entry, so the
table fills with exemptions for calls that read nothing, and an exemption is
what a real unbounded read would want to be mistaken for.
`test_a_string_that_merely_names_a_route_is_not_a_read` falsifies the guard in
both directions.

### The bound is checked before the request, and only here

D42's rule is that the assertion bites on what came back, because ImmuDB drops
an unrecognised parameter without comment and the response is the only place
the difference shows. **A count has no rows.** The response is one integer,
and a prefix-bounded count and a ledger-wide count are both plausible
integers. There is nothing in the answer to check.

So `_ledger_decision_count` refuses, fail-closed, to issue a count whose
prefix segment is empty. What is enforced is that the request carried its
bound. **That is strictly narrower than what every other site gets**, and it
is recorded in the function's docstring, in the driver's docstring and in the
coverage table rather than presented as equivalent.

### Mutation, both spellings

| mutation | result |
|---|---|
| the prefix segment dropped from the URL | 2 failed, including `test_no_entry_in_the_table_names_a_read_that_no_longer_exists` |
| the fail-closed guard removed | `test_the_bounded_read_asserts_its_bound[control_plane/main.py::_ledger_decision_count[0]]` |

Four new sites recorded: the production count read and the test-side control
`/audit`'s total is compared against, both driven; the two cost-probe halves
recorded as not applying, with reasons. `tests/test_bounded_reads.py` is
`24 passed`, up from 20.

The module's stated limits are corrected at source. They described a
derivation that reads bodies on two routes, and the fourth shape was not among
them.

---

## P3c3g-2. Bounded-read assertions that have never run

**Verdict: R3 closed.**

### Reproduced, deterministically and without a stack

Each of the five `assert_at_or_above_min_score` call sites, driven against a
stub answering one page under the ceiling, which is what every walk meets
today:

```
walk                                             pages calls  vac  rows
test_view_invariants::_view_rows                     1     1    1     0
test_backfill_index::_view_rows                      1     1    1     0
test_audit_ordering::_view_rows_paged                1     1    1     0
test_audit_read_correctness::_view_row_count         1     1    1     0
test_reconciliation::_positions_for_key              1     1    1     0
```

Every walk opens with `min_score = None` and terminates on the first short
page, so page one is the only page and page one carries no bound. The
assertions were enumerated, correct, and never executed against anything.

### The obvious fix is not the one taken

Running the check on page one checks nothing: the walk has not asked for
anything yet, so there is nothing for the answer to be outside of. Moving the
`min_score` update alone leaves assertions that are no longer vacuous and
still never execute, because the walk still stops after one page.

Non-vacuity needs the walk to page, and today that happens only because
`tests/test_backfill_index.py` pads a view past 2600 rows for an unrelated
reason. That is a fixture accident of exactly the collection-order class D44
exists for.

### Demonstrated

The same five walks against a stub whose first page fills to the ceiling:

```
walk                                             pages calls  vac  rows
test_view_invariants::_view_rows                     2     2    1     8
test_backfill_index::_view_rows                      2     2    1     8
test_audit_ordering::_view_rows_paged                2     2    1     8
test_audit_read_correctness::_view_row_count         2     2    1     8
test_reconciliation::_positions_for_key              2     2    1     8
```

One vacuous call remains in every walk and that is correct: `min_score` is
`None` on the first iteration, forever. **The rule is over a walk's whole
life.** A walk with no non-vacuous call in its entire life is the defect.

### Two ways the fixture was made able to fail

First-page scores ascend rather than repeating one value. With a constant
score the named mutation would compare every row against its own score and
pass. And the stub asserts it served at least two pages: a stub whose ceiling
drifted from the walks' page limit would never reach the second page, and the
file would pass while measuring nothing.

### Mutation

The `min_score` update moved above the check in
`tests/test_view_invariants.py`: `1 failed, 5 passed`, and the failure is the
parametrised case for that walk. It fails rather than passing vacuously.

### Stated limit

This does not establish that the five walks page against the real ledger. They
page here because a stub says so. Whether a production view ever exceeds 2500
rows is a property of the ledger, and it is asserted nowhere.

---

## P3c3g-3. Exemptions that match more than they name

**Verdict: R4 and R5 closed.** One fix, as the instruction requires: fixing
them separately would produce two mechanisms where one is needed.

### What was wrong

`explains()` matched `entry.key_fragment in key`, and a key's agent-id segment
is chosen by whoever writes the record. Two consequences, which the red team
found as two findings:

  * **R4.** A real decision record through `POST /write-ordered` with agent id
    `p3c3c-padded-batch-7` contains the registered fragment `p3c3c-pad`, so it
    inherited the padding exemption. A genuine violation of
    `HISTORY_SCORE_IS_ITS_TRANSACTION` on that record was never reported,
    while the identical violation under an ordinary agent id was.
  * **R5.** `test_the_registered_violations_are_the_only_exemptions_in_use`
    required every entry to match a row in the **decision** view that breaks
    something. The `p3c3c-zero` entry's violation is a zero score in the
    **intent** view, and `test_backfill_index.py` also indexes that same
    record into the decision view at its own transaction id, which is an
    entirely ordinary row. So the test passed or failed on whether the
    backfill had already run: `b` sorts before `r`, CI collects
    alphabetically, and both green runs the phase cited were green for that
    reason.

### The fix, one mechanism

Entries are keyed on an **exact marker** the polluting test writes into the
record value, under `ail_deliberate_violation`, and each entry names the
**view** its violation lives in. `explains()` is equality, not containment.
`registered_for()` takes the view as part of the question.

**Where the marker is read, and at what cost.** The invariant walk still keeps
`(key, score, tx)` from zscan and never reads record values. Markers are
fetched only for rows **already violating an invariant**, by one exact
`getAll` over that handful of keys. A view of 2600 rows yields a violating set
in the single digits, so this is one bounded read per assertion rather than a
second walk. A key that does not come back, or whose value does not decode to
an object carrying a string marker, is `None` and therefore explains nothing:
failing to read a marker exempts no row.

**The marker is not unforgeable and is not claimed to be.** Anything that can
write a record value can write the field. The claim is the narrower one that
matters here: an ordinary record cannot drift into an exemption by resembling
one.

### R4, reproduced and demonstrated

The old matcher, on the two keys the live probe wrote:

```
OLD matcher, substring over the key:
   attack : "p3c3c-pad" in key -> True   => EXEMPT
   control: "p3c3c-pad" in key -> False  => REPORTED
```

Live against the stack, two identical violations: an ordinary decision record
through the real `POST /write-ordered`, verified, with a position injected at
score 42.0, which is inside the reserve and is not its transaction id. One
carries the agent id `p3c3c-padded-batch-7`; the control carries an ordinary
one.

After the fix, the invariant reports both:

```
E  AssertionError: backfilled position(s) in ail_view:decision:v1 that are not
   their record's transaction id and are not registered in
   tests/ledger_pollution.py:
   [('tool_call:p3c3c-padded-batch-7:...', 42.0, 62),
    ('tool_call:p3c3g-control-669ce8:...', 42.0, 64)]
1 failed, 1 passed
```

The red team's run on the old code reported the control and not the attack.
That asymmetry is gone: nine characters in a field the caller chooses no
longer buy an exemption from a ledger-wide invariant.

The marker read, measured on the view this probe left behind:

```
rows walked        : 2628
candidates         : 2603   (rows already violating the invariant)
markers fetched    : 2603   (one exact getAll, not a second walk)
offenders          : 2      (both probe rows)
```

### R5, reproduced and demonstrated

**Before**, the pre-change code stashed back, fresh ledger,
`test_reconciliation.py` collected first:

```
E  AssertionError: the registry entry 'p3c3c-zero-' matches 1 row(s) in the
   view and none of them breaks any of the invariants it claims to exempt.
1 failed, 22 passed in 64.43s
```

Message for message the red team's.

**After**, the same three modules on fresh ledgers in both orders:

| order | result |
|---|---|
| A, alphabetical, what CI runs | `23 passed in 84.29s` |
| B, `test_reconciliation.py` first | `23 passed in 68.64s` |

### Mutation

Restoring substring matching fails both named tests. The attack is carried
permanently rather than as a probe:
`test_a_key_with_no_registered_violation_is_not_explained_by_one` asserts that
`explains("p3c3c-padded-batch-7")` is `None`, and that `p3c3c-zero` is
registered for the intent view and not for the decision view.

The static check that keeps an entry honest is tightened to the call form
`marker="..."` rather than the bare string: `p3c3c-pad` appears in
`test_backfill_index.py` in key literals and in a substring filter as well as
in the write, so requiring the string alone would pass on a module that had
stopped writing the marker entirely.

### Also: can the order sweep be made to see this class

**The instruction's reason is not the operative one, and the sweep is less
blind than it says.** The instruction states that the sweep "only compares
failing sets and a skip is never in one". That sentence is real and is quoted
from `tests/test_view_invariants.py`'s own docstring, where it describes
P3c3f-10: an invariant that `pytest.skip`ped on a clean ledger, so whether it
asserted anything depended on collection order and the sweep could not see it,
because a skip never enters a failing set.

R5 is a different shape. The test **fails** in order B rather than skipping,
and a test that passes alphabetically and fails in reverse is exactly a
failing-set difference, which is the one thing the sweep's `comm` exists to
surface. The sweep's five orders are alphabetical, reverse, and three seeded
shuffles, and **reverse puts `test_reconciliation.py` before
`test_backfill_index.py`**, which is the order R5 needs.

So the answer is: the method can see this class, and it did not see R5 for a
reason of chronology rather than method. The sweep ran in Phase 3c-3d;
`test_the_registered_violations_are_the_only_exemptions_in_use` was added in
Phase 3c-3e. It could not see a test that did not exist.

The skip blindness is nonetheless real and is worth carrying forward on its
own terms, because it is broader than R5: `@requires_stack` turns a would-be
failure into a skip, so if anything earlier in an order leaves the stack
unhealthy, every stack-dependent test after it goes quiet rather than red and
the sweep's diff sees nothing. Whether that happens in reverse order is not
established here and is not claimed.

**What would close it:** re-running the sweep at this head, and having it diff
skipped sets alongside failing sets. Not built this phase. Stated as the
answer to the item's question rather than scheduled.

---

## P3c3g-5. The untested claims

Nothing to build. Recorded so they are not lost.

**C7, C8 and C9 were untested, not holding.** The Phase 3c-3f red team did not
attempt them, for time, and recorded them as untested for the right reason: a
confirmation nobody exercised is worth nothing. They carry forward to the next
brief unchanged.

  * **C7** the `_committed_position_for` disagreement path, and `scan_all`'s
    two bounds against the per-bound `COVERAGE` table.
  * **C8** the detector's closed shapes and the `_b64_candidates` re-padding
    on the hot path.
  * **C9** an identity that passes both checks and still cannot be written.
    The red team left one unverified hypothesis worth someone's time: the two
    checks are byte length and encodability, so a `call_id` set to the sha256
    digest of a different record's key would pass both and collide with that
    record's fallback identity. It was not driven and may be nothing.

The "Also" items B2, B3, B7 and B9 were also not attempted.

**`docker-compose.override.yml` was demonstrated, not left undemonstrated.**
See the verdict table above. The instruction's wording here is corrected.

**The exact-match stateful-path list** (`STATEFUL_CONTAINER_PATHS`) remains
undemonstrated, and that half of the instruction's sentence stands.

---

## Verdicts on the C-claims

| claim | verdict |
|---|---|
| C1 write-route enumeration | refuted as R1, **closed this phase** |
| C2 bounded-read enumeration | refuted as R2, **closed this phase** |
| C3 the bound assertions | refuted as R3, **closed this phase** |
| C4 the third state | refuted as R4, **closed this phase** |
| C5 the trust anchor | attacked and not refuted; **not re-verdicted here** |
| C6 `POST /verify`'s failure mode | refuted as R6, closed out of band, see `r6-headstate.md` |
| C7 position and `scan_all` bounds | **untested**, not holding |
| C8 the detector | **untested**, not holding |
| C9 fault identity | **untested**, not holding |
| C10 ledger-wide invariants | refuted as R5, **closed this phase** |

C5 is the one the red team attacked without refuting, and nothing this phase
did touches it. It is not upgraded to "holds" on the strength of one pass that
could not build a control for its state-file path.

---

## Residual limits

Stated, not scheduled.

  * **D48's coverage is a hand-list of the falsifiers in two files**,
    `tests/test_route_parity.py` and `tests/test_bounded_reads.py`. A
    falsifier elsewhere in the tree is not covered and nothing enumerates
    falsifiers tree-wide.
  * **The clause enumeration inside those two files is also a hand-list**, and
    this is wider than the instruction's Residual Limits entry as written.
    `test_route_parity.py`'s selector is one predicate whose conjuncts are
    unambiguous. `test_bounded_reads.py`'s is not a predicate at all: the
    discrimination is spread across `_module_files`'s skip set, `_rest_target`,
    `_bound_keys`, `_grpc_bound_keys`, `_HTTP_READ_CALLS`, and the
    `BOUNDED_ROUTES` and `GRPC_READS` membership tests. Six clauses are
    covered; the enumeration of clauses is typed out, checked against a second
    typed list, and parsed from nothing. Deriving clauses needs a selector over
    selectors, which is the regress one level down.
  * **The count read's bound is checked at the request, not in the response.**
    Every other bounded read asserts on what came back. A count answers one
    integer and cannot say whether its prefix survived. This is a narrower
    guarantee and it is the only site with it.
  * **P3c3g-2 does not establish that the five walks page against the real
    ledger.** They page against a stub. Whether a production view exceeds 2500
    rows is a property of the ledger and is asserted nowhere.
  * **The registry check no longer sees whether an entry matches only ordinary
    rows.** A key fragment could be tested against every row in a view for
    free; a marker lives in the record value, and reading values for a whole
    view is the read this item's cost constraint forbids. The check is scoped
    to rows already violating an invariant, and
    `test_every_entry_is_produced_by_a_test` is what keeps an unused entry
    honest. This is a reduction in what that test sees and it is recorded
    rather than absorbed.
  * **The marker is not unforgeable.** Anything that can write a record value
    can write the field. The claim is narrower and is the one that matters
    here: an ordinary record cannot drift into an exemption by resembling one,
    which is what R4 exploited. A caller that deliberately writes the field is
    outside what this registry is for.
  * The unverified-write path's caller count is not enforced.
  * `/write-ordered` accepts a key of any shape into a view.
  * 35 test modules were never isolated; isolation was per module, not per
    test.
  * The 16 KiB detector head bound stays, with its measured cost and the
    dependency test key that dropping it would hit.
  * **`tests/test_selector_clauses.py` costs about four minutes**, one
    subprocess per clause, and grows linearly with the hand-list.

---

## Pre-registered negatives

Each confirmed individually.

| negative | result |
|---|---|
| a falsifier within D48's coverage that passes when its selector clause is broken | **none.** Six clauses, each pinned to a node id that must run and fail |
| a walk that never compares a row in any call and reports a pass | **none.** Five walks, 8 rows compared each, asserted per walk |
| an exemption matched by substring rather than by an explicit marker | **none.** `explains` is exact equality on a marker in the record value |
| a bounded read outside the enumerated site list | **none found.** The count route closed the one R2 named; the enumeration is a derivation with its own falsifiers, and its stated limits are above |
| a Claim cell describing a goal rather than a behaviour | **none.** Every verdict above names a measured outcome |
| an assertion weakened, or a refutation closed by narrowing without saying so | **one narrowing, said.** The registry check is scoped to violating rows, in Residual Limits above and in the test's own docstring. No assertion was weakened |

The fourth row is the weakest of the six and is stated as such: "no bounded
read outside the site list" is a claim about a derivation whose limits are
hand-listed, so it means "none this derivation can see", not "none".

---

## An order interaction this phase found and did not cause

**Not one of the five items.** Found while verifying them, recorded here with
its reproduction so it is actionable rather than an anecdote. This project's
order findings have been useful exactly when the order was preserved, as the
sweep's seeds were, and useless when they were described as "some
non-alphabetical run".

### The reproduction

Stack under an explicit project name, fresh ledger, module order preserved:

```
docker compose -p p3c3gfix -f docker-compose.test.yml down -v
docker compose -p p3c3gfix -f docker-compose.test.yml up -d --wait

python -m pytest \
  tests/test_backfill_index.py \
  tests/test_reconciliation.py \
  tests/test_view_invariants.py \
  tests/test_audit_ordering.py \
  tests/test_audit_read_correctness.py \
  tests/test_raw_ledger_fields.py \
  tests/test_record_profile.py \
  tests/test_route_parity.py \
  tests/test_bounded_reads.py \
  tests/test_bound_assertions_are_reached.py \
  tests/test_docs_references_resolve.py \
  -q -p no:randomly
```

`9 failed, 106 passed in 244.71s`. Five of the nine are in
`tests/test_record_profile.py`:

```
test_audit_response_carries_profile_from_closed_set
test_audit_response_surfaces_exclusivity_for_mediated_records
test_one_session_produces_both_observed_and_mediated_records
test_raw_decision_record_for_mediated_tool_carries_mediated_profile_and_demonstrated_exclusivity
test_raw_decision_record_for_observed_tool_carries_no_exclusivity_key_at_all
```

The same module alone, same stack: `8 passed in 62.12s`. CI is green on the
same commit, alphabetically, on a fresh ledger.

The four modules after `test_record_profile.py` in that order cannot affect
it, so the control below drops them and keeps the first seven in the same
sequence.

### The control: the same order against pre-change code

`tests/` and `control_plane/` checked out at `2cdcec3`, fresh ledger, the same
seven modules in the same sequence. The four modules that ran after
`test_record_profile.py` are dropped, because a module that runs later cannot
affect one that ran earlier.

```
git checkout 2cdcec3 -- tests/ control_plane/

docker compose -p p3c3gfix -f docker-compose.test.yml down -v
docker compose -p p3c3gfix -f docker-compose.test.yml up -d --wait

python -m pytest \
  tests/test_backfill_index.py tests/test_reconciliation.py \
  tests/test_view_invariants.py tests/test_audit_ordering.py \
  tests/test_audit_read_correctness.py tests/test_raw_ledger_fields.py \
  tests/test_record_profile.py -q -p no:randomly
```

`11 failed, 56 passed in 222.78s`, of which **seven** are in
`tests/test_record_profile.py`:

```
test_raw_decision_record_carries_observed_profile
test_raw_tombstone_record_carries_observed_profile
test_audit_response_carries_profile_from_closed_set
test_raw_decision_record_for_mediated_tool_carries_mediated_profile_and_demonstrated_exclusivity
test_raw_decision_record_for_observed_tool_carries_no_exclusivity_key_at_all
test_one_session_produces_both_observed_and_mediated_records
test_audit_response_surfaces_exclusivity_for_mediated_records
```

plus two in `tests/test_raw_ledger_fields.py`.

**The five failures seen with this phase's code are a strict subset of these
seven**, and the control has two more this phase's run did not. The
interaction is pre-existing at `2cdcec3` and this phase did not cause it. **No
claim is made that this phase improved it**: the two runs covered different
module counts, and the difference between five and seven is not something one
pair of runs establishes.

### The mechanism is open, and the smaller reproduction failed

A two-module pair was tried, on the reasoning that
`tests/test_backfill_index.py` pads the decision view past 2600 rows and
`tests/test_record_profile.py` reads `/audit` at `limit=200` and scans at
`limit=500`, so its own record could be pushed out of the window it looks in.

```
docker compose -p p3c3gfix -f docker-compose.test.yml down -v
docker compose -p p3c3gfix -f docker-compose.test.yml up -d --wait
python -m pytest tests/test_backfill_index.py tests/test_record_profile.py \
  -q -p no:randomly
```

**`11 passed in 122.32s`. The pair is insufficient and the padding alone does
not cause it.** Something else in the seven-module order is required, and this
phase did not find out what.

The window story above is therefore recorded as **an unverified hypothesis
that the two-module control did not support**, not as a diagnosis. It fits
what the source does; that is not the same as being the cause, and this
project's standard for a mechanism is the failure text, not the plausibility
of the code. An earlier draft of this section asserted the window story as the
cause and also explained the green CI by collection order, which is
self-contradicting: `test_backfill_index.py` sorts before
`test_record_profile.py`, so the padding lands first under CI's alphabetical
collection too. Both were removed before this report was committed.

**The known-good reproduction is the seven-module order above.** Whoever picks
this up starts there and bisects toward a smaller one; the obvious smaller one
is already ruled out.

Carried to the next red-team brief as an observation with a reproduction, not
as a finding this phase closed.

---

## D48's own hole, measured rather than left for the next pass

The instruction pre-committed a failure condition for D48: it has the same
defect it exists to find if its own coverage check is derived rather than
mutation-driven. The establishment is described above and it is two hand-typed
lists that must agree. **That is weaker than it sounds, and here is the
measurement.**

A third conjunct added to `_service_routes`, recorded in neither
`D48_CLAUSES` nor `CLAUSES_IN_THE_COVERED_SELECTORS`:

```python
    return [route for route in verifier.app.routes
            if isinstance(route, APIRoute)
            and not route.path.startswith("/internal")]
```

```
$ python -m pytest tests/test_selector_clauses.py::test_every_clause_of_a_covered_selector_has_a_recorded_state \
                  tests/test_selector_clauses.py::test_every_clause_has_exactly_one_state -q
2 passed
```

**A clause added to a covered selector and to neither list is undetected.**
Both lists are typed by hand by the same person in the same commit, so they
disagree only when someone updates one and forgets the other. They do not
disagree when someone updates neither, which is the likelier mistake.

This is D48 at level four having the shape D46 had at level three: a claim
about covering something, with nothing that fails when a site is added and
missed. It is stated here rather than generalised, per the response this
phase's instruction pre-committed to: the claim is scoped down to what the
tests demonstrate and the enumeration limit goes to Residual Limits.

What D48 does buy, and it is not nothing: for the six clauses that **are**
listed, breaking each one fails a named falsifier that has to run, and two of
those falsifiers did not exist before this phase because nothing had ever
broken those clauses on purpose.

---

## CI

| run | head | what it validates | result |
|---|---|---|---|
| `34052065067` | `077ccae` | the erratum, P3c3g-1, D48, P3c3g-4, P3c3g-2 | **success** |
| `34053108493` | `d92157f` | all five items, including P3c3g-3 | **success** |
| `34053211227` | `39d2e37` | this report as first committed | **success** |

The commit carrying this section is docs-only and is not itself named by a run
id here, for the reason the instruction gives about forward references: a
commit cannot cite the run its own push triggers. `d92157f` is the run that
validates every executable byte this phase changed.

**Local runs are not a regression signal on this host** and are not used as
one. The host cannot install `sigstore`, and the tests that drive
`decision_service/main.py` in process cannot resolve the compose service
names. The local figures quoted in this report are all scoped runs over named
modules, each stated with its module list.
