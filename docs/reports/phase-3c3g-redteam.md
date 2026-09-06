# Red team, Phase 3c-3g (narrow): the merge decision

**Run id:** `p3c3g-red`.
**Base:** `002a9a2`, the head of `p3c3b-order`, PR #14. Nothing merged, nothing
fixed.
**Working directory:** a fresh clone under
`AppData\Local\Temp\claude\...\scratchpad\ail-p3c3g-red`, never the primary
working directory. Compose project `p3c3gred`, named explicitly on every
invocation.
**Keys** generated in the clone with the openssl commands `make keygen` runs,
because `make` is not on PATH here. Without them `tests/test_route_parity.py`
reads `1 failed` at baseline for environmental reasons.

**Baseline before anything was touched**, all on the fresh clone at `002a9a2`:

```
tests/test_route_parity.py                      16 passed
tests/test_bounded_reads.py                     24 passed
tests/test_post_proof_reporting.py              12 passed
tests/test_ledger_state_does_not_survive_teardown.py   6 passed
```

`docker compose ls` was empty when this session opened. No stack was running
against the primary working directory.

---

## The decision, in one table

Per the brief's pre-committed criterion. The classification, not the severity,
is what the merge turns on.

| # | Finding | Cell |
|---|---|---|
| F1 | A selector's discrimination lives in four places and the clause enumeration sees one of them. Three live instances: `app.mount`, `_gate_names`, and the path-keyed dict | **Recursive gap** |
| F2 | Four replacement mutations change a selector's output with no falsifier failing; one silently removes `POST /write` from the site list | Application |
| F3 | A production record written through `POST /write-ordered` exempts itself from two ledger-wide invariants | Application |
| F4 | The anchored half of `state_read` is constructed at three sites and asserted at none; it can report `status: "failed"` with the suite green | Application |
| F5 | Nothing anywhere closes `state_read`'s vocabulary or its shape | Application (no instance reachable from the verifier today) |
| F6 | `maxscore` is a declared bound in the per-bound `COVERAGE` table that no driver drives | Application |
| F7 | The image detector misses three compositions one step from ones it catches, including `base64(gzip(key))` | Application |
| F8 | `test_every_constructor_of_a_verification_object_agrees_on_its_shape` is a hand-list of five and its limit is unstated | Application |
| F9 | `STATEFUL_CONTAINER_PATHS` is an exact match, so a host bind one directory deeper passes | **Carried** (named undemonstrated by the phase; demonstrated here) |
| F10 | `COMPOSE_FILES` still omits `docker-compose.override.yml` | **Carried** (R7, one line) |
| F11 | `POST /write-ordered` answers `committed: false` on a branch where an ExecAll reached the wire, refuting P3c3e-2 | **Carried** |

**One recursive gap, F1.** The brief's pre-committed response therefore
applies: no further generalisation, the claim is scoped down to what the tests
demonstrate, the enumeration limit goes to Residual Limits, and the project
shares a smaller claim. The argument for that classification, and the reading
under which F1 is instead an application, are both in T1 below; the reader
should judge it there rather than from this table.

Nothing else here blocks the merge.

---

## Verdicts per target

| target | verdict |
|---|---|
| T1 D48's hand-lists and whether the listed clauses are the ones that matter | **refuted**, three instances and four replacement mutations, all with controls |
| T2 the exemption marker through a production path | **refuted**, driven live through `POST /write-ordered` with a control |
| T3 `state_read` | **refuted** on the anchored half; **no instance today** on the vocabulary, with the enumeration |
| T4 C9, the digest-collision identity | **not refuted.** The collision is real and reaches the fault key; the join does not use it |
| T5 the count read between the guard and the wire | **no instance today**, with the enumeration and the wire measurement |
| T6 C7 | **partly refuted.** The disagreement path holds; one declared bound is undriven |
| T6 C8 | **refuted**, three undetected compositions with controls |
| T6 the exact-match stateful-path list | **refuted**, demonstrated with a control |
| Diagnosis task | the branch is real, driven with a control. The live intermittent failure did **not** reproduce here in six runs |

**Nothing was dropped.** Every target in the brief was attempted, including
all of T6. The drop order was not reached.

---

## T1. The clauses that matter are not the clauses that are listed

`D48_CLAUSES` and `CLAUSES_IN_THE_COVERED_SELECTORS` enumerate the conjuncts
of a comprehension's `if`. A selector discriminates in four places, and the
other three are not clauses in that sense, so no hand-list would ever hold
them and D48's check cannot reach them:

```python
def _service_routes(verifier):
    return [route for route in verifier.app.routes      # (1) the traversal
            if isinstance(route, APIRoute)]             # (2) the listed clause

def write_routes(verifier):
    return {route.path: route                           # (4) the key
            for route in _service_routes(verifier)
            if "_require_write_key" in _gate_names(route)}   # (3) the helper
```

Three of the four are live at `002a9a2`, and each hides a route that is
gated by `_require_write_key`, reachable, and holds none of the four write
properties.

### T1a. The traversal: `app.mount`

`app.routes` is walked non-recursively. A sub-application mounted with
`app.mount` contributes a `starlette.routing.Mount` and never its own routes.

```
app.routes types : ['Route /openapi.json', 'Route /docs',
                    'Route /docs/oauth2-redirect', 'Route /redoc', 'Mount /ext']
_service_routes  : []
write_routes     : []
CONTROL include_router write_routes: ['/ext/write-express']
POST /ext/write-express no key   : 422
POST /ext/write-express with key : 200
```

The route enforces the same key and answers 200. The control is the identical
handler under the identical prefix through `app.include_router`, which is
selected.

Driven as a whole-file attack, the same shape red-team R1 used. A
`POST /ext/write-express` added to `verifier/main.py` on a mounted
sub-application, doing an unverified `client.set()` under a caller-supplied
key and answering a hardcoded `committed: true`:

```
$ python -m pytest tests/test_route_parity.py -q -p no:randomly
16 passed          # byte-identical to baseline
```

Control, the identical handler at the identical path through
`app.include_router` instead of `app.mount`, one line different:

```
3 failed, 13 passed
  test_every_selected_route_durably_changes_state
  test_every_write_route_has_a_recorded_state_for_every_property
  test_no_write_route_reaches_the_unverified_path_with_anything_but_a_fault_record
```

R1's finding class reproduces at the head that closed R1. The clause deleted
in P3c3g-1 was the one that excluded `include_router`; nothing excluded
`mount`, and nothing enumerates the traversal.

### T1b. The helper: `_gate_names` is one level deep and name-based

`_gate_names` reads `{dep.call.__name__ for dep in route.dependant.dependencies}`.
A route whose write gate arrives through a composite dependency enforces the
same key and is invisible:

```python
def _authorised(_: None = Depends(v._require_write_key)) -> None: ...

@app.post("/write-express")
def _h(_: None = Depends(_authorised)): ...
```

```
_gate_names            : [['_authorised']]
write_routes           : []
POST no key            : 422
POST wrong key         : 403
POST right key         : 200
CONTROL, gate declared directly : ['/write-express']
```

The gate is enforced (403 on a wrong key) and the selector does not see it.
Composing dependencies is ordinary FastAPI.

### T1c. The key: two verbs at one path collapse

`write_routes` returns a dict keyed by `route.path`. P3c3f-2 removed the
method from the selector deliberately, so the selector admits any verb, and
then the dict can hold only one route per path. `_service_routes` sees both;
`write_routes` keeps whichever was registered last.

```
_service_routes    : [('/write', ['POST']), ('/write', ['PUT'])]
write_routes keys  : ['/write']
which route kept   : {'/write': ['PUT']}
endpoint kept      : {'/write': '_bad'}
```

Driven whole-file. A `@app.put("/write")` added to `verifier/main.py`
**above** the real `POST /write`, gated by `_require_write_key`, doing an
unverified `client.set()` under a caller-supplied key:

```
16 passed          # byte-identical to baseline
```

Control, the identical handler at `/write-express` so it does not collide:

```
3 failed, 13 passed          # the same three tests
```

The only difference between the attack and the control is whether the second
route's path collides with an existing write route.

### T1d. Replacement mutations against the two listed clauses

The brief's floor. Nine replacements, each changing one clause and nothing
else, each run over the whole file with the selector's output set recorded
beside the outcome. Baseline is 17 because an output-printing probe module ran
alongside.

| mutation | `_service_routes` | `write_routes` | outcome |
|---|---|---|---|
| `type(route).__name__ == "APIRoute"` | same | same | 17 passed |
| `hasattr(route, "dependant")` | same | same | 17 passed |
| `isinstance(route, starlette.routing.Route)` | changed | changed | 2 errors |
| `isinstance(...) and route.path != "/verify"` | **changed** | same | **17 passed** |
| `isinstance(...) and "_require_read_key" not in _gate_names(route)` | **changed** | same | **17 passed** |
| gate replaced by `"_require_read_key" not in gates and path != "/health"` | same | same | 17 passed |
| gate `and route.path != "/write"` | same | **changed** | **14 passed** |
| gate `and route.path != "/write-ordered"` | same | **changed** | **14 passed** |
| gate `or route.path == "/state"` | same | changed | 3 failed |

Four output-changing replacements with nothing failing. Two of them remove a
production write route from the site list. The last row is the control: an
output change that IS caught, so the instrument is not blind to the whole
class.

The worst is `and route.path != "/write"`. Diffing collected node ids:

```
baseline collected: 16
mutated  collected: 13
VANISHED:
  test_the_property_holds_on_the_route[/write-committed_is_a_fact_about_the_ledger]
  test_the_property_holds_on_the_route[/write-refuses_a_ledger_fault_record_from_a_caller]
  test_the_property_holds_on_the_route[/write-refuses_a_record_that_belongs_on_the_ordered_route]
```

`POST /write` leaves the enumeration and three of its four asserted properties
stop being asserted. The suite is green and three characters shorter in its
count. This is the same "a broken selector deletes the tests that would catch
it" hazard the phase identified and defended against **inside D48's own
check**, by pinning a node id that must run and fail. `tests/test_route_parity.py`
has no equivalent defence: `UNGATED_BY_DESIGN` has a staleness assertion and
`PROPERTIES` has none, so a recorded cell for a route that has left the site
list is never noticed.

The sixth row is a second instance of the coincidental-equivalence class the
phase found with gate-versus-path. "Not gated by the read key and not
`/health`" is a completely different rule with the same output on this app,
and `test_the_selector_is_the_gate_and_not_the_path`, the falsifier P3c3g-1
added, passes under it: that falsifier pins gate-versus-path specifically, not
gate-versus-anything.

### Why T1 is classified as a recursive gap

The distinguishing question is whether D48, applied faithfully as written,
could have caught it. It could not, and not because someone forgot an entry.
D48's unit is a clause of a covered selector, its coverage is two hand-lists
of such clauses, and its check breaks each listed clause and requires a named
falsifier to fail. The traversal, the helper and the dict key are not clauses
of that kind: no faithful application of D48 puts them in either list, and
breaking every listed clause leaves all three untouched. That is the shape
D48's own measured failure condition predicts, with three instances present in
the code at the head rather than one constructed by adding a conjunct.

**The reading under which this is an application**, stated because the merge
turns on the cell: each of the three is a missed instance of D46's
"property-true, selector-false" direction, and each is fixable exactly as R1
was, by widening the selector and adding a falsifier. `test_route_parity.py`
already carries two falsifiers for that direction; these would be the third,
fourth and fifth. On that reading nothing about the design is wrong and three
sites are missing.

What decides it, for this report, is that there are three at once and they
share one cause. The enumeration reads a comprehension's `if` and the
selectors discriminate in four places, so the count of missing falsifiers is
not a property of how carefully the list was typed. That is a claim about the
mechanism, which is the recursive-gap cell.

---

## T2. A production record can exempt itself from a ledger-wide invariant

**Refuted, driven live, with a control.**

The brief records the build session's belief that a real record cannot claim
an exemption "because `registered_for` also requires the invariant and the
view to match". Matching them costs nothing: the `p3c3d-dup` entry in
`tests/ledger_pollution.py` already names two invariants
(`ONE_POSITION_PER_KEY`, `HISTORY_SCORE_IS_ITS_TRANSACTION`) and the decision
view, so one copied string buys both.

Two records written through the real `POST /write-ordered`, both verified,
both with ordinary agent ids, differing in exactly one field of the record
value, each then given a second position at score 42.0 in
`ail_view:decision:v1` (R4's injection):

```
ATTACK  key= tool_call:p3c3gred-ordinary-e82bbf:p3c3gred-attack-f88c5593:query_database
        tx=1   value carries "ail_deliberate_violation": "p3c3d-dup"
CONTROL key= tool_call:p3c3gred-ordinary-e92df7:p3c3gred-control-95fb91df:query_database
        tx=3   value carries no marker field
```

`tests/test_view_invariants.py` against that ledger:

```
E  AssertionError: record(s) in ail_view:decision:v1 at more than one position
   that are not registered in tests/ledger_pollution.py:
   {'tool_call:p3c3gred-ordinary-e92df7:p3c3gred-control-95fb91df:query_database':
    [42.0, 1000000002.0]}

E  AssertionError: backfilled position(s) in ail_view:decision:v1 that are not
   their record's transaction id and are not registered in
   tests/ledger_pollution.py:
   [('tool_call:p3c3gred-ordinary-e92df7:p3c3gred-control-95fb91df:query_database', 42.0, 3)]

2 failed, 11 passed
```

Both ledger-wide invariants report the control and neither reports the attack.
This is R4's asymmetry exactly, through a different door: the caller-supplied
field moved from the key into the value and is still caller-supplied. The
ordered write route accepts the unknown field without comment.

**What this does and does not refute.** The Residual Limit as written in
`docs/reports/phase-3c3g.md` already concedes the mechanism: "The marker is
not unforgeable and is not claimed to be... A caller that deliberately writes
the field is outside what this registry is for." That sentence stands. What is
refuted is the narrower belief the brief states, and what is new is that the
exemption is now shown reaching a ledger-wide invariant on a record the
production write path accepted, rather than being conceded in the abstract.

Cell: application. The registry can bind an entry to something the caller does
not choose, and `explains()` is the one place that would change.

---

## T3. `state_read`

### T3a. The anchored half is constructed three times and asserted zero times

**Refuted.** `_state_read` builds a `StateRead` at five sites
(`verifier/main.py:2408, 2418, 2426, 2435, 2442`). Three of them can carry
`source="anchor"`. `tests/test_post_proof_reporting.py` asserts on the field
only in `test_a_failed_head_read_is_reported_rather_than_swallowed`, which
drives the head; the parametrised
`test_a_failure_after_the_proof_does_not_change_the_verification_state[anchored_rs_get]`
asserts `verified`, `error_class`, `tx_id` and the rendered `/audit` state, and
nothing about `state_read`.

Four mutations, one at a time, each reverted before the next, whole file each
time:

| mutation | result |
|---|---|
| the anchored OK read reports `status="failed"` | **12 passed** |
| the anchored unchecked read reports `status="failed"` | **12 passed** |
| the unavailable branch reports `source="head"` on the anchored path | **12 passed** |
| **control:** the same `status="failed"` on the head/unavailable branch | **1 failed**, 11 passed |

The control is what separates "the assertions do not bite here" from "this
file asserts nothing". The three green mutations put the word `"failed"` on an
`/audit` row's `state_read.status`, which is the one word R6's design says the
vocabulary deliberately does not contain, because `/audit` renders `"failed"`
as a positive tamper claim about a record.

`test_a_failed_head_read_is_not_a_verification_state` does not catch it: it
asserts that `"failed"` is not among three module constants, which is a
statement about the constants and not about the field.

### T3b. The vocabulary and the shape are closed nowhere

**No instance today, with the enumeration.** `StateRead.source` and
`StateRead.status` are `str`, not `Literal`. `_verification_from_200` passes
`vdata.get("state_read")` through verbatim in all four branches, and `/audit`
carries no `response_model` at all, so nothing types the row on the way out:

```
verified      -> {"state": "verified", "state_id": 9,
                  "state_read": {"source": "moon", "status": "failed",
                                 "detail": "tampering detected in the state read"}, ...}
not_found     -> same sibling, verbatim
failed        -> same sibling, verbatim
unverifiable  -> same sibling, verbatim

state_read = 'failed'          -> row['state_read'] = 'failed'
state_read = 17                -> row['state_read'] = 17
state_read = ['failed']        -> row['state_read'] = ['failed']
```

Reachability, enumerated: three constants (`STATE_READ_OK`,
`STATE_READ_UNCHECKED`, `STATE_READ_UNAVAILABLE`) and five construction sites,
all five inside `_state_read`, `grep -rn "StateRead(" verifier/ control_plane/`
returning nothing else. So a value outside the vocabulary is not reachable
from this verifier's own code, and that is why this is "no instance today"
rather than a refutation. The finding is that the claim rests entirely on
those five sites, with no type, no validation at the `/audit` boundary, and no
test over the field.

### T3c. A null `state_id` with no sibling explaining it

**No instance found.** Enumerated over the six ways a row can carry a null
`state_read`:

```
deferred (nothing attempted)          state_id=None  state_read=None
verifier unreachable                  state_id=None  state_read=None
verifier answered non-200             state_id=None  state_read=None
verified, verifier too old to send    state_id=None  state_read=None
not_found (verifier failure path)     state_id=None  state_read=None
failed (verifier failure path)        state_id=None  state_read=None
```

The four failure and deferred rows carry `state` and `detail` that explain
themselves, and on the verified row a verifier old enough to omit `state_read`
is also old enough to populate `state_id` on a verified response, because in
that build a failed head read produced `verified=False` (which is R6 itself).
So the combination the brief asks about, a verified row with a bare null
`state_id`, is not reachable across either version. The docstring claim at
`control_plane/main.py:845` covers `_deferred_verification` only and is true
for it; the two literals at `:817` and `:829` carry no stated reason and need
none, since no verify completed.

One small thing, recorded rather than argued: on an empty ledger the head is
transaction 0, so a sound row can carry `state_id: 0` with
`state_read.status: "ok"`. A consumer testing truthiness reads that as absent.

### T3d. The five-constructor shape test is a hand-list

`test_every_constructor_of_a_verification_object_agrees_on_its_shape` builds
its `built` dict by naming five constructors. A sixth constructor added
elsewhere in `control_plane/main.py` is outside it. `docs/reports/r6-headstate.md`
states this limit for `POST_PROOF_SITES` and not for this test. One line,
application.

---

## T4. C9, the digest-collision identity

**Not refuted.** The hypothesis's premise is exactly right and the conclusion
does not follow.

A victim record with no `call_id` gets the fallback identity
`"key:" + sha256(record_key)[:32]`. An attacker record whose `call_id` is that
literal string passes both checks in `_fault_identity` (36 bytes, encodable)
and produces the identical identity:

```
victim  identity : key:e4d88d1b7ddbcbc37e6ae98c94d535ac
attack  identity : key:e4d88d1b7ddbcbc37e6ae98c94d535ac
identities collide: True
both checks passed (length, encodability): True
```

Driven through `_write_fault_record` for both, with `_committed_tx_for_value`
stubbed to put both records at the same transaction so the transaction
component cannot do the separating:

```
victim components: ['ledger_fault','00000000000000000100','key','e4d8...5ac','cf2637b6c72e47fa']
attack components: ['ledger_fault','00000000000000000100','key','e4d8...5ac','10b106bd2e3f43c3']
identity component equal: True | nonce equal: False
```

Both fault records fed to `control_plane._rendered_fault`:

```
victim: joins to committed_key = tool_call:victim-agent:victim-call-0001:query_database
attack: joins to committed_key = tool_call:attacker-agent:attacker-call-0001:query_database
```

Each joins to its own record. The join is `committed_key` out of the signed
body, which the verifier writes from the record it just committed and which
D41 checks against the writer key before rendering, and the key's transaction
must equal the body's. Nothing joins by identity. D38's nonce is a second
separator and the real transaction ids are a third.

The control matters here and cost one iteration: on the first run both faults
were refused by `_rendered_fault` because `AIL_FAULT_WRITER_PUBLIC_KEY` was
unset in the probe, which would have read as a refutation of nothing. With it
set, both render, and the attack renders too, joined to the wrong place only
if the join used identity.

Residual: the attacker's fault body does carry
`"call_id": "key:<digest of the victim's key>"`. Nothing reads a fault
record's `call_id` (`grep` over `control_plane/bundle.py` and
`tools/ail_verify_bundle.py` returns nothing), and `_rendered_fault` does not
put it on the row. A consumer that grouped faults by `call_id` would
mis-group them; none exists.

---

## T5. The count read between the guard and the wire

**No instance today.** What is between `_ledger_decision_count`'s guard and
ImmuDB, enumerated:

1. Nothing inside the function. `urllib.parse.quote(..., safe="")` runs
   **before** the guard; after it there is an f-string and the `client.get`.
2. The client, `httpx.Client(timeout=30.0)` at `control_plane/main.py:1951`.
   `grep -n "event_hooks\|transport=\|proxies\|follow_redirects\|trust_env\|base_url" control_plane/main.py`
   returns nothing, so there is no custom transport, no hook, no redirect
   following and no base URL rewriting. httpx's default `trust_env=True` means
   `HTTP_PROXY` or `ALL_PROXY` in the container environment would be honoured;
   `docker inspect` on the running control plane shows no proxy variable.
3. The network. `IMMUDB_URL=http://immudb:8080` in both compose files. The
   test stack has no envoy service at all
   (`docker compose ps --services` lists seven, envoy not among them), and
   both containers sit on `p3c3gred_default`. In `docker-compose.yml` the
   control plane and immudb are both and only on `backend`; envoy is dual
   homed on `edge` and `backend` and is used for
   `DECISION_SERVICE_URL=https://envoy:8443/decide` and nothing else. No
   service reaches ImmuDB through it.
4. ImmuDB.

Measured on the wire rather than reasoned:

```
prefix b64        : dG9vbF9jYWxsOg==
quoted segment    : dG9vbF9jYWxsOg%3D%3D
httpx raw_path    : /api/v2/db/count/dG9vbF9jYWxsOg%3D%3D
count(tool_call:) : 200 {'count': '8'}
count(empty seg)  : 200 {"count":"15"}
count(ail_view:)  : 200 {}
```

httpx does not normalise the percent-encoding away, the bound reaches the
server, and the empty segment the guard refuses does answer HTTP 200 with the
ledger-wide count, which is the condition the guard exists for.

---

## T6. The remaining untested set

### C7. Partly refuted

**The `_committed_position_for` disagreement path holds.** It is driven in
`tests/test_bounded_reads.py::_drive_committed_position_for` in both
directions, disagreement and agreement, and the agreement case is a real
control rather than a restatement.

**One declared bound in the per-bound `COVERAGE` table is not driven.** The
entry for `verifier/main.py::_committed_position_for` claims
`("minscore", "maxscore")`. Its driver asserts `client.asked.get("minscore")`
and nothing about `maxscore`.

| mutation of the verifier's bounded zScan | `tests/test_bounded_reads.py` |
|---|---|
| `maxscore` removed from the call | 1 failed (`test_every_bound_at_a_driven_read_has_a_driver`) |
| `maxscore=float(attempted_seq) + 1e9`, kwarg kept | **24 passed** |
| control: `_faults_in_tx_window`'s `endKey` widened by 1,000,000 transactions | 1 failed (`test_the_bounded_read_asserts_its_bound[...]`) |

Removing the bound is caught by the derivation. Keeping the name and
destroying the value is not, on this entry. The control shows the same class of
mutation IS caught on another multi-bound entry, so this is one entry's gap and
not the table's shape. What limits the harm is that `_committed_position_for`
compares the returned score against `attempted_seq` itself, so the code catches
what the test does not.

### C8. Refuted

The detector composes one level and its shape set is closed at that level.
Against the live `keys/writer-decision.key`:

```
  raw PEM                             232 bytes -> 'pem'
  base64(PEM)                         312 bytes -> 'base64-pem'
  gzip(PEM)                           215 bytes -> 'gzip-pem'
  base64(gzip(PEM))                   288 bytes -> None
  gzip(base64(PEM))                   268 bytes -> None
  env line: KEY_B64=base64(PEM)       340 bytes -> 'base64-pem'
  base64(base64(PEM))                 416 bytes -> None
  raw DER                             121 bytes -> 'sec1-der'
  base64(DER)                         164 bytes -> 'base64-sec1-der'
  base64(gzip(DER))                   192 bytes -> None
```

Every `None` row is one composition step from a row above it that is detected,
which is what makes these controls rather than a list of things a detector
does not do. `key_material` offers a decoded base64 body to the armour rule
and the binary rule and never to the gzip rule, and offers a decompressed gzip
body to the armour rule and the binary rule and never to the base64 loop.

`base64(gzip(key))` is not contrived: a Kubernetes Secret is base64 by
definition, and gzipping before storing is an ordinary size optimisation. The
phase that closed the base64 and gzip shapes drove them separately.

`_b64_candidates`'s re-padding is correct on the shape it was written for: the
`NAME_B64=<body>` env line is detected, and the split-then-re-pad recovers the
body's own alignment.

### The exact-match stateful-path list. Refuted

`STATEFUL_CONTAINER_PATHS` is matched with `target not in
STATEFUL_CONTAINER_PATHS: continue`, so a stateful mount at any other path is
skipped entirely, and `assert covered` is satisfied by the other services'
mounts.

```
ATTACK  ./ledger-on-the-host mounted at /var/lib/immudb/data   -> 6 passed
CONTROL ./ledger-on-the-host mounted at /var/lib/immudb        -> 1 failed
```

`/var/lib/immudb/data` is where ImmuDB actually writes. One directory deeper
than the listed path, the same host bind, and the check that exists to stop a
ledger surviving `down -v` says nothing. The list is a hand-list of three exact
strings with no prefix rule.

Carried rather than an application: `docs/reports/phase-3c3g.md`'s own P3c3g-5
records this half as undemonstrated and unfixed, and it predates D46, D47 and
D48. It is demonstrated now.

### R7. One line

`COMPOSE_FILES = ("docker-compose.yml", "docker-compose.test.yml")` at
`tests/test_ledger_state_does_not_survive_teardown.py:33`. The override file
`docker compose` loads by default is still not read. Carried, demonstrated by
the Phase 3c-3f red team with a control, unfixed at `002a9a2`. Not
re-demonstrated here.

---

## The diagnosis task

**The live failure did not reproduce. The branch is real and is driven below
with a control.**

### The reproduction attempt

`tests/test_committed_is_a_fact.py::test_a_retry_after_a_dropped_response_is_told_the_record_already_exists`,
six consecutive runs on a fresh ledger, stack under `-p p3c3gred`, with
`docker compose logs --follow verifier` capturing across the container
recreations the relay fixture performs:

```
RUN 1..6:  1 passed each
verifier log:  "before the ExecAll was issued"  x0
               "after the ExecAll was issued"   x4
```

Every run took the `OrderedCommitUncertain` path, and it answered honestly
each time:

```
ordered write: the response was lost and the record is in the ledger at
  tx=2 position=1000000002        (committed: true)
ordered write: the ExecAll was issued and the ledger could not be read back,
  so whether the record committed is not established   (committed: null)
```

So the timing did not land on the failing branch here either, and six green
runs say no more about the branch than one did.

### The window, read out of the source

There is a path that answers `committed: false` with `StatusCode.UNAVAILABLE`
in `detail` while the record is in the ledger, and it is not one of D45's four
states:

1. The ExecAll comes back `precondition failed`. It reached the wire.
2. `_record_key_present` (`verifier/main.py:1877`) is the read that tells the
   unretryable precondition from the two retryable ones. It **swallows** a
   read failure and answers `False`, documented as costing "an attempt".
3. The loop continues. The next attempt's first act is `_read_bound_reserve`
   (`verifier/main.py:1820`), which is **not** guarded, and on the same dead
   channel it raises.
4. That exception is not `OrderedCommitUncertain`, so `write_ordered`'s bottom
   handler takes it. That handler says "Nothing reached the wire" and
   "`committed: false` is a fact on this branch and on no other".

It is not a fact on this branch. An ExecAll reached the wire in step 1 and came
back refused, and one of the three preconditions that produce that refusal is
`KeyMustNotExist` on the record key, which is true exactly when the record is
already committed. Step 2 is the read that would have established which one it
was, and step 2 is allowed to fail silently.

### Driven, with a control

`write_ordered` in process, against a stub whose ExecAll is refused on a
precondition and whose channel dies after a chosen number of reads. The reads
in one attempt are, in order, the bound reserve, the counter, and then, after
the refusal, the record key. The only thing that moves between the two runs is
that number.

```
=== ATTACK: the channel dies after the ExecAll is refused (dies_after=2) ===
  HTTP: 200
  body: {"tx_id": null, "seq": null, "verified": false, "committed": false,
         "attempts": 0, ...,
         "detail": "<_InactiveRpcError of RPC that terminated with:
                    status = StatusCode.UNAVAILABLE
                    details = \"Socket closed\">"}
  reads attempted: 4  ExecAlls issued: 1

=== CONTROL: the same ExecAll refusal, one read further (dies_after=3) ===
  HTTP: 409
  body: a record is already committed under this key
        (tool_call:diag-agent:diag-call-0001:query_database); the ordered
        route writes a record key once...
  reads attempted: 3  ExecAlls issued: 1
```

One read's worth of difference turns the honest 409 that D39 exists to give
into `committed: false` on a record that is in the ledger, with the exact
detail shape the CI failure carried. `attempts: 0` on that branch also
understates the one attempt the ledger did serve.

This is the sequence the failing test exists to keep out, stated in its own
docstring: `committed: false` followed by a bare conflict on the retry.

**What this establishes and what it does not.** It establishes that a branch
producing exactly the observed symptom exists, is reachable whenever the
channel dies between a precondition refusal and the next attempt's first read,
and is misclassified by P3c3e-2's exception-type rule. It does not establish
that this is what CI hit; I could not make the existing fixture produce a
precondition refusal and a dead channel in the same call, because the
`cutresponse` relay cuts the ExecAll's own response, which produces the
uncertain path and not a refusal.

**Cell: carried.** It refutes P3c3e-2, a claim closed in Phase 3c-3e. It
predates D46, D47 and D48, and none of them closes it.

---

## Which of my own checks I established could fail

Every finding above carries a control differing from the attack by one thing,
and in each case the control produced the other outcome:

* **T1a** the same handler through `include_router` instead of `mount`:
  3 failed against 16 passed.
* **T1b** the same gate declared directly instead of behind a composite
  dependency: `['/write-express']` against `[]`.
* **T1c** the same handler at a path that does not collide: 3 failed against
  16 passed.
* **T1d** one output-changing replacement that IS caught (`or path == "/state"`,
  3 failed), so the sweep is not blind to the class it reports as unseen.
* **T2** the identical record and injection without the marker field: reported
  by both invariants in the same run that did not report the attack.
* **T3a** the same `status="failed"` on the head branch instead of the anchored
  one: 1 failed against 12 passed.
* **T4** the fault-writer public key configured, so both faults render: without
  it both were refused and the probe would have proved nothing. Caught and
  corrected before the result was used.
* **T5** the same request with the prefix segment dropped: 15 against 8.
* **C7** the same widening on `_faults_in_tx_window`'s `endKey`: 1 failed
  against 24 passed.
* **C8** every undetected shape sits one composition step from a detected one
  in the same table.
* **Stateful paths** the identical host bind one directory up: 1 failed against
  6 passed.
* **Diagnosis** one read's difference: 409 against `committed: false`.

Where I could not build a control, I said so: T3b and T5 are reported as "no
instance today" with their enumerations rather than as refutations, and the
diagnosis is reported as a driven branch rather than as a reproduction of the
CI failure.

---

## Anything not on the brief's list

The four replacement mutations in T1d that silently change a selector's output
were found by the brief's own instrument, but the consequence, that
`tests/test_route_parity.py` has no staleness assertion over `PROPERTIES`
while it has one over `UNGATED_BY_DESIGN`, is not something the brief asked
about.

T3d, the hand-list of five constructors, arrived out of reading T3 and is not
on the list.

---

## What could not be removed from the machine

Nothing. Every source mutation was reverted and `git status --porcelain` shows
only this report and one untracked `env.sh` (the environment the Makefile's
`test-integration` target exports, written so every invocation in this run
could state it). `git checkout --` was used after each mutation because the
probe harness rewrites line endings.

Mutated and reverted: `tests/test_route_parity.py` (nine replacements),
`verifier/main.py` (the mounted sub-application, the colliding `PUT /write`,
four `_state_read` mutations, two `maxscore` mutations),
`control_plane/main.py` (one `endKey` mutation), `docker-compose.test.yml`
(two mount mutations).

Probe scripts are outside the repository, in
`AppData\Local\Temp\claude\probe-p3c3g-red\`.

Two records written by T2 through `POST /write-ordered`, plus one padded
decision view, were in the ledger of the `p3c3gred` volumes. The stack was torn
down with

```
docker compose -p p3c3gred -f docker-compose.test.yml down -v
```

which removes `p3c3gred_test-immudb-data`, `p3c3gred_test-verifier-state` and
`p3c3gred_test-control-plane-data`. `docker compose ls` is empty afterwards.
The scratch clone remains on disk with the generated keys, this report, and
`env.sh`.
