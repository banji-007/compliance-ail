# Red-team report: Phase 3c-3f, run `p3c3f-red`

**Target:** PR #14 at `cc06ed4`, branch `p3c3b-order`. Not merged, nothing
fixed. The working head was `740215a`, which differs from `cc06ed4` in docs
alone: `git diff --name-only cc06ed4 740215a -- . ':(exclude)docs'` prints
nothing, so every executable byte under test is `cc06ed4`'s.

**Environment:** scratch clone `C:\Users\banji\ail-p3c3f-red`, never the
primary working directory. Compose project `p3c3fred`, stated with `-p` on
every invocation. No stack was running on this host when the session opened
(`docker compose ls` was empty). Keys generated in the clone with the openssl
commands `make keygen` runs, because `make` is not on PATH here.

**Baseline before anything was touched:** `tests/test_route_parity.py` =
**13 passed**. `tests/test_route_parity.py tests/test_bounded_reads.py
tests/test_ledger_state_does_not_survive_teardown.py` = **40 passed**. Against
the stack, `tests/test_view_invariants.py tests/test_audit_ordering.py
tests/test_reconciliation.py tests/test_raw_ledger_fields.py
tests/test_record_profile.py tests/test_audit_read_correctness.py` =
**64 passed in 177.63s**, and `tests/test_backfill_index.py
tests/test_committed_is_a_fact.py` = **15 passed in 497.78s**.

**Verdict: six refuted, one attacked and not refuted, three could not test.**

| claim | verdict | application of D46/D47, or gap in it |
|---|---|---|
| C1 write-route enumeration | **refuted** (R1) | **gap** in D46, and D46 not applied to itself |
| C2 bounded-read enumeration | **refuted** (R2) | **gap** in D46 |
| C3 the bound assertions | **refuted** (R3) | **gap**: D46 covers the enumeration, not the checks it feeds |
| C4 the third state | **refuted** (R4) | application of the phase's defect class; the criterion is a gap |
| C5 the trust anchor | not refuted | - |
| C6 `POST /verify`'s new failure mode | **refuted** (R6) | **gap**: a behaviour D47 introduced, untested and unstated |
| C7 position and `scan_all` bounds | could not test | - |
| C8 the detector | could not test | - |
| C9 fault identity | could not test | - |
| C10 ledger-wide invariants | **refuted** (R5) | application of D44's class, in this phase's own new test |
| Also: teardown `COMPOSE_FILES` | **refuted** (R7) | pre-existing, recorded last pass, now driven |

**PR #14 should not merge on this pass.** R1 alone settles it: it is D46
failing to apply to the file that implements D46, and closing it needs a
mechanism that does not exist yet. R2, R3 and R6 are also gaps rather than
applications. The three findings that are applications (R4, R5, R7) would not
by themselves block a merge.

**The count is six, again.** Eight, nine, a wrong clean, six, six, six. The
brief called four a plateau; five is not a different shape.

---

## The most serious finding: D46 does not apply to itself

**R1. `tests/test_route_parity.py::_service_routes` cannot see a write route
whose handler is defined in another module, and the suite reads exactly its
baseline with one present.** This is the brief's "Start here", and it lands.

`_service_routes` discriminates on
`route.endpoint.__module__ == verifier.__name__`. A route registered from an
`APIRouter` assembled elsewhere and included with `app.include_router` reports
its own module, so it is filtered out before `write_routes()` ever sees it.
It is then outside all of: the site list, the three-state matrix, the
`_require_write_key` selector, the gate check in
`test_the_write_routes_are_selected_by_their_gate_and_not_by_their_path`, and
both of D46's falsifiers.

A new module `verifier/extra_routes.py` holding a router with one
`@router.post("/write-express")` handler gated by `Depends(require_write_key)`,
included into the app from `verifier/main.py` with six lines. The handler does
an unverified `client.set()` under a caller-supplied key: it holds none of the
four properties, allocates no position, carries no `KeyMustNotExist`, refuses
no fault record, and answers a hardcoded `committed: True`.

    $ python -m pytest tests/test_route_parity.py -q
    13 passed, 1 warning in 5.10s

Identical to the untouched baseline. What the application actually holds:

    $ python  # driving _service_routes and write_routes against the app
    ALL registered APIRoutes on app:
      ['GET']     /health         module=v_probe                gates=[]
      ['POST']    /write          module=v_probe                gates=['_require_write_key']
      ['POST']    /write-ordered  module=v_probe                gates=['_require_write_key']
      ['GET']     /state          module=v_probe                gates=['_require_read_key']
      ['POST']    /verify         module=v_probe                gates=['_require_read_key']
      ['POST']    /write-express  module=verifier.extra_routes  gates=['_require_write_key']

    _service_routes() sees : ['/health', '/state', '/verify', '/write', '/write-ordered']
    write_routes() sees    : ['/write', '/write-ordered']

**The control, which is what makes this a finding about `__module__` and not
about the handler.** The same handler, same verb, same path, same gate, same
body, moved into `verifier/main.py` so that only `endpoint.__module__`
differs:

    $ python -m pytest tests/test_route_parity.py -q
    FAILED tests/test_route_parity.py::test_every_selected_route_durably_changes_state
    FAILED tests/test_route_parity.py::test_every_write_route_has_a_recorded_state_for_every_property
    FAILED tests/test_route_parity.py::test_no_write_route_reaches_the_unverified_path_with_anything_but_a_fault_record
    3 failed, 10 passed, 1 warning in 6.13s

Three failures against thirteen passes, and the only difference between the
two runs is which file the function was typed in.

**Why this is a gap and not an application.** The file's own docstring says a
selector is a claim and is falsified in both directions. `_service_routes` is
a selector, it sits underneath `write_routes()`, and it has neither falsifier.
`test_a_write_route_is_selected_under_any_verb` looks like it might be one,
but it builds a `SimpleNamespace(app=app, __name__=_handler.__module__)`,
which sets the stand-in's `__name__` to whatever module the handler was
defined in. The falsifier is constructed so that the discriminator under test
always agrees. It cannot fail in this direction by construction, which is the
exact defect D46 was written to remove, one level down.

Note also that the FastAPI-framework routes the discriminator exists to
exclude (`/openapi.json`, `/docs`, `/docs/oauth2-redirect`, `/redoc`) are
already excluded by the gate check's own `UNGATED_BY_DESIGN` logic having
nothing to say about them, because they carry no `_require_*` dependency and
would land in the `ungated` list. So the discriminator buys the exclusion of
four framework paths and pays for it with every route this service might ever
mount from a router. That trade is not stated anywhere.

**Closing this needs new mechanism**, and the brief anticipates which:
a check that every selector in the tree carries both falsifiers. D43 did that
for constants and D46 did it for enumerations; nothing does it for the
selectors those enumerations are built out of. `_service_routes` is the third
level and there is no reason to think it is the last.

---

## R2. A prefix-bounded production read that the bounded-read enumeration cannot see

C2 asks for a bounded read that decides something and is not enumerated. There
is one in the tree already, and it is not one of the three limits the module
states.

`control_plane/main.py::_ledger_decision_count` reads

    GET /api/v2/db/count/{base64(prefix)}

with `_TOOL_CALL_PREFIX`. It satisfies `BOUNDED_READ_PROPERTY` word for word:
it asks the ledger for less than everything, by a prefix. It decides the
`total` every `/audit` page reports, which is the number
`tests/test_audit_read_correctness.py` compares the view row count against.
And nothing checks what came back: the body is
`int(resp.json().get("count", 0))`.

It is invisible to the enumeration three times over, not once:

  * the route is `/api/v2/db/count/...`, and `BOUNDED_ROUTES` is
    `("/api/v2/db/scan", "/api/v2/db/zscan")`;
  * the bound is a path segment, and `_bound_keys` reads a JSON request body;
  * it is `client.get`, and both REST detection and `GRPC_READS` look
    elsewhere.

`bounded_read_sites()` returns 19 sites and this is not among them:

    $ python -c "import sys; sys.path.insert(0,'tests'); import test_bounded_reads as B; ..."
    enumerated sites: 19
      control_plane/main.py   _faults_in_tx_window   L1553  rest  ('endKey', 'seekKey')
      ... (18 more, no /api/v2/db/count site)

The bound is droppable in exactly the way the property describes, measured on
the wire against the running ledger:

    GET /api/v2/db/count/{prefix} - the read _ledger_decision_count makes:
      prefix 'tool_call:' (as shipped)   HTTP 200  count=2624
      prefix '' (the bound dropped)      HTTP 200  count=2631
      prefix 'tool_call' (no colon)      HTTP 200  count=2629
      prefix 'ail_view:'                 HTTP 200  count=None

A dropped bound is HTTP 200 and a larger number, with nothing saying so, which
is the sentence `BOUNDED_READ_PROPERTY` is made of.

**Gap.** The module states three limits (a read behind an argument-taking
helper, a positional gRPC bound, one-hop name resolution). A bound carried in
a URL path on a third route is a fourth, and it is not stated. Turning the
limits into checks would not have found this one, because it is not among the
limits.

---

## R3. The bound assertions compare nothing, as shipped, in a green run

C3 predicts vacuity is reachable by moving one line. It is not necessary to
move anything: four of the five `assert_at_or_above_min_score` sites are
vacuous on every call in every green run today.

Every one of those sites is a page walk that opens with `min_score = None`,
passes `min_score` to the check, and terminates on the first iteration when
`len(rows) < 2500`. `assert_at_or_above_min_score` opens with

    if min_score is None:
        return

so page one is never checked, and there is no page two unless a view holds
2500 rows or more.

Measured, not argued. `tests/bounded_read_checks.py` was instrumented to tally
calls, early returns on `None`, and rows actually compared, and the six
consumer modules were run against the stack (`64 passed in 177.63s`):

    call site                     calls  vac(None) vac(empty)   rows cmp
    _keys_under_prefix                1          0          0         24
    _positions_for_key                1          1          0          0
    _raw_scan                         8          0          0       1031
    _view_row_count                   2          2          0          0
    _view_rows                        9          9          0          0
    _view_rows_paged                  4          4          0          0
    ------------------------------------------------------------------------
    TOTAL                            25         16          0       1055

Sixteen calls to `assert_at_or_above_min_score` in a fully green run, sixteen
early returns, zero rows compared. That includes all nine calls from
`tests/test_view_invariants.py::_view_rows`, which is the site the module's
own docstring names as the reason it exists and which feeds all four
ledger-wide invariants.

**The instrument was controlled.** Its ability to distinguish a real
comparison from a vacuous one is demonstrated by the same instrument on
`tests/test_backfill_index.py`, whose `_pad_view_past_the_ceiling` deliberately
takes the view past 2600 rows:

    call site                     calls  vac(None) vac(empty)   rows cmp
    _members_at_position              1          0          0          1
    _view_rows                        9          5          0       1148

Four of nine calls there did page and did compare 1148 rows. So one of the
five sites is genuinely exercised, and only because a different module pads
the ledger for an unrelated reason. The other four are structurally vacuous.

`assert_under_prefix` and `assert_inside_score_window` do real work (1055 and
1 rows). The finding is specific to the `minScore` walks.

**Gap.** D46 requires a selector to be falsified in both directions. Nothing
requires the assertion the enumeration hands off to actually assert. The nine
sites were enumerated correctly and then wired to a check that returns before
looking, and every one of them is green.

---

## R4. An exemption is inherited by any record whose caller-supplied key segment contains the fragment

C4 names `explains()` as a substring match on a caller-controllable key
segment and records that it was never driven. Driven here, live, against the
stack.

One ordinary decision record written through the real `POST /write-ordered`,
verified, with one unusual property: its agent-id segment is
`p3c3c-padded-batch-7`, which contains the registered fragment `p3c3c-pad`.
Then one position injected inside the reserve that is not its transaction id,
which is a genuine violation of `HISTORY_SCORE_IS_ITS_TRANSACTION` and of
`ONE_POSITION_PER_KEY`:

    wrote an ordinary decision record through POST /write-ordered
      key      : tool_call:p3c3c-padded-batch-7:813e65ab...:query_database
      tx       : 274  verified: True
      injected a position at score 42.0 (reserve is <= 1000000000);
      the record's own transaction is 274

    explains(key)                                          -> p3c3c-pad
    registered_for(key, HISTORY_SCORE_IS_ITS_TRANSACTION)  -> True

    view rows walked                : 2795
    rows violating the invariant    : 2602  (mine: 1 )
    rows the test would REPORT      : 0     (mine: 0 )
    assert not offenders  -> PASSES

**Control:** the identical record and the identical injection with an ordinary
agent id.

    explains(key)                                          -> None
    registered_for(key, HISTORY_SCORE_IS_ITS_TRANSACTION)  -> False
    rows the test would REPORT      : 1     (mine: 1 )
    assert not offenders  -> FAILS

The suite itself then confirms both halves in one output, with the two records
sitting side by side in the same ledger:

    $ python -m pytest tests/test_view_invariants.py::test_a_historical_position_is_its_transaction_or_a_registered_violation -q
    E  AssertionError: backfilled position(s) in ail_view:decision:v1 that are
       not their record's transaction id and are not registered in
       tests/ledger_pollution.py:
       [('tool_call:p3c3f-red-control-d38f22:...:query_database', 42.0, 276)]

Two identical violations. The one named `p3c3f-red-control` is reported; the
one named `p3c3c-padded-batch-7` is not. Nine characters in a field the caller
chooses.

`test_the_registered_violations_are_the_only_exemptions_in_use` does not catch
it, for the reason the last pass recorded and did not drive: `breaks_something`
is an `any` over every row matching the fragment, and the 2600 genuine padding
rows satisfy it on their own. The exemption's blast radius is never measured
per row.

**Application, with a gap underneath it.** That a substring match over
attacker-chosen input is a weak exemption is an instance of the phase's own
class. What is a gap is the criterion: `len(reason) >= 80` (four sites:
`test_bounded_reads.py:1105`, `test_route_parity.py:666` and `:861`,
`test_view_invariants.py:290`) counts characters, and the registry's matching
rule is never checked against the set of rows it actually covers.

---

## R5. `test_the_registered_violations_are_the_only_exemptions_in_use` is order dependent, and CI is green by alphabetical accident

Found while establishing R4's control, then isolated on a fresh ledger twice.

Three modules, same clean ledger each time (`down -v` and `up -d --wait`
between runs), only the collection order differs:

    ### ORDER A: alphabetical, which is what CI runs ###
    $ python -m pytest tests/test_backfill_index.py tests/test_reconciliation.py \
                       tests/test_view_invariants.py -q -p no:randomly
    23 passed in 85.25s

    ### ORDER B: reconciliation first ###
    $ python -m pytest tests/test_reconciliation.py tests/test_backfill_index.py \
                       tests/test_view_invariants.py -q -p no:randomly
    E  AssertionError: the registry entry 'p3c3c-zero-' matches 1 row(s) in the
       view and none of them breaks any of the invariants it claims to exempt.
       An exemption that covers ordinary rows exempts whatever lands on that
       name next.
    1 failed, 22 passed in 66.62s

**The mechanism, established rather than guessed.**
`test_reconciliation.py::test_a_row_with_no_score_is_reported_and_does_not_stop_the_pass`
writes a `p3c3c-zero-` record with `_write_historical` (straight to the ledger,
no index entry) and zAdds it into the **intent** view at score 0. If
`test_backfill_index.py` runs afterwards, the backfill indexes that record into
the **decision** view at its own transaction id, which is a completely ordinary
row. `test_the_registered_violations_are_the_only_exemptions_in_use` walks the
decision view, matches it on the `p3c3c-zero-` fragment, finds it breaks
nothing, and fails. Confirmed by reading both views directly:

    ail_view:decision:v1 -> p3c3c-zero rows: [(... , 152.0, 152)]   ordinary
    ail_view:intent:v1   -> p3c3c-zero rows: [(... ,   0.0, 152)]   the violation

`b` sorts before `r`, so in CI the backfill has already run when the record is
written and the record never reaches the decision view. Both green CI runs the
brief cites are green for that reason.

**Application of D44's class, in a test this phase added.** D44 exists because
`docs/reports/phase-3c3d-order-sweep.md` measured exactly this shape: a
ledger-wide assertion that passes only under alphabetical collection. The
remediation scoped four victims and built `tests/ledger_pollution.py`. The new
registry test in that same module then reintroduced the shape, ledger-wide and
unscoped, and no order sweep was run over it.

---

## R6. D47 turns a sound record proof into tamper evidence

C6 asks what a caller sees. The answer is worse than the claim states, and it
reaches `/audit` as a positive claim of tampering.

`head_state(client)` sits at `verifier/main.py:2425`, inside the route's
`try`, **after** `sdk_verified_get.call(...)` has already returned a verified
entry. It makes a `CurrentState` RPC and calls `state.Verify(client._vk)`. Any
failure of that call, of the RPC behind it, or of the transport, lands in the
route's own handlers and replaces a successful verification with a failed one.

Driven in process. The record's inclusion and consistency proof succeeds
identically in every row below; only the head read that happens after it
varies:

    POST /verify. The record proof SUCCEEDS in every row below;
    only the head read that happens AFTER it varies.

      head fine (control)                  -> verified=True  error_class=None                state_id=4242
      head signature does not verify       -> verified=False error_class='signature_failure' state_id=None
      head Verify raises a transport error -> verified=False error_class='unknown'           state_id=None
      CurrentState RPC unavailable         -> verified=False error_class='unknown'           state_id=None

The control returns `verified=True`, so the probe can distinguish the two
outcomes.

`signature_failure` is in `control_plane/main.py::_TAMPER_ERROR_CLASSES`.
Feeding these exact bodies to the control plane's own mapping function:

    head fine (control)    -> /audit renders {'state': 'verified',     ...}
    head signature fails   -> /audit renders {'state': 'failed',       'error_class': 'signature_failure'}
    head RPC unavailable   -> /audit renders {'state': 'unverifiable', 'error_class': 'unknown'}

`state: "failed"` is, in that function's own words, "a positive claim of tamper
evidence". `/audit` verifies per entry, so one head whose signature does not
check out marks **every record on the page** as tampered with, while every one
of those records proved sound.

**Gap, and the inverse of the finding D10 exists for.** D10 was written after
red-team T1 turned a never-written key into a tamper alarm by routing an
unrecognised `error_class` to `failed`. D10's fix was to require positive
identification. This path produces one of the two positively identified
classes, so D10's guard passes it straight through. The behaviour is new in
this phase, it is not tested anywhere, and `docs/reports/phase-3c3f.md` does
not state it. Before D47 the same line called `client.currentState()`, which
reaches `currentRoot.call` and checks no signature, so this failure mode did
not exist.

Note the asymmetry that makes it reachable: `head_state` verifies only
`if client._vk is not None`, while `_VerifiedRootService._checked` refuses
outright when no key is configured. The two D47 surfaces disagree about what
"no signing key" means.

---

## R7. The teardown check does not read the compose file `docker compose` loads by default

Recorded by the last pass, never demonstrated. Demonstrated here.

`COMPOSE_FILES` is `("docker-compose.yml", "docker-compose.test.yml")`.
`docker compose` also loads `docker-compose.override.yml` when it is present,
with no flag. A four-line override replacing ImmuDB's named volume with a host
bind mount:

    services:
      immudb:
        volumes:
          - ./ledger-on-the-host:/var/lib/immudb

What compose resolves:

    $ docker compose -p p3c3fred-probe config | grep -B3 -A3 "/var/lib/immudb"
          - type: bind
            source: C:\Users\banji\ail-p3c3f-red\ledger-on-the-host
            target: /var/lib/immudb

What the suite says:

    $ python -m pytest tests/test_ledger_state_does_not_survive_teardown.py -q
    6 passed in 6.88s

**Control:** the identical mount line written into `docker-compose.yml`
instead.

    E  AssertionError: ["docker-compose.yml: immudb mounts './ledger-on-the-host'
       at '/var/lib/immudb', which is a host path and survives `down -v` entirely"]
    1 failed, 5 passed in 7.52s

The ledger survives `down -v` in both cases. The check sees one of them. This
is the module whose entire subject is a ledger surviving teardown.

Not a D46 or D47 gap: it is older than both, and the last pass named it. It is
reported again because it was named and not closed, and because it is now
driven rather than asserted.

---

## C5. Attacked, not refuted

`_VerifiedRootService` holds on the three entry points. With a server whose
states never verify:

    _VerifiedRootService seeding, with a signing key configured:
      head reports tx=4242 (non-empty ledger)  -> REFUSED: UnverifiedState
      head reports tx=0    (the exemption)     -> seeded at tx=0, signature checked 0 times
          then set() a state at tx=0           -> ACCEPTED, anchor tx=0, file written

    and with NO signing key configured:
      head reports tx=4242, no verifying key   -> REFUSED: UnverifiedState
      head reports tx=0,    no verifying key   -> seeded at tx=0, signature checked 0 times

Both seeds and `set` refuse a non-empty unverified state in both key
configurations. The `txId == 0` exemption behaves exactly as its docstring
says, and what it admits is a **downgrade to the empty anchor, not the
installation of a chosen one**: a proof from tx 0 forward is sound and
uninformative, and the next real proof moves the anchor forward through the
signature check. Reaching it also requires the state file to be absent, which
is already the condition that re-seeds from the server by design. I could not
turn it into an anchor an attacker picks.

The state file is read unchecked, as documented. I did not find a way to turn
that into an installed anchor rather than a detected corruption, which is what
ADR-0006 says it is for.

`_PinnedRootService.set` records rather than persists, so the caller-supplied
anchor on `POST /verify` does not reach the volume. That half holds.

## C7, C8, C9. Could not test

Not attempted, for time. I am recording them as untested rather than as
holding, because the brief is right that a confirmation nobody exercised is
worth nothing. Specifically:

  * **C7** the `_committed_position_for` disagreement path and `scan_all`'s
    two bounds against the per-bound `COVERAGE` table;
  * **C8** the detector's closed shapes and the new `_b64_candidates`
    re-padding on the hot path;
  * **C9** an identity that passes both checks and still cannot be written.
    I read `_fault_identity` and formed one unverified hypothesis worth
    someone's time: the two checks are byte length and encodability, and a
    `call_id` set to the sha256 digest of a *different* record's key would
    pass both and collide with that record's fallback identity. The code's
    defence is that a fault joins by `committed_key` rather than by identity.
    I did not drive it and it may be nothing.

The "Also" items B2, B3, B7, B9 and the `STATEFUL_CONTAINER_PATHS` half of the
teardown check were also not attempted.

---

## Which of my own checks I established could fail

Every finding above carries a control that produced the other outcome, and in
each case the control differs from the attack by one thing:

  * **R1** the same handler in a different module: 3 failed against 13 passed.
  * **R2** the same read with the prefix dropped: a different count at HTTP 200.
  * **R3** the same instrument on `test_backfill_index.py`: 1148 rows compared
    where the other four sites compared zero.
  * **R4** the same record and injection with an ordinary agent id: the
    assertion fails, and the suite's own run reports the control row and not
    the attack row.
  * **R5** the same three modules on a fresh ledger in the other order.
  * **R6** the head read left working: `verified=True`.
  * **R7** the same mount line in `docker-compose.yml`: 1 failed.

The one place I could not build a control is C5's state-file path, which is
why C5 is "attacked, not refuted" rather than "holds".

## Anything not on the brief's list

R5 is not on the list. It arrived out of R4's control and is a D44 finding
rather than a D46 or D47 one.

R2's shape is on the list (C2 asks for an unenumerated bounded read) but the
instance is not one of the three limits the module states, which is the part
worth carrying forward: the limits are a hand-list too.

## What could not be removed from the machine

Nothing. The stack was torn down with

    docker compose -p p3c3fred -f docker-compose.test.yml down -v

which removes `p3c3fred_test-immudb-data`, `p3c3fred_test-verifier-state` and
`p3c3fred_test-control-plane-data`. `docker compose ls` is empty afterwards.

The scratch clone `C:\Users\banji\ail-p3c3f-red` remains on disk, with the
keys generated into it, this report committed, and one untracked file
`env.sh` (the environment the Makefile's `test-integration` target exports,
written so every invocation in this run could state it). No probe file was
left in the repository: `verifier/extra_routes.py`, the `main.py` edits, the
`bounded_read_checks.py` instrumentation, the `docker-compose.yml` control
mutation and `docker-compose.override.yml` were all reverted, and
`git status --porcelain` shows only `env.sh` and this report.

Probe scripts are outside the repository, in
`C:\Users\banji\AppData\Local\Temp\claude\probe-p3c3f-red\`.

Two records written by R4 are in the ledger of a volume that no longer exists.

**2026-09-05, after this report was committed:** clone removed after commit,
keys and `env.sh` destroyed with it. The probe scripts under
`AppData\Local\Temp` were removed in the same pass. Nothing this run generated
remains on the machine.
