# Red-team report: Phase 3c-3d, run `p3c3d-red`

**Target:** PR #14 at `2595a9c`, branch `p3c3b-order`. Not merged, nothing fixed.
The working head was `88cce1d`, which differs from `2595a9c` by
`docs/reports/phase-3c3d-redteam-brief.md` alone
(`git diff --stat 2595a9c 88cce1d` = 1 file, the brief).

**Environment:** scratch clone `C:\Users\banji\OneDrive\Documents\p3c3d-red`,
never the primary working directory. Compose project `p3c3dred`, stated with
`-p` on every invocation. All six images built `--no-cache` at the start of
the run. Keys generated in the clone with the openssl commands `make keygen`
runs, because `make` is not on PATH here.

**Baseline:** `tests/test_ordered_route_refusals.py`,
`tests/test_fault_key_and_page_read.py`, `tests/test_committed_is_a_fact.py`
and `tests/test_image_contents.py` = **27 passed in 239.42s** against the
stack, before anything was touched.

**Six of ten claims refuted: A1, A2, A4, A7, A8, A9, A10.** That is seven
labels for six claims plus A8's split verdict; the tally below is per claim.
A3, A5 and A6 were attacked and not refuted.

The most serious finding is A4, and it is not a variant of the branch this
phase fixed. `POST /write-ordered`, the route every decision and intent
record takes, was never given D40's treatment at all: its generic handler
answers `committed: false` without asking the ledger anything. Driven live,
a record, its commit position and its view index entry all committed and
reached `/audit` while the response said the write did not happen. On `POST
/write`, the route D40 did change, one more cut reproduces the Phase 3c-3c
GDPR `erasure_conflict` in full: DELETE 503, tombstone in the ledger, 772
bytes of payload still in the store, content writes frozen at 409.

Not on the list: two CI-green tests in this repository contradict each other
depending on which order they run in, and one of them fails permanently
against any ledger the other has touched.

---

## Verdicts

| Claim | Verdict | In one line |
| :--- | :--- | :--- |
| A1 | **Refuted** | The identity component is unvalidated caller input. A `call_id` past about 1000 characters pushes the fault key past ImmuDB's max key length and no fault record is written at all. |
| A2 | **Refuted** | A fault whose key names a transaction the record does not occupy is invisible on the page at HTTP 200, and nothing compares the key's transaction against the body's own `committed_tx_id`. |
| A3 | Not refuted | 2499, 2500, 2501 and 2502 faults in one window all came back complete and gap-free. |
| A4 | **Refuted, twice** | `/write-ordered`'s generic handler asks the ledger nothing; `POST /write`'s asks and, when the ask cannot run, guesses `committed: false` anyway. |
| A5 | Not refuted | No write this system makes can collide: both ordered keys carry a fresh uuid4. The composed condition is established below and is real. |
| A6 | Not refuted | Legacy `ledger_fault:{call_id}` faults render. The only faults dropped are those not signed by the verifier's writer key, which is D41 working. |
| A7 | **Refuted** | One fault in the ledger, `count: 2` on the page, from the write credential alone. |
| A8 | **Refuted on the parse, not on the guard** | Two live second callers that the AST reference count does not see. The guard does check the bytes it writes, and refuses a decision record. |
| A9 | **Refuted** | Two bounded reads in `tools/ail_backfill_index.py` assert nothing, and both decide what the backfill writes into a view index. |
| A10 | **Refuted, twice** | A DER private key rides into the real image with the test green; and a PEM deleted by a later layer is recovered byte-identical from `docker save`. |

---

## Checks I established could fail before trusting them

Every attack below has a recorded control from the same session.

| Check | How I established it can fail |
| :--- | :--- |
| `tests/test_image_contents.py` | the same key as a PEM in the same directory: `2 failed, 3 passed`, both checks naming `decision_service/leaked_credential.pem` |
| the response-drop relay (A4) | a write through the same relay with no marker: `tx_id 54, seq 1000000016, verified true, committed true` |
| the blackhole relay (A4, second form) | `POST /write` through it with no marker: `tx_id 117, verified true, committed true`; and a control erasure: `POST /content 204, DELETE 204` |
| the fault write path (A1) | a 32-character `call_id` under the same corrupt anchor: `fault_record ledger_fault:00000000000000000123:36eac95104574fc48e783e39116fa3a6:21c158f1cbbe4a10`, rendered on the page |
| the page-side fault join (A2) | a fault keyed at the record's own transaction: `{"fault_class": "write_verification_failed", "committed_tx_id": 98, "count": 1}` |
| the D41 signature check (A6) | the same legacy-shape fault signed with `keys/writer-decision.key` instead: row `ledger_fault` is `null` |
| the AST parse (A8) | the previous pass's own alias form: `FAILED ... at line(s) [624]` |
| the D42 assertions (A9) | `_faults_in_tx_window` raised `BoundedReadFault`; `collect_positions` reported `score_outside_requested_bound` |
| the fault count (A7) | the row read `count: 1` before the second write and `count: 2` after |
| the reconciler | it reported `state: findings` with `foreign_count: 5` naming five positions and keys, and `foreign_count` unchanged for the conditions it does not catch |
| `/audit` itself | it answered HTTP 200 at limit 2500 throughout, and 47 then 49 rows against `total` 44 then 47 |

---

## A1 - Refuted

The key is `ledger_fault:{committed_tx_id:020d}:{identity}:{nonce}` and
`identity` is `verifier/main.py::_fault_identity`, which is:

```python
call_id = json.loads(record_value).get("call_id")
if call_id:
    return str(call_id)
return "key:" + hashlib.sha256(record_key).hexdigest()[:32]
```

Nothing validates it. It is a caller-supplied string interpolated into a key
that is otherwise structured, and the page reads that key range.

Driven under a live `consistency_failure` (`tests/anchor_helpers.py::anchor`,
`corrupt`), so every ordered write faults for real and the verifier writes the
fault record itself. Every write below returned `committed: true,
verified: false, error_class: consistency_failure`:

```
--- call_id with colons
    fault_record : ledger_fault:00000000000000000075:aa:bb:cc:151b6e13d2c14978
--- call_id is a 20-digit padded number
    fault_record : ledger_fault:00000000000000000077:00000000000000000007:c4c8a5b9ed9746e7
--- call_id literally 'key:<32 hex>'
    fault_record : ledger_fault:00000000000000000079:key:0184f593a866d97e928ba76cec64f3db:85635bad5654442f
```

All three go into the key unaltered. The second one puts a component into the
key that is byte-identical to the shape of a transaction bound, and the third
occupies the digest fallback's own namespace. Nothing today splits the key, so
none of these misparse as another record's fault, and I could not make one
record's fault join as another's: the join is `committed_key` from the body
and the body is inside the signature.

**The decisive form is the length, and it is not a parsing problem.** ImmuDB
refuses a key past its maximum length, and the fault key inherits its length
from the `call_id`:

```
--- call_id of  700 chars -> fault_record: ledger_fault:00000000000000000081:LLLL...   (written)
--- call_id of 1000 chars -> fault_record: null
                             fault_record_error: "max key length exceeded"
--- call_id of 1024 chars -> fault_record: null,  "max key length exceeded"
--- call_id of 2000 chars -> fault_record: null,  "max key length exceeded"
```

Two identical writes under one live proof failure, control first:

```
--- CONTROL: a 32-char call_id
    write  -> {"tx_id": 123, "seq": 1000000054, "verified": false, "committed": true,
               "error_class": "consistency_failure"}
    fault_record       : ledger_fault:00000000000000000123:36eac95104574fc48e783e39116fa3a6:21c158f1cbbe4a10
    fault_record_error : None
    page row           : {"outcome_type": "policy_allow", "ledger_fault":
                          {"fault_class": "write_verification_failed", ...,
                           "committed_tx_id": 123, "committed_position": 1000000054, ...}}

--- ATTACK : a 1200-char call_id
    write  -> {"tx_id": 125, "seq": 1000000055, "verified": false, "committed": true,
               "error_class": "consistency_failure"}
    fault_record       : None
    fault_record_error : _InactiveRpcError: ... "max key length exceeded"
    page row           : {"outcome_type": "policy_allow", "ledger_fault": null}
```

A committed record whose write-time proof failed, on the audit page reading
`policy_allow` with nothing recording why its proof failed. That is precisely
the condition D35 says the fault record exists to remove, and a caller selects
it by choosing its own `call_id`. The failure is reported in
`fault_record_error` on a response the middleware discards, and the verifier
logs it, so it is loud in the log and silent on the page.

---

## A2 - Refuted

The window is `min_tx`/`max_tx` over the page's rows and the fault is placed
by the transaction in its **key**. The fault body carries `committed_tx_id`
too, and nothing compares the two.

A fault seeded the way `tests/test_fault_key_and_page_read.py` seeds one
(built by the verifier's own `_fault_key`, signed with the verifier's own
writer key through `provenance.sign_record`), naming the right record in
`committed_key` and the right transaction in `committed_tx_id`, keyed at a
transaction the record does not occupy:

```
  CONTROL, key tx == record tx : {"fault_class": "write_verification_failed",
                                  "committed_tx_id": 98, "count": 1}

  record committed at tx 100 ; fault key names tx 1000100
  fault key                    : ledger_fault:00000000000001000100:b3707b257f004e1a9b7bdcfab3e78c27:7f037c898cd64756
  ATTACK, key tx != record tx  : HTTP 200 row ledger_fault = null
```

HTTP 200, no error, no log line, a page that looks exactly like a page with no
fault. "Every fault belonging to a page row is returned by the page's bounded
read" is true only because the transaction in the key is trusted to be the
record's, and the page has both numbers in front of it and does not look. The
brief's three shapes all land here: written wrong, written for a record on a
different page, and written before the record commits are the same condition
seen from three sides, and all three are invisible rather than reported.

I could not make the verifier itself write such a fault: every call site
passes the transaction it got from the write. So this is a robustness claim
rather than an attack, and it is the claim A2 makes.

---

## A3 - Not refuted

The boundary, driven directly on `control_plane/main.py::_faults_in_tx_window`
with 2502 faults seeded across consecutive transactions:

```
  seeded 2502 faults at transactions [100000007000000, 100000007002501]
  window of exactly  2499 faults -> returned  2499, distinct  2499, complete=True
  window of exactly  2500 faults -> returned  2500, distinct  2500, complete=True
  window of exactly  2501 faults -> returned  2501, distinct  2501, complete=True
  window of exactly  2502 faults -> returned  2502, distinct  2502, complete=True
```

Exactly `limit`, exactly `limit + 1`, and a window whose faults exceed 2500
across a cursor advance: complete, no key returned twice, terminates. The
`inclusiveSeek: False` cursor is what makes the 2500 case exact rather than
2499 or 2501.

**What I did not test:** a fault written concurrently with a page read that
spans two cursor pages. I could not drive that deterministically inside this
session. Reading the loop, a key sorting at or below the advanced cursor is
missed and a key above it is included, and neither duplicates, because a fault
key is written once and never rewritten. That is reasoning, not a measurement,
and it is recorded as such.

---

## A4 - Refuted, two independent ways

### A4.1 The ordered route was never given D40's treatment

`tests/test_committed_is_a_fact.py` has four tests and every one of them
drives `POST /write`. `POST /write-ordered`, which is the route
`ledger/immudb_ledger.py` takes for every decision and every intent, still
reads:

```python
except Exception as exc:                        # verifier/main.py:1546
    logger.error("ordered write error: %s", exc)
    return OrderedWriteResponse(tx_id=None, seq=None, verified=False,
                                committed=False, detail=str(exc))
```

It asks the ledger nothing.

A relay between the verifier and ImmuDB, on the compose network, source passed
to `python -c` the way the committed fixture does it, relays the marked
request upstream so it commits and then drops its response and closes. That is
"connection reset after commit" on the commit's own RPC rather than on the one
after it.

```
### CONTROL: the same write through the relay with NO marker ###
  -> 200 {"tx_id": 54, "seq": 1000000016, "verified": true, "committed": true,
          "attempts": 1, ...}

### ATTACK: the ordered write's own ExecAll response is dropped ###
  WRITE -> 200 {"tx_id": null, "seq": null, "verified": false, "committed": false,
                "attempts": 0, "detail": "StatusCode.UNAVAILABLE ...
                                          Stream removed (Socket closed)"}
  relay log: ['CUT: dropping the 42B response to the marked request and closing',
              'CUT: up pump ended: [Errno 104] Connection reset by peer']
  LEDGER-> {"tool_call:p3c3dred-a4:f8204a3b...:query_database": {"tx": "55", "revision": "1"}}
  top of the decision view:
     (1000000017, 'tool_call:p3c3dred-a4:f8204a3b...:query_database', '55')
     (1000000016, 'tool_call:p3c3dred-a4c:af66a85e...:query_database', '54')
  /audit -> 200 rows for this call_id: 1
     row: {"call_id": "53c2170535c54d9ea0cb9624775e4378",
           "outcome_type": "policy_allow", ...}
```

The whole ExecAll landed. The record is at transaction 55, the counter
advanced, the zAdd is in the view at position 1000000017, and the row is on
the audit page reading `policy_allow`. The response says the write did not
happen.

`ledger/immudb_ledger.py::log_tool_call` raises on anything but
`verified: true`, and `decision_service` turns that into a denied call. So the
ledger and the audit page carry an allow decision for a call the gateway
denied, which is the same divergence in the other direction from the one D35
and D40 were written for.

`attempts: 0` on that response is also wrong: the commit took one.

### A4.2 On `POST /write`, the ledger read itself can be the thing that is cut

D40's generic handler on the plain route does ask the ledger:

```python
tx_id = _committed_tx_for_value(client, key, value)
if tx_id is None:
    return WriteResponse(tx_id=None, verified=False, committed=False, detail=str(exc))
```

and `_committed_tx_for_value` answers `None` on any exception. So the guess is
still there, one RPC further along. A second relay relays the marked request,
drops its response, and then refuses every connection for 25 seconds, which is
what "ImmuDB went away right after the commit" looks like:

```
### CONTROL: the same route, same relay, no marker ###
  -> 200 {"tx_id": 117, "verified": true, "committed": true, ...}

### ATTACK: POST /write, response dropped, immudb then unreachable ###
  WRITE -> 200 {"tx_id": null, "verified": false, "committed": false}
           detail: StatusCode.UNAVAILABLE ... "Stream removed (Socket closed)"
  elapsed 0.1s
  relay: ['CUT: armed on a 940B request carrying the marker',
          'CUT: dropped the 30B response and blackholed immudb for 25s',
          'CUT: refusing a connection during the blackhole']
  LEDGER-> {"probe:ZZHOLEZZ-a4b-6ca670": {"tx": "118", "revision": "1"}}
```

The record is at transaction 118. The response says `committed: false`.

**And the GDPR consequence comes back with it.** The same cut on the erasure
path reproduces Phase 3c-3c's A8 transcript line for line against the head
that reports it closed:

```
### CONTROL: an erasure through the relay with no marker ###
  POST /content -> 204   DELETE -> 204

### ATTACK: erasure, tombstone commits, immudb then unreachable ###
  POST /content -> 204
  DELETE -> 503 {"detail":"Tombstone write failed; erasure refused: Tombstone
                  write not verified: StatusCode.UNAVAILABLE ..."}
  tombstone in the ledger -> {"content_erasure:a8ZZHOLEZZa4188d8c": {"tx": "121"}}
  re-POST /content -> 409 {"detail":"call_id 'a8ZZHOLEZZa4188d8c' has been erased;
                            content writes are refused"}
  control-plane store  -> call_content [('a8ZZHOLEZZa4188d8c', 772)]
```

The ledger says this call_id was erased. The store still holds 772 bytes of
payload. The caller was told the erasure was refused. Content writes for it
are frozen at 409. `P3c3d-7`'s enforcing test asserts this cannot happen; it
asserts it for the cut that lands on the RPC after the commit, and the
condition is a property of the cut and not of the route.

The third cut the brief asks about with the value readable but different is
the one case that is right: `_committed_tx_for_value` compares bytes, and a
different record under the same key correctly answers `committed: false`. That
half of D40 holds.

---

## A5 - Not refuted, and the composed condition is real

`KeyMustNotExist` cannot deny any write this system makes. Both ordered write
paths mint a fresh key per call:

```
ledger/immudb_ledger.py:210  key = f"tool_call:{agent_id}:{uuid.uuid4().hex}:{tool_name}"
ledger/immudb_ledger.py:293  key = f"tool_call_intent:{agent_id}:{uuid.uuid4().hex}:{tool_name}"
```

so a retry is a new key and never collides. `/write-ordered` has no other
production caller (`grep -rn "write-ordered"` outside `docs/reports/` and
`tests/` finds `ledger/immudb_ledger.py` and nothing else). The reserve
precondition, the other `KeyMustNotExist` in the same `ExecAll`, is retried
correctly: a failure there clears both caches and re-reads.

**The composition the brief names does happen, and it is a dead end for the
caller.** Continuing A4.1, with the relay removed, the same key retried:

```
RETRY (relay gone) -> 409
{"detail":"a record is already committed under this key
 (tool_call:p3c3dred-a4:f8204a3b854c4230983b5ca252c101df:query_database);
 the ordered route writes a record key once. ..."}
```

So a caller told `committed: false` has exactly two options, and both are
wrong: believe the response and retry, which is refused forever, or disbelieve
it. Before D39 the retry would have succeeded and put the key at two positions,
which is the defect D39 closed. The route now has no state a caller can reach
that says what actually happened. That is a consequence of A4 and not of A5,
which is why A5 stands.

---

## A6 - Not refuted

Both halves tested against the live page.

```
  legacy key ledger_fault:{call_id}, signed by the VERIFIER writer key
    -> {"fault_class": "write_verification_failed", "committed_tx_id": 102, "count": 1}
  legacy key ledger_fault:{call_id}, signed by the DECISION writer key
    -> null
```

The first is the claim; the second is D41 doing its job and is the control
that shows the check fires. I looked for a class of genuine old fault that
D41 drops and did not find one:

- Phase 3c-3c already signed the fault record. `git show e3d8284:verifier/main.py`
  line 654 is `signed = sign_record(fault, signing_key, verifying_key)`, so
  there is no era of unsigned faults to drop.
- `provenance/record_signature.py` gained `load_verifying_key` and
  `verify_record` in this phase and `sign_record` and
  `canonical_record_bytes` are unchanged (`git diff e3d8284 HEAD --
  provenance/` is 61 lines, all additions), so a fault signed before D41
  verifies under it.
- The legacy fault body carries `committed_key`, which `_rendered_fault`
  requires, at `git show e3d8284:verifier/main.py` line 635.

The residual is the one the code already states: `_fault_writer_key()` caches
its own failure, so a control plane that started before
`AIL_FAULT_WRITER_PUBLIC_KEY` was readable renders no fault on any page until
it is restarted, and the page looks clean. That is C3's class, it is logged at
error, and it is in the docstring. I did not count it as a refutation because
it is stated.

---

## A7 - Refuted

The count is inflated from the write credential alone, with one fault in the
ledger.

`_tombstones_and_faults` still asks for the legacy key
`ledger_fault:{call_id}` for every `call_id` on the page, and `call_id` is a
caller-supplied string. A new-shape fault key is
`ledger_fault:{tx:020d}:{identity}:{nonce}`, so a record whose `call_id` is
spelled `{tx:020d}:{identity}:{nonce}` makes the derived legacy key equal to
that fault key. The getall then returns the fault, `_merge_fault` folds it in
at `count = revision = 1`, and `_faults_in_tx_window` returns the same entry
again and folds it in a second time.

The caller does not have to guess the key: the write response hands it over in
`fault_record`.

```
  fault key                    : ledger_fault:00000000000000000106:11a19025b81548d68c1ddb203841011b:4ea2f03d65c14cff
  BEFORE, one fault exists     : {"fault_class": "write_verification_failed",
                                  "committed_tx_id": 106, "count": 1}
  second record's call_id      : 00000000000000000106:11a19025b81548d68c1ddb203841011b:4ea2f03d65c14cff
  its write                    : 200 {"tx_id": 108, "seq": 1000000044, "committed": true}
  AFTER, still one fault       : {"fault_class": "write_verification_failed",
                                  "committed_tx_id": 106, "count": 2}
  faults in the ledger for it  : 1
```

`count` is the field P3c3d-11 introduced so the page could say how many faults
exist for a record. It says two where one exists, on a row belonging to a
different record than the one the attacker wrote, and the attacker needs only
the write key it already holds.

Two further things follow from the same mechanism and are worth stating
separately.

**The page's fault read is not bounded by the page on its legacy half.** The
pre-registered negative in section 8 of the phase report is "any page-side
fault read whose bound is not derived from the page", answered with
`_page_faults` taking its window from the truncated zscan rows. The legacy
getall beside it takes its keys from `page_call_ids`, which are caller-authored
strings, so a caller chooses which `ledger_fault:` key that read fetches. The
fault it fetched is genuine and lands on its own record's row, so today the
damage is the count; the bound is still caller-directed rather than
page-derived.

**The brief and the implementation disagree on the shape.** The brief states
A7 as "a list, newest first, ordered by the `scan` entry's own `tx`". Section 6
of the phase report chose the opposite and says so: `ledger_fault` stays one
object, the most recent fault, with a count. The implementation matches the
report. I tested the report's contract, and the ordering half of it holds:
three faults about one record came back ordered by the entry's own `tx` and
the most recent one is what the row carries.

---

## A8 - Refuted on the parse. Not refuted on the guard.

**The guard holds.** `_set_without_verification(client, key, value)` parses the
bytes it is about to write and there is no longer a parameter that can
disagree with them. Driven with a stub client through both of the second
callers below:

```
_second_caller: a fault record  -> tx 999, stub recorded 1 write(s),
                                   bytes committed = {"record_type": "ledger_fault", ...}
_second_caller: a DECISION record -> refused: refusing an unverified write for a
                                     'decision' record: this path exists only for
                                     'ledger_fault' ...
```

I could not get a non-fault record past it. `json.loads` is what both this
guard and every consumer use, so duplicate keys, trailing bytes and non-UTF-8
all fail identically on both sides rather than diverging.

**The parse is defeated again.** It counts `ast.Name` nodes whose `id` is
`_set_without_verification`. Neither of these is one.

Control first, the previous pass's own alias, to show the check can fail:

```
_unverified_write = _set_without_verification
def _aliased_second_caller(client, key, value):
    return _unverified_write(client, key, value)

FAILED tests/test_ledger_faults.py::test_the_unverified_write_path_has_exactly_one_caller_including_aliases
  AssertionError: the unverified write path is named outside _write_fault_record,
  at line(s) [624].
```

Then the attack, two live second callers in `verifier/main.py`:

```python
_UNVERIFIED = "_set_" + "without_verification"

def _second_caller(client, key, value):
    return globals()[_UNVERIFIED](client, key, value)

def _third_caller(client, key, value):
    import sys as _sys
    return getattr(_sys.modules[__name__], _UNVERIFIED)(client, key, value)
```

```
$ python -m pytest tests/test_ledger_faults.py -q -k "unverified_write_path"
2 passed, 18 deselected in 7.12s
```

Both callers reach the function, proved above with the stub. The reference
count is a better check than the line count it replaced and it is still a
check on how the name is spelled, so a spelling that is a string rather than a
name is invisible: `globals()[...]`, `getattr(module, ...)`, `vars()`, `eval`.
The claim in the report is "there is no spelling of reach this function that
is not a reference to its name"; there are at least four.

**One thing the guard does not check is the key.** The same driven run:

```
_second_caller: a fault record under the COUNTER key -> tx 999,
                key committed = ail_seq:counter
```

The no-proof path will write a well-formed fault record over
`ail_seq:counter`. That is not a non-fault record, so it is not a refutation
of A8 as worded, but the path's stated bound is "this path exists only for
`ledger_fault`" and a fault record under the sequence counter's key is not
one.

All mutations were reverted; `git status --short` was empty afterwards and
`2 passed` again.

---

## A9 - Refuted

D42 says a bounded read asserts on what came back, in the form its bound takes,
and section 8 of the phase report says "both forms implemented; no third thing
invented". There are four bounded reads in this codebase and two of them
assert nothing. Both unasserted ones are in `tools/ail_backfill_index.py`, and
both are what decides which keys the backfill zAdds into a view index.

Each was driven with a client that answers outside the bound it was asked for,
which is exactly how `tests/test_fault_key_and_page_read.py::test_a_bounded_read_asserts_on_what_came_back`
drives the one it covers.

```
1. control_plane/main.py::_faults_in_tx_window - bounded by a KEY RANGE
   BoundedReadFault: a bounded read returned a key outside the range it asked
   for: 'ledger_fault:00000000000001000000:someone:else' is not in [...]

2. anchor_service/main.py::collect_positions - bounded by minScore
   ail_view:decision:v1: positions=[1.0, 500.0]
     malformed=[{'reason': 'score_outside_requested_bound', 'score': 1.0,
                 'requested_min_score': 500.0, 'key': 'dG9vbF9jYWxsOmI='}]

3. tools/ail_backfill_index.py::indexed_keys - the SAME minScore bound
   RETURNED, no complaint: ['tool_call:a', 'tool_call:b']
   (the second page's score is 1.0 for a minScore of 500.0)

4. tools/ail_backfill_index.py::scan_all - bounded by a PREFIX
   asked for prefix 'tool_call:', RETURNED, no complaint:
      ail_seq:counter
      ail_seq:reserve
      ledger_fault:00000000000000000001:x:y
      content_erasure:abc
```

1 and 2 are the controls; they fire.

The consequence is not symmetric with the two that were fixed. `indexed_keys`
is the snapshot of what a view already holds, and P3c3c-5 fixed this exact
function once already because an incomplete snapshot indexes records a second
time: `docs/reports/phase-3c3c.md` records 25 records at two positions each
from one pass at 2535 rows. A record at two positions is the condition the
previous red-team pass showed kills `/audit` with `audit_ordering_fault` at
every limit, permanently. `scan_all`'s results are zAdded directly
(`tools/ail_backfill_index.py:406`), so a dropped prefix bound indexes the
sequence counter, the reserve, fault records and erasure tombstones into
`ail_view:decision:v1`, each of which then becomes a page row.

`indexed_keys` also shares `collect_positions`' other termination clause,
`len(seen) == before`, which stops the walk on a full page that adds nothing
new rather than reporting it.

---

## A10 - Refuted, two independent ways

The detector is a PEM armour BEGIN line at column zero with a matching END
line, plus the PuTTY header, over the first 16 KiB of every file in the
running image.

### A10.1 DER

Control first, so the check is known to be able to fail. One P-256 key,
written into `decision_service/` (which `.dockerignore` does not exclude and
`COPY decision_service/ ./` sweeps up) as a PEM, `p3c3dred-decision-service`
rebuilt:

```
FAILED tests/test_image_contents.py::test_no_image_built_from_the_repository_root_carries_key_material[decision-service]
FAILED tests/test_image_contents.py::test_no_dockerfile_copies_key_material
  AssertionError: ... 'COPY decision_service/ ./' reaches
  decision_service/leaked_credential.pem
2 failed, 3 passed in 79.91s
```

Then the same key, as DER, both SEC1 and PKCS8, and the PEM removed:

```
$ ls decision_service/leaked_*
decision_service/leaked_credential.der
decision_service/leaked_pkcs8.der
$ python -m pytest tests/test_image_contents.py -q
5 passed in 76.67s
```

Read back out of the image that was just built and shipped:

```
$ docker create --name p3c3dred-a10-extract p3c3dred-decision-service
$ docker cp p3c3dred-a10-extract:/app/leaked_credential.der /tmp/out_sec1.der
$ openssl ec -inform DER -in /tmp/out_sec1.der -text -noout
read EC key
Private-Key: (256 bit)
priv:
    ae:cb:0d:25:81:f0:ef:41:44:69:0e:ff:66:6c:2b:
    5a:1c:8c:b7:18:3c:a0:29:5f:35:57:58:aa:14:50:
    0e:ee
$ openssl ec -inform DER -in /tmp/out_sec1.der -out /tmp/out.pem
$ sha256sum /tmp/a10.key /tmp/out.pem
5d1a6c8658b13519483f5431841651977a55fa60d66264fefe5f5d64d8b55d61 *a10.key
5d1a6c8658b13519483f5431841651977a55fa60d66264fefe5f5d64d8b55d61 *out.pem
```

The key that came out of the image is byte-identical to the key generated on
the host once re-armoured, and it re-armours into exactly the PEM the same
check would have caught. DER is not an exotic encoding: `openssl ec -outform
DER` is one flag, and `cryptography.load_der_private_key` reads it directly.
The same hole covers a base64 body with the armour stripped, and a key past
16 KiB of other content, which the module already states.

### A10.2 A layer a later layer deletes

The image check runs `docker run` and walks the resulting filesystem, so a
file that a later layer removes is invisible to it while remaining in the
image.

```
FROM p3c3dred-decision-service
COPY id_ecdsa /app/id_ecdsa
RUN rm -f /app/id_ecdsa
```

```
p3c3dred-a10-layer returncode 0 hits: []

$ docker save p3c3dred-a10-layer -o /tmp/a10layer.tar
$ cd /tmp/a10x/blobs/sha256
$ tar -xzf 179eecb618a674e6d469527c290ba04a94e3f9769735024e6b7f747c5087bd51 -C /tmp app/id_ecdsa
$ head -1 /tmp/app/id_ecdsa
-----BEGIN EC PRIVATE KEY-----
$ sha256sum /tmp/app/id_ecdsa /tmp/a10.key
5d1a6c8658b13519483f5431841651977a55fa60d66264fefe5f5d64d8b55d61 */tmp/app/id_ecdsa
5d1a6c8658b13519483f5431841651977a55fa60d66264fefe5f5d64d8b55d61 */tmp/a10.key
```

A plain PEM at column zero, the exact thing the detector was rewritten to
find, recovered byte-identical from the image with two commands. "No image
carries key material" is a claim about layers; the check is a claim about the
last one.

A third scope note rather than a finding: `ROOT_CONTEXT_SERVICES` is four
services, so `p3c3dred-dashboard` is never content-inspected at all. Its own
build context cannot reach `keys/`, so nothing gets in today.

All A10 artefacts were removed and `p3c3dred-decision-service` was rebuilt
clean; `git status --short` was empty afterwards.

---

## Also: what `/write-ordered` still permits into a view

The raised-not-taken item, measured. Every write below used only
`VERIFIER_WRITE_KEY` and every one returned `verified: true, committed: true`.

```
BEFORE: entries 43  total 43  has_more False

--- an erasure tombstone key, into the decision view
    content_erasure:140ee0faada94cfd9b87e2e54526d8ed        -> tx 109 seq 1000000045
--- an intent key + intent record, into the DECISION view
    tool_call_intent:also:4f9e8af2...:query_database         -> tx 110 seq 1000000046
--- a decision key + decision record, into the INTENT view
    tool_call:also:3a9cef75...:query_database                -> tx 111 seq 1000000047
--- an arbitrary prefix, no record_type, into the decision view
    zzz-arbitrary:953f7b90...                                -> tx 112 seq 1000000048
--- the reserve key's own namespace, into the decision view
    ail_seq:not-the-counter-a9293ca5...                      -> tx 113 seq 1000000049

AFTER : entries 47  total 44  has_more False
    tombstone key      -> {"call_id": "140ee0fa...", "outcome_type": null,
                           "payload_state": "erased"}
    intent record      -> {"call_id": "1a7cd04a...", "outcome_type": null,
                           "tool_name": "query_database", "agent_id": "also",
                           "payload_state": "unavailable"}
    decision in intent -> NOT a page row
    arbitrary prefix   -> {"call_id": null, "outcome_type": null,
                           "payload_state": "lost"}
    ail_seq: namespace -> {"call_id": null, "outcome_type": null,
                           "payload_state": "lost"}
```

The reconciler catches all five, which is the good news:

```
{"state": "findings", "allocated": 49, "indexed": 49, "foreign_count": 5, ...}
FOREIGN: content_erasure:140ee0fa... expected_prefix tool_call:
         tool_call_intent:also:...   expected_prefix tool_call:
         zzz-arbitrary:953f7b90...   expected_prefix tool_call:
         ail_seq:not-the-counter-... expected_prefix tool_call:
         tool_call:also:3a9cef75...  expected_prefix tool_call_intent:
```

**The reconciler catches them because they are foreign to the view's prefix.
Keep the prefix and it does not.**

```
-- tool_call: key, body = {} (no record_type)          -> tx 114 seq 1000000050
-- tool_call: key, body = a content_erasure record     -> tx 115 seq 1000000051
-- tool_call: key, body = not JSON at all              -> tx 116 seq 1000000052

AFTER  entries 49  total 47  has_more False
   body = {}                     -> {"call_id": null, "outcome_type": null,
                                     "payload_state": "lost"}
   body = a content_erasure rec  -> {"call_id": "822246de...", "outcome_type": null,
                                     "payload_state": "lost"}
   body = not JSON at all        -> NOT a page row

RECONCILE: {"state": "findings", "allocated": 52, "indexed": 52,
            "foreign_count": 5, "missing_count": 0, "unallocated_count": 0,
            "shared_count": 0, "duplicated_count": 0, "malformed_count": 0}
```

`foreign_count` is unchanged at 5. So the blast radius is:

- **The page.** Any prefix produces a row. `outcome_type: null` on all of
  them; `payload_state` reads `lost`, which is the operational-incident state,
  or `erased`, which is an Article 17 claim, or `unavailable`. A reader cannot
  tell an injected row from a real one by the row.
- **`total`.** `total` counts `tool_call:` keys ledger-wide, so a
  `tool_call:`-prefixed injection raises it and any other prefix does not.
  `entries` exceeded `total` in every measurement here, 47 against 44 and then
  49 against 47. The phase report says "what changed is that a caller can no
  longer inflate `entries` with a fault key", which is true and covers exactly
  one prefix.
- **Reconciliation.** Foreign only. A `tool_call:`-prefixed injection is
  `clean` on every category, and so is a record whose value is not JSON at
  all: that one is committed, holds a position, is counted by the reconciler,
  is skipped by `/audit` with a log warning, and appears on no page ever.

---

## Not on the list

**1. Two CI-green tests in this repository contradict each other, and one of
them fails permanently against any ledger the other has touched.**

`tests/test_reconciliation.py:325-328` zAdds a deliberately fractional
position into `ail_view:decision:v1` and never removes it:

```python
surplus = _counter() + 0.5
key = f"tool_call:p3c3c-surplus-{uuid.uuid4().hex[:8]}:..."
_write_historical(key, ...)
_zadd(VIEW_DECISION, surplus, key)
```

`tests/test_audit_ordering.py:997` asserts, ledger-wide over the whole view:

```python
assert all(float(x).is_integer() for x in live), (
    "an allocated position is not an integer, so it did not come from the counter")
```

Both pass in CI. CI runs `pytest tests/`, whose collection order is
alphabetical, and `test_audit_ordering.py` sorts before `test_reconciliation.py`;
each CI job also starts from `docker compose down -v`. Run in the other order,
or run at all against a ledger that has seen `test_reconciliation.py`:

```
$ python -m pytest tests/test_reconciliation.py tests/test_audit_ordering.py ... -q
FAILED tests/test_audit_ordering.py::test_the_seam_is_monotone_across_the_boundary
  AssertionError: an allocated position is not an integer, so it did not come
  from the counter
1 failed, 68 passed in 264.06s

$ python -m pytest "tests/test_audit_ordering.py::test_the_seam_is_monotone_across_the_boundary" -q
1 failed in 14.12s
```

The offending member, read straight out of the view:

```
view members: 208
non-integer scores: 1
    1000000077.5 tool_call:p3c3c-surplus-e93d64d2:ec458d9136ec4783be9f87b9aef1ce97:query_database
```

This is the class the brief points at, in its purest form: an assertion about
"the ledger" that is really an assertion about the ledger this suite happens
to build, in the order it happens to build it. It is not a defect in the
gateway. It is a test that will fail the first time anyone runs the suite
twice without `down -v`, or reorders a module, or adds a module that sorts
between the two.

**2. `attempts` is reported as 0 on the ordered route's generic-exception
branch** while the commit took one. Section 7.9 of the phase report records
fixing exactly this understatement on the proof-failure branch and left the
branch beside it. Visible in the A4.1 transcript above.

**3. `entries` exceeding `total` is one line of code away from being
harmless.** `total` is `_ledger_decision_count`, a count of `tool_call:` keys;
`entries` is the view index. They will differ whenever anything that is not a
`tool_call:` key is in the decision view, which `/write-ordered` permits. This
is Phase 3c-3c's unlisted finding 3, carried unchanged, and it is now
reachable in more ways than the fault key it was measured with.

---

## Could not test

1. **A fault written concurrently with a page read that spans two cursor
   pages.** No deterministic way to interleave a write into the middle of
   `_faults_in_tx_window`'s loop from outside the process, and I did not want
   to report a race I had only reasoned about as if I had driven it. See A3.

2. **Whether a real pre-D38 ledger reads correctly under this build.** Every
   stack here was built from a checkout that has D38 in it, so my legacy
   faults are seeded rather than migrated. This is the same limit the phase
   report states in its section 11 item 5, and I did not lift it.

3. **The upper reaches of the reserve.** A6's 2^53 finding from the previous
   pass is now bounded in source, and I did not attempt to reach the ceiling
   for the reason the phase report gives: no test can build a counter at 2^53.

4. **A getall larger than about 5000 keys.** `/audit?limit=2500` derives a
   getall of two keys per page call_id, which is close to 5000 at a full page,
   and the only measurement on record is 3000. This ledger never had enough
   distinct call_ids on one page to reach it, so I could neither confirm nor
   refute that the tombstone and legacy-fault join survives a full page.

---

## Environment cleanup

Removed:

- Compose project `p3c3dred`: all seven containers, the three volumes
  (`p3c3dred_test-immudb-data`, `p3c3dred_test-verifier-state`,
  `p3c3dred_test-control-plane-data`) and the network `p3c3dred_default`,
  with `docker compose -p p3c3dred -f docker-compose.test.yml down -v`.
- The six images built by this run: `p3c3dred-verifier`,
  `p3c3dred-ail-control-plane`, `p3c3dred-decision-service`,
  `p3c3dred-anchor-service`, `p3c3dred-dashboard`, and the throwaway
  `p3c3dred-a10-layer` that carried a live P-256 key in a deleted layer.
- The two relay containers, `p3c3dred-p3c3dred-cutresp` and
  `p3c3dred-p3c3dred-blackhole`, and the extraction container
  `p3c3dred-a10-extract`.
- The scratch clone `C:\Users\banji\OneDrive\Documents\p3c3d-red` in full,
  including the generated `keys/*.key`, `keys/*.pub` and
  `decision_service/secrets/vault_api_token.txt`.
- The extracted key material outside the clone: `/tmp/a10.key`,
  `/tmp/out_sec1.der`, `/tmp/out_pkcs8.der`, `/tmp/out.pem`,
  `/tmp/a10layer.tar`, `/tmp/a10x/`, `/tmp/app/id_ecdsa`,
  `/tmp/verifier_main.bak`.
- Every probe script, written to the session scratchpad and never into the
  tree, so none could be committed by accident.

Verified empty afterwards, each filtered on the project name:

```
$ docker ps -a --format '{{.Names}}'   | grep -i p3c3dred   ->  (nothing)
$ docker images --format '{{.Repository}}' | grep -i p3c3dred -> (nothing)
$ docker volume ls --format '{{.Name}}'    | grep -i p3c3dred -> (nothing)
$ docker network ls --format '{{.Name}}'   | grep -i p3c3dred -> (nothing)
$ ls /tmp/*.key /tmp/*.der /tmp/*.pem  ->  No such file or directory
$ ls -d C:/Users/banji/OneDrive/Documents/p3c3d-red -> No such file or directory
```

**Could not remove: nothing of this run.** The Docker daemon stayed healthy
throughout.

Untouched, and belonging to earlier runs rather than this one:
`p3c3d-keyprobe-*`, `p3c3brepro-*` and `p3bverify-*` images, the
`ail-scratch_*` and `compliance-ail_*` volumes, and one stray
`/tmp/verifier_main.orig.py` dated 2026-08-31 21:05, which is a copy of
`verifier/main.py` carrying no key material and predates this session by a
day. All were present at the start and are left as found.

All source mutations were reverted in the scratch clone before teardown and
`git status --short` was empty at `88cce1d` after each one. The A8 mutations
were reverted and the two parse tests re-run green; the A10 files were deleted
and `decision-service` rebuilt clean.

The primary working directory was never used for a stack. The only thing this
run wrote there is this report.
