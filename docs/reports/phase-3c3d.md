# Phase 3c-3d: Fault records, route refusals, and the 3c-3c red-team set

**Run id:** `p3c3d-fix`.
**Working directory:** `C:\Users\banji\OneDrive\Documents\p3c3d-fix` (a scratch clone; not the primary working directory).
**Branch:** `p3c3b-order`, continuing PR #14. No rebase, no second PR, not merged.
**Compose project:** `p3c3dfix`, stated explicitly on every invocation.
**Instruction:** `docs/reports/phase-3c3d-instruction.md`.
**Base:** `e3d8284`.

---

## 1. Objective

Everything Phase 3c-3c claimed is true, or is scoped down to what it can support.

The red-team pass `p3c3c-red` (`docs/reports/phase-3c3c-redteam.md`) refuted nine of ten claims: A1, A2, A3, A4, A5, A6, A8, A9, A10. A7 was not refuted. A key-shape probe (`docs/reports/phase-3c3d-keyprobe.md`) then established that D38 as originally written was a rename that closed nothing. This phase closes that set.

---

## 2. Environment

No stack was running at the start. Leftover images from `p3c3d-keyprobe`, `p3c3brepro` and `p3bverify` were present and untouched; no volume, network or container matching `p3c3d` or `p3c3c` existed. Keys were generated in the scratch clone with the same openssl commands `make keygen` runs, because `make` is not on PATH here.

Every image was built `--no-cache` at the start of the phase and rebuilt from the layer cache after each source change. Every stack was brought up under `-p p3c3dfix`. The ledger was destroyed with `down -v` and rebuilt from virgin between reproduction groups, because two of the reproductions leave `/audit` permanently dead and one needs a virgin counter.

---

## 3. Raised before building

### 3.1 "The ordered route applies the same refusals" cannot be read literally, and the reading taken is stated

D39's item text says the ordered route applies "the same refusals", and the pre-registered negative says *any caller-authored record accepted on `/write-ordered` that the plain route would refuse*. Read literally that includes a `decision` record, which `POST /write` refuses and which `/write-ordered` exists to write. The two routes are not symmetric and cannot be.

What the two share is the `ledger_fault` refusal, and that one is not a statement about which route a record belongs on at all: a fault record is the verifier's own account of its own failed proof, and one arriving from a caller on any route is an unverified assertion about another record's standing. That is the refusal implemented, by key prefix and by `record_type`, and it is the refusal the keyprobe's own section 12 names as the fix.

**What that leaves open is stated rather than absorbed.** The ordered route allocates a position for whatever it accepts, so a caller holding `VERIFIER_WRITE_KEY` can still write a key of some other shape into the decision view and it becomes a page row with `outcome_type: null`. Closing that means requiring the key prefix to match the requested view. It was not taken, for a reason that is not convenience: `tests/test_reconciliation.py::test_a_record_indexed_into_the_wrong_view_is_a_finding` and `::test_reconciliation_reports_a_disagreement_no_page_can_reach` both write a `tool_call:` record into the intent view **through this route on purpose**, because that is how they prove D37 finds a record indexed into the wrong view (red-team C6a, closed in Phase 3c-3c). Adding the refusal would refuse those writes and the D37 check would lose its enforcing test, which would have to be re-expressed as a direct `zAdd` injection. That is a design change inside a remediation phase, so it is escalated: `TODO.md`'s deferred list, README section 5, and ADR-0014's Consequences all carry it, with the shape of the fix.

The measured injection the keyprobe found *was* a `ledger_fault`, and it is refused. The demonstration for "an injected row with `outcome_type: null` refused, and `entries` no longer exceeding `total`" is that case.

### 3.2 D40's "`except Exception` never produces `committed: false`" needed one more step than moving a line

The instruction's D40 names the state call inside the proof's `try`. Reproducing it showed that moving the state call out is necessary and not sufficient. Driven live (section 4.6), the same relay produced the same `{"tx_id": null, "committed": false}` from **two** different branches depending on where the cut landed: after `verifiedSet` returned, which the move fixes, and inside `verifiedSet`'s own completion, which it does not. The second is the generic handler, and answering `committed: false` there is a guess.

So the generic handler asks the ledger, with the value as well as the key. Byte equality is narrower than the proof-failure branch's key-only read on purpose: there the commit is known to have happened and only its transaction is in question, whereas here nothing is known, and a record that was already under this key would otherwise be reported as this write. This is a widening of D40 as written, in the direction D40 states, and it is named here rather than folded in silently.

### 3.3 A5's fourth condition is about a key at two positions, not about a range

The red team framed it as "any score below the reserve is assumed to be history and is never checked against live positions". Implementing it that way would make the check depend on which range a position is in, and the same defect exists entirely above the reserve. The check implemented is: **a key at more than one position, in any range, is a finding.** History is scored one position per record, the CAS allocates one per commit, and since D39 a record key is written once, so there is no legitimate second `zAdd` for a key. Two records *sharing* a score is a different thing and remains `shared`.

---

## 4. Reproduction on unmodified `e3d8284`

Every defect below was reproduced live before anything was changed.

### 4.1 D39, both halves

```
=== R1: a caller-authored ledger_fault takes /write-ordered ===
  seed decision write: {'tx_id': 1, 'seq': 1000000001, 'verified': True, 'committed': True}
  page row ledger_fault BEFORE: None
  POST /write         -> 400 "key prefix 'ledger_fault:' does not belong on the plain write route..."
  POST /write-ordered -> 200 {"tx_id":2,"seq":1000000002,"verified":true,"committed":true,...}
  page row ledger_fault AFTER : {'fault_class': 'FORGED-BY-CALLER', 'error_class': 'signature_failure',
                                 'committed_tx_id': 999999, 'committed_position': 123,
                                 'timestamp': '2026-01-01T00:00:00', 'count': 1, ...}
  entries=2 total=1
  rows with outcome_type None: 1
     ledger_fault:387b36afb58c47179f2e5855c95b8d14 | call_id 387b36afb58c47179f2e5855c95b8d14

=== R2: one record key, written twice through /write-ordered ===
  first : {'tx_id': 3, 'seq': 1000000003, 'verified': True, 'committed': True}
  second: {'tx_id': 4, 'seq': 1000000004, 'verified': True, 'committed': True}
  index entries for that one key:
    score=1000000004 entry_tx=4
    score=1000000003 entry_tx=4
  GET /audit?limit=1     -> HTTP 500 audit_ordering_fault
  GET /audit?limit=5     -> HTTP 500
  GET /audit?limit=200   -> HTTP 500
  GET /audit?limit=2500  -> HTTP 500
```

The fault body, in full:

```
"message": "the view index and the ledger disagree: position 1000000004.0 resolves to
 transaction 4 and position 1000000003.0 resolves to transaction 4, so the index no
 longer describes the order the ledger committed in"
```

Two ordinary well-formed writes, both verified and committed, no corruption and no privileged access, and the audit page is dead at every limit.

### 4.2 D38: the old shape, and the original D38

```
=== R3: D38 as originally written is a rename (two faults, one record) ===
  key   = ledger_fault:00000000000000004242:3d10361b60db4c9294f8ed55c7a8d1e1
  head  = SECOND  revision=2
  range read over the record's transaction returns 1 key(s)

=== R3b: today's shape, three record kinds for one call_id ===
  three faults for one call_id -> 1 row(s), head detail='tombstone fault', revision=3
```

### 4.3 D42: a dropped bound is silent

```
=== R4: D42, a misspelled bound is dropped silently ===
  correct  endKey : ['00', '01', '02', '03', '04', '05', '06']
  misspelt endkey : ['00', '01', '02', '03', '04', '05', '06', '07', '08', '09']
  unknown param   : ['00', '01', '02', '03', '04', '05', '06', '07', '08', '09']

=== R4b: D42, the half-open end bound on a composite key ===
  bare hi, inclusiveEnd=True : []
  half-open hi+1, exclusive  : ['00000000000000999999']
```

### 4.4 The unlisted red-team finding 2, and A6

```
=== R5: a non-string record_type crashes POST /write with a 500 ===
  POST /write record_type=['decision'] -> 500 Internal Server Error

=== R6: validate_reserve bounds below only ===
  validate_reserve(                   0) -> refused
  validate_reserve(                  -1) -> refused
  validate_reserve(    9007199254740992) -> 9007199254740992
  validate_reserve( 9223372036854775807) -> 9223372036854775807
  float64 distinctness: 9007199254740992 and 9007199254740993 -> True (same score)
```

### 4.5 A3, both bounds

```
=== R7: the A3 static parse, defeated by a binding ===
  lines the parse counts (with the paren): 1
  lines naming the function at all       : 2

== CONTROL: the record argument is a decision record ==
   -> refused: refusing an unverified write for a 'decision' record...
== ATTACK: record argument claims ledger_fault, value IS a decision record ==
   -> accepted, tx=159
   -> bytes committed: {"record_type":"decision","call_id":"a3probe001","outcome_type":"policy_allow"}
   -> key committed  : tool_call:a3probe001
```

The guard refuses when it is told the truth and accepts when it is not. The bytes it wrote are a decision record through the one path in this system that requires no proof.

### 4.6 A1 and A8, driven with a relay

A TCP relay between the verifier and ImmuDB, on the compose network, passing the write through and cutting the connection so the client's next RPC fails.

```
STATE BEFORE: {"immudb:3322/b'defaultdb'": 7, "cutproxy:3399/b'defaultdb'": 13}
WRITE -> (200, {'tx_id': None, 'verified': False, 'committed': False,
                'detail': 'StatusCode.UNAVAILABLE ... "Stream removed (Socket closed)"'})
LEDGER-> {"probe:ZZCUTZZ-a1-5172ec": {"tx": "14", "revision": "1"}}
STATE AFTER : {"immudb:3322/b'defaultdb'": 7, "cutproxy:3399/b'defaultdb'": 14}
```

The verifier's own persisted trust anchor advanced to 14, the transaction the response says never happened: `verifiedSet` completed, the proof passed, the state was persisted, and then `currentState()` raised.

A8 on the same relay:

```
##### ATTACK: erasure, cut on the RPC after the tombstone commits #####
  POST /content -> 204
  DELETE -> 503 {"detail":"Tombstone write failed; erasure refused: Tombstone write not
                  verified: ... StatusCode.UNAVAILABLE ..."}
  is the tombstone in the ledger? {"content_erasure:a8ZZCUTZZ007": {"tx": "16", "rev": "1"}}
  control-plane store row: a8ZZCUTZZ007 -> [('a8ZZCUTZZ007', 22)]
  re-POST /content -> 409 "call_id 'a8ZZCUTZZ007' has been erased; content writes are refused"
```

The ledger says erased, the store holds the payload, the caller was told the erasure was refused, and content writes are frozen at 409.

### 4.7 A5's fourth condition, A9, A10, D41, P3c3d-8, P3c3d-11

```
=== R11: a below-reserve duplicate reconciles clean ===
  live write: {'tx_id': 7, 'seq': 1000000003, 'verified': True}
  injected a SECOND position for the SAME key, below the reserve: score=42
  reconciliation verdict: {"state": "clean", "allocated": 3, "indexed": 3, "backfilled": 1,
   "missing_count": 0, "unallocated_count": 0, "foreign_count": 0, "shared_count": 0,
   "malformed_count": 0, "views": {"ail_view:decision:v1": 4, "ail_view:intent:v1": 0}}
  HTTP 200 rows 4 total 3
  call_ids appearing more than once on ONE page: ['d7461d51dec74aa5ac299e076d325830']
```

A9, the fifth vocabulary module: `tools/ail_ordering_cost_probe.py:52` pointed at `ail_view:decision:v2`, `tests/test_ledger_vocabulary.py` **6 passed**.

A10, key material by content: an image built `FROM p3c3dfix-decision-service` carrying `/app/deploy_credential.pem`, `/app/id_rsa` and `/usr/local/lib/python3.11/site-packages/leaked.key`, all three live P-256 keys with `-----BEGIN EC PRIVATE KEY-----` at the head. The enforcing test's own detector: `returncode=0 hits=[]`.

D41, P3c3d-11 and P3c3d-8 on one virgin ledger:

```
=== R8: a fault with no writer signature is rendered as a record's standing ===
  page row ledger_fault: {'fault_class': 'UNSIGNED-BY-ANYONE', 'error_class': 'signature_failure',
                          'committed_tx_id': 1, 'committed_position': 1000000001, 'count': 1, ...}

=== R9: the fault count is `revision`, the number of writes to the key ===
  three writes to one fault key -> count: 3
  distinct fault keys in the ledger for that record: 1

=== R10: a fault for a record with no call_id is never joined onto its page row ===
  the record reaches a page: True
  row call_id: None | row ledger_fault: None
  sha256(ledger_key raw)[:32] derivable from the row: f5c13ca88149764e829fab7b9ebb9bdc
  fault written at: ledger_fault:key:f5c13ca88149764e829fab7b9ebb9bdc
```

R10 is two findings in one transcript. `verifier/main.py:597` justified the digest fallback with "a record with no `call_id` never reaches a page"; the record reaches a page, and the digest is derivable from the row today. And the join never had it under any key shape.

---

## 5. Verdict per item

| Item | Verdict |
| :--- | :--- |
| P3c3d-1 | Done. Landed first and separately, commit `77b431c`, before anything else in the phase. |
| P3c3d-2 | Done. |
| P3c3d-3 | Done. |
| P3c3d-4 | Done. The `getall` keeps exactly today's keys; the range read is added beside it. |
| P3c3d-5 | Done, with the asymmetry and the ceiling stated. |
| P3c3d-6 | Done, and widened by one step (section 3.2). |
| P3c3d-7 | Done, including the narrow `_tombstone_present_in_ledger` finding. |
| P3c3d-8 | Done. Comment corrected, join closed. |
| P3c3d-9 | Done, all six. |
| P3c3d-10 | Done, corrected at the source. |
| P3c3d-11 | Done. The contract choice is stated in section 6. |
| P3c3d-12 | Done. The parse is no longer a line count. |

### Which red-team claims are now true, and which were scoped down

| Claim | Was | Now |
| :--- | :--- | :--- |
| A1 | Refuted | **True.** D40. The state call is outside the proof's handler and the generic handler asks the ledger. Section 7.6. |
| A2 | Refuted | **True.** D39 closes the write path on both routes, D41 the read path. Section 7.1, 7.5. |
| A3 | Refuted on both bounds | **True.** The guard reads the bytes it writes; the parse counts AST references. Section 7.12. |
| A4 | Refuted | **True.** The count is how many faults exist, and a caller cannot author one. Section 7.11, 7.1. |
| A5 | Refuted, fourth condition | **True**, and **scoped wider than the red team stated it**: a key at more than one position is a finding in either range, not only below the reserve. Section 3.3, 7.9. |
| A6 | Refuted, third limit | **True.** The reserve is bounded above at 2^53 in all four copies and the allocator refuses to cross it. Section 7.9. |
| A7 | Not refuted | Still holds. **No item, and no change**: the twelve shapes were measured against the plain route's two conditions, which are unchanged. The non-string `record_type` A7 recorded as a 500 is fixed under P3c3d-9, which strengthens A7's own table rather than touching what it establishes. |
| A8 | Refuted | **True.** The erasure completes. Section 7.7. |
| A9 | Refuted, scope wider than stated | **True.** The fifth module is compared, and what is compared is the whole key format. Section 7.9. |
| A10 | Refuted | **True.** Key material by content, and a COPY resolved against its real build context. Section 7.9. |
| Unlisted 1 (two writes kill the page) | Reproduced | **Closed.** D39's `KeyMustNotExist`. Section 7.1. |
| Unlisted 2 (non-string `record_type`) | Reproduced | **Closed.** Section 7.9. |
| Unlisted 3 (`total` and the page) | Carried | **Carried unchanged.** It is not this phase's, and the difference is documented in `get_audit`. What changed is that a caller can no longer inflate `entries` with a fault key. |
| Unlisted 4 (every service holds every writer key) | Carried | **Carried, and now load-bearing on D41.** README section 5 and `TODO.md`. |
| The keep-alive failure | Diagnosed | **Closed.** `--timeout-keep-alive` stated. Section 7.9. |

Nothing was closed by narrowing a claim. The one place the scope moved is A5, and it moved **wider**, which is stated above and in section 3.3.

---

## 6. The `/audit` contract change

With more than one fault possible per record, `ledger_fault` could stay one object or become a list. **Chosen: it stays one object - the most recent fault, by the ledger's own transaction for the fault record - with `count` reporting how many faults exist.**

Why. The field answers "what is this record's standing", and the most recent fault is that. A list would put an unbounded structure on every row of a 2500-row page for a field that is null on almost every row. And no consumer changes.

That last point was verified rather than taken on trust: `grep -rn ledger_fault dashboard/` returns nothing, and no test asserted `count` before this phase (`tests/test_audit_read_correctness.py:195` is an ImmuDB key count, not this field).

What is given up: the page no longer names the older faults for a record. They are readable in the ledger under their own keys, and the write response that produced each one names it in `fault_record`. The bookkeeping field `_tx` that orders them is dropped before the row is built, and a test asserts it does not leak into the response.

---

## 7. Per item: demonstration, enforcing test, mutation

### 7.1 P3c3d-1, D39

**Demonstration.** A caller-authored `ledger_fault:` write on `/write-ordered` answers 400. A forged fault does not replace the genuine one on the page: the row still reads `write_verification_failed` with the record's own transaction. No row with `outcome_type: null` and no `ledger_fault:` key reaches the page. A re-write of an existing record key answers 409 with nothing committed, the key holds exactly one index entry, and `/audit` answers 200 at limits 1, 5, 200 and 2500.

**Enforcing tests.** `tests/test_ordered_route_refusals.py`, six of them, one per demonstration plus the `record_type` condition that covers the key prefix's blind spot.

**Mutation A** - the refusal removed from the ordered route:

```
FAILED test_a_caller_authored_fault_is_refused_on_the_ordered_route
FAILED test_a_fault_record_type_is_refused_on_the_ordered_route_under_any_key
FAILED test_an_injected_row_is_refused_and_entries_does_not_exceed_total
FAILED test_a_forged_fault_does_not_replace_a_genuine_one_on_the_page
4 failed, 2 passed
```

Worth recording from that run: the forged fault got a 409 rather than a 200, because the genuine fault key already existed and `KeyMustNotExist` caught it. The two halves of D39 back each other up; the named test fails either way, which is what the mutation asks.

**Mutation B** - `KeyMustNotExist` dropped:

```
FAILED test_an_injected_row_is_refused_and_entries_does_not_exceed_total
FAILED test_a_record_key_cannot_be_written_twice_through_the_ordered_route
FAILED test_the_audit_page_survives_a_repeated_record_key
FAILED test_a_forged_fault_does_not_replace_a_genuine_one_on_the_page
  AssertionError: {"error":"audit_ordering_fault","message":"the view index and the
  ledger disagree: position 1000000023.0 resolves to transaction 29 and position
  1000000022.0 resolves to transaction 29 ..."}
4 failed, 2 passed
```

**`_REFUSED_KEY_PREFIXES` covers both key shapes unchanged.** It matches on `b"ledger_fault:"`, which is a prefix of D38's composite shape as well as of the old one, so P3c3d-1 and P3c3d-2 are independent and P3c3d-1 needed no knowledge of the key change to land first.

### 7.2 P3c3d-2, D38

**Demonstration.** Three faults about one record produce three distinct keys, all three returned by one range read over the record's transaction, ordered by the `scan` entry's own `tx`. Then the non-adversarial case: an intent fault, a decision fault and a tombstone fault for one `call_id` are three distinct keys, all three in the ledger, and the decision row on `/audit` names the decision's fault (`committed_tx_id` equal to the decision's transaction, `count` 1) rather than the tombstone fault written after it.

**Enforcing tests.** `tests/test_fault_key_and_page_read.py::test_three_faults_about_one_record_all_survive_and_none_is_shadowed` and `::test_faults_about_an_intent_a_decision_and_a_tombstone_do_not_collide`.

**Mutation A** - the nonce removed:

```
FAILED test_three_faults_about_one_record_all_survive_and_none_is_shadowed
FAILED test_a_record_with_three_faults_reports_three
  AssertionError: three faults exist for this record and the row reports 1
```

**Mutation B** - keyed on `{call_id}:{nonce}`:

```
FAILED test_faults_about_an_intent_a_decision_and_a_tombstone_do_not_collide
FAILED test_three_faults_about_one_record_all_survive_and_none_is_shadowed
FAILED test_the_bounded_read_returns_the_window_and_nothing_outside_it
FAILED test_a_single_transaction_window
FAILED test_a_window_needing_more_than_one_page_terminates_and_is_gap_free
FAILED test_a_page_carrying_an_old_shape_and_a_new_shape_fault_renders_both
FAILED test_a_fault_for_a_record_with_no_call_id_is_joined_onto_its_page_row
FAILED test_a_record_with_three_faults_reports_three
8 failed, 4 passed
```

The named test fails, and so does every test that depends on the page read, which is the second thing that mutation costs.

**Why the faults in these tests are seeded rather than induced.** A record key is written once (D39), so the real write path produces at most one fault per record and cannot produce three. The seeds are built by the verifier's own `_fault_key`, executed out of `verifier/main.py`, and signed with the verifier's own writer key through `provenance.sign_record`, so a change to either the key format or the signing rule changes what these tests assert. The mutations above prove that: both were made in `verifier/main.py` and both failed these tests.

### 7.3 P3c3d-3, the bounded page read

One paginated half-open range scan, `seekKey = ledger_fault:{min_tx:020d}` inclusive, `endKey = ledger_fault:{max_tx + 1:020d}` exclusive, limit 2500, cursor on `seekKey`, stopping when a page comes back short. The window is over both zscans, decision and intent, taken after the `limit + 1` truncation.

**Demonstration.** A window with faults on both sides returns exactly its own. A single-transaction window (`lo == hi`) returns that transaction's fault. A window of 2600 faults terminates, returns every one, and returns none twice. An empty page issues no read at all.

**Enforcing tests.** Four in `tests/test_fault_key_and_page_read.py`, plus `::test_a_bounded_read_asserts_on_what_came_back` for D42's assertion on the read.

The empty-page test is worth naming for how it asserts: `_page_faults` is handed a client that raises `AssertionError` on any attribute access, so if the read is issued at all the test fails with that raise rather than with an assertion about a result.

**Mutation A** - the end bound made inclusive on a bare `hi`:

```
FAILED test_a_single_transaction_window
  AssertionError: a single-transaction window returned nothing for the transaction it
  names: asked for [1000767474007, 1000767474007], got []
FAILED test_the_bounded_read_returns_the_window_and_nothing_outside_it
FAILED test_three_faults_about_one_record_all_survive_and_none_is_shadowed
```

**Mutation B** - `endKey` misspelled as `endkey`:

```
FAILED test_the_bounded_read_returns_the_window_and_nothing_outside_it
FAILED test_a_single_transaction_window
  p3c3d_control_plane.BoundedReadFault: a bounded read returned a key outside the range
  it asked for: 'ledger_fault:00000001000724854999:4a765e8c...:16000fb0bdb947b9' is not
  in ['ledger_fault:00000001000557576007', 'ledger_fault:00000001000557576008') with
  inclusiveSeek=True. The bound was not applied, which is what a dropped or misspelled
  parameter looks like on this route: an unbounded read at HTTP 200.
```

The D42 assertion fired. The read did not silently widen.

**Mutation C** - the window taken from the fetched rather than the rendered set. **This one passes, and that is the result:**

```
12 passed in 66.32s
```

The property under test is superset-safety, not an arbitrary preference between two sets: a window taken from the wider set is a superset and a superset cannot exclude a page row. The rendered set is chosen anyway, and named in the code, because "bounded by the page" is what the property is called and a reader must not have to work out which set was meant.

### 7.4 P3c3d-4, legacy faults

The exact `getall` keeps **exactly today's keys, unchanged**: `content_erasure:{call_id}` and `ledger_fault:{call_id}`, still fused, still one round trip. No keys were added to it, because under the nonce a new-shape key is not derivable from a page row and cannot go into a `getall` at all. **The whole added cost is the range read: two round trips per page against one.**

**No figure is reported as matching the keyprobe report's section 11 `BOTH` row.** That row measures the exact-derivable variant D38 abandoned, and it does not describe this item. The headroom figure in the same section does stand on its own and is what the legacy half sits inside: a 3000-key `getall` is one round trip at 162 ms. No README limit is needed.

**Demonstration.** A page carrying an old-shape fault for one record and a new-shape fault for another renders both, each naming its own record's transaction.

**Enforcing test.** `::test_a_page_carrying_an_old_shape_and_a_new_shape_fault_renders_both`.

**Mutation** - the legacy key dropped from the `getall`:

```
FAILED test_a_page_carrying_an_old_shape_and_a_new_shape_fault_renders_both
  AssertionError: a fault committed under the pre-D38 key shape stopped rendering;
  those keys keep that shape permanently
```

### 7.5 P3c3d-5, D41

**Demonstration.** A fault with no writer signature at all is not rendered. A fault signed correctly and then edited is not rendered either. Both are still in the ledger and readable there; what they are not is the page's account of a record's standing.

**Enforcing tests.** `::test_a_fault_with_no_writer_signature_is_not_rendered_as_a_standing` and `::test_a_fault_whose_signature_does_not_check_out_is_not_rendered`.

**Mutation** - the check skipped:

```
FAILED test_a_fault_with_no_writer_signature_is_not_rendered_as_a_standing
FAILED test_a_fault_whose_signature_does_not_check_out_is_not_rendered
  AssertionError: a fault edited after it was signed is rendered as this record's
  standing: {'fault_class': 'EDITED-AFTER-SIGNING', ...}
```

**The asymmetry, stated rather than left to be inferred.** `/audit` renders a decision record without checking its writer signature, and at the default `verify=false` without checking its inclusion proof either. That is deliberate and defensible: a record's own state is explicitly reported as `asserted` and is never self-certified (D2, ADR-0006), whereas a fault is presented as authoritative metadata about *another* record. It is written into `_rendered_fault`'s docstring, into ADR-0014's D41, and into README section 5, in each case with the sentence that it must not be extended to every row - because that is the per-record round trip D29 removed.

**Residual limit, carried.** The fingerprint names a key, not a component. Every service mounts `./keys:/keys:ro`, so what D41 establishes is that a fault was signed by the key the verifier signs faults with, not that the verifier process wrote it. The ceiling is the open D22 mount split, and README section 5 says so on the D41 bullet itself rather than only in the D22 entry.

### 7.6 P3c3d-6, D40

**Demonstration**, the same relay, after the fix:

```
=== AFTER THE FIX: A1, the same cut ===
STATE BEFORE: {"immudb:3322/b'defaultdb'": 218, "cutproxy:3399/b'defaultdb'": 220}
WRITE -> (200, {'tx_id': 221, 'verified': True, 'committed': True, 'error_class': None,
                'fault_record': None, 'fault_record_error': None, 'detail': None})
LEDGER-> {"probe:ZZCUTZZ-after-48ef29": {"tx": "221", "revision": "1"}}
STATE AFTER : {"immudb:3322/b'defaultdb'": 218, "cutproxy:3399/b'defaultdb'": 221}
CUT: armed on a 941B request carrying b'ZZCUTZZ'
CUT: the marked response was relayed; cutting the NEXT RPC
```

The write reports its real transaction with `committed: true`, and the persisted anchor and the response agree at 221.

**Enforcing tests.** `tests/test_committed_is_a_fact.py`, four of them, and **the relay is a committed test fixture rather than a described mechanism**: the attack itself runs. The fixture starts the relay as a container on the compose network (source passed to `python -c`, so no bind mount and no host path translation) and recreates the verifier through Compose's own `${IMMUDB_ADDR:-immudb:3322}` substitution, so nothing on disk changes and the teardown is unconditional.

Two of the four drive the route directly against a client whose `currentState` raises, and against one whose `verifiedSet` raises after the bytes landed. That is where the mutation is aimed: a branch that can only be observed through a race is a poor place to put one.

Both live tests assert that the relay actually cut (`"cutting the NEXT RPC" in the relay log`) and that the record actually reached the ledger, so a run that did not exercise the condition fails loudly rather than passing vacuously.

**Mutation** - the state call returned to the proof call's `try`, and the generic handler returned to guessing:

```
FAILED test_a_write_that_committed_is_reported_as_committed_when_the_state_call_fails
FAILED test_the_state_call_cannot_describe_the_write
FAILED test_a_transport_failure_on_the_write_itself_asks_the_ledger
FAILED test_an_erasure_completes_when_its_tombstone_commits_and_the_state_call_fails
```

### 7.7 P3c3d-7, the GDPR erasure path

**Demonstration**, the probe's attack sequence after the fix:

```
=== AFTER THE FIX: A8, the erasure ===
  POST /content -> 204
  DELETE -> 204
  tombstone in the ledger: {"content_erasure:a8ZZCUTZZ06c0f1": {"tx": "222"}}
  control-plane store row: []
  CUT: armed on a 770B request carrying b'ZZCUTZZ'
  CUT: the marked response was relayed; cutting the NEXT RPC
```

The erasure completes, the tombstone is in the ledger, and the row is gone. Before the fix: 503, tombstone at tx 16, row still holding 22 bytes of payload, content writes frozen at 409.

**Enforcing test.** `::test_an_erasure_completes_when_its_tombstone_commits_and_the_state_call_fails`.

**Mutation** - D40 reverted:

```
FAILED test_an_erasure_completes_when_its_tombstone_commits_and_the_state_call_fails
  AssertionError: the erasure was refused while its tombstone was in the ledger: 503
  {"detail":"Tombstone write failed; erasure refused: Tombstone write not verified:
  ... StatusCode.UNAVAILABLE ..."}. The ledger says this call_id was erased, the store
  still holds the payload, and content writes for it are now frozen at 409.
```

**The separate finding: `_tombstone_present_in_ledger` asked the wrong question.** It read the head and asked only whether a tombstone exists, never whether it is the one this call just wrote, so a pre-existing tombstone satisfied a later confirmation - and this confirmation is the only thing between a write that did not land and a deleted row. **Fixed**, not deferred: it takes the transaction the write response named and requires the entry the ledger holds to be at it. No transaction to check against is not a confirmation and fails closed, the same rule the exception handler applies. `tests/test_ledger_faults.py::test_an_erasure_is_refused_when_the_tombstone_is_not_in_the_ledger` asserts the call site names the transaction.

### 7.8 P3c3d-8, a fault for a record with no `call_id`

**The comment is corrected at its source.** `verifier/main.py`'s `_fault_identity` now says what was measured: such a record does reach a page, the row's `ledger_key` is the base64 raw key, and `sha256(record_key)[:32]` is derivable from a page row today. It is not an unjoinable last resort; it is a second identity a reader can compute.

**The join is closed for free.** `_tombstones_and_faults` was only ever handed `page_call_ids`, so a fault for a record with no `call_id` was joined onto no page under any key shape including the old one. The transaction-window read selects on the window rather than on an identity the row may not have, and the placement is by the record key each fault names.

**Demonstration.** A record written with no `call_id` key at all reaches a page with `call_id: null`, and its fault is on the row with the record's own transaction.

**Enforcing test.** `::test_a_fault_for_a_record_with_no_call_id_is_joined_onto_its_page_row`.

**Mutation** - the `call_id` filter restored on the join:

```
FAILED test_a_fault_for_a_record_with_no_call_id_is_joined_onto_its_page_row
  AssertionError: a fault for a record with no call_id is joined onto no page row
```

### 7.9 P3c3d-9, the red-team blocking set

**Reserve upper bound.** `validate_reserve` refuses at or above 2^53 in all four copies, and the allocator refuses to hand out a position at or above it - the reserve check catches a seam already past the boundary, the allocator check catches the write that would cross it. `tests/test_reserve_binding.py`, three new tests. Mutation, the upper bound removed from the verifier's copy:

```
FAILED test_a_reserve_at_or_above_2_to_the_53_is_refused_everywhere[9007199254740992]
FAILED ...[9007199254740993]
FAILED ...[9223372036854775807]
  Failed: DID NOT RAISE <class 'RuntimeError'>
```

**Below-reserve duplicates.** Scoped as a key at more than one position in either range (section 3.3), reported as `duplicated` with both positions named. `tests/test_reconciliation.py::test_a_second_position_below_the_reserve_for_an_indexed_record_is_a_finding`, which asserts the finding, asserts the page shows the row twice so the test cannot pass without exercising the condition, and asserts the running service says the same thing. Mutation, the check dropped:

```
FAILED test_a_second_position_below_the_reserve_for_an_indexed_record_is_a_finding
  ERROR anchor-service: ... 0 key(s) at more than one position ...
```

**The fifth vocabulary module.** `tools/ail_ordering_cost_probe.py` is loaded and its `VIEW_DECISION` compared, and the module docstring's stated scope is corrected: it said "a rename, or a sixth module hardcoding a string", and a fifth module defining a named constant was also invisible. **And under D38 what has to agree is the whole key format, not the prefix constant**: the two modules are compared on what `fault_key_tx_bound`/`_fault_key_tx_bound` produce for five transactions, and on the pad width. Two mutations:

```
VIEW_DECISION = "ail_view:decision:v2" in the fifth module
  FAILED test_the_view_index_names_agree_everywhere
  where 2 = len({'ail_view:decision:v1', 'ail_view:decision:v2'})

FAULT_KEY_TX_PAD = 12 in the verifier, prefix unchanged
  FAILED test_the_fault_key_format_agrees_and_not_only_its_prefix
  where 2 = len({'ledger_fault:000000000000', 'ledger_fault:00000000000000000000'})
```

The second is the point: the prefix constant still agreed and the format did not.

**Image contents by content, not filename.** The in-image detector matches a PEM armour BEGIN line **at column zero** with a matching END line, plus the PuTTY header, and it prunes only `/proc`, `/sys`, `/dev` and `/run`. Column zero is what separates a key file from source code that mentions the header inside a quoted string - a bare substring match flags `ecdsa/test_keys.py`, `cryptography/.../ssh.py` and their bytecode, which are in every image this project builds, so it is not a check that can pass. The vault token has no content signature and is still matched by name, stated as a limit. Control, the rewritten detector against the red team's own image:

```
   returncode 0  hits: 3
    content:/usr/local/lib/python3.11/site-packages/leaked.key
    content:/app/id_rsa
    content:/app/deploy_credential.pem
```

All three, including the one in site-packages the old prunes hid.

The static second line no longer matches strings in a `COPY` line. It resolves each COPY source against **that Dockerfile's own build context**, read from the compose files, applies that context's `.dockerignore`, and asks what the daemon would receive. Resolving everything against the repository root would be wrong for two services here - the verifier builds from the root and the dashboard from `./dashboard`, whose `COPY . .` cannot reach `decision_service/`. Control, the `decision_service/secrets/*.txt` rule commented out of `.dockerignore`:

```
FAILED test_no_dockerfile_copies_key_material
  AssertionError: ... ["decision_service/Dockerfile:28: 'COPY decision_service/ ./'
  reaches decision_service/secrets/vault_api_token.txt"]
```

That is the exact line the old string match read and found nothing in.

**Non-string `record_type`.** Refused with a 400 before the set membership test. `tests/test_ledger_faults.py::test_a_non_string_record_type_is_refused_rather_than_crashing`, parameterised over a list, a dict, an int, a bool and `None` - `None` is in the set because an absent `record_type` under a benign key is accepted, which A7 measured and which nothing here changed.

**`--timeout-keep-alive`.** Set to 65 on all three uvicorn services, in the Dockerfiles so it holds in every deployment rather than only in the test stack. The diagnosis is recorded there and in the enforcing test's docstring: httpx expires an idle pooled connection at 5.0s and uvicorn closed one at 5.0s, so the two expired together; the red team demonstrated causation by moving the server setting and watching the window move with it (2 of 6 failures at a 5.00s gap, 0 of 6 at 4.99s and 5.01s; moved to 2s, the window moved to 2.00s). 65 puts the server's expiry well beyond the client's, so the client always drops first. `::test_every_uvicorn_service_states_its_keep_alive_timeout` asserts the value is present - there is no behaviour to drive, and driving the race would be a test that fails 2 times in 6 by design.

### 7.10 P3c3d-10, prose and tests that become false

Corrected at the source, not only where cited:

| Where | What was false |
| :--- | :--- |
| `control_plane/main.py::_tombstones_and_faults` | claimed `ledger_fault:{call_id}` is derivable from a page row exactly as a tombstone key is. Rewritten; that derivability is what is given up. |
| `verifier/main.py`, the D35 block and the module docstring | claimed the join is the same exact `getall` the tombstone join uses. Half true after D38: legacy is, the new shape is not. |
| `docs/adr/0014-ordered-audit-view-index.md` D35 | same claim, plus "`POST /write` refuses a `ledger_fault`" where both routes now do, plus the `_set_without_verification` bound stated as a `record` check. |
| `docs/adr/0005-outcome-taxonomy.md:254` | spelled the key. |
| `readME.md` §5 | spelled the key, and stated three bounds where there are now four. |
| `tests/test_ledger_faults.py` | four constructions of the old key string, at what were lines 311, 313, 340 and 517. |

The sweep was `grep -rn "ledger_fault:{call_id}"` plus `"same exact getall"` plus `"POST /write refuses"` across `--include=*.md --include=*.py --include=*.yml`, excluding `docs/reports/` (historical records, which stay as written). The four remaining occurrences of the old key string in `verifier/main.py` are all in "it was X" clauses describing what changed, which is what a decision record is for. `TODO.md`'s two mentions are of `ledger_fault:` generically and remain true.

`tests/test_ledger_faults.py::test_a_second_fault_for_one_call_id_does_not_lose_the_first` was **replaced rather than adapted**, and the replacement is not weaker. It asserted `revision=2` on one key with the first readable at `atRevision=1` - true, and not enough: `getall` returns the head, a prefix scan returns one row per key, and the page's own count came from `revision`, so a reader saw the last fault and none of the others. The replacement asserts two distinct keys, both present, each at `revision=1`. The docstring says why the old assertion was insufficient rather than deleting it silently.

### 7.11 P3c3d-11, the count

**Demonstration.** A record with three faults reports three, and `ledger_fault` is one object with the fields it had before.

**Enforcing test.** `::test_a_record_with_three_faults_reports_three`, which asserts the count, the shape, and that `_tx` does not leak.

**Mutation** - the count returned to `revision`:

```
FAILED test_a_record_with_three_faults_reports_three
  AssertionError: three faults exist for this record and the row reports 1
```

That is the reproduction and the mutation in one figure: under D38 `revision` is permanently 1.

### 7.12 P3c3d-12, the unverified-write path

**The guard.** The `record` parameter is gone. `_set_without_verification(client, key, value)` parses the bytes it is about to write and refuses anything that is not a `ledger_fault` record, including bytes that will not parse. **There is no longer an argument that can disagree with the write**, which is why the mutation has to restore the parameter before it can pass a disagreeing one.

**Demonstration.** The function is executed with a stub client. A decision record raises and the stub records no write; a fault record is written and the bytes committed are the bytes passed.

**Enforcing test.** `::test_the_unverified_write_path_checks_the_bytes_it_writes`, which drives the function rather than pattern-matching it, and additionally asserts the signature carries no `record` parameter as a second line.

**Mutation A** - the `record` parameter restored and checked:

```
FAILED test_the_unverified_write_path_checks_the_bytes_it_writes
  TypeError: _set_without_verification() missing 1 required positional argument: 'record'
```

**The parse.** Replaced, not repaired. "A parse that can be defeated by removing a paren is the second line in name only" is the brief's phrase and it is right: the old check counted lines containing `_set_without_verification(`. It now walks the AST and counts every `Name` reference to the function outside `_write_fault_record`, so a binding, an argument, a dict value and a call are all counted. There is no spelling of "reach this function" that is not a reference to its name.

**Mutation B** - the red team's own alias:

```
_unverified_write = _set_without_verification
def _aliased_second_caller(client, key, value):
    return _unverified_write(client, key, value)

FAILED test_the_unverified_write_path_has_exactly_one_caller_including_aliases
  AssertionError: the unverified write path is named outside _write_fault_record, at
  line(s) [706]. Every reference is a way to reach it, including a binding with no
  parentheses, which is how this check was defeated before it counted references
  instead of lines.
```

---

## 8. Pre-registered negatives

All false at the end, each confirmed individually.

| Negative | How it was confirmed false |
| :--- | :--- |
| Any caller-authored record accepted on `/write-ordered` that the plain route would refuse | Read as the shared `ledger_fault` refusal (section 3.1), confirmed by `tests/test_ordered_route_refusals.py`'s first two tests. **The literal reading is impossible and the residual it leaves is stated**, not treated as absent. |
| Any record key writable twice through the ordered route | `::test_a_record_key_cannot_be_written_twice_through_the_ordered_route`: 409, one index entry. |
| Any two faults about one record where the second replaces the first | `::test_three_faults_about_one_record_all_survive_and_none_is_shadowed`: three distinct keys, all three returned. |
| Any two faults about different records sharing a `call_id` that collide | `::test_faults_about_an_intent_a_decision_and_a_tombstone_do_not_collide`: three distinct keys, and the decision row names the decision's fault. |
| Any page-side fault read whose bound is not derived from the page | `_page_faults` takes its window from the truncated zscan rows; `_faults_in_tx_window` takes no other bound. `::test_the_bounded_read_returns_the_window_and_nothing_outside_it`. |
| Any range read issued for a page with no rows | `::test_an_empty_page_issues_no_range_read`, asserted with a client that raises on any use. |
| Any bounded read that does not assert on what came back, in the form its bound takes | Key range: `_faults_in_tx_window`, `::test_a_bounded_read_asserts_on_what_came_back`. Score bound: `collect_positions`, reported as `score_outside_requested_bound`. Both forms implemented; no third thing invented. |
| Any response reporting `committed: false` for a write that committed | `tests/test_committed_is_a_fact.py`, three tests covering the state-call branch and the transport-failure branch. |
| Any erasure refused to the caller while its tombstone is in the ledger | `::test_an_erasure_completes_when_its_tombstone_commits_and_the_state_call_fails`. |
| Any rendered fault count that is not the number of faults | `::test_a_record_with_three_faults_reports_three`. |
| Any record reaching the unverified-write path whose committed bytes were never the bytes the guard checked | The `record` parameter no longer exists. `::test_the_unverified_write_path_checks_the_bytes_it_writes`. |
| Any caller of the unverified-write path invisible to the check that counts them | AST reference count. `::test_the_unverified_write_path_has_exactly_one_caller_including_aliases`. |
| Any prose or test still asserting the old key shape | Section 7.10. The remaining occurrences are historical clauses in decision records. |
| Any figure reported as matching the keyprobe report's abandoned `BOTH` row | Section 7.4 states which two rows of that table describe an abandoned design and reports no figure against them. |
| Any Claim cell describing a goal rather than a behaviour | Section 10's table, checked row by row; each names what happens, not what should. |
| Any assertion weakened, or any refutation closed by narrowing the claim without saying so | Section 5's second table. A5 moved **wider**; nothing moved narrower. One test was replaced rather than adapted and section 7.10 says why the old assertion was insufficient. |

---

## 9. Residual limits

1. **`/write-ordered` accepts a key of any shape into a view.** Section 3.1. `TODO.md` deferred list, README section 5, ADR-0014 Consequences.
2. **D41's fingerprint names a key, not a component.** Every service mounts `./keys:/keys:ro`. The ceiling is the open D22 mount split, and it is on the D41 bullet in README section 5, not only in the D22 entry.
3. **A bundle does not name a record's ledger fault, and D38 widens that gap slightly**: a record can now carry more than one, so a bundle that named only one would be incomplete as well as absent. README section 5, unchanged in kind.
4. **The image check reads the first 16 KiB of each file.** A PEM P-256 key is about 230 bytes and an RSA 4096 key about 3.2 KiB, so a key file is covered whole; a key buried past 16 KiB of other content is not. Stated in the module.
5. **The vault token is still matched by name.** It is 64 hex characters and has no content signature. Stated in the module.
6. **`.dockerignore` negations are refused rather than honoured** by the static check, deliberately: a rule that re-includes a path is a rule that can switch the check off. If one is ever added the check fails with a message saying so.

---

## 10. Mapping

| Claim | Backed by | Kind |
| :--- | :--- | :--- |
| A caller-authored fault record is refused on the ordered write route | `tests/test_ordered_route_refusals.py::test_a_caller_authored_fault_is_refused_on_the_ordered_route` | test |
| A fault record disguised under a decision key is refused on the ordered route | `tests/test_ordered_route_refusals.py::test_a_fault_record_type_is_refused_on_the_ordered_route_under_any_key` | test |
| A forged fault does not replace the verifier's own fault on the page | `tests/test_ordered_route_refusals.py::test_a_forged_fault_does_not_replace_a_genuine_one_on_the_page` | test |
| No row with no outcome type and no fault key reaches the audit page | `tests/test_ordered_route_refusals.py::test_an_injected_row_is_refused_and_entries_does_not_exceed_total` | test |
| A record key written twice through the ordered route is refused and holds one position | `tests/test_ordered_route_refusals.py::test_a_record_key_cannot_be_written_twice_through_the_ordered_route` | test |
| The audit page survives a repeated record key at every limit | `tests/test_ordered_route_refusals.py::test_the_audit_page_survives_a_repeated_record_key` | test |
| Three faults about one record are three keys, all returned, ordered by the entry transaction | `tests/test_fault_key_and_page_read.py::test_three_faults_about_one_record_all_survive_and_none_is_shadowed` | test |
| An intent fault, a decision fault and a tombstone fault for one call do not collide | `tests/test_fault_key_and_page_read.py::test_faults_about_an_intent_a_decision_and_a_tombstone_do_not_collide` | test |
| The page read returns every fault in its window and nothing outside it | `tests/test_fault_key_and_page_read.py::test_the_bounded_read_returns_the_window_and_nothing_outside_it` | test |
| A single-transaction window returns that transaction's faults | `tests/test_fault_key_and_page_read.py::test_a_single_transaction_window` | test |
| A window larger than one page terminates and returns no key twice | `tests/test_fault_key_and_page_read.py::test_a_window_needing_more_than_one_page_terminates_and_is_gap_free` | test |
| A page with no rows issues no range read | `tests/test_fault_key_and_page_read.py::test_an_empty_page_issues_no_range_read` | test |
| A key-range read refuses a result outside the range it asked for | `tests/test_fault_key_and_page_read.py::test_a_bounded_read_asserts_on_what_came_back` | test |
| A page carrying a pre-D38 fault and a post-D38 fault renders both | superseded by P3c3e-8 (Phase 3c-3e); see the erratum below | **marked: the legacy read is deleted and no test asserts it** |
| A fault carrying no writer signature is not rendered as a record's standing | `tests/test_fault_key_and_page_read.py::test_a_fault_with_no_writer_signature_is_not_rendered_as_a_standing` | test |
| A fault edited after signing is not rendered as a record's standing | `tests/test_fault_key_and_page_read.py::test_a_fault_whose_signature_does_not_check_out_is_not_rendered` | test |
| A fault for a record carrying no call identifier reaches that record's page row | `tests/test_fault_key_and_page_read.py::test_a_fault_for_a_record_with_no_call_id_is_joined_onto_its_page_row` | test |
| A record with three faults reports three on its page row | `tests/test_fault_key_and_page_read.py::test_a_record_with_three_faults_reports_three` | test |
| A write that committed reports its transaction when the state call fails | `tests/test_committed_is_a_fact.py::test_a_write_that_committed_is_reported_as_committed_when_the_state_call_fails` | test |
| A failing state call cannot describe the write it followed | `tests/test_committed_is_a_fact.py::test_the_state_call_cannot_describe_the_write` | test |
| A transport failure on the write itself asks the ledger instead of guessing | `tests/test_committed_is_a_fact.py::test_a_transport_failure_on_the_write_itself_asks_the_ledger` | test |
| An erasure completes when its tombstone commits and the state call fails | `tests/test_committed_is_a_fact.py::test_an_erasure_completes_when_its_tombstone_commits_and_the_state_call_fails` | test |
| An erasure is refused unless the tombstone this call wrote is confirmed at its own transaction | `tests/test_ledger_faults.py::test_an_erasure_is_refused_when_the_tombstone_is_not_in_the_ledger` | test |
| The unverified write path refuses bytes that are not a fault record | `tests/test_ledger_faults.py::test_the_unverified_write_path_checks_the_bytes_it_writes` | test |
| The unverified write path is named in exactly one place, aliases included | superseded by P3c3e-9 (Phase 3c-3e); see the erratum below | **marked: the parse is retired and nothing replaces it** |
| A record classification that is not a string is refused rather than crashing the route | `tests/test_ledger_faults.py::test_a_non_string_record_type_is_refused_rather_than_crashing` | test |
| Every uvicorn service states its keep-alive timeout | `tests/test_ledger_faults.py::test_every_uvicorn_service_states_its_keep_alive_timeout` | test |
| A reserve at or above two to the fifty-third is refused in every module that reads one | `tests/test_reserve_binding.py::test_a_reserve_at_or_above_2_to_the_53_is_refused_everywhere` | test |
| The allocator refuses a commit position that is not a distinct float64 score | `tests/test_reserve_binding.py::test_the_allocator_refuses_a_position_that_is_not_a_distinct_score` | test |
| The float64 position ceiling is the same value in every module | `tests/test_reserve_binding.py::test_the_float64_ceiling_agrees_everywhere` | test |
| A record holding a second position below the reserve is a reconciliation finding | `tests/test_reconciliation.py::test_a_second_position_below_the_reserve_for_an_indexed_record_is_a_finding` | test |
| The fault key format agrees between writer and reader, not only its prefix | `tests/test_ledger_vocabulary.py::test_the_fault_key_format_agrees_and_not_only_its_prefix` | test |
| Five modules agree on the view index names, not four | `tests/test_ledger_vocabulary.py::test_the_view_index_names_agree_everywhere` | test |
| No image built from the repository root carries private key material | `tests/test_image_contents.py::test_no_image_built_from_the_repository_root_carries_key_material` | test |
| No COPY or ADD reaches key material its build context would send | `tests/test_image_contents.py::test_no_dockerfile_copies_key_material` | test |
| A caller holding the verifier write key can put a row of another key shape on the page | `readME.md` §5, Residual Limits | residual limit |
| A ledger fault's writer signature is checked and a decision record's is not | `readME.md` §5, Residual Limits | residual limit |
| A dropped or misspelled request bound is silent at HTTP 200 on this route | `python tools/immudb_read_api_probe.py`, transcribed in `docs/reports/phase-3c3d-keyprobe.md` section 2 | **command, marked: no test covers this** |
| An over-width transaction component is pulled into a window that should exclude it | `python tools/immudb_read_api_probe.py`, transcribed in `docs/reports/phase-3c3d-keyprobe.md` section 4 | **command, marked: no test covers this** |

---

## 11. Could not verify

1. **The bound the relay cuts on is a byte-size heuristic, not a protocol parse.** It arms on a request frame carrying the marker and at least 600 bytes, which distinguishes a write from the small reads the same connection carries. That is enough to reproduce the condition reliably here and both live tests assert the cut actually happened, so a run where the heuristic missed fails rather than passing. What was not established is whether the heuristic holds on a runner with different framing; if it stops arming, the tests fail loudly and say so.

2. **Which RPC raised, on the relay's first configuration, could not be separated.** The first cut form produced the same reported shape from a raise that left the anchor un-advanced, and the second produced one that advanced it. Both were fixed by the same change, and both branches are driven deterministically by the two in-process tests, but the live relay does not tell you which line raised.

3. **The allocator's float64 ceiling is asserted on the source, not driven.** Reaching it needs a counter at 2^53, which no test can build. The reserve half is driven; the allocator half is a source assertion and is marked as such in its own docstring.

4. **The 16 KiB read bound in the image check was chosen, not measured against an adversarial layout.** A key placed past 16 KiB of other content in one file is not found. Stated as a residual limit.

5. **A ledger written by a pre-D38 build was not exercised.** Every stack here was built from a checkout that has D38 in it, so the legacy `getall` path is exercised by seeding an old-shape key rather than by upgrading a real pre-3c-3d ledger. The seeding uses the same signing rule, so what is unexercised is the migration, not the read.

6. **The local full suite does not pass on this host, before or after this change**, for the two reasons already recorded in this project's local-environment notes: `sigstore` cannot be installed into the host Python, and the tests that drive `decision_service/main.py` in-process cannot resolve compose service names. **CI is the authority for the suite result.** The targeted runs are in section 12.

---

## 12. Suite and CI

### Files changed

| File | What changed |
| :--- | :--- |
| `verifier/main.py` | D39's ordered-route refusal and `KeyMustNotExist`; D38's key construction and its two helpers; D40's split and the ledger read; P3c3d-9's reserve ceiling and allocator ceiling and non-string `record_type`; P3c3d-12's guard |
| `control_plane/main.py` | the bounded page read, D42's assertion and `BoundedReadFault`, D41's signature check, the fault merge and count, the join by record key, P3c3d-7's tombstone confirmation, the reserve ceiling |
| `anchor_service/main.py` | the `duplicated` finding, D42's score-bound assertion, the reserve ceiling |
| `provenance/record_signature.py` | `load_verifying_key` and `verify_record`, the checker half of `sign_record` |
| `tools/ail_backfill_index.py` | the reserve ceiling |
| `verifier/Dockerfile`, `control_plane/Dockerfile`, `decision_service/Dockerfile` | `--timeout-keep-alive 65` and the diagnosis |
| `docker-compose.yml`, `docker-compose.test.yml` | `AIL_FAULT_WRITER_PUBLIC_KEY`; `IMMUDB_ADDR` made substitutable in the test stack |
| `tests/anchor_helpers.py` | new: the trust-anchor surgery, one copy for three modules |
| `tests/test_ordered_route_refusals.py`, `tests/test_fault_key_and_page_read.py`, `tests/test_committed_is_a_fact.py` | new |
| `tests/test_ledger_faults.py` | the new key shape, the AST parse, the driven guard, the non-string `record_type`, the keep-alive value; one test replaced (section 7.10) |
| `tests/test_ledger_vocabulary.py`, `tests/test_reserve_binding.py`, `tests/test_reconciliation.py` | the fifth module and the key format; the reserve and allocator ceilings; the duplicate-position finding |
| `tests/test_image_contents.py` | rewritten, both checks |
| `docs/adr/0014-ordered-audit-view-index.md` | D38 through D42, revised D35, revised Consequences and References |
| `docs/adr/0005-outcome-taxonomy.md`, `readME.md`, `TODO.md` | the key shape, D41's asymmetry, the open item |
| `docs/reports/phase-3c3d.md` | new |

### Local runs

Against the stack at the final head, on a virgin ledger:

```
tests/test_ordered_route_refusals.py tests/test_fault_key_and_page_read.py
tests/test_committed_is_a_fact.py tests/test_ledger_faults.py
tests/test_audit_ordering.py tests/test_reconciliation.py
tests/test_reserve_binding.py tests/test_ledger_vocabulary.py
tests/test_image_contents.py
  -> 105 passed in 435.95s
```

And the modules that read `/audit` without being this phase's, as a regression check on the changed join:

```
tests/test_audit_read_correctness.py tests/test_deferred_verification.py
tests/test_intent_completion_visibility.py tests/test_content_states.py
tests/test_verification.py tests/test_record_profile.py
  -> 57 passed in 365.35s
```

Every mutation in section 7 was applied one at a time, with the owning service rebuilt where it is containerised, and reverted before the next.

### Mapping check

`python tools/mapping_check.py` over 351 rows in 14 reports: **this report's own 39 rows are clean**, 0 class (a) and 0 class (b) failures. Against the committed baseline: **0 new, 12 known, 0 stale**, and 33 heading pins recorded with 0 unpinned, 0 retitled, 0 stale. `tests/test_mapping_tables.py`: 18 passed.

**One coupling instance, the shape Phase 3c-1 recorded and every phase since has hit.** This report's first draft used `instruction` in five of its thirteen top-level sections and `number` in five, which pushed both stems past the distinctiveness bound and retired two historical class (b) failures - `phase-1-3.md` rows 16 and 18 - without either row changing. A class (b) failure has no pass bucket, so retiring one moves it from failed to not-decided, which is a weakening. **The new text was reworded rather than letting the entries go** (`instruction` to `brief` and to `COPY or ADD`, `number` to `figure` and `value` and `how many`), both stems are back under the bound at two sections each, and the two entries fire again.

**Two rows of `phase-3c3c.md`'s own table were broken by this phase and are repaired with a dated erratum, not silently.** Row 4's claim - a second fault for one call_id retains the first as a prior version - is superseded by D38 and its backing is marked as superseded rather than repointed, because a test asserting the new behaviour does not back the old claim. Row 6's test was renamed and its claim stands, so its backing is repointed and its Claim cell is untouched. The erratum at the end of that report says which is which and why.

### CI

**Run `33477596287`, green: 442 passed, 9 skipped, 138.16s.** Commit `9f44360` on `p3c3b-order`, PR #14, which is the whole of this phase including this report.

**The run before it, `33475430028`, failed, and it is recorded rather than only fixed.** 2 failed, 440 passed, 9 skipped, 134.40s, on `ff6e8fa`. Both failures were **this phase's own tests, and both were over-assertions rather than defects in the code they cover.** Neither was closed by weakening an assertion; each was replaced by one that states exactly what the item delivers, and both replacements were then re-run against a ledger in the same state that broke them.

**Failure 1: `test_an_injected_row_is_refused_and_entries_does_not_exceed_total` asserted a property this phase did not deliver.**

```
AssertionError: rows with no outcome type reached the audit page; every row must
be a decision or a synthesized intent: ['cDNiX21hdGVyaWFsX3Rlc3Q6...', ...]
```

Those keys decode to `p3b_material_test:`, and `tests/test_evidence_bundle.py:272` writes them through `/write-ordered` on purpose, with no `record_type` and no `call_id`, to produce real proof material for the offline checker. **That is the open item in section 3.1 doing exactly what section 3.1 says it does**, and the test was claiming its absence. D39 refuses a `ledger_fault` on both routes; it does not make "no page row has a null outcome type" true, and no wording of the item claimed it would.

The test now asserts what the refusal delivers: the injection answers 400, no `ledger_fault:` key is a page row, and the injected `call_id` contributes exactly one row rather than the two it contributed before. The docstring says which assertion was dropped and why, so the narrowing is on the record rather than inferable from a shorter test. The mutation still bites: with the refusal removed, `injected.status_code` is 200 with `tx_id 381, seq 1000000250`.

**Failure 2: `test_a_second_position_below_the_reserve_for_an_indexed_record_is_a_finding` had a guard that a bounded page cannot satisfy.**

```
AssertionError: this test is not exercising the condition it describes:
the record appears 1 time(s) on the page
```

Every assertion about the reconciler passed; the failing line was the guard asserting the duplicated row is visible twice on `/audit`. **Diagnosed rather than assumed.** The first hypothesis, that a page silently drops one of two index entries at scale, was measured and is false: a duplicated key renders twice at 2, 122 and 402 view members. The real cause is `tests/test_backfill_index.py::_pad_view_past_the_ceiling`, which takes the decision view past 2600 rows on purpose and runs before `test_reconciliation.py`. `/audit?limit=2500` renders the top 2499 by score, and a position of 42 is far below that bound, so the row appears once through its live position. That is `has_more` working.

The guard now reads the view index directly, paged past the ceiling, and asserts the key holds exactly `[42.0, seq]`. That is a stronger statement than the page one, not a weaker one: it is the condition itself, it is what the reconciler walks, and it holds at every ledger size. The page evidence stays in the docstring as the reproduction, with the reason it cannot be an assertion here.

**Both were confirmed against the condition that broke them** rather than against a clean ledger: the modules that precede `test_reconciliation.py` were run first, leaving the decision view padded past 2600 and the `p3b_material_test:` rows in place, and both files then passed (13 passed). The three `tests/test_evidence_bundle.py` failures in that local run are the known host `sigstore` problem, not this phase's.

**What this cost, stated plainly.** Both tests passed every local run before the push, because a targeted run builds a small ledger and the full suite does not. The general lesson is the one this project keeps re-learning: an assertion about "the page" is an assertion about a bound, and a test that shares a ledger with 440 others is not testing what a test on a virgin ledger tests.


---

## 13. Environment cleanup

Removed:

- Compose project `p3c3dfix`: all containers, the three volumes
  (`test-immudb-data`, `test-verifier-state`, `test-control-plane-data`), and
  the network. Verified empty by `docker ps -a`, `docker volume ls`,
  `docker network ls` and `docker images`, each filtered on the project name.
- The six images built from this run (`p3c3dfix-verifier`,
  `-ail-control-plane`, `-decision-service`, `-anchor-service`, `-dashboard`)
  and the throwaway `p3c3dfix-a10repro` that carried three live P-256 keys for
  the A10 control.
- The relay container and the temporary verifier container the first
  reproduction ran through, both from before the relay became a test fixture.
- Every probe script, written to the session scratchpad rather than into the
  tree, so none of them could be committed by accident.

**Removed last, after the report was final.** The scratch clone held this
phase's commits, so it could only go once they were on the remote and green:
`33477596287` on `9f44360`. Nothing of this run survives on this machine.

Images from earlier sessions (`p3c3d-keyprobe-*`, `p3c3brepro-*`,
`p3bverify-*`) were present at the start and are untouched: they belong to
other runs.

The primary working directory was never used for a stack and is untouched:
`p3c3b-order` at `e3d8284`, `git status` clean.


---

## Erratum, 2026-09-02 (Phase 3c-3e)

Two rows of section 10's table are superseded, and one pre-registered negative
in section 8 no longer has the enforcement it names. Neither claim was
over-stated when it was written; one of them was refuted, and the other was
deleted deliberately.

**Row 14, "A page carrying a pre-D38 fault and a post-D38 fault renders both",
is superseded.** P3c3d-4 kept the legacy `ledger_fault:{call_id}` `getall`
beside the range read so faults committed under the pre-D38 key shape would
still render. That read is deleted in Phase 3c-3e, so the claim is no longer
true and its test is gone with it. Two reasons, and the second is the one that
forced it:

- It protected nothing. Every ledger that has ever held a fault record in this
  project is a CI stack or a scratch stack destroyed by
  `docker compose down -v`, and no volume in either compose file survives that
  - `tests/test_ledger_state_does_not_survive_teardown.py` asserts the volume
  half of that, and the deployment half is recorded rather than derived.
- It was red-team A7. The legacy key is built from `call_id`, a caller-authored
  string, so a record whose `call_id` is spelled `{tx:020d}:{identity}:{nonce}`
  made this request fetch a fault the range read also returns, and
  `_merge_fault` counted it twice. One fault in the ledger, `count: 2` on a
  page row belonging to a different record, from the write credential alone.

The row is marked rather than repointed: the test that now stands in that
place, `::test_a_crafted_call_id_no_longer_makes_one_fault_count_twice`,
asserts the opposite behaviour and does not back the old claim.

**Row 25, "The unverified write path is named in exactly one place, aliases
included", is superseded.** The AST reference count was refuted in the same
pass that this report's own section 7 describes replacing a line count with
it: `globals()["_set_" + "without_verification"](...)` and
`getattr(sys.modules[__name__], _UNVERIFIED)(...)` carry the name only as a
string literal, and both were proved with a stub client to reach the function
while the parse reported one caller. It is retired rather than repaired,
because a source parse is not a control against anything that can write
Python, and catching a dynamic lookup means flagging dynamic lookup, which is
defeatable in turn.

**Nothing replaces it, and the two properties are not merged.** The runtime
guard - which row 24 backs, and which the red team did not defeat - reads the
bytes it is about to commit and refuses anything that is not a fault record.
`tests/test_route_parity.py` asserts over every write route that a failed
proof makes exactly one unverified write whose bytes are a fault record about
the record just committed. Neither of those bounds how many callers exist,
which is what the parse counted. That is a Residual Limit in README section 5
now, stated rather than absorbed.

**Section 8's pre-registered negative "Any caller of the unverified-write path
invisible to the check that counts them" is therefore answered differently
than it reads.** It was answered "false, by AST reference count"; the honest
answer as of Phase 3c-3e is that there is no such check, and the negative
cannot be confirmed. It is not re-asserted anywhere.

See `docs/reports/phase-3c3e.md`.
