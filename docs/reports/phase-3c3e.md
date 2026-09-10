# Phase 3c-3e: enumerated guarantees

**Run id:** `p3c3e-fix`.
**Working directory:** `C:\Users\banji\OneDrive\Documents\p3c3e-fix`, a scratch
clone. Never the primary working directory.
**Branch:** `p3c3b-order`, continuing PR #14. No rebase, no second PR, no
merge; new commits only.
**Compose project:** `p3c3efix`, stated with `-p` on every invocation.
**Base:** `e3cdd1d`.

All five images built `--no-cache` at the start of the run. Keys generated in
the clone with the openssl commands `make keygen` runs, because `make` is not
on PATH here.

---

## 1. What this phase was for, and the one shape underneath it

The Phase 3c-3d red team refuted six of ten claims. Read individually they are
six unrelated defects. Read together they are one:

> a rule that has to hold at N sites, with nothing enumerating the sites.

Two write routes covered at one. Four bounded reads covered at two. N key
encodings covered at one. N inspection surfaces covered at one. Earlier
passes: five modules compared at four, four copies of a validator, two copies
of a Compose rule.

D40 is the worked example and it is worth stating plainly, because it is the
reason this phase's items are shaped the way they are. Phase 3c-3d made
`committed` a fact about the ledger and wrote four tests enforcing it. Every
one of them drove `POST /write`. `POST /write-ordered` - the route
`ledger/immudb_ledger.py` takes for every decision and every intent record -
still answered `committed: false` from a generic handler that asked the ledger
nothing. It survived a full phase and a red-team brief that named the route by
name, because the enforcing test was written pointing at the route that was
already correct.

So the shape of a fix here is: **the enumeration is written first and is
expected to fail; the fix follows.** Two items have that evidence recorded
verbatim below, and neither fix would have been produced by writing the test
after the change.

---

## 2. Verdicts

### By item

| Item | Verdict | In one line |
| :--- | :--- | :--- |
| P3c3e-1 | **Closed** | The write routes are derived from `app.routes` by their `_require_write_key` dependency, four properties are asserted per route in three states, and the enumeration failed on unmodified head naming `/write-ordered`. |
| P3c3e-2 | **Closed** | The ordered route asks the ledger; a fourth response state carries "not established"; the false comment is corrected; both relay cases are committed tests. |
| P3c3e-3 | **Closed** | Driven from both ends: a caller who retries after a dropped response is told the record already exists, and a write that genuinely did not land can be retried and succeeds. |
| P3c3e-4 | **Closed** | The bounded reads are derived from the source; the enumeration failed on the two named; both now assert their bound and refuse the pass. |
| P3c3e-5 | **Closed** | Seven encodings and two inspection surfaces, both enumerations hand-listed and both said to be so in the module and in a test. |
| P3c3e-6 | **Closed** | `call_id` is bounded at key construction against the ledger's measured maximum; an unwritable fault is reported in `detail` and not only in the log. |
| P3c3e-7 | **Closed** | Derivation, not cross-check: the key's transaction is read back from the committed record, and the page refuses a fault whose key and body disagree. |
| P3c3e-8 | **Closed** | The legacy read is deleted, its test with it, and A7's `count: 2` is no longer constructible. |
| P3c3e-9 | **Closed** | The parse is retired. Nothing replaces the half it carried, and that is a Residual Limit rather than a merged property. |
| P3c3e-10 | **Closed** | Four tests scoped, the ledger-wide statements moved to a file that names the deliberate violations, and the suite passes in four collection orders. |

### By the red team's own labels

| Claim | 3c-3d verdict | Now |
| :--- | :--- | :--- |
| A1 | Refuted | **Closed** by P3c3e-6. |
| A2 | Refuted | **Closed** by P3c3e-7, at the writer; the reader half is a second line and its ceiling is stated. |
| A3 | Not refuted | Untouched. Still not refuted; nothing in this phase changes `_faults_in_tx_window`'s cursor. |
| A4 | Refuted, twice | **Closed** by P3c3e-2 and D45, both forms. |
| A5 | Not refuted | Untouched as a claim. The composition it names is closed by P3c3e-3. |
| A6 | Not refuted | Untouched as a claim; the legacy read it was about is deleted by P3c3e-8, which the erratum on `phase-3c3d.md` records. |
| A7 | Refuted | **Closed** by P3c3e-8. |
| A8 | Refuted on the parse, not on the guard | The parse is **retired**, not repaired (P3c3e-9). The guard held and still holds. |
| A9 | Refuted | **Closed** by P3c3e-4. |
| A10 | Refuted, twice | **Closed** by P3c3e-5, both forms. |

**Not refuted, stated explicitly:** A3, A5 and A6. Nothing in this phase
re-opens them, and nothing in this phase claims credit for them.

---

## 3. P3c3e-1. The route parity test

**Decision:** D43.

**The site list is derived and the discriminator is named.** `app.routes`
carries POST `/write`, `/write-ordered` and `/verify`, and the last is a read.
Write routes are selected by their dependency being `_require_write_key`;
`/verify` takes `_require_read_key`. Hand-listing which POST routes are writes
would sweep `/verify` in or out by judgement, which is this decision failing
on its own terms at the first step.

**Three states per cell.** Holds, does not apply with a reason recorded in the
test, or missing - and missing fails. The reasons are load-bearing, not tidy:

| Property | `/write` | `/write-ordered` |
| :--- | :--- | :--- |
| refuses a `ledger_fault` from a caller | holds | holds |
| refuses a record that belongs on the ordered route | holds | does not apply: this route exists to write exactly those, and the symmetric refusal is the standing residual limit, not this property |
| `KeyMustNotExist` on the record key | does not apply: this route allocates no position, and applying it would refuse a second erasure attempt after a partial failure | holds |
| `committed` is a fact about the ledger | holds | holds (this phase) |

**Demonstration: the enumeration failing on unmodified head.** Written before
`verifier/main.py` was touched:

```
$ python -m pytest tests/test_route_parity.py -q
.......F..
_ test_the_property_holds_on_the_route[/write-ordered-committed_is_a_fact_about_the_ledger] _
E   AssertionError: /write-ordered: the bytes are in the ledger at transaction
    77 and the response says the write never happened:
    tx_id=None seq=None verified=False committed=False attempts=0
    detail='StatusCode.UNAVAILABLE: Stream removed (Socket closed)'
1 failed, 9 passed
```

That is the evidence the enumeration produces the fix rather than ratifying
it. The same file, pointed at the same property, passes on `/write` in the
same run.

**Authoring order, not commit order.** The test was written first and its
failing output recorded; it lands in the same commit as the fix it produced,
because pushing a knowingly-red commit to a branch the red team also works on
gains nothing.

**Driven, not parsed.** Every cell is asserted by executing the route function
against a stub client and looking at what it answered and at what it asked the
ledger for. A property asserted by reading the source is a property about how
the source is spelled, and the 3c-3d red team defeated two such checks in one
session.

**The no-proof path is one assertion, not a column.**
`_set_without_verification` is module-level and no route selects it, so "route
by no-proof guard" has no meaning as a cell. What is assertable is that no
write route reaches it with anything but a fault record, over every derived
route: a write whose proof could not be attempted makes no unverified write at
all, and a write whose proof failed makes exactly one, whose bytes are a
`ledger_fault` record naming the record just committed. Both of the red team's
dynamic second callers would be recorded by this and are invisible to a parse.

**Enforcing test:** `tests/test_route_parity.py`, 10 tests.

**Mutation M1** - a third write route, `POST /write-express`, with none of the
properties:

```
E  AssertionError: a write route carries no recorded state for a property this
   service claims: ["/write-express x 'refuses a ledger_fault record from a
   caller'", "/write-express x 'refuses a record that belongs on the ordered
   route'", "/write-express x 'KeyMustNotExist on the record key'",
   "/write-express x 'committed is a fact about the ledger'"]
E  AssertionError: no driver knows how to call '/write-express'.
2 failed, 8 passed
```

Reverted: `10 passed`. The parity test was not edited.

---

## 4. P3c3e-2. `committed` is a fact on the ordered route

**Decision:** D45.

### 4.1 The false comment, corrected

`verifier/main.py` carried this three lines above the handler:

> Split from the commit deliberately: everything before this line can fail
> without anything having been written, and everything after it has a
> committed transaction to report.

It is false. `_ordered_commit` issues the `ExecAll` inside that block, so a
failure raised out of it can be the failure of a write that committed. That is
the sentence that would have caught A4.1, and it is replaced with one that
says which exception means what.

### 4.2 A4.1 reproduced live

Driven against the pre-fix handler (mutation M2 below restores it byte for
byte), through a relay that relays the marked request upstream so its ExecAll
commits and then drops its own response and closes:

```
AssertionError: the record is in the ledger at transaction 296 and the ordered
route says the write never happened:
{'tx_id': None, 'seq': None, 'verified': False, 'committed': False,
 'attempts': 0, 'error_class': None, 'fault_record': None,
 'detail': '<_InactiveRpcError ... UNAVAILABLE ... "Stream removed (Socket closed)">'}
```

`attempts: 0` on a commit that took one is the same understatement 3c-3d fixed
on the branch beside this one.

### 4.3 What changed

- **`OrderedCommitUncertain`** carries the attempted position and the real
  attempt count out of `_ordered_commit` when the ExecAll reached the wire.
  Every other exception means nothing was written, and that branch is now the
  only one that may answer `committed: false` without reading anything.
- **The route asks the ledger** with the value as well as the key, exactly as
  `POST /write` does, so a record that was already under this key is not
  reported as this write.
- **The position is confirmed, not asserted.** `_committed_position_for`
  zScans the view bounded to exactly the attempted score and reports it only
  if the index holds this key there. `seq: null` beside `committed: true`
  means the record is in the ledger and its position could not be confirmed,
  which is a different statement from position zero.
- **A fourth response state.** `committed` is `bool | None`. Null means the
  write raised and the read that would settle it raised too. It is refused
  exactly as false is, because every caller keys on `verified`; what changes
  is that the service no longer states a fact it does not have. This closes
  A4.2, where the guess had moved one RPC along rather than gone away.
- **The control plane asks the ledger itself when told null.** It has its own
  path to ImmuDB, which the verifier's relay does not sit on. Without a
  transaction to confirm against it asks the narrower question - is there a
  `content_erasure` record for this call_id at all - through an explicit
  `require_transaction=False` rather than by passing `None` and having the
  exact-transaction rule P3c3d-7 added quietly answer something else.

**Both answers on that last one are safe, which is why it is not a
weakening.** A tombstone found means the ledger already says this call_id is
erased, and completing the erasure is what removes the divergence. None found
means nothing says erased, no write is frozen at 409, and the refusal leaves
the row intact with no conflict to resolve.

**Enforcing tests.** `tests/test_route_parity.py` covers the property on both
routes. The relay cases are committed against both routes:

- `::test_an_ordered_write_that_committed_is_reported_as_committed_when_its_response_is_dropped`
- `::test_a_plain_write_states_no_fact_when_the_confirming_read_is_cut_too`
- `::test_an_erasure_completes_when_the_ledger_goes_away_after_the_tombstone_commits`

The relay gained three modes for these (`response`, `blackhole`,
`drop-request`) beside the `next-rpc` mode 3c-3d wrote, and each test asserts
the relay actually cut, so a run that missed fails rather than passing
vacuously.

**Mutation M2** - the generic handler's `committed: false`, restored:

```
$ python -m pytest tests/test_route_parity.py -q
FAILED ::test_the_property_holds_on_the_route[/write-ordered-committed_is_a_fact_about_the_ledger]
1 failed, 9 passed
```

and live, against the rebuilt verifier, the transcript in 4.2. Reverted and
rebuilt: `10 passed`.

---

## 5. P3c3e-3. A retry the caller was wrongly told to make

D39 and D40 are each correct and their interaction was not. A caller told
`committed: false` about a write that committed has two options and both are
wrong: retry, which `KeyMustNotExist` refuses with 409 forever, or disbelieve
the response.

P3c3e-2 removes the cause. This item establishes the interaction is closed
from both ends, and that no legitimate retry is permanently denied.

**Demonstration, end to end.**

- `::test_a_retry_after_a_dropped_response_is_told_the_record_already_exists` -
  the write's response is dropped, the response now says `committed: true`
  with the real transaction and position, and a caller who retries anyway gets
  **409 whose detail names the key and says a record is already committed
  under it**. Asserted on the text, not only the status: a bare conflict is
  not an answer a caller can act on.
- `::test_a_write_that_genuinely_did_not_land_can_be_retried` - the relay
  drops the marked request without relaying it and then blackholes, so nothing
  about the write reaches the ledger. The response is not `committed: true`,
  the key is absent from the ledger, and the same key written again with the
  relay gone answers `verified: true, committed: true`.

**Mutation:** M2 (revert P3c3e-2). Both named tests fail; the first at

```
AssertionError: the caller is being told to retry a write that committed:
{'tx_id': None, 'seq': None, 'verified': False, 'committed': False, ...}
```

---

## 6. P3c3e-4. Bounded reads, enumerated

**How the list is derived.** Every call in the repository to
`/api/v2/db/scan` or `/db/zscan` whose request body carries a selective bound
- `prefix`, `seekKey`, `endKey`, `minScore`, `maxScore` - attributed to its
innermost enclosing function. `set`, `limit` and `desc` are not selective
bounds: `set` names a collection, `desc` an order, and `limit` truncates, a
bound whose violation is a superset the caller already pages through. That
discriminator is what makes this a derivation rather than a list, and it is
asserted in both directions:
`control_plane/main.py::_zscan_view` issues a zscan, carries no selective
bound, and is correctly **not** in the enumeration.

**Demonstration: the enumeration failing before the fix.**

```
$ python -m pytest tests/test_bounded_reads.py -q
....FF..
FAILED ::test_the_bounded_read_asserts_its_bound[tools/ail_backfill_index.py::indexed_keys]
FAILED ::test_the_bounded_read_asserts_its_bound[tools/ail_backfill_index.py::scan_all]
2 failed, 6 passed
```

Exactly the two the red team named, and no others. Each driver executes the
real function against a client that answers outside the bound it asked for,
which is what a dropped bound looks like from inside the function.

**The fix.** Both raise `SystemExit` now, which is this module's rule: the
reconciler reads and describes, a backfill reads and then writes, so a pass
that cannot trust what it read must not write. The consequence each refusal
names is the one that was measured, not a generic one: an incomplete snapshot
of a view produces records at two positions (25 of them, at 2535 rows), and a
dropped prefix bound zAdds the sequence counter, the reserve, fault records
and erasure tombstones into the decision view, each of which becomes a page
row.

**The four sites, and the four probe sites recorded as not applying.** The
probes `raise_for_status()` and discard without reading a row, so a bound that
did not survive changes what the call costs and nothing else; or their subject
IS what the bound does, in which case asserting the bound held would assert
the answer they were written to find. Every reason is in the test.

**What the derivation does not see, stated in the module:** a bounded read
issued through a local helper that takes its bound as a keyword argument.
`tools/immudb_ordering_probe.py::zscan` has that shape. None of the four
production reads does.

**Enforcing test:** `tests/test_bounded_reads.py`, 8 tests.

**Mutation M4** - `scan_all`'s prefix assertion removed:

```
FAILED ::test_the_bounded_read_asserts_its_bound[tools/ail_backfill_index.py::scan_all]
1 failed, 7 passed
```

The enumeration was not edited. Reverted: `8 passed`.

---

## 7. P3c3e-5. Key material in images, enumerated

Two enumerations, **both hand-listed and both weaker for it**, and the module
says so in its own docstring with a test asserting that it still does.

**Why neither can be derived.** The encodings are a fact about cryptography
and about what tools people have; the surfaces are a fact about Docker's image
format. Nothing in this repository names either, so there is nothing to derive
them from. What is checkable is that the detector honours the list it is
given, and that is what is checked: real P-256 key material is generated
in-process in each enumerated encoding and each one has to be found.

**Encodings:** PEM, PEM-PKCS8, DER-SEC1, DER-PKCS8 (both the version-1 form
`ecdsa` writes and the version-0 form OpenSSL writes, which are byte-identical
otherwise), OpenSSH, and base64 with no armour.

**Surfaces:** the running filesystem (`docker run`, walking everything outside
`/proc`, `/sys`, `/dev` and `/run`), and every layer in `docker save`, which
is A10.2's surface. The layer walk is streamed through the test process rather
than written to disk - the four images are about 1.2 GB together and none of
it needs to land anywhere.

**How a mention is told from material.** The armour rule already required a
BEGIN line at column zero, which is what separates `keys/writer-verifier.key`
from `ecdsa/test_keys.py`. Binary material is anchored the same way: at offset
zero of a file, or of a base64 body inside one, which is what a key file is.
Without that anchor the OpenSSH magic matches
`ecdsa/__pycache__/ssh.cpython-311.pyc`, which carries it as a constant
because it is the module that parses the format - measured, one hit, and it is
not key material.

**Demonstration: both red-team cases caught.** A10.1 is a DER key by content,
which the encoding table now covers directly and which the previous detector
walked straight past; A10.2 is a file a later layer deleted, which the running
filesystem cannot see and the layer surface reads.

**Enforcing test:** `tests/test_image_contents.py`, 18 tests: seven encodings
driven against the detector, a control that asserts it does not fire on public
key material or prose, the assertion that the module still says its lists are
hand-listed, four services by two surfaces, and the static Dockerfile check.

**Mutation M5** - PKCS8 dropped from the detector:

```
FAILED ::test_the_detector_finds_every_encoding_this_file_enumerates[der-pkcs8]
   AssertionError: a der-pkcs8 key was detected as 'sec1-der' rather than 'pkcs8-der'
FAILED ::test_the_detector_finds_every_encoding_this_file_enumerates[der-pkcs8-openssl]
   AssertionError: a der-pkcs8-openssl key was detected as 'sec1-der' rather than 'pkcs8-der'
2 failed, 6 passed
```

Worth recording precisely: with PKCS8 dropped, both PKCS8 forms are still
*detected*, because a PKCS8 blob carries a SEC1 structure inside its
`privateKey` OCTET STRING and the SEC1 rule reaches it within the first 64
bytes. The mutation is caught on the classification rather than on the
detection, and the message says which. Reverted: `8 passed`.

---

## 8. P3c3e-6. Fault keys are bounded and validated

**Measured first.** `POST /api/v2/db/set` on this ImmuDB accepts a key of 1023
bytes and answers HTTP 500 `max key length exceeded` at 1024:

```
1000 bytes -> 200 ok        1024 bytes -> 500 max key length exceeded
1020 bytes -> 200 ok        1025 bytes -> 500 max key length exceeded
1023 bytes -> 200 ok        1030, 1050  -> 500 max key length exceeded
```

So `MAX_LEDGER_KEY_BYTES = 1023`, and the identity component's budget is that
minus the fixed parts of the key: prefix, 20 transaction digits, two
separators and a 16-character nonce.

**The fix, and what it does not do.** An over-long `call_id` is refused **as a
key component** and the digest fallback `key:sha256(record_key)[:32]` is used
instead, so the fault is still written. Refusing to write the fault would be
the defect the fault record exists to prevent, wearing a different coat.
Nothing is lost by the substitution: a fault joins onto its record by
`committed_key`, not by identity, and the fallback is derivable from a page
row's own `ledger_key`.

The assembled key is then checked against the ledger's maximum at
construction, and a key that cannot be written raises there rather than at the
ledger, where the failure lands on a response field the middleware discards.

**Loudness.** `fault_record_error` has always been on the response and the
middleware discards the response. The response `detail` now carries a sentence
saying what the absence means - `NO FAULT RECORD WAS WRITTEN for this record
(...), so nothing durable records why its proof failed and the audit page will
show it with ledger_fault null` - which is the field every caller that logs
anything logs.

**Enforcing tests:**
`tests/test_fault_key_and_page_read.py::test_an_over_long_call_id_is_refused_as_an_identity_and_the_fault_is_still_written`,
`::test_a_fault_key_that_would_exceed_the_ledgers_maximum_fails_at_construction`,
`::test_an_unwritable_fault_is_reported_rather_than_silently_absent`.

**Mutation M6** - the length validation removed:

```
FAILED ::test_an_over_long_call_id_is_refused_as_an_identity_and_the_fault_is_still_written
   AssertionError: an over-long call_id was accepted as a key component: aaaa...
1 failed, 1 passed
```

Reverted: `2 passed`.

---

## 9. P3c3e-7. A fault key's transaction is not caller-supplied

**Derivation, which the item prefers, and it was available on both
fault-producing paths.** Both reach `_write_fault_record` immediately after a
commit, and the read is a plain `get`, which is what `_committed_tx_for`
already relies on when a proof has just failed. So the transaction in the key
is read back from the committed record and there are no longer two numbers
that can disagree - there is one, and it comes from the ledger.

`tx_id` is still passed in, is still used for the body and the response, and
is **cross-checked** against the derived value. A disagreement is refused
loudly rather than smoothed over, and the error names both numbers.

**The reading half, and its ceiling stated.** `_rendered_fault` now parses the
key's transaction and compares it against the body's `committed_tx_id`,
refusing on disagreement. What that catches is a fault that lands in some
page's window carrying a body about a record at another transaction. What it
cannot catch is A2's own shape - a fault keyed far from its record falls
outside the window and is never fetched, so nothing on the reading side ever
sees it. **That direction is closed at the writer, and only there**, and the
comment in `control_plane/main.py` says so rather than implying the reader
covers it.

`_fault_key_transaction` is the inverse of `_fault_key_tx_bound`, and
`tests/test_ledger_vocabulary.py` already compares what the verifier and the
control plane produce for the same transaction, so a pad width that drifted
fails there.

**Enforcing tests:**
`::test_the_fault_keys_transaction_is_derived_from_the_committed_record`,
`::test_a_fault_whose_key_and_body_disagree_is_not_rendered`,
`::test_the_key_transaction_reader_is_the_inverse_of_the_bound_builder`.

**Mutation M7** - the caller's transaction accepted:

```
FAILED ::test_the_fault_keys_transaction_is_derived_from_the_committed_record
   AssertionError: ledger_fault:00000000000000099999:p3c3e-derive:78146568b8d646b9
```

The key was built at the caller's 99999 while the ledger held the record at
1234. Reverted: `3 passed`.

---

## 10. P3c3e-8. The legacy fault-key read path is deleted

**The condition was answered in the instruction and is not re-decided here:
there is no deployment outside CI.** What this session verifies is the half it
can - that no volume in either compose file survives `down -v`, so no ledger
persists between runs - and it does not verify deployments and did not try.

**The volume check.** Both compose files, every mount whose container path is
one this project keeps state at (`/var/lib/immudb`, `/data`,
`/data/verifier-state`): each is a named volume declared in the file that uses
it, none is a host path, and no volume is `external: true`, which `down -v`
would leave alone.

```
docker-compose.yml       ail-control-plane control-plane-data:/data
                         immudb            immudb-data:/var/lib/immudb
                         verifier          verifier-state:/data/verifier-state
docker-compose.test.yml  the same three, test- prefixed
```

`tests/test_ledger_state_does_not_survive_teardown.py`, 4 tests. The parse
asserts it matched something, so a check that silently stopped seeing the
mounts fails rather than passing.

**The deletion.** `_tombstones_and_faults` is `_tombstoned_call_ids`: the
getall asks for `content_erasure:{call_id}` and nothing else, `_page_faults`
takes no `legacy` argument, and `/audit` reads its faults in one call whose
bound is derived from the page in both halves rather than in one.

**Demonstration.** A7 driven exactly as the red team drove it - a victim
record, one seeded fault, then a second ordinary record whose `call_id` is
spelled as the tail of the victim's fault key - and the count stays 1. Under
the mutation it is 2:

```
M8 (legacy read restored), rebuilt control plane:
AssertionError: one fault is in the ledger and the page counts 2 for it, from a
call_id the attacker chose:
  ... 'ledger_fault': {'fault_class': 'write_verification_failed',
                       'committed_tx_id': 355, 'count': 2}
```

Reverted and rebuilt: `1 passed`.

**Migration.** There is none, and that is the statement: no ledger outside CI
has ever held a fault record, so there is nothing under the old key shape to
read. `docs/reports/phase-3c3d.md` carries a dated erratum marking its row 14
superseded rather than repointed, because the test that stands in that place
asserts the opposite behaviour.

**Its tests are removed**, not left passing against a path that no longer
exists.

---

## 11. P3c3e-9. The source parse is retired

Defeated three times in three passes: a plainly-named second caller past the
line count it started as, `_unverified_write = _set_without_verification` past
the same line count, and `globals()["_set_" + "without_verification"](...)`
plus `getattr(sys.modules[__name__], _UNVERIFIED)(...)` past the AST reference
walk that replaced it - both proved with a stub client to reach the function
while the parse reported `2 passed`.

A source parse is not a control against anything that can write Python, and
keeping it invites the belief that it is a second line. Catching the third
form means flagging dynamic lookup, which is defeatable in turn; and the
reference walk is itself a source parse, so it cannot be repaired by another
one.

**What replaces the half it was carrying: nothing.** This is the expected
answer and it is not merged into the guard's property:

- The **runtime guard** covers what gets *written*. It reads the bytes it is
  about to commit and refuses anything that is not a fault record, and
  `tests/test_ledger_faults.py::test_the_unverified_write_path_checks_the_bytes_it_writes`
  drives it rather than describing it.
- `tests/test_route_parity.py` asserts over **every** write route that a
  failed proof makes exactly one unverified write and that its bytes are a
  fault record about the record that route just committed.
- Neither bounds **how many callers exist**, which is what the parse counted.

That is a Residual Limit in README section 5 and in the erratum on
`docs/reports/phase-3c3d.md`, which also records that phase's pre-registered
negative "any caller of the unverified-write path invisible to the check that
counts them" as no longer having a check behind it. It is not re-asserted
anywhere.

---

## 12. P3c3e-10. The four order-dependent tests

**Decision:** D44.

The four, their polluters and the one shared victim are named in
`docs/reports/phase-3c3d-order-sweep.md`. Two were scoped to the records the
test wrote; two were replaced by a stronger form that holds at every ledger
size, because scoping is not what they needed.

| Test | What changed |
| :--- | :--- |
| `test_audit_ordering.py::test_the_seam_is_monotone_across_the_boundary` | Scoped to the two records it writes: the backfilled one and the allocated one. Its three ledger-wide assertions move to `tests/test_view_invariants.py`. |
| `test_audit_ordering.py::test_a_record_written_before_the_index_appears_in_the_ordered_page_after_backfill` | Its precondition was `has_more is False` at limit 2500, a claim about ledger size. It now asks the view index directly whether the record is indexed, which is the condition actually under test, and the page assertion is stated in both directions: on the page, or the page is full of rows sorting above it. |
| `test_audit_read_correctness.py::test_has_more_is_false_when_the_page_covers_everything_behind_it` | Renamed `test_has_more_agrees_with_whether_the_page_was_actually_truncated` and made two-directional against the view's real size. Strictly more than it asserted before. |
| `test_backfill_index.py::test_one_pass_over_a_view_past_the_ceiling_leaves_no_record_at_two_positions` | Scoped to the rows this module writes, which is exactly where C2's defect appears. It also asserts it has more than 2500 of its own rows in scope, so it cannot pass on a view that happened to fit. |

**Scoping alone would have lost something, so it is not done alone.** Three of
the four assertions were true statements about the whole view. They are in
`tests/test_view_invariants.py` now, addressed to every row the suite did not
deliberately break, with the deliberate ones named and argued for in
`tests/ledger_pollution.py`:

- every allocated position is an integer, or a registered violation;
- every record holds one position, or is a registered violation;
- every historical position is its record's transaction id, or is registered;
- the seam holds, and that one needs no exemptions at all.

**The registry is checked in both directions**, which is what makes it more
than an exemption list: an entry naming a key fragment that no test module
produces fails, and a violating row that no entry explains fails. A hand
listed registry is acceptable here for the reason D43 gives about the
encodings - what has to be enumerated is a set of intentions, and an intention
is not in the code.

**The sweep found a defect in this phase's own work, which is what it is
for.** `tests/test_view_invariants.py` guards each ledger-wide check on the
decision view being non-empty, because a check over zero rows asserts nothing,
and then assumed some other module had written a decision. In reverse
collection order this module runs before anything else does, and the guard
fired three times:

```
tests/test_view_invariants.py:155: AssertionError: the decision view is empty,
    so this asserts nothing
tests/test_view_invariants.py:178: AssertionError: the decision view is empty,
    so this asserts nothing
tests/test_view_invariants.py:224: AssertionError: the decision view is empty,
    so this asserts nothing
```

That is D44's defect in the file that enforces D44. Each test seeds one
ordered write now and asserts its own record is in the walk it is about to
make, so a walk reading something else fails rather than passing over rows it
did not cause. Recorded here rather than quietly fixed, because a phase whose
subject is "the enforcing test was written pointing at the site that was
already correct" has no business hiding the same shape in its own output.

**Demonstration: four collection orders.** Full suite, each preceded by
`docker compose down -v`, so the only variable is the order modules are
collected in. Seeds recorded so any run is reproducible:

| Order | Failed | Passed | Phase-owned failures | Wall |
| :--- | ---: | ---: | ---: | ---: |
| alphabetical (CI's order) | 50 | 445 | 1 | 51m22s |
| reverse | 36 | 458 | 0 | 33m48s |
| shuffle-1 | 15 | 479 | 0 | 43m03s |
| shuffle-2 | 36 | 459 | 0 | 37m07s |

Orders are the sorted module list, its reverse, and
`random.Random(seed).shuffle(sorted(modules))` for **seeds 1 and 2**. Each
order's first three modules, so a reader can confirm which is which:

```
reverse    test_writer_signing / test_view_invariants / test_verifier_auth
shuffle-1  test_audit_read_correctness / test_deferred_verification / test_verifier_auth
shuffle-2  test_host_port_bindings / test_opa_request_count / test_writer_signing
```

**The four tests this item scoped pass in all four orders.** That is the
claim, checked directly rather than inferred from a count:
`test_the_seam_is_monotone_across_the_boundary`,
`test_a_record_written_before_the_index_appears_in_the_ordered_page_after_backfill`,
`test_has_more_agrees_with_whether_the_page_was_actually_truncated` and
`test_one_pass_over_a_view_past_the_ceiling_leaves_no_record_at_two_positions`
appear in none of the four failing sets. Before this phase, the first and
third failed whenever `test_backfill_index.py` ran first and the fourth
whenever `test_reconciliation.py` did.

**One phase-owned failure across the four runs, and it is not order
dependence.** `test_audit_ordering.py::test_the_sequence_is_gapless_under_concurrent_writes`
failed once, in the alphabetical run, with one gap in a block of forty-eight
allocated positions (`1000000068` missing, `1000000075` present). It is a
Phase 3c-3b concurrency test, it passes in every CI run of this branch, and it
passed twice in a row when re-run alone here immediately afterwards. Recorded
as an observed flake on this host under a loaded stack rather than reported as
a result, because a test that fails once in four local runs and never in five
CI runs is not evidence of anything this phase changed - and calling it order
dependence would be the substitution these rules exist to prevent.

**What the diff is against, and why the raw counts are large.** This host
fails around fifty tests before and after any change, from two causes neither
of which is the code: `sigstore` cannot be installed here, and the tests that
drive `decision_service/main.py` in-process cannot resolve the compose service
names it talks to. `docs/reports/phase-3c3d-order-sweep.md` established the
method that handles it - each order's failing SET is diffed against the
alphabetical baseline's, and anything host-broken appears in both and cancels.

**One thing that method has to say out loud here, because it did not arise in
the 3c-3d sweep.** Part of the host-broken set is itself order-dependent:
`tests/test_evidence_bundle.py` sets an environment override at import, so
which compose service names resolve depends on which module is imported first,
and roughly twenty host-broken tests move between the failing and passing
columns as the order changes. That is noise about this machine and not about
the suite, and it is why the claim below is stated as **no test this phase
owns or changed is order-dependent** rather than as a raw count.

**Mutation M9** - one ledger-wide assertion restored to the seam test, run in
the polluting order (`test_reconciliation.py` before
`test_audit_ordering.py`):

```
FAILED tests/test_audit_ordering.py::test_the_seam_is_monotone_across_the_boundary
   AssertionError: an allocated position is not an integer, so it did not come
   from the counter
1 failed, 30 passed
```

Reverted, same order, same ledger: `31 passed`.

---

## 13. Pre-registered negatives

All false at the end, each confirmed individually and derived per row.

| Negative | Confirmed by |
| :--- | :--- |
| Any property that holds on one write route and is, on another, neither held nor recorded as inapplicable with its reason | `tests/test_route_parity.py::test_every_write_route_has_a_recorded_state_for_every_property`, over routes derived from `app.routes` |
| Any enumeration hand-listed where it could have been derived | **Stated judgement, not a confirmed negative.** See below. |
| Any bounded read that does not assert its bound | `tests/test_bounded_reads.py`, 4 derived production reads driven, 4 probe sites recorded with reasons |
| Any response reporting `committed: false` for a write that committed, on either route | `tests/test_route_parity.py` on both routes, plus three live relay tests |
| Any legitimate retry permanently denied | `tests/test_committed_is_a_fact.py::test_a_write_that_genuinely_did_not_land_can_be_retried` |
| Any fault key accepted whose transaction the caller supplied | `tests/test_fault_key_and_page_read.py::test_the_fault_keys_transaction_is_derived_from_the_committed_record` |
| Any unwritable fault failing silently | `::test_an_unwritable_fault_is_reported_rather_than_silently_absent` |
| Any test asserting ledger-wide what it can only assert about records it wrote | The four rewrites in section 12, plus `tests/test_view_invariants.py` for what genuinely is ledger-wide |
| Any Claim cell describing a goal rather than a behaviour | Section 15's table, read row by row |
| Any assertion weakened, or any refutation closed by narrowing the claim without saying so | Section 14 |

### Which enumerations were derived, which were hand-listed, and why

This is the one that cannot be checked mechanically, so it is stated.

**Derived from the code:**

- The verifier's write routes: `app.routes`, filtered by the
  `_require_write_key` dependency.
- The bounded reads: every call to ImmuDB's `scan`/`zscan` routes carrying a
  selective bound, attributed to its innermost enclosing function.
- The stateful compose mounts: parsed out of both compose files.
- The five modules `tests/test_ledger_vocabulary.py` compares (unchanged from
  ADR-0013, listed here because it is the same control).

**Hand-listed, and why each could not be derived:**

- **Key encodings** (six). A fact about cryptography and about what tools
  people have. Nothing in this repository enumerates them. Checked against
  itself: real key material in each encoding, each one has to be found.
- **Inspection surfaces** (two). A fact about Docker's image format. Same
  reasoning. These are the two that exist for a local image; a registry or a
  remote build cache would be a third and is not one this suite can reach.
- **The deliberate ledger-violation registry** (three entries). A set of
  intentions, not a set of code sites. Checked in both directions instead: an
  entry no test produces fails, and a violation no entry explains fails.
- **The property list in the parity matrix** (four). The *routes* are derived;
  the properties are the guarantees this system claims, and a claim is not in
  the code either. What is derived is the requirement that every route has a
  state for every one of them.

---

## 14. What was not weakened, and what was

**Nothing was closed by narrowing a claim.** Two changes look like narrowing
and are not, and one is a genuine narrowing that is recorded rather than
absorbed.

- **The four order-dependent tests.** Two were scoped to their own records,
  which is narrower for those tests - and the ledger-wide statements they used
  to make are asserted in `tests/test_view_invariants.py` against everything
  the suite did not deliberately break, with a registry that fails if an
  exemption outlives its test. Net, the ledger-wide claim is stronger: it now
  also fails on a violation nobody registered, wherever it came from.
- **`has_more`.** The old assertion held only while the ledger was small. The
  new one holds at every size and asserts both directions. That is a
  strengthening.
- **`_tombstone_present_in_ledger(require_transaction=False)` is a genuine
  narrowing, on one caller and one condition.** P3c3d-7 made the confirmation
  exact-at-a-transaction because a tombstone from an earlier erasure satisfied
  a later call's confirmation. When the verifier answers `committed: null`
  there is no transaction to confirm against and there never will be for that
  call, so the question asked is the weaker one: is there a `content_erasure`
  record for this call_id at all. It is an explicit parameter rather than a
  `None` that quietly answers something else, it logs at error what it is
  accepting, and the exact rule is untouched on every other path. Both answers
  are safe, which section 4 argues rather than asserts.

**One thing genuinely lost, and it is a Residual Limit rather than a
substitution:** nothing bounds how many callers the no-proof write path has.
See section 11.

---

## 15. Mapping

| Claim | Backed by | Kind |
| :--- | :--- | :--- |
| Every POST route is gated by a read key or a write key, and the write routes are selected by that gate | `tests/test_route_parity.py::test_the_write_routes_are_selected_by_their_gate_and_not_by_their_path` | test |
| Every write route carries a recorded state for every property this service claims | `tests/test_route_parity.py::test_every_write_route_has_a_recorded_state_for_every_property` | test |
| Each property recorded as holding is driven against the route it holds on | `tests/test_route_parity.py::test_the_property_holds_on_the_route` | test |
| A property recorded as not applying to a route carries a reason | `tests/test_route_parity.py::test_a_property_that_does_not_apply_says_why` | test |
| No write route reaches the unverified path with anything but a fault record | `tests/test_route_parity.py::test_no_write_route_reaches_the_unverified_path_with_anything_but_a_fault_record` | test |
| An ordered write whose own response is dropped is reported as committed at its real transaction and position | `tests/test_committed_is_a_fact.py::test_an_ordered_write_that_committed_is_reported_as_committed_when_its_response_is_dropped` | test |
| A plain write whose confirming read is also cut states no fact about whether it committed | `tests/test_committed_is_a_fact.py::test_a_plain_write_states_no_fact_when_the_confirming_read_is_cut_too` | test |
| An erasure completes when the ledger becomes unreachable after its tombstone commits | `tests/test_committed_is_a_fact.py::test_an_erasure_completes_when_the_ledger_goes_away_after_the_tombstone_commits` | test |
| A caller retrying after a dropped response is told the record already exists | `tests/test_committed_is_a_fact.py::test_a_retry_after_a_dropped_response_is_told_the_record_already_exists` | test |
| A write that never reached the ledger can be retried and succeeds | `tests/test_committed_is_a_fact.py::test_a_write_that_genuinely_did_not_land_can_be_retried` | test |
| The bounded-read derivation finds the four production reads and excludes a read carrying no selective bound | `tests/test_bounded_reads.py::test_the_derivation_finds_the_reads_it_is_supposed_to_find` | test |
| Every bounded read in the repository carries a recorded state | `tests/test_bounded_reads.py::test_every_bounded_read_has_a_recorded_state` | test |
| Every bounded read recorded as covered refuses a result outside its bound | `tests/test_bounded_reads.py::test_the_bounded_read_asserts_its_bound` | test |
| A bounded read recorded as not applying carries a reason | `tests/test_bounded_reads.py::test_a_read_recorded_as_not_applying_says_why` | test |
| The bounded-read table names no read that has been deleted or renamed | `tests/test_bounded_reads.py::test_no_entry_in_the_table_names_a_read_that_no_longer_exists` | test |
| The image detector finds a private key in every encoding this suite enumerates | `tests/test_image_contents.py::test_the_detector_finds_every_encoding_this_file_enumerates` | test |
| The image detector does not fire on public key material or on prose | `tests/test_image_contents.py::test_the_detector_does_not_fire_on_public_key_material_or_prose` | test |
| No image built from the repository root carries key material on either inspection surface | `tests/test_image_contents.py::test_no_image_built_from_the_repository_root_carries_key_material` | test |
| An over-long call identifier is refused as a fault key component and the fault is still written | `tests/test_fault_key_and_page_read.py::test_an_over_long_call_id_is_refused_as_an_identity_and_the_fault_is_still_written` | test |
| A fault key past the ledger's maximum length raises where it is built | `tests/test_fault_key_and_page_read.py::test_a_fault_key_that_would_exceed_the_ledgers_maximum_fails_at_construction` | test |
| A fault that could not be written is reported in the write response | `tests/test_fault_key_and_page_read.py::test_an_unwritable_fault_is_reported_rather_than_silently_absent` | test |
| The transaction in a fault key is read back from the committed record and a disagreeing one is refused | `tests/test_fault_key_and_page_read.py::test_the_fault_keys_transaction_is_derived_from_the_committed_record` | test |
| A fault whose key transaction and body transaction disagree is not rendered | `tests/test_fault_key_and_page_read.py::test_a_fault_whose_key_and_body_disagree_is_not_rendered` | test |
| The page's fault key reader is the inverse of the bound builder at the boundaries | `tests/test_fault_key_and_page_read.py::test_the_key_transaction_reader_is_the_inverse_of_the_bound_builder` | test |
| A crafted call identifier no longer makes one fault count twice on a page row | `tests/test_fault_key_and_page_read.py::test_a_crafted_call_id_no_longer_makes_one_fault_count_twice` | test |
| Every mount holding ledger state is a named volume that `down -v` removes | `tests/test_ledger_state_does_not_survive_teardown.py::test_every_stateful_mount_is_a_named_volume_that_down_v_removes` | test |
| No compose volume is external, which `down -v` would leave behind | `tests/test_ledger_state_does_not_survive_teardown.py::test_no_volume_is_external` | test |
| Every deliberate ledger violation this suite creates is produced by a test that still exists | `tests/test_view_invariants.py::test_every_entry_is_produced_by_a_test` | test |
| Every allocated position in the decision view is an integer or a registered violation | `tests/test_view_invariants.py::test_every_allocated_position_is_an_integer_or_a_registered_violation` | test |
| Every record in the decision view holds one position or is a registered violation | `tests/test_view_invariants.py::test_every_record_holds_one_position_or_is_a_registered_violation` | test |
| Every backfilled position is its record's transaction id or is a registered violation | `tests/test_view_invariants.py::test_a_historical_position_is_its_transaction_or_a_registered_violation` | test |
| The seam between backfilled history and allocated positions holds ledger-wide | `tests/test_view_invariants.py::test_the_seam_between_history_and_allocation_holds` | test |
| A registered violation that exempts ordinary rows is reported | `tests/test_view_invariants.py::test_the_registered_violations_are_the_only_exemptions_in_use` | test |
| The seam is monotone across the two records that test writes | `tests/test_audit_ordering.py::test_the_seam_is_monotone_across_the_boundary` | test |
| A record written before the index is indexed by the backfill and reaches the ordered page or is excluded by the page's own boundary | `tests/test_audit_ordering.py::test_a_record_written_before_the_index_appears_in_the_ordered_page_after_backfill` | test |
| The truncation flag agrees with whether the page was truncated, in both directions | `tests/test_audit_read_correctness.py::test_has_more_agrees_with_whether_the_page_was_actually_truncated` | test |
| One backfill pass over a padded view leaves none of that module's records at two positions | `tests/test_backfill_index.py::test_one_pass_over_a_view_past_the_ceiling_leaves_no_record_at_two_positions` | test |
| The verifier and the control plane build the same fault key transaction bound | `tests/test_ledger_vocabulary.py::test_the_fault_key_format_agrees_and_not_only_its_prefix` | test |
| D43, D44 and D45 are recorded as decisions | `docs/adr/0014-ordered-audit-view-index.md` | document |
| The caller count of the no-proof write path is unbounded, and two enumerations are hand-listed | readME.md §5, Residual Limits | document |

---

## 16. Could not verify

1. **Whether any deployment outside CI exists.** P3c3e-8 rests on it and the
   instruction answers it; this session verified the half that is a property
   of the compose files and did not attempt the other half. Recorded, not
   derived.
2. **Why `tests/test_committed_is_a_fact.py::test_a_write_that_committed_is_reported_as_committed_when_the_state_call_fails`
   is intermittently red on this host.** A Phase 3c-3d test, not one of this
   phase's, and this phase's own fixture correction is what exposes it. Its
   last assertion is `str(ledger_tx) in after` - if the response says the
   proof checked out, the persisted trust anchor carries that transaction.
   Observed failing with the record at transaction 46 and the anchor reading
   `{"immudb:3322/b'defaultdb'": 43, "cutproxy:3399/b'defaultdb'": 47}`.

   What changed. Until this session `wait_for_health` could pass against the
   outgoing verifier, so that test sometimes ran against a verifier still
   pointed straight at ImmuDB - no relay in the path, a clean write, an anchor
   that trivially matched. Waiting for the container to actually be replaced
   puts the relay in the path every time, which is what the test says it is
   doing, and the assertion is now reached under the condition it was written
   for. It passed 9 of 9 in three CI runs on Linux and failed roughly one run
   in three here.

   **It is left alone.** Weakening a prior phase's assertion to make this
   phase's fixture look clean is exactly the substitution the standing rules
   forbid, and the honest statement is that the assertion may be too strong
   for the cut it runs under, or the anchor may be advancing for a reason
   nobody has named. Either is a finding for whoever takes it, not something
   to close here by editing the assertion. It appears in the sweep's
   alphabetical baseline where it fires, and section 12 says which orders it
   appeared in rather than counting it as order dependence.

3. **A fault written concurrently with a page read spanning two cursor
   pages.** Carried unchanged from the 3c-3d red team's own could-not-test
   list; nothing in this phase touches that loop.
4. **Whether a real pre-D38 ledger reads correctly under this build.** Now
   moot rather than open: the path that would read one is deleted.
5. **Per-test isolation.** The 3c-3d sweep isolated 11 modules and 118 tests
   and found zero hidden dependence. Thirty-five modules were not isolated,
   and isolation was per module rather than per test. Nothing measured
   indicates it; it is in `TODO.md` as deferred work with the shape it would
   take.
6. **An encoding or an inspection surface nobody thought of.** The honest
   ceiling of both hand-listed enumerations in P3c3e-5.
7. **The full local suite is not a green signal on this host.** Around 14
   failures before and after any change, from `sigstore` being uninstallable
   here and from in-process tests resolving compose service names. CI is the
   signal; what the local sweep measures is order, by diffing each order's
   failing set against the alphabetical baseline's.

---

## 17. Residual limits, stated rather than scheduled

- 35 modules were not isolated. Nothing in the sweep data points at them;
  nothing excludes them.
- Isolation was per module, not per test. A dependence one test satisfies for
  a later test in the same module is invisible to it. Per-test isolation is
  442 runs and nothing measured indicates it.
- The unverified-write path's caller count is no longer enforced. The runtime
  guard bounds what that path writes; nothing bounds how many callers reach
  it. Section 11.
- `/write-ordered` accepts a key of any shape into a view. Closing it would
  refuse the deliberately mismatched writes `tests/test_reconciliation.py`
  uses to prove D37 finds a record in the wrong view. Carried, not taken.
- The two hand-listed enumerations in P3c3e-5, and the intention registry in
  P3c3e-10. Section 13 says which and why.

---

## 18. Files changed

| File | What |
| :--- | :--- |
| `verifier/main.py` | D45's four response states and `OrderedCommitUncertain`; the position confirmation; the fault key's length budget and derived transaction; the corrected comment |
| `control_plane/main.py` | The legacy fault read deleted; `_fault_key_transaction` and the render-time cross-check; the `committed: null` branch on the tombstone path |
| `tools/ail_backfill_index.py` | Bound assertions on `scan_all` and `indexed_keys` |
| `tests/test_route_parity.py` | New. D43 for the write routes |
| `tests/test_bounded_reads.py` | New. D43 for the bounded reads |
| `tests/test_view_invariants.py`, `tests/ledger_pollution.py` | New. D44's other half |
| `tests/test_ledger_state_does_not_survive_teardown.py` | New. P3c3e-8's volume check |
| `tests/test_committed_is_a_fact.py` | Three relay modes and five tests |
| `tests/test_fault_key_and_page_read.py` | P3c3e-6, P3c3e-7 and A7; the legacy render test removed |
| `tests/test_image_contents.py` | Two enumerations, one shared detector, two surfaces |
| `tests/test_ledger_faults.py` | The caller-count parse removed |
| `tests/test_audit_ordering.py`, `tests/test_audit_read_correctness.py`, `tests/test_backfill_index.py` | The four order-dependent tests |
| `docs/adr/0014-ordered-audit-view-index.md` | D43, D44, D45 |
| `readME.md`, `TODO.md` | Three Residual Limits entries; the phase closure and the deferred isolation work |
| `docs/reports/phase-3c3a.md`, `docs/reports/phase-3c3d.md` | Dated errata |

---

## 19. Evidence

### Mapping check

`python tools/mapping_check.py` over 391 rows in 15 reports: **this report's
own 40 rows are clean**, 0 class (a) and 0 class (b) failures. Against the
committed baseline: **0 new, 12 known, 0 stale**, and 34 heading pins recorded
with 0 unpinned, 0 retitled, 0 stale. `tests/test_mapping_tables.py`: 20
passed.

Two rows of this report needed correcting before that held, and both are the
check doing its job rather than the check being appeased. A `doc` Kind is not
in the derived vocabulary, so two rows declared a backing shape nothing knows
how to look for; they say `document` now. And a `readME.md` citation narrowed
to section 5 has to be pinned to the heading it matched, so the pin is
recorded in `docs/reports/heading-pins.json` - the mechanism that stops a row
silently re-scoping itself when a heading is renamed.

**The pin and the report have to land in one commit, and the first attempt did
not.** Pushing the pin ahead of the report left `1 pin(s) match no narrowing
any more` in CI: the pin named a row in a file that commit did not carry. It
is a small thing and it is the same shape as everything else here - a rule
that holds at two places, with the two able to disagree.

### CI

**Run `33665124730`, green: 495 passed, 9 skipped, 199.81s.** Commit `3109e0f` on `p3c3b-order`, PR #14.

The runs before it are recorded rather than only fixed, because two of them
found defects in this phase's own work and one was inherited.

| Run | Commit | Result | What it found |
| :--- | :--- | :--- | :--- |
| `33570462476` | `e3cdd1d` | 1 failed, 441 passed | **Inherited red.** The branch was already failing before this session: `docs/reports/phase-3c3e.md` is referenced by the instruction that asks for it, and it did not exist yet. |
| `33620001018` | `899874a` | 3 failed, 492 passed | Two of this phase's own relay tests, failing on **their own guard**: `the ExecAll did not reach the ledger, so this test is not exercising the condition it describes`, with `attempts: 1, committed: false` and the record absent. The relay cut on an HTTP/2 control frame before the write committed. |
| `33623844441` | `fd09105` | 1 failed, 494 passed | The relay fix confirmed on Linux; all five relay tests pass. The one failure is the inherited one. |
| `33629407221` | `a711115` | 2 failed, 493 passed | The heading pin pushed one commit ahead of the report it pins. |
| `33663495874` | `8133f3c` | 1 failed, 494 passed | The report lands and both references to it resolve. The one failure is **this phase's own over-assertion**: `test_a_retry_after_a_dropped_response_is_told_the_record_already_exists` asserted `committed is True` where CI produced `committed: null` - the relay closes the connection it cut, so the verifier's confirming read can hit a dead socket. Null is D45 being honest, and the assertion was wrong to exclude it. |
| `33665124730` | `3109e0f` | **495 passed, 9 skipped** | Green. |

**None of the three defects CI found in this phase's work was closed by
weakening a test, and the third is the one worth reading closely.**

- The relay cut on the wrong frame: a fixture that did not do what it said.
- A heading pin was committed apart from what it pins.
- `test_a_retry_after_a_dropped_response_is_told_the_record_already_exists`
  asserted `committed is True` where `committed: null` is equally honest.

**The third looks like a weakening and is not.** The record is in the ledger,
and two answers describe that truthfully: `true` when the verifier read it
back, and `null` when the relay had already closed the connection the
confirming read needed. `false` is the only answer that is a lie, and it is
the one that sends a caller into D39's permanent 409 - so `is not False` is
the claim this test was always about, and `is True` was narrower than the
property rather than stronger. The `null` state is not thereby unasserted:
`test_a_plain_write_states_no_fact_when_the_confirming_read_is_cut_too`
asserts it exactly, and P3c3e-2's own demonstration still asserts `true` with
the real transaction and position, its fixture retried until the confirming
read could run.

That is the distinction the standing rules are about. A weakening drops a
claim the system makes; this dropped a claim the test made and the system
never did.

### Environment cleanup

Removed:

- Compose project `p3c3efix`: all seven containers, the three volumes
  (`p3c3efix_test-immudb-data`, `p3c3efix_test-verifier-state`,
  `p3c3efix_test-control-plane-data`) and the network `p3c3efix_default`, with
  `docker compose -p p3c3efix -f docker-compose.test.yml down -v`.
- The five images this run built `--no-cache`: `p3c3efix-verifier`,
  `p3c3efix-ail-control-plane`, `p3c3efix-decision-service`,
  `p3c3efix-anchor-service`, `p3c3efix-dashboard`.
- The relay containers the fixture starts and removes per test
  (`p3c3efix-p3c3d-cutproxy`, `p3c3efix-p3c3e-cutresponse`,
  `p3c3efix-p3c3e-blackhole`, `p3c3efix-p3c3e-droprequest`). The fixture
  removes each one unconditionally on the way out; the check below confirms
  none survived.
- The scratch clone in full, including the generated `keys/*.key`,
  `keys/*.pub` and `decision_service/secrets/vault_api_token.txt`, and the
  `.env` written for it from CI's own test values.
- Every probe and patch script, written to the session scratchpad and never
  into the tree, so none could be committed by accident. The one piece of key
  material this session produced outside the tree - a PKCS8 DER written to the
  scratchpad while measuring the detector's ASN.1 signatures - went with it.

Verified empty afterwards, each filtered on the project name:

```
$ docker ps -a  --format '{{.Names}}'      | grep -i p3c3efix  ->  (nothing)
$ docker images --format '{{.Repository}}' | grep -i p3c3efix  ->  (nothing)
$ docker volume ls --format '{{.Name}}'    | grep -i p3c3efix  ->  (nothing)
$ docker network ls --format '{{.Name}}'   | grep -i p3c3efix  ->  (nothing)
```

**Could not remove: nothing of this run.** The Docker daemon stayed healthy
throughout.

Untouched, and belonging to earlier runs rather than this one: the
`ail-scratch_*` and `compliance-ail_*` volumes. They were present at the start
and are left as found.

The scratch clone is removed after this report is pushed, which is the last
act of the session - the report cannot be written from a directory that no
longer exists.

The primary working directory was never used for a stack. Nothing was written
there by this run.

---

## Erratum, 2026-09-04 (added by Phase 3c-3f, `p3c3f-fix`)

**Section 16 item 2's second alternative had a named path handed over with
it. That path is refuted. The observation is unexplained again, and it is now
unexplained-and-established rather than unexplained-and-assumed.**

Item 2 offered two alternatives for the intermittent failure of
`tests/test_committed_is_a_fact.py::test_a_write_that_committed_is_reported_as_committed_when_the_state_call_fails`:
the assertion may be too strong for the cut it runs under, or "the anchor may
be advancing for a reason nobody has named." The Phase 3c-3f instruction
handed the second one over with a candidate mechanism:
`control_plane/main.py::_has_tombstone` calls `POST /verify` on every
`POST /content`, and `POST /verify` advanced the persisted trust anchor. An
ordinary content write would therefore move the anchor as a side effect of a
check, and the test reads the anchor immediately after its own write.

**Measured, and it does not.** `_has_tombstone` asks about
`content_erasure:{call_id}` for a call_id that has no tombstone. ImmuDB
answers "key not found", and `POST /verify` returns from its
`except grpc.RpcError` handler - **before** the line that reads the head. The
anchor is never touched. Driven on a build with the pre-D47 route deliberately
restored, so this is not an artefact of the fix:

```
1. what _has_tombstone's own call answers for a fresh call_id
    200 {'verified': False, 'error_class': 'not_found', 'state_id': None}

   anchor before                : 442
   anchor after 6 direct writes : 442   (unchanged)
   POST /content -> 204
   anchor after one POST /content: 442

2. the same route for a key that EXISTS, on the same build
    wrote at tx 485
    anchor before the read      : 485
    POST /verify -> 200 {'verified': True, 'tx_id': 485, 'state_id': 491}
    anchor after the read       : 491
    moved: True
```

Section 2 is the control: the mechanism is real, and it is narrower than the
handover said. Only a `POST /verify` **that finds its key** moved the anchor.
`_has_tombstone` reaches that only when a tombstone actually exists for the
call_id, which is after an erasure; `GET /audit`'s per-entry verification and
`GET /audit/bundle` reach it on every ordinary page.

Four runs per arm with about 300 content writes in flight throughout each run,
with and without the pre-D47 route, produced no failure in either arm, so that
experiment has no discriminating power on its own and is recorded as a
negative. The flake did not appear in twenty-two runs of any kind during Phase
3c-3f.

**What this changes about item 2.** The first alternative - the assertion may
be too strong for the cut it runs under - is untouched and remains open. The
second alternative is unchanged in substance and changed in standing: "the
anchor may be advancing for a reason nobody has named" was a possibility
nobody had tested, and it is now a possibility whose only named candidate has
been tested and eliminated. Whoever takes it next should not re-derive the
`_has_tombstone` path; it is closed.

D47 (Phase 3c-3f) removes the anchor mutation from every caller of
`POST /verify` regardless of this result, so the item stands on its own
argument and not on this one. Full measurement in `docs/reports/phase-3c3f.md`
section 12.

Nothing in the body of this report above is edited. This erratum is additive.
