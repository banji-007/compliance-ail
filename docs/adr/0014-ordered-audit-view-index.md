# ADR-0014: An ordered audit view, selected by a CAS-allocated sequence

**Status:** Accepted (Phase 3c-3b)
**Decisions:** D32, D33, D34
**Supersedes nothing. Extends:** ADR-0002 (the `/audit` proxy), ADR-0006 (verification states), ADR-0009 (write-ahead intents)

---

## Context

`GET /audit` paged the ledger with `scan` over the `tool_call:` prefix under
`desc: true`. That walks keys, and a decision key is
`tool_call:{agent_id}:{uuid}:{tool_name}`, so the page returned the
lexicographically-largest agent ids and presented them as the most recent
decisions. A record written seconds ago was absent once the ledger exceeded
`limit`. Observed during `p3c2-defer` at 211 entries: the newest transaction
was 573 and the page's first row was not it. Reproduced during this phase at
501 entries, where the newest transaction was 638 and the page's highest was
630, in an order that was not descending by transaction at all.

No read parameter fixes this. `scan` has no ordering option, `TxScan` is not
routed over the REST API the control plane uses, and no key this project
writes is temporal or monotonic. The ordering has to be put somewhere the
ledger enforces, at write time.

## D32. A zset index selects; a CAS-allocated sequence scores it

`zscan` is routed and orders by a caller-supplied score. The question is
where the score comes from.

**Not a clock.** A timestamp is globally comparable and wrong under skew, and
the thing being ordered is commits, not wall time.

**Not a per-writer counter.** `p3c3-scoring` had four writers each claim
positions 1 to 15. Signing the claim does not help: it proves the writer
*said* position 3, not that position 3 is where the record belongs. A
per-writer sequence is not an ordering.

**A single counter, allocated under a compare-and-set the ledger enforces.**
One `ExecAll` carries three operations - the record, the advanced counter,
and the `zAdd` into the view index - gated by a `KeyNotModifiedAfterTX`
precondition on the counter. A writer that read a stale counter is rejected
outright, so any position that commits is the unique next one from the state
that writer read. All three operations land in one transaction or none do.

Verified live against immudb 1.9.5 during this phase: a three-operation
`ExecAll` commits with `nentries=3` under one transaction id, and repeating
it against the now-stale precondition is refused with `precondition failed:
KeyNotModifiedAfterTxID`. Under 8 concurrent writers, 64 writes produced 142
rejected attempts, a gapless block of positions, and score order equal to
commit order.

**The index is a view index, not the ordering.** The ledger's ordering is its
transaction sequence; this is one view over it. Hence the naming:
`ail_view:decision:v1` and `ail_view:intent:v1`, scored from one shared
`ail_seq:commit`. A second view - incident-first, say - is a new zset over
the same positions and needs no second backfill. `p3c3-question` established
that no scan can filter on outcome, because `outcome_type` lives in the
record's value and not in its key, so such a view would need its own index;
adopting the shape now is nearly free and cannot be adopted cheaply later.

The counter key sits outside `tool_call:`, `tool_call_intent:` and
`content_erasure:`, or it would be counted as a decision by the ledger count
Phase 3c-3a added.

### What the write path gave up, and got back

`immudb-py` 1.5.0 has no `verifiedExecAll`, and its `execAll()` wrapper
cannot express a precondition at all - the handler builds
`ExecAllRequest(Operations=..., noWait=...)` with no preconditions field, so
the whole mechanism is unreachable through it. Two consequences, both
deliberate:

**The request goes to the generated gRPC stub rather than the wrapper.** No
verification code is reimplemented; only a request the wrapper cannot
express. This is a much narrower thing than the hand-rolled `Alh()` ADR-001
exists as a warning about.

**The proof check moved from inside the write call to immediately after it.**
`verifiedSet` ran the inclusion and consistency proofs as part of writing.
`ExecAll` does not, so the ordered write issues a `verifiedGet` on the record
key straight afterwards. It is the same SDK verification code over the same
proofs, and it raises on the same conditions, so the fail-closed rule is
unchanged: an unverifiable write raises, `ledger/immudb_ledger.py` turns that
into an exception, and the decision service denies the call. Confirmed live
that a `verifiedGet` on an `ExecAll`-written key succeeds and that the
consistency proof keeps advancing across `ExecAll` transactions. **The
guarantee moved; it did not weaken.** Measured cost of the move: none
distinguishable from noise (`docs/reports/phase-3c3b.md`, section 7.1).

### The seam between history and live traffic

The boundary is a number, not a cursor:

    positions 1 .. RESERVED_POSITIONS      backfilled history, score == entry.tx
    positions RESERVED_POSITIONS + 1 ..    allocated by the CAS

**A historical record's position is its own `entry.tx`.** That is the ledger's
own commit order for it, already recorded and needing no reconstruction. The
live counter is seeded above the reserve - `verifier/main.py` starts a fresh
counter at `RESERVED_POSITIONS + 1`, and `tools/ail_backfill_index.py` raises
an existing counter that is still running below the reserve, under the same
precondition every allocation uses - so every live position is strictly
greater than every historical one and the page is monotone across the
boundary by construction.

Why `entry.tx` and not a rank within the backfill pass. A rank is monotone
within one pass and not across two, because a second pass computes a different
rank against a different denominator and interleaves with the first. A
position that *is* the transaction id is stable however many
passes run and in whatever order, so re-running after finding more history
extends the ordering rather than disturbing it, and no cursor is needed to say
where history ends.

`RESERVED_POSITIONS` defaults to 1e9 and must exceed every historical
transaction id. The backfill refuses to run rather than guess if it finds a
record at or above it, because scoring history on top of live positions would
interleave the two and fault D33.

Two measured constraints ruled out the obvious alternatives, both discovered
by trying them:

- `zscan` under `desc: true` **silently omits negatively-scored members**,
  and an explicit `minScore` does not bring them back. A backfill that placed
  history below zero would produce records that are indexed and still absent
  from every page, which is this ADR's own defect reintroduced by the
  migration meant to fix it.
- A score of exactly `0` comes back with **no `score` field at all**, because
  protobuf's JSON mapping omits zero-valued fields.

Transaction ids start at 1, so both are avoided by construction. Records
sharing one transaction share a position, which is honest: they are one
commit, and the page presents them adjacently in an unspecified order.

## D33. The index selects, the record proves

`zscan` returns the caller's score and the resolved `entry.tx` in the same
response, so comparing them costs no extra call.

Under the CAS this is no longer a defence against a writer that can misorder;
the ledger refuses to commit an out-of-order position at all. It is a cheap
assertion that the enforcement is still in place, and it is what would catch
the precondition having been dropped. That is not hypothetical: applying this
phase's own "drop the precondition" mutation left 48 writes sharing 10
positions, and the resulting duplicate scores made every sufficiently deep
page fault.

**A disagreement is a fault, not a sort order.** Reordering the page to
match the transaction ids would hide precisely the condition worth reporting -
an index that no longer describes the ledger it indexes - and would show a
reader a page that looks fine.

**It is a chosen response with a structured body, not an escaping exception.**
`/audit` answers `500` with:

    {"detail": {"error": "audit_ordering_fault",
                "message": "<the two positions and the transactions they resolve to>",
                "view": "decision" | "intent",
                "disagreement": {"higher_position": {"position", "transaction"},
                                 "lower_position":  {"position", "transaction"}},
                "page_served": false,
                "scope": "<what this check can see>",
                "on_retry": "<what a later request means, and does not mean>",
                "authoritative_check": "<where the durable answer lives>",
                "remediation": "<what to do>"}}

`500` and not `4xx`, because nothing about the request is wrong; `500` and not
`503`, because the ledger is append-only and a position once written cannot be
withdrawn, so the "try again shortly" that `503` promises would be false.
`page_served` is stated in the body rather than left for a caller to infer
from a status code, so no reader mistakes the fault for an empty ledger. The
handler sits above every handler broad enough to catch it: an `except
Exception` above it would swallow the fault into a `503 ImmuDB unavailable`
and tell a reader something false.

**What the body must not say, corrected in Phase 3c-3c (P3c3c-7).** It said
`transient: false`. The corruption is not transient; this fault is. The
check's window is the top of the index at the requested limit, so newer
commits push a disagreement below the window and every limit answers `200`
again with the corruption still indexed - measured in
`docs/reports/phase-3c3b-redteam.md` C5 and C10 and reproduced in
`docs/reports/phase-3c3c.md`. A field asserting a durability the code does
not have is worse than no field: its absence tomorrow reads as repair. What
replaces it is the scope the check actually has, what a later success does
and does not mean, and a pointer to D37's reconciliation, which has no
window.

**What the check covers, stated precisely.** Only positions the CAS
allocated, which are the integers from 1 up. Backfilled history was ordered
by an offline pass from transaction ids of records already committed, and
was never subject to the CAS, so a pre-index record can legitimately carry a
higher transaction id than a record indexed after it. Comparing those two
would report a fault about a rule that never applied to either. The check is
scoped to the rows the CAS produced and is not weakened for them.

## D35. A committed write is reported as committed, and its standing is durable

Added in Phase 3c-3c, closing red-team C7 and C1.

Both write routes commit before their proof runs. The ordered route's
`ExecAll` commits the record, the counter advance and the index entry, and
then runs `verifiedGet`; `verifiedSet` commits at
`service.VerifiableSet(rawRequest)` and every `ErrCorruptedData` raise is
after that line. So a proof failure can no longer prevent the write, and
answering `{"tx_id": null, "seq": null, "verified": false}` told the caller
the opposite of what happened - it is the exact shape
`ledger/immudb_ledger.py` reads as "the write did not happen". Reproduced:
the response said null while the record sat at tx 7, position 1000000005,
indexed, with the counter advanced.

The response now carries the real transaction, the real position and
`committed: true` beside `verified: false`. **The call still denies.**
Fail-closed on execution is unchanged and the caller's rule is still keyed on
`verified`; what changed is the description of the ledger.

**The page's `unverifiable` is not the record's standing.**
`control_plane/main.py::_verify_one_key` computes verification fresh at read
time, so repairing the trust anchor makes the same record read `verified` on
the next page with nothing recording that its write-time proof failed -
measured, including a clean `ail-evidence-bundle/2` exported for it
afterwards. The durable qualification is therefore a **record**, classified by
`record_type`, carrying the committed key, transaction and position. It was
keyed `ledger_fault:{call_id}` and joined by the same exact `getall` the
tombstone join issues; **D38 (Phase 3c-3d) replaced that key and that join**,
because a second fault for one `call_id` was a new version of the same key
and three records sharing a `call_id` collided into it. See D38 below.

**The fault record's own write is the one write in this system whose success
does not require write-time proof.** The condition that produces a fault is
the condition that breaks every proof, so requiring one would mean the
qualification can never be recorded exactly when it is needed. Three
constraints hold it in place: `_set_without_verification` refuses any bytes
that are not a `ledger_fault` record - it reads the bytes it is about to
write, since P3c3d-12 found that inspecting a parallel `record` argument
bounded nothing; **both** write routes refuse a `ledger_fault` arriving from a
caller (D39; until Phase 3c-3d only the plain route did); and a failure to
write the fault fails loudly, logged and reported as `fault_record_error`,
because a silent absence would leave a committed record unqualified with
nothing saying why.

**The verifier is a writer now, so it has a writer key.** D22's rule is one
dedicated long-lived key per writer; `keys/writer-verifier.key` is the third.
An unsigned fault record would be a record `tools/ail_verify_bundle.py`
refuses outright, which is a poor thing for a record whose whole job is to
qualify another record's standing.

## D36. The reserve is bound into the ledger at first allocation

Added in Phase 3c-3c, closing red-team C3 and the named half of C4.

Raising `AIL_RESERVED_POSITIONS` after allocation put committed CAS positions
inside the new reserve, where they are neither reconciled (`anchor_service`
counts only positions above it) nor order-checked (D33 is scoped to the same
range), permanently, with the verdict still reading `clean`. Nothing
distinguished "raised after allocation" from "always was this value", and the
backfill's own refusal message instructed exactly that raise.

The reserve is written into the ledger at `ail_seq:reserve`, in the same
`ExecAll` as the first allocation, under a `KeyMustNotExist` precondition.
That gives immutability and the runtime agreement check from one mechanism
rather than pairwise probes between three services: every reader compares its
own configured value against the bound one and refuses on disagreement - the
writer refuses to allocate, the control plane refuses to serve a page, the
reconciler refuses to report, and the backfill refuses to run.

The key lives outside every counted prefix, the same rule the counter follows
and for the same reason. Reading it costs no round trip per write: it is
cached, re-read at cold start and after a rejection. The value is validated as
a positive integer wherever it is read, in all four copies - C4 was not
refuted, but an unvalidated reserve is the one input that puts every position
at or below zero, where `zscan desc` silently omits it.

**A reserve that turns out too small is a re-index into a new view, not a
moved boundary.** A second zset scored from the same counter takes the
history that does not fit. The refusal message says so, in place of the
instruction that was the attack.

**One limit, stated rather than assumed away.** A ledger that was already
allocating before this phase has no first allocation left to catch, so the
binding attaches to its next one. A deployment that had already raised its
reserve before upgrading therefore binds the raised value, and nothing can
retroactively distinguish that.

## D37. Reconciliation is the authoritative order check

Added in Phase 3c-3c, closing red-team C6 and, with D35, C10.

D33's comparison stays as a cheap assertion that enforcement is in place, but
its window is the top-of-index page, so a disagreement below it is
unreachable at any limit and newer traffic clears the fault while the
corruption stays. The authoritative check is the reconciliation, which
already walks every position.

**Per view, and per view means precisely three things:**

1. every member of a view matches that view's prefix;
2. the union across views equals the allocated range exactly, **in both
   directions** - positions the counter handed out that no view holds, and
   positions no counter ever handed out that a view does;
3. no position appears in two views.

Clause 1 is what a union across views could not see: a decision record
indexed into the intent view balanced the arithmetic while being on no page
at all, and reconciled `clean`. Clause 2's second direction is new: 2510
positions nobody allocated sat in a view and the verdict was `clean`, which
matters because D33's own remediation sends an operator here.

**Clause 3 is a property of the current view set, not a law.** It is retired
the first time a view legitimately overlaps the existing ones, which is the
incident-first view D32 anticipated. Stated here so that is a known
consequence rather than a surprise to whoever adds it.

**Reconciliation must not die on a malformed row.** `min_score =
float(rows[-1]["score"])` sat two lines after a correct `.get("score", 0.0)`,
so a page ending on a zero-scored row - protobuf omits a zero-valued field
entirely - raised `KeyError` out of the whole pass, which `run_forever`
swallowed into one log line per interval, permanently dark. A row that cannot
be read is now a finding in the same shape as every other finding, and a
zero-scored row is itself a finding: no write path this project has produces
one.

**It runs in the test stack, and anchoring still does not.**
`AIL_ANCHOR_MODE=reconcile-only` runs the reconciliation half with no
anchoring key, no `/state` read and no submission anywhere on the path, so
`docker-compose.test.yml` gets a genuinely running reconciler while P3b-5's
demonstration - the whole suite running with anchoring entirely broken -
survives. Each pass writes its verdict to `AIL_RECONCILE_REPORT_PATH`, which
is how a test observes the running service rather than its own in-process
call.

## D39. The ordered route carries the refusals, and a record key is written once

Added in Phase 3c-3d, closing red-team A2 and A4 and the unlisted finding the
same report called the most serious thing it found.

`_refuse_reason_for_plain_write` was wired into `POST /write` and was called
from nowhere else, so `/write-ordered` refused nothing at all. Every bound
P3c3c-2 established was therefore a true statement about a route no decision
takes any more. Measured (`docs/reports/phase-3c3d-keyprobe.md` section 12): a
caller holding only `VERIFIER_WRITE_KEY` wrote a `ledger_fault:` key that
`/audit` rendered as the ledger's own account of another record's standing,
with an attacker-chosen `fault_class`, `committed_tx_id` and timestamp; and
because the ordered route allocates a position, the same write became a page
row with `outcome_type: null`, so `entries` exceeded `total`.

**The two routes are deliberately not symmetric, and the shared refusal is
narrower than "the same set".** `POST /write` refuses a `decision` because a
decision with no commit position is absent from every ordered page, and
`/write-ordered` exists to write exactly those. What the two share is the
`ledger_fault` refusal, and that one is not a statement about which route a
record belongs on: a fault record is this service's own account of its own
failed proof, and one arriving from a caller on any route is an unverified
assertion about another record's standing. Both conditions again - key prefix
and `record_type` - because each covers the other's blind spot.
`_REFUSED_KEY_PREFIXES` matches on `ledger_fault:`, which is still a prefix of
D38's composite shape, so this refusal covers both key shapes unchanged: D39
and D38 are independent.

**A record key is written once.** Re-writing an existing key through the
ordered route is not an update. The key gets a second index entry at a second
position and both resolve to the key's current transaction, which D33 reads as
a disagreement, so `/audit` is refused at every limit for as long as the pair
is in the window. Measured: two ordinary well-formed writes, both
`verified: true, committed: true`, no corruption and no privileged access, and
HTTP 500 at limits 1, 5, 200 and 2500. The record key now carries a
`KeyMustNotExist` precondition in the same `ExecAll`, so the losing write
commits nothing at all and answers 409. Nothing this project writes wants a
second version of a record key: every ledger key carries a fresh uuid, and the
tombstone key is written once per erasure.

ImmuDB names the precondition type and not the key it was about, so the one
unretryable cause is told apart from the two retryable ones by asking the
ledger whether the record key is present. A read that cannot run answers "not
present", which retries; the precondition is what refuses, so a wrong answer
there costs an attempt and never admits a second write.

**What is not closed, stated rather than implied.** A caller holding the write
key can still write a key of some other shape into a view, and it becomes a
page row. Refusing that would mean requiring the key prefix to match the
requested view, which would also refuse the writes
`tests/test_reconciliation.py` uses to prove the reconciler finds a record
indexed into the wrong view - the D37 check would lose its enforcing test.
That is a decision this phase raises rather than takes.

## D38. The fault key carries a transaction and a nonce

Added in Phase 3c-3d, closing the loss D35's key shape carried from the day
it was written, and the shape half of red-team A2 and A4.

```
ledger_fault:{committed_tx_id:020d}:{call_id or "key:" + sha256(record_key)[:32]}:{nonce}
```

`nonce` is `uuid4().hex[:16]`, minted in `_write_fault_record`.

**The transaction separates faults about different records; the nonce
separates faults about the same record. Neither substitutes for the other.**

*What the nonce closes.* Under `ledger_fault:{call_id}` a second fault about
one record was a new version of the same key, so `getall` returned the head
and a prefix scan returned one row: three faults about one record were one
row and two hidden. D38 as first written, `ledger_fault:{call_id}:{tx_id}`,
did not close it. The only transaction available when the key is built is
`committed_tx_id`, the qualified record's own, which is fixed per record.
Measured: the same key twice, `revision=2`, and a range read over the
record's transaction returning one key. That was a rename.

*What the transaction closes, separately.* `tool_call_intent:` and
`tool_call:` for one call carry the same `call_id` and both take the ordered
route; the erasure tombstone takes `POST /write` with that same `call_id`.
All three can fault. Under `ledger_fault:{call_id}` an intent fault, a
decision fault and a tombstone fault for one call collide and silently
replace each other, non-adversarially, with no second writer involved. A
scheme keyed on `{call_id}:{nonce}` would re-merge them, and would also drop
the bounded page read.

*Why twenty digits.* uint64 max is twenty digits, so overflow is unreachable,
and the ledger is append-only, which makes a narrower pad a bet that cannot
be un-made. Both failure modes past a short pad are silent and arrive at HTTP
200: over-width keys are pulled into a window that should exclude them, and a
window whose own bound is over-width returns empty.

*Ordering between two faults about one record* comes from the `scan` entry's
own `tx`, which the read that already ran returns. It costs nothing, and no
timestamp component is needed or present.

*What is given up.* The fault key is no longer derivable from a page row.
That derivability is exactly what the original form preserved by closing
nothing. Anything that needs to name a specific fault key gets it from the
write response's `fault_record`.

*The page read.* The fault key leads with the qualified record's transaction,
so a page's faults are a key range: one paginated half-open scan from
`ledger_fault:{min_tx:020d}` inclusive to `ledger_fault:{max_tx+1:020d}`
exclusive, with the window taken from the rows the response will render,
across both zscans rather than the decision page alone. Half-open is
required, not stylistic: a bare padded `hi` with `inclusiveEnd=True` sorts
before that transaction's own composite keys and silently drops the last row
of the page. An empty page has no window and issues no read. Filtering back
to the page is client-side membership on the record key each fault names, so
the range is a superset and never a subset - which is also what joins a fault
onto a row whose record carries no `call_id`, something no key shape did
before, including the old one.

Every `ledger_fault:{call_id}` already committed keeps that shape
permanently, so the exact `getall` stays, with exactly today's keys and no
keys added - a nonce-carrying key cannot go into a `getall` at all. The cost
is two round trips per page against one.

*And the count.* `ledger_fault.count` was `revision` on the head entry, which
was the number of faults only because the single key was rewritten in place.
Under D38 each fault is its own key written once, so `revision` is
permanently 1 and the field would report one fault where three exist - the
failure D38 exists to fix, surviving inside the field that describes it. The
count is the number of hits for that record. **Contract change:**
`ledger_fault` stays one object, the most recent fault by the ledger's own
transaction for the fault record, with a true `count`. A list of faults was
the alternative and is equally defensible; one object keeps the field
answering "what is this record's standing", avoids an unbounded structure on
every row of a 2500-row page for a field that is null on almost all of them,
and changes no consumer. `ledger_fault` appears nowhere in `dashboard/` and
no test asserted `count`, both checked rather than taken on trust.

## D40. `committed` is a fact about the ledger

Added in Phase 3c-3d, closing red-team A1 and, through it, A8.

`POST /write` issued `currentState()` in the same `try` as `verifiedSet`,
under a broad `except Exception` that answered `committed: false`. Measured
with a relay that passed the write through and cut the connection afterwards:
the record committed at tx 14, the SDK's persisted trust anchor advanced to
14, and the response said `{"tx_id": null, "verified": false, "committed":
false}` - the exact shape `ledger/immudb_ledger.py` reads as "the write did
not happen".

The state read is now outside the proof's handler and cannot describe the
write. And the generic handler no longer guesses: a transport error raised by
`verifiedSet` itself is genuinely ambiguous, so the ledger is asked, with the
value as well as the key. Byte equality answers exactly the question being
asked, and keeps a record that was already under this key from being reported
as this write. `verified` stays false there and no fault record is written -
the proof did not fail, it could not be attempted, which is not tamper
evidence.

## D41. A fault is verified before it is rendered as a record's standing

Added in Phase 3c-3d.

Nothing on the read path checked `writer_signature` or
`writer_key_fingerprint` before `/audit` rendered a fault. D39 closes the
write path; D41 means a fault that arrived some other way is not presented as
the ledger's account of anything. The check is `provenance.verify_record`
against the verifier's own writer public key, and it refuses four ways: no
signature, a format string this rule does not cover, a fingerprint that is
not this key, and a signature that does not verify.

**The asymmetry is deliberate and is stated rather than left to be
inferred.** `/audit` renders a decision record without checking its writer
signature, and at the default `verify=false` without checking its inclusion
proof either. That is defensible: a record's own state is explicitly reported
as `asserted` and is never self-certified (D2, ADR-0006), whereas a fault is
presented as authoritative metadata about *another* record. Extending the
check to every row on the default page would be the per-record round trip D29
removed. **It is not extended.**

The ceiling: every service mounts `./keys:/keys:ro`, so a fingerprint names a
key and not a component (ADR-0012, corrected in Phase 3c-3c). D41 establishes
that a fault was signed by the writer key the verifier signs faults with, and
the D22 mount split is what would make that a statement about which process
wrote it.

## D42. A bounded read asserts on what came back

Added in Phase 3c-3d.

ImmuDB's REST route drops an unrecognised or misspelled field without
comment, so a bounded read whose bound did not survive becomes an unbounded
read at HTTP 200 with nothing in the response saying so. Measured: `endkey`
for `endKey` returned all ten keys where `endKey` returned seven. That is the
whole distance between a correct read and a wrong one, and it is why the
assertion is on what came back rather than on what was sent.

Two forms, because a bound has two shapes here and one assertion does not fit
both.

- **Key-range scans** assert that every returned key falls within the range
  actually requested for that page, seek to end, with the seek bound
  inclusive only on the first page. A violation raises, and `/audit` answers
  `bounded_read_fault` rather than serving a page whose fault join may have
  silently widened.
- **Score-bounded reads are a separate case with their own form.** The
  view-index reads are `zscan` bounded by `minScore`, not by keys, so the
  key-range assertion does not apply to them and is not bolted on. Their
  equivalent is that every returned row's score falls within the requested
  bound, read from the row's own `score` field with `.get("score", 0.0)`
  because protobuf omits a zero score entirely. Reported as a reconciliation
  finding rather than raised, which is that function's standing rule for
  every bad row: a pass that dies on one row reports nothing about the rest.

## D43. A guarantee holds at every site, and the sites are enumerated from the code

Added in Phase 3c-3e.

**The defect this closes is not any one of the six the red team refuted; it
is what all six had in common.** A rule that has to hold at N sites, with
nothing enumerating the sites. Two write routes covered at one. Four bounded
reads covered at two. N key encodings covered at one. N inspection surfaces
covered at one. Earlier passes: five modules compared at four, four copies of
a validator, two copies of a Compose rule.

D40 is the worked example. It made `committed` a fact about the ledger and
every one of the four tests enforcing it drove `POST /write`. `POST
/write-ordered` - the route every decision and every intent record takes -
still answered `committed: false` from a generic handler that asked the
ledger nothing, and survived a full phase and a red-team brief that named the
route by name. The fix was correct; what was missing was anything that fails
when a site is missed.

This project built the control once and scoped it to constants
(`tests/test_ledger_vocabulary.py`, ADR-0013). D43 generalises it: **any
property this system claims is asserted against a site list the test derives
from the code, so a new site fails the suite until a decision is recorded
about it.**

**The site list is derived, and the discriminator is named.**
`tests/test_route_parity.py` reads `app.routes`, which carries POST `/write`,
`/write-ordered` and `/verify`, and selects the write routes by their
dependency: a write route is one gated by `_require_write_key`, and `/verify`
takes `_require_read_key`. Hand-listing which POST routes are writes would
sweep `/verify` in or out by judgement, which is this decision failing on its
own terms at the first step. `tests/test_bounded_reads.py` derives its sites
the same way: every call to `/api/v2/db/scan` or `/db/zscan` whose request
body carries a selective bound (`prefix`, `seekKey`, `endKey`, `minScore`,
`maxScore`), attributed to its innermost enclosing function.

**Three states per cell, not two: holds, does not apply, or missing.** A
property that does not apply to a site is recorded as such *with its reason,
in the test*, so a new site forces a decision rather than defaulting silently
to either state. That distinction is load-bearing rather than tidy.
`KeyMustNotExist` does not belong on `POST /write`: D39's reason for it is
that a second write gives the key a second entry in the view index at a
second position, and the plain route allocates no position. Applying it there
would refuse a second erasure attempt after a partial failure, on the GDPR
path, which is the harm D45 exists to close.

**Where an enumeration cannot be derived, it is hand-listed and the test says
so.** Two are: the encodings a private key can be written in, and the
surfaces a Docker image can be read on. Both are facts about the world rather
than about this repository, so nothing in the tree can produce them. What is
checked instead is that the detector honours the list it is given - real key
material is generated in-process in each enumerated encoding and each one has
to be found - and that the module docstring still says the lists are hand
listed.

**What this does not reach.** An enumeration is only as good as its
discriminator. `tests/test_bounded_reads.py` reads call sites, so a bounded
read issued through a helper that takes its bound as an argument is invisible
to it; one probe script has that shape and it is stated in the module. And no
enumeration here can see a property nobody stated.

## D44. A test's assertions are scoped to the records that test wrote

Added in Phase 3c-3e.

A test proving the reconciler finds a fractional position has to create one.
A test proving the seam is monotone has to assert none exists. Both are
correct; the defect is the second stating its precondition as a ledger-wide
fact when it is not one.

Measured before it was fixed (`docs/reports/phase-3c3d-order-sweep.md`): five
full-suite runs in five collection orders found **four order-dependent tests
out of 442**, all of them in one cluster - two polluters, three polluting
actions, and every one about the view index and a global assertion over it.
The suite's green was fragile rather than false: in all four non-alphabetical
orders, the set of tests passing there and failing alphabetically was empty.
The same sweep established what this decision does *not* need to cover:
hidden dependence came back zero across 11 modules and 118 tests run alone, so
tests already build their own preconditions. Scoping assertions is the whole
of it.

**Scoping alone would lose something, so it is not done alone.** Three of the
four assertions were true statements about the whole view. They move to
`tests/test_view_invariants.py`, addressed to every row the suite did not
deliberately break, with the deliberate ones named and argued for in
`tests/ledger_pollution.py`. The registry is checked in both directions: an
entry naming a key fragment no test produces fails, and a violating row no
entry explains fails. A hand-listed registry is acceptable here for the
reason D43 gives about the encodings - what has to be enumerated is a set of
intentions, and an intention is not in the code.

Two assertions were not scoped but rewritten, because a stronger form exists
that holds at every ledger size. `has_more` no longer asserts "false when the
ledger is small"; it asserts that it agrees with whether truncation actually
happened, in both directions. And the backfilled record's appearance on the
page is asserted as "on the page, or the page is full of rows that sort above
it", which is a complete statement rather than a conditional one.

## D45. `committed: false` is a claim, and this service only makes it after reading the ledger

Added in Phase 3c-3e, closing red-team A4 in both its forms.

D40 made `committed` a fact about the ledger, and then collapsed two different
facts onto one answer: `_committed_tx_for_value` returned `None` both when the
ledger holds nothing under the key and when this process could not ask. So the
one branch that exists to stop a guess made one whenever the confirming read
was itself unavailable.

**A4.1: the ordered route never got D40 at all.** Its generic handler answered
`committed: false` with no ledger read. Driven with a relay that let the
ExecAll commit and dropped its own response: the record at transaction 55, the
counter advanced, the index entry at position 1000000017, the row on `/audit`
reading `policy_allow`, and the response saying the write did not happen.
`log_tool_call` raises on anything but `verified: true`, so the decision
service denied a call whose allow decision is on the audit page. The retry is
then 409 forever under D39.

**A4.2: on the plain route, the confirming read can be cut too.** A relay that
dropped the response and then refused every connection for 25 seconds left the
record at transaction 118 with `committed: false`; on the erasure path the
same cut reproduced Phase 3c-3c's `erasure_conflict` verbatim - DELETE 503,
tombstone committed at 121, 772 bytes of payload still in `call_content`, and
content writes for that call_id frozen at 409.

Three changes, and they are one decision:

- **The ordered route distinguishes "the ExecAll reached the wire" from "it
  did not".** `OrderedCommitUncertain` carries the attempted position and the
  real attempt count out of `_ordered_commit`; the route then asks the ledger
  with the value as well as the key, exactly as `POST /write` does, and
  confirms the position against the view index rather than reporting what it
  intended to write. Everything raised before the ExecAll is still
  `committed: false`, and that branch is now the only one that may say so
  without reading anything. The comment claiming everything before the commit
  could fail with nothing written was false, and it is corrected.
- **A fourth response state.** `committed` is `bool | None`, and null means
  the outcome is not established. It is refused exactly as false is, because
  every caller keys on `verified`; what changes is that the service no longer
  states a fact it does not have.
- **The control plane asks the ledger itself when told null.** It has its own
  path to ImmuDB, which the verifier's relay does not sit on. Without a
  transaction to confirm against it asks the narrower question - is there a
  `content_erasure` record for this call_id at all - through an explicit
  `require_transaction=False`, because the exact-transaction rule P3c3d-7
  added is a correctness rule on the GDPR path and a silent exemption from it
  is how such rules stop applying. Both answers are safe: a tombstone found
  means the ledger already says this call_id is erased and completing the
  erasure removes the divergence; none found means nothing says erased, no
  write is frozen, and the refusal leaves the row intact.

**And the retry that D39 and D40 produced between them.** Neither decision
creates it alone: a caller wrongly told `committed: false` about a write that
committed can either retry, which `KeyMustNotExist` refuses forever, or
disbelieve the response. D45 removes the cause. What is left is asserted from
both ends - a caller who retries anyway gets a 409 that names the key and says
a record is already committed under it, and a caller whose write genuinely did
not land can retry and succeed.

## D34. The serialisation ceiling is accepted, documented, and measured

The CAS globally serialises the ledger write path: every write contends on
one counter key.

**Concurrency stops buying anything, and this deployment reproduces that.**
Measured here: one writer sustained about 8.7 writes per second; eight
concurrent writers sustained 5.9 to 8.0, with 142 of 206 attempts rejected
and retried. Adding writers moved no more traffic and made tail latency
much worse (median 325 to 657 ms against 115 ms for one writer). This is a
property of the design, not a defect in it: the ordering is what is being
bought, and a total order over commits is inherently serialised.

**Caching the counter is worth paying for.** A writer that caches
`(seq, tx)` from its own last successful commit measured indistinguishable
from the pre-ordering write path; reading the counter from the ledger on
every write cost noticeably more. `AIL_SEQUENCE_CACHE=0` turns the cache off,
so both figures are reproducible rather than asserted. Correctness does not
depend on the cache either way - the CAS rejects a stale read whichever
place it came from.

**One decision writer exists today.** `docker-compose.yml`'s
`decision-service` has no `replicas` or `deploy` stanza, and the Helm chart
deploys no decision service at all. The ceiling is therefore not currently
reached; it is documented because it is what would be hit first if it were.

**The retry budget is an availability parameter, not a correctness one.**
`AIL_SEQUENCE_MAX_ATTEMPTS` defaults to 300. An exhausted budget is a failed
ledger write, which the existing rule turns into a denied call - so lowering
it can deny traffic and raising it trades latency for availability. Zero
writers gave up at 8 concurrent in either this phase's measurements or
`p3c3-scoring`'s.

## Consequences

- A record with no index entry is absent from every ordered page, not merely
  unordered. That is why `tools/ail_backfill_index.py` ships in the same
  phase as the index rather than after it: on an append-only ledger the set
  of unreadable records would only grow.
- Gaplessness makes reconciliation arithmetic over the index alone rather
  than a full key scan, because a rejected precondition consumes no position.
  A hole is therefore evidence that a committed record is missing from its
  view, not an unremarkable crash artifact. `anchor_service` runs the check:
  it is already a periodic loop that observes and reports and never gates a
  write, which is exactly what a detector should be.
- `has_more` now means more *recent* records exist behind the page, which is
  a stronger claim than the one Phase 3c-3a shipped. README's Residual Limits
  states the new meaning rather than leaving both alive.
- `POST /write` is still live: `control_plane/main.py::_write_tombstone` uses
  it. A tombstone is not a decision and is never a row on the ordered page -
  it is joined by keyed lookup - so it takes no position. If it took one, that
  position would sit in no view index and reconciliation would report it as a
  hole on every pass. **Since Phase 3c-3c the route refuses a decision, an
  intent or a fault record itself** (P3c3c-2): the split used to rest on
  convention plus a static parse of two files, and the parse was defeated by
  holding the route in a variable. The parse survives as a second line, over
  every production module rather than two. A `record_type` that is not a
  string is refused with a 400 rather than raising `TypeError` and answering
  500, which is what a route whose job is to refuse deliberately owes a
  caller (P3c3d-9).
- An erasure completes against a committed-unverified tombstone (P3c3c-12),
  after the tombstone is confirmed present by an exact read. Refusing it
  instead left the ledger saying erased while the content it names was still
  in the store, which is `_payload_state`'s `erasure_conflict` - P13-4's own
  finding, manufactured by the refusal. What has not changed is the invariant:
  no row is ever deleted without a tombstone behind it.
- **A position is a float64 score, and both ends of that are bounded now.**
  `validate_reserve` used to bound the reserve below only, so a reserve at or
  above 2^53 made allocated positions unrepresentable as distinct scores:
  measured, six writes produced four scores, the response named a position the
  index does not hold, and `/audit` was dead at every limit from the sixth
  write on a virgin ledger, with all four readers agreeing about a number that
  cannot work. The reserve is refused at or above 2^53, and the allocator
  refuses to hand out a position at or above it. With the reserve at 1e9 and
  one write per second that ceiling is about 285 million years away.
- **A key at more than one position is a finding, in either range.**
  Reconciliation assumed every score below the reserve was history and never
  checked it against anything, so an already-indexed record given a second
  position at score 42 reconciled `clean` with every category empty while the
  page showed the row twice. History is scored one position per record, the
  CAS allocates one per commit, and since D39 a record key is written once, so
  there is no legitimate second `zAdd` for a key. Two records sharing a score
  is a different thing and stays `shared`.
- A bundle does not name a record's ledger fault. `GET /audit/bundle` takes a
  key and passes no revision, and the bundle has no section for one; adding
  one is a format change (`ail-evidence-bundle/3`), which is a D18-D20
  decision this phase deliberately did not make. README's Residual Limits
  states it. **D38 widens the gap slightly and it is stated rather than left
  to be found**: a record can now carry more than one fault, so a bundle that
  named only one would be incomplete as well as absent.
- **`/write-ordered` still accepts a key of any shape into a view.** D39
  refuses a `ledger_fault` on both routes, and the injected row the keyprobe
  found was one; a caller holding the write key can still write some other key
  shape into the decision view and it becomes a page row with `outcome_type:
  null`. Refusing that means requiring the key prefix to match the requested
  view, which would also refuse the writes
  `tests/test_reconciliation.py` uses to prove the reconciler finds a record
  indexed into the wrong view - the D37 check would lose its enforcing test.
  Raised rather than taken.

## References

- `docs/reports/phase-3c3b.md` - the measurements, the mutation transcripts,
  and the before/after demonstration
- `docs/reports/phase-3c3b-redteam.md` - the ten claims, eight refuted
- `docs/reports/phase-3c3c.md` - D35, D36 and D37, and the reproduction of
  every refutation they close
- `docs/reports/phase-3c3c-probe.md` - the ImmuDB read-API facts these rest on
- `docs/reports/phase-3c3c-redteam.md` - the ten claims, nine refuted
- `docs/reports/phase-3c3d-keyprobe.md` - what a composite fault key does and
  does not close, and every measurement D38 and D42 rest on
- `docs/reports/phase-3c3d.md` - D38 through D42, and the reproduction of
  every refutation they close
- `docs/reports/phase-3c3d-redteam.md` - the ten claims, six refuted
- `docs/reports/phase-3c3d-order-sweep.md` - the five collection orders, the
  four order-dependent tests, and the isolation run D44 rests on
- `docs/reports/phase-3c3e.md` - D43, D44 and D45, the enumerations' failing
  output before each fix, and every mutation
- `docs/reports/phase-3c2.md` - where the defect was first observed
- `tools/ail_backfill_index.py`, `tools/ail_ordering_cost_probe.py`
- `tests/test_audit_ordering.py`
