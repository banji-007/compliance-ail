# The fault key probe: what a composite key does and does not close

**Run id:** `p3c3d-keyprobe`. **Driven live** against `immudb 1.9.5` on a
`docker-compose.test.yml` stack, Compose project `p3c3d-keyprobe`, scratch
clone of `p3c3b-order` at `9af28e1`, 2026-08-31. Brief:
`docs/reports/phase-3c3d-keyprobe-brief.md`.

## Why this record exists

The brief asked for the answers inline and no file. That was a mistake, and
it is the same mistake `docs/reports/phase-3c3c-probe.md` was written to stop:
`p3c3-question`, `p3c3-probe` and `p3c3-scoring` all lived in conversations
and cost three phases the same re-derivation. Phase 3c-3d's instruction then
cited "the keyprobe report" as required reading for a session that would have
had no such document. This is that document, written from the run's own
output.

Everything below is this run's output. Nothing is quoted from memory.

Method note: the probe seeded its own key spaces under uuid-suffixed prefixes
rather than writing under `ledger_fault:` itself, so no figure here depends on
the base ledger's contents. Where a real route was driven (`/write-ordered`,
`GET /audit`) it is named.

---

## 1. `scan`'s range parameters are all routed and honoured

Ten keys `…:00` to `…:09`, one `POST /api/v2/db/scan` per line.

```
prefix only                                    -> 00 01 02 03 04 05 06 07 08 09
prefix + seekKey=05                            -> 06 07 08 09
prefix + seekKey=05, inclusiveSeek=True        -> 05 06 07 08 09
prefix + seekKey=05, inclusiveSeek=False       -> 06 07 08 09
seekKey only, no prefix, =05, limit 4          -> 06 07 08 09
prefix + endKey=07                             -> 00 01 02 03 04 05 06
prefix + endKey=07, inclusiveEnd=True          -> 00 01 02 03 04 05 06 07
prefix + endKey=07, inclusiveEnd=False         -> 00 01 02 03 04 05 06
seekKey=02 endKey=06, both inclusive           -> 02 03 04 05 06
seekKey=02 endKey=06, both exclusive           -> 03 04 05
prefix, desc=True                              -> 09 08 07 06 05 04 03 02 01 00
prefix, desc=True, seekKey=05                  -> 04 03 02 01 00
prefix, desc=True, seekKey=05, endKey=02, incl -> 05 04 03 02
```

`seekKey`, `endKey`, `inclusiveSeek` and `inclusiveEnd` are all **routed**.
Both bounds default to exclusive, both work with or without `prefix`, and
both reverse meaning under `desc`. An impossible ascending range
(`seek=07 end=02`) returns an empty result rather than ignoring the bound, so
the bounds are genuinely applied.

`TxScan` remains unrouted (Phase 3c-3b). The precedent that this REST route
exposes less than the SDK holds; it does not extend to `scan`'s bounds.

## 2. A dropped bound is silent, and is the reason for D42

```
endKey outside the prefix entirely (zzz)       -> all ten
unknown parameter noSuchParam=True             -> all ten
endKey misspelled as endkey (lowercase k)      -> all ten
```

An unrecognised field is dropped without comment. A bounded read whose bound
is misspelled becomes an **unbounded read at HTTP 200**, and nothing in the
response distinguishes the two. `endkey` for `endKey` is the whole distance
between a correct read and a wrong one.

This is why D42 asserts on the returned key range rather than on the request
that was sent. The assertion that bites is that every returned key falls
inside the requested bound, because a dropped bound only reveals itself when
something out-of-window comes back.

## 3. The 2500 ceiling applies to a range result, and truncates silently

3000 keys inside one `seekKey`..`endKey` window.

```
range limit=None   n=2500  first=00000 last=02499
range limit=1      n=1
range limit=1000   n=1000
range limit=2500   n=2500  first=00000 last=02499
range limit=2501   HTTP 500 "result size limit exceeded: the specified limit
                            (2501) is larger than the maximum allowed one (2500)"
range limit=5000   HTTP 500 (same)
range limit=0      n=2500  first=00000 last=02499
```

Identical numbers on the prefix form, so the ceiling belongs to `scan`, not to
the bound type. Omitting `limit` and passing `limit=0` both cap at 2500 with a
200 and no truncation flag; over-asking is a 500 rather than a clamp.

A cursor is available: the `seekKey` analogue of the reconciler's `minScore`
paging (`anchor_service/main.py:428`), with `endKey` held fixed.

```
pages=2 total=3000 distinct=3000 expected=3000 wall=1.39s
first=00000 last=02999 gap-free=True
```

So the page-side read is **one paginated read per page**, terminating on
`len(entries) < limit`. Stated rather than discovered, because the single-shot
form returns a plausible 2500-row answer and says nothing.

## 4. Zero-pad width: 20, and both failure modes past it

Probe width `W=6`, deliberately small so it could be exceeded. Transactions
1, 999, 999998, 999999, 1000000, 1000001, 1234567. The order the ledger
actually stored them in:

```
000001  000999  1000000  1000001  1234567  999998  999999
```

Ranges derived from a transaction window, all four wrong, all HTTP 200:

```
window entirely under the pad   want 1,999,999998,999999
                                got  1,999,999998,1000000,1000001,1234567
window spanning the boundary    want 999998,999999,1000000,1000001   got (empty)
window entirely past the pad    want 1000000,1000001,1234567         got 1000000,1000001
window past the pad, wide       want 999999,1000000,1000001,1234567  got (empty)
```

Two distinct silent failures: over-width keys are **pulled into** a window
that should exclude them, and a window whose own bound is over-width returns
**empty**.

At `W=20` every window is exact. uint64 max is 18446744073709551615, twenty
digits, so overflow is unreachable. A 20-padded composite key is accepted and
sorts correctly; the longest key written was 66 bytes.

```
window spanning the old boundary  want 999998,999999,1000000,1000001  got same
uint64 max window (0..2^64-1)     want all seven                      got all seven
wrote len=66 key=…:18446744073709551615:9865a77… ; desc-first = that key
```

The ledger is append-only, so a narrower pad is a bet that cannot be un-made.

## 5. The end-bound trap, and why the read is half-open

A composite key is **longer** than its transaction component, so an `endKey`
set to the bare padded `hi` with `inclusiveEnd=True` excludes that
transaction's own faults: `…00999999` sorts before `…00999999:{call_id}`. It
surfaces only when `hi` is exactly a transaction that has a fault, which is to
say **the last row of the page**.

```
single-tx window (lo == hi == 999999)
  WRONG bare, inclusiveEnd=True   end='…00000000000000999999'  want 999999  got (empty)
  OK    half-open hi+1            end='…00000000000001000000' inclusiveEnd=False
                                                              want 999999  got 999999
```

A raw `0xFF` sentinel suffix also works and is a second thing to get right.
The read is therefore half-open: `seekKey = {lo:020d}`, `inclusiveSeek=True`,
`endKey = {hi+1:020d}`, `inclusiveEnd=False`.

## 6. Both orderings, both consumers

Measured at the REST layer, seeded fault keys, 7 repetitions, median with
min/max, two ledger sizes.

The noise floor first, because this host is bad: **one trivial `getall` round
trip is median 52.0 ms, range 8.8 to 63.5 ms.** Anything with a median under
roughly 200 ms is inside host noise. Round-trip counts are the only figure
worth trusting here, and every wall-clock figure below is labelled.

```
NOISE FLOOR: one trivial getall round trip  median=52.0ms  range 8.8-63.5ms

===== 1000 fault keys per ordering =====
page rows=100 (every row has a fault), tx window 397 wide
  page   {tx}:{cid}  exact getall of page rows       rt=  1  median=   68.8ms  inside noise
  page   {tx}:{cid}  range scan over tx window       rt=  1  median=   62.6ms  inside noise
  page   {cid}:{tx}  one prefix scan per row         rt=100  median= 5514.3ms
  page   {cid}:{tx}  one full prefix walk            rt=  1  median=  336.1ms
  record {tx}:{cid}  exact getall (tx known)         rt=  1  median=   58.9ms  inside noise
  record {tx}:{cid}  full prefix walk (tx NOT known) rt=  1  median=  444.5ms
  record {cid}:{tx}  one prefix scan                 rt=  1  median=   54.5ms  inside noise

===== 25000 fault keys per ordering =====
  page   {tx}:{cid}  exact getall of page rows       rt=  1  median=   68.5ms  inside noise
  page   {tx}:{cid}  range scan over tx window       rt=  1  median=   70.5ms  inside noise
  page   {cid}:{tx}  one prefix scan per row         rt=100  median= 5576.9ms
  page   {cid}:{tx}  one full prefix walk            rt= 11  median=10190.6ms
  record {tx}:{cid}  exact getall (tx known)         rt=  1  median=   51.5ms  inside noise
  record {tx}:{cid}  full prefix walk (tx NOT known) rt= 11  median=10211.9ms
  record {cid}:{tx}  one prefix scan                 rt=  1  median=   52.8ms  inside noise
```

| | page consumer | per-record consumer |
|---|---|---|
| `{tx}:{call_id}` | 1 RT, flat across a 25x ledger | 1 RT, flat |
| `{call_id}:{tx}` | 100 RT / 5.5 s, or a full walk: 1 to 11 RT and 336 ms to 10.2 s | 1 RT, flat |

**The per-record direction is not a discriminator, which reverses the brief's
premise.** `GET /audit/bundle` and `GET /audit/verify` take only the base64
raw key (`control_plane/main.py:2060`, `:1805`), but both already read the
record's value and its transaction as work they do anyway, so `call_id` and
the transaction are both in hand at no extra cost. A transaction-leading key
does not disadvantage the exporter.

The page direction carries the whole cost, and `{call_id}:{tx}` has no
acceptable form of it. The 100-RT variant is 5.5 s per page. The full-walk
variant is the failure the brief forbids: unbounded, growing 30x over a 25x
ledger, with no page-derived bound available to it.

The 25000-row full-walk figures are outside noise and reproducible. The
336 ms figure at 1000 rows is marginal; its round-trip count is not.

## 7. A record with no `call_id` does reach a page

Written through `/write-ordered`, view `decision`, with no `call_id` key at
all, then read back through `GET /audit`.

```
POST /write-ordered -> 200 {"tx_id":12,"seq":1000000001,"verified":true,"committed":true}

GET /audit -> 200   entries=2 total=2 has_more=False
{
  "call_id": null,
  "tx_id": 12,
  "ledger_key_decoded": "tool_call:agent-79f26dd3:9b39a424…:probe_tool",
  "sha256(ledger_key_raw)[:32]": "8ad1d6a1fe65e8d84621bf0a079e7f72",
  "ledger_fault": null
}
```

`verifier/main.py:597` justifies the digest fallback with "a record with no
`call_id` never reaches a page". **That is false.** The record reaches a page,
and the row's `ledger_key` is the base64 raw key, so
`sha256(record_key)[:32]` is derivable from a page row today with no format
change.

Underneath it is a live gap that predates D38 and that no key shape fixes.
`_tombstones_and_faults` is only ever handed `page_call_ids`, built at
`control_plane/main.py:1571-1577` under `if log_entry.get("call_id")`, and its
decode loop drops rows at `:1221`. **A fault for a no-`call_id` record is
never joined onto a page under any key shape, including today's.** A
transaction-window read closes it for free, because it selects on the window
rather than on an identity the row may not have.

## 8. D38 as originally written was a rename

The transaction available at key-construction time is `committed_tx_id`, the
qualified record's own transaction, because the fault's own transaction is not
known until after it commits. `committed_tx_id` is fixed per record.

```
key   = ledger_fault:00000000000000004242:63e0727c792a4c9d98117fe85c41f3b3
head  = FORGED   revision=2
range read over the record's transaction returns 1 key
```

Two faults about one record produce the same key, and the second is a new
version of the first, exactly as before. Because the key is then fully
derivable from a page row, the page-side read stays the exact `getall` it
already is. **The key string changes, no read changes, no attack closes.**

This is the D35 failure repeating one level along: an answer that satisfied
the question asked while the question that mattered went unasked.

## 9. What the transaction does earn, separately

The transaction is not decorative. `tool_call_intent:` and `tool_call:` for
one call carry the same `call_id` and both take the ordered route; the erasure
tombstone takes `POST /write` with that same `call_id`
(`verifier/main.py:734`). All three can fault. Under `ledger_fault:{call_id}`
an intent fault, a decision fault and a tombstone fault for one call collide
and silently replace each other, **non-adversarially, with no second writer
involved**.

The transaction separates faults about different records. The nonce separates
faults about the same record. Neither substitutes for the other. A scheme
keyed on `{call_id}:{nonce}` would re-merge the three record kinds and would
also drop the bounded page read.

Position cannot take the transaction's place: `POST /write`'s fault path
passes `seq=None` (`verifier/main.py:790-793`), because the plain route
allocates no position, and the tombstone writer is still a live caller of it.
The transaction is the only component present on both fault-producing paths.

## 10. The recommended shape, validated

```
ledger_fault:{committed_tx_id:020d}:{call_id or "key:" + sha256(record_key)[:32]}:{nonce}
```

`nonce` is `uuid4().hex[:16]`, generated in `_write_fault_record`.

Validated end to end: 100 page rows, one of them carrying three faults,
against 20000 unrelated faults elsewhere in transaction space.

```
PAGE   one bounded range read over the page's tx window
       rt=1 median=64.7ms (min 34.2/max 121.7) faults returned=102   match=True
RECORD one prefix scan ledger_fault:{tx}:{call_id}:
       rt=1 median=56.3ms faults returned=3   match=True
         …9d16d51:933ea5a85a014271
         …9d16d51:e0049ce09e3448bb
         …9d16d51:fddb91c4a4cb4138
       all three survive, none shadowed

the same three faults under today's single-key shape
       getall head detail=FORGED revision=3  ->  1 row, 2 hidden
```

Both wall-clock figures are inside this host's noise. The round-trip counts
are the claim.

**Ordering between two faults about one record** comes from the `scan` entry's
own `tx`, returned by the read that already ran. No timestamp component is
needed and none should be added.

## 11. Reading both shapes costs no round trip in the legacy half

Every `ledger_fault:{call_id}` already committed keeps that shape
permanently, so the page reads both.

```
today: tombstone + old fault    (2 keys/row, 200)  rt=1 median= 68.6ms entries=70
D38 only: tombstone + new fault (2 keys/row, 200)  rt=1 median= 66.9ms entries=70
BOTH: tombstone + old + new     (3 keys/row, 300)  rt=1 median= 74.3ms entries=120
3000-key getall                                    rt=1 median=162.1ms
```

**Read this table carefully; two of its rows describe a design that was
abandoned.** The `NEW` keys here are exact `getall` keys, which assumed the
new-shape key was derivable from a page row. Under the nonce it is not. The
`BOTH` row and its +5.7 ms therefore describe the exact-derivable variant, not
what is being built.

What the shipped shape costs: the existing `getall` keeps **exactly today's
keys, unchanged, no extra keys**, still fused with the tombstone join, and the
range read is added beside it. **Two round trips per page against one today.**
The `getall` headroom figure stands on its own and is generous: 3000 keys in a
single request at 162 ms.

No `readME.md` limit is needed for this.

## 12. Found, not asked, and worth more than some of the answers

**`/write-ordered` refuses nothing.** `_refuse_reason_for_plain_write` is
wired into `POST /write` (`verifier/main.py:724`) and is not called by
`write_ordered` (`:1146`).

```
POST /write         key='ledger_fault:cid-27bc4ac7' -> 400 "key prefix
                    'ledger_fault:' does not belong on the plain write route…"
POST /write-ordered key='ledger_fault:cid-27bc4ac7' -> 200 {"tx_id":16,
                    "seq":1000000004,"verified":true,"committed":true}

page BEFORE: ledger_fault.fault_class = write_verification_failed  (detail "GENUINE FAULT")
page AFTER : ledger_fault.fault_class = "none"                     (detail "FORGED - nothing wrong here")
getall head: revision=2, tx=16, detail="FORGED - nothing wrong here"
```

A caller holding only `VERIFIER_WRITE_KEY` authors the ledger's own account of
another record's standing.

**The same write became a page row.** The ordered route allocated the forged
fault a position in the `decision` view.

```
entries 4 total 3
 tx 16 key ledger_fault:cid-27bc4ac7  | call_id cid-27bc4ac7 | outcome None | fault {...}
 tx 14 key tool_call:agent-27bc4ac7:… | call_id cid-27bc4ac7 | outcome policy_deny | fault {...}
 tx 13 key tool_call:agent-79f26dd3:… | call_id cid-79f26dd3 | outcome policy_deny | fault null
 tx 12 key tool_call:agent-79f26dd3:… | call_id None         | outcome policy_deny | fault null
```

`entries` (4) exceeds `total` (3), which counts `tool_call:` keys. Arbitrary
rows with `outcome_type: null` are injectable into the audit page.

`_REFUSED_KEY_PREFIXES` matches on `b"ledger_fault:"`, which is still a prefix
of the composite shape, so the refusal covers both key shapes unchanged. D39
and D38 are independent.

**`ledger_fault.count` becomes permanently 1.**
`control_plane/main.py` sets `"count": int(raw.get("revision", 1) or 1)`. That
was correct only because the single key was rewritten. Under D38 each fault is
its own key written once, so `revision` is always 1 and the field reports one
fault where three exist. Checked: `ledger_fault` appears nowhere in
`dashboard/`, and no test asserts `count`, so there is no consumer to break;
it is a rendered falsehood with a cheap fix, in the field that describes the
very thing D38 exists to make visible.

---

## Reproducing this

The probe scripts were written to a scratch directory and removed with it, so
this record is the artifact rather than a committed tool. Every figure above
is a `POST /api/v2/db/scan`, `POST /api/v2/db/getall`, `POST /api/v2/db/set`,
`POST /write-ordered` or `GET /audit` against a `docker-compose.test.yml`
stack, and sections 1 through 6 need nothing from this project beyond a
running `immudb 1.9.5`.

Where a future phase needs these facts re-derived rather than cited, the
models are `tools/immudb_read_api_probe.py` and
`tools/immudb_ordering_probe.py`.
