# The ImmuDB wire facts the ordered audit view rests on

**Run id:** `p3c3c-fix`. **Re-derived live** against `immudb 1.9.5` on a
`docker-compose.test.yml` stack, Compose project `p3c3cfix`, 2026-08-31.
**Tool:** `tools/immudb_ordering_probe.py`, committed with this record.

## Why this record exists (P3c3c-9)

Phase 3c-3b's instruction attributed these facts to three run ids,
`p3c3-question`, `p3c3-probe` and `p3c3-scoring`, and asked that they be
cited rather than re-derived. **No artifact for any of the three exists in
this repository.** Phase 3c-3a said so, Phase 3c-3b said so again and
re-derived every fact by hand into its own report (`docs/reports/phase-3c3b.md`
section 2), and Phase 3c-3c has now re-derived them a third time. That is
three phases spending the same effort on the same questions because the
answers lived in a conversation.

This is the artifact. It is written from two places and cites them as its
provenance rather than implying anyone recalls the original sessions:

- `docs/reports/phase-3c3b.md` section 2, which carries the transcript of
  the second re-derivation and names the four findings that changed D32's
  design;
- `tools/immudb_read_api_probe.py`, Phase 3c-3a's committed probe for the
  read-path facts (`count`, `countall`, `getall`, the `scan` ceiling), and
  the model this one follows.

Everything below is **this run's own output**, not a quotation. The
transcript is reproducible with `python tools/immudb_ordering_probe.py`.

---

## 1. What `zscan` returns, by score sign

```
  desc=True  -> [(2, 'two'), (1, 'one'), (0.25, 'quarter'), ('<NO SCORE FIELD>', 'zero')]
  desc=False -> [('<NO SCORE FIELD>', 'zero'), (0.25, 'quarter'), (1, 'one'), (2, 'two'), (-1, 'neg1'), (-3, 'neg3')]
  desc=True minScore=-10 -> ['two', 'one', 'quarter', 'zero']
```

Two facts, both load-bearing:

**Under `desc: true`, negatively-scored members are omitted, and `minScore`
does not bring them back.** A record scored below zero is indexed, exists,
and is absent from every page - which is the exact defect the index exists to
remove, reintroduced by the migration meant to fix it. Phase 3c-3b's first
backfill implementation placed history in `(0, 1)` and was caught by a test
rather than by review; the shipped one scores history at each record's own
transaction id, and transaction ids start at 1.

**A score of exactly zero arrives with no `score` field at all**, because
protobuf's JSON mapping omits zero-valued fields. Every reader of a zscan row
in this project therefore uses `.get("score", 0.0)`. One did not:
`anchor_service/main.py`'s paging cursor read `rows[-1]["score"]` two lines
after a correct `.get`, which raised `KeyError` out of the whole
reconciliation pass (red-team C6, third way). D37 makes a zero-scored row a
reported finding rather than either an exception or a silent zero, because no
write path this project has produces one.

**Consequence for the reserve.** A reserve at or below zero would put every
allocated position at or below zero, where both facts above apply at once.
That is why D36 validates `AIL_RESERVED_POSITIONS` as a positive integer in
all four modules that read it.

## 2. Limit ceilings

```
  zscan limit=2500  -> HTTP 200
  zscan limit=2501  -> HTTP 500
  scan  limit=2500  -> HTTP 200
  scan  limit=2501  -> HTTP 500
```

`zscan` carries the same 2500 ceiling `scan` does. This is why `GET /audit`
shrinks the page with the scan at that boundary rather than clamping the scan
alone (P3c3a-2), and why anything walking a whole view has to page. The
backfill's index snapshot did not, which produced records at two positions in
a single pass (red-team C2, closed by P3c3c-5).

## 3. Which routes exist

```
  POST /api/v2/db/zscan             -> HTTP 200
  POST /api/v2/db/zadd              -> HTTP 200
  POST /api/v2/db/execall           -> HTTP 200
  POST /api/v2/db/set               -> HTTP 200
  POST /api/v2/db/getall            -> HTTP 200
  POST /api/v2/db/history           -> HTTP 200
  POST /api/v2/db/verifiable/get    -> HTTP 200
  POST /api/v2/db/txscan            -> HTTP 404
  POST /api/v2/db/setall            -> HTTP 404
  POST /api/v2/db/get               -> HTTP 404  (GET db/get/{key} does exist)
```

`TxScan` is not routed, which is why no parameter produces a time-ordered
page and the ordering has to come from a score the ledger itself allocates.

`POST /api/v2/db/get` not existing is the one that bites silently: it answers
404 for every key, which reads exactly like "this key was never written". It
reached two files of Phase 3c-3b before a probe caught it, and it is why
`current_sequence`, `_bound_reserve` and every other exact lookup in this
project use `getall`.

## 4. `ExecAll` with a precondition

```
  KeyMustNotExist, first time  -> HTTP 200 tx 16
  KeyMustNotExist, second time -> HTTP 400 precondition failed: KeyMustNotExist
  KeyNotModifiedAfterTX, stale -> HTTP 400 precondition failed: KeyNotModifiedAfterTxID
```

Both preconditions D32 and D36 rest on are enforced by the server, and a
rejection writes nothing at all: the operations in a rejected `ExecAll` land
together or not at all, which is what makes an allocated position gapless and
a hole evidence.

One caveat this probe cannot show, because it speaks REST while the write
path speaks gRPC: `immudb-py` 1.5.0's own `execAll()` wrapper builds
`ExecAllRequest(Operations=..., noWait=...)` with **no preconditions
parameter**, so the mechanism is unreachable through the SDK's own method.
`verifier/main.py` calls the generated stub with the SDK's protobuf types
instead. Recorded in `docs/reports/phase-3c3b.md` section 2 (b) and unchanged
by this phase.

## 5. Prior versions of one key, five ways

Three writes to one key, then read back:

```
  getall head        -> revision 3 tx 20 value {"version": 3}
  get atRevision=-1  -> HTTP 200 revision 2 value {"version": 2}
  get atRevision=1   -> HTTP 200 revision 1 value {"version": 1}
  get atTx           -> HTTP 200 revision None value {"version": 3}
  history            -> HTTP 200 [('3', ...), ('2', ...), ('1', ...)]
  verifiable/get atRevision=1 -> HTTP 200 keys ['entry', 'inclusionProof', 'verifiableTx']
```

Five ways, one of them with an inclusion proof. Two consequences that decide
a design rather than describing an API:

**`getall` already returns `revision` on the head entry, and head revision is
the number of writes.** So a count of how many times a key has been written
costs nothing on a join that was already doing an exact `getall`. That is why
the `/audit` row's `ledger_fault.count` is free.

**A prior version is provable, not merely readable.** `verifiable/get`
accepts `keyRequest.atRevision`. This project's bundle exporter does not pass
one through (P3c3c-11), so the capability exists at the ledger and is not
reachable through `GET /audit/bundle`; that gap is stated in README's
Residual Limits rather than closed here, because closing it changes the
bundle format.

Note the one asymmetry: `atTx` returns the entry without a `revision` field,
so `atRevision` and `history` are the two routes that answer "which version
is this".

## 6. Versions do not inflate a prefix scan

```
  scan over the 3-version key -> 1 row(s), revision 3
```

One row per distinct key, at its latest version. This is what makes
`ledger_fault:{call_id}` safe as an exact key that accumulates versions: a
second fault for one call_id is a new version rather than a replacement, no
earlier fault is lost, and nothing that walks a prefix gets more expensive.
The alternative, a composite key like `{prefix}:{call_id}:{tx_id}`, would
avoid a read-modify-write that an unconditional `set` does not need anyway,
and would convert an exact-key join into a prefix scan needing its own
explicit bound - giving back what Phase 3c-3a bought by making the tombstone
join exact.

---

## What this record does not cover

The write-path throughput figures D34 states (one writer about 8.7 writes per
second; eight concurrent writers 5.9 to 8.0 with about 70 percent of attempts
rejected and retried) are measurements of this deployment, not wire facts,
and they have their own committed tool: `tools/ail_ordering_cost_probe.py`,
with the figures in `docs/reports/phase-3c3b.md` section 7. They are not
re-derived here.
