# Spike: Consistency Proof Between Two Arbitrary Transactions

Run id: p3b1-gate

**Verdict: GO.** The SDK's own verification is drivable over an arbitrary
transaction pair without modification, via the injected `RootService` seam
Phase 3a already depends on. This is deliberately *not* the claim that
"the SDK exposes a method for it", which is false: probe 6 enumerates every
public `ImmudbClient` method and finds zero that accept a source or
`proveSinceTx` argument. The capability is reachable only because
`verifiedtxbyid.call()` derives its source transaction entirely from
whatever `rs.get()` returns, and `rs` is a caller-supplied object.

## Question

Does immudb-py 1.5.0 permit a consistency (dual) proof between two
ARBITRARY transactions -- source A, target B, neither of them the caller's
current head -- reusing only the SDK's own verification code, with no
hand-rolled crypto and no patched SDK?

## Environment

- `codenotary/immudb:1.9.5` (container `ail-p3b1-gate-immudb-1`), brought up
  as `docker compose -p ail-p3b1-gate -f docker-compose.test.yml up -d immudb`,
  the only compose file that publishes gRPC port 3322 to the host.
- `immudb-py==1.5.0`, matching the pin in `verifier/requirements.txt`.
- Python 3.11.1, host-side.
- Fresh volume (`docker compose ... down -v` first), so the ledger starts
  empty and transaction ids below are 1-based and deterministic.

## 1. Why the seam exists: what the handler actually does

Read from the installed `immudb/handler/verifiedtxbyid.py`, not from docs.

```python
def call(service, rs: RootService, tx: int, verifying_key=None):
    state = rs.get()
    request = schema_pb2.VerifiableTxRequest(
        tx=tx,
        proveSinceTx=state.txId
    )
    vtx = service.VerifiableTxById(request)
    return verify(vtx, state, verifying_key, rs)
```

The target transaction is the `tx` parameter. The source transaction is
`state.txId` -- and `state` comes from `rs.get()`, where `rs` is an
argument, not a global. There is no code path by which the source is
constrained to the client's real head; it is simply whatever the injected
`RootService` reports. That is the entire mechanism.

`verify()` then orders the pair by comparison rather than assuming the
requested tx is newer:

```python
if state.txId <= vtx.tx.header.id:
    sourceid, sourcealh = state.txId, DigestFromProto(state.txHash)
    targetid, targetalh = vtx.tx.header.id, dualProof.targetTxHeader.Alh()
else:
    sourceid, sourcealh = vtx.tx.header.id, dualProof.sourceTxHeader.Alh()
    targetid, targetalh = state.txId, DigestFromProto(state.txHash)
verifies = store.VerifyDualProof(dualProof, sourceid, targetid, sourcealh, targetalh)
if not verifies:
    raise exceptions.ErrCorruptedData
```

Two consequences that matter for D23 and are established below by probe,
not by reading alone: the older of the two is *always* the proof source, and
the resulting trust anchor (`newstate.txId = targetid`) is *always* the
newer of the two.

This is the same injected-`RootService` seam the offline-verify spike used
to replay a `verifiedGet` with no live server
(`docs/reports/spike-offline-verify.md`, item 3), and the same seam
`verifier/`'s `PersistentRootService` already occupies in production. Phase
3a therefore already depends on this seam; this spike does not introduce a
new dependency on private surface, it reuses an existing one.

## 2. Probe table

Two scripts, run in order against the fresh stack described above. Output
below is verbatim from `spikes/consistency-proof/`, run from their committed
location.

`python spikes/consistency-proof/p3b1_gate.py`:

```
write 0: tx=1 verified=True alh=af447f07177cf782...
write 1: tx=2 verified=True alh=6889b39553a4c11f...
write 2: tx=3 verified=True alh=40247d631846ca0b...
write 3: tx=4 verified=True alh=005a413cbc6284ed...
write 4: tx=5 verified=True alh=fcf3b7af8b3c4273...
write 5: tx=6 verified=True alh=69a741faf428c9b3...

head tx = 6
arbitrary pair: source tx=2  target tx=5  (both strictly < head)

PROBE 1 (wire): VerifiableTxById(tx=5, proveSinceTx=2)
  dualProof.sourceTxHeader.iD = 2
  dualProof.targetTxHeader.iD = 5
  vtx.tx.header.id            = 5
  sourceAlh matches recorded  = True
  serialized bytes            = 901

PROBE 2 (SDK store.VerifyDualProof, arbitrary pair): True

PROBE 3 (verifiedtxbyid.call, vk=None): OK keys=[b'p3b1:e4']
  new state txId=5 alh=fcf3b7af8b3c4273

PROBE 4 (verifiedtxbyid.call, vk=signing.pub): OK keys=[b'p3b1:e4']
  new state txId=5

PROBE 5 (corrupt source alh): refused ErrCorruptedData

PROBE 6 (public ImmudbClient methods exposing a source/proveSince tx): []
```

`python spikes/consistency-proof/p3b1_gate2.py`:

```
head tx = 12
record tx=3, anchor tx=11, head=12

PROBE 7a (record older than anchor, verifiedTxById): OK keys=[b'p3b1:e2']
   resulting state txId=11 (unchanged anchor: True)
PROBE 7b (verifiedGet against arbitrary anchor): OK id=3 verified=True
   resulting state txId=11
PROBE 7c (corrupt anchor alh): refused ErrCorruptedData
PROBE 7d (server signature over state at non-head tx 11): VALID
```

What each probe settles:

| Probe | Question | Result |
| --- | --- | --- |
| 1 | Does the server honour an arbitrary `proveSinceTx`? | Yes. Asked for `tx=5, proveSinceTx=2` with head at 6; got back a dual proof whose `sourceTxHeader.iD=2` and `targetTxHeader.iD=5`, and whose source Alh equals the one independently recorded at write time. |
| 2 | Does the SDK's own proof checker accept that pair? | Yes. `store.VerifyDualProof` returns `True` over the arbitrary pair, with no patched SDK and nothing hand-rolled. |
| 3 | Does the unmodified public handler drive it? | Yes. `verifiedtxbyid.call()` with an injected `RootService` pinned at tx 2 verifies tx 5 and returns the entry key. |
| 4 | Does it still hold with the server signature checked? | Yes. Same call with `vk=signing.pub` passes, so the ECDSA state signature is not an obstacle to an arbitrary pair. |
| 5 | Is the proof actually bound to the source, or is the source decorative? | Bound. Flipping one bit of the source Alh is refused with `ErrCorruptedData`. This is the negative control that makes probes 2-4 meaningful. |
| 6 | Is any of this reachable from the public API? | No. Zero public `ImmudbClient` methods take a source/`proveSinceTx` parameter. Hence "seam, not an API". |
| 7a | The direction D23 needs: prove an OLD record against a NEWER trusted anchor. | Works. Record tx 3 verified against an anchor at tx 11, head at 12, so neither member of the pair is the head. |
| 7b | Same shape through `verifiedGet`, which is what a bundle export uses. | Works. `id=3 verified=True` against the arbitrary anchor. |
| 7c | Is the anchor binding in that direction too? | Yes. Corrupting the anchor Alh is refused with `ErrCorruptedData`. |
| 7d | Will the server sign a state at a non-head transaction? | Yes. The signature over the state at tx 11 (head being 12) verifies against `signing.pub`. |

Reproducibility note: transaction ids, the pair chosen, and every
pass/fail outcome above are deterministic on a fresh volume. The Alh hex
digests and the serialized proof size are not -- immudb puts a timestamp in
each transaction header, so those vary per run (an earlier run of the same
scripts produced 902 bytes rather than 901). Nothing in the verdict depends
on those two fields.

## 3. Seam, not an API

Probe 6 is the finding that constrains how this may be used. The
enumeration walks every public method on `ImmudbClient` and reports those
whose signature contains a source-transaction parameter under any of the
plausible spellings (`proveSinceTx`, `provenSinceTx`, `sourceTx`, `fromTx`).
The result is the empty list.

So the capability is real but unexposed. Driving it requires:

- `immudb.handler.verifiedtxbyid.call` / `immudb.handler.verifiedGet.call`,
  module-level functions rather than client methods;
- `client._stub`, the private gRPC stub, for the raw-wire probe;
- an object satisfying the `RootService` shape (`init`/`get`/`set`) passed
  in place of the real one.

None of that is covered by a public-API compatibility promise. It is,
however, exactly the surface `verifier/` and the offline-verify spike
already use, so the marginal risk is an upgrade past the pinned
`immudb-py==1.5.0`, not a new class of coupling. Any Phase 3b work building
on this should treat the pin as load-bearing and state so.

The correct phrasing of the capability, then, is the verdict above: the
SDK's own verification is drivable over an arbitrary transaction pair
without modification, via the injected `RootService` seam. Not that a
method exists for it.

## 4. Proof-direction constraint

The pair is arbitrary but the roles are not chosen by the caller. From
`verify()` (quoted in item 1) and confirmed by probes 3 and 7a:

- The **older** transaction is always the proof source; the **newer** is
  always the target. The caller cannot invert this by argument order.
- The retained trust anchor after the call is always the **newer** of the
  two, `newstate.txId = targetid`.

That yields two distinct usages, and only one of them is the D23 shape:

1. **Anchor older than the record** (probe 3): source is the anchor, target
   is the record. The call *advances* the caller's anchor to the record's
   transaction (`new state txId=5`).
2. **Anchor newer than the record** (probe 7a): source is the record,
   target is the anchor. The anchor is *unchanged* -- probe 7a prints
   `resulting state txId=11 (unchanged anchor: True)`.

D23 needs case 2. Checkpoints are anchored periodically, after records land,
so the trusted checkpoint is newer than the record being audited. Case 2
is the favourable one: auditing a record does not consume, advance, or
mutate the anchor, so one anchored checkpoint can be reused to audit
arbitrarily many records that precede it, in any order.

One asymmetry to carry forward. In case 2 the signature that
`newstate.Verify(verifying_key)` checks is over the *target*, which is the
anchor the caller already held -- not over the record being audited. The
record's integrity comes from `VerifyDualProof` binding it into the chain
beneath that anchor (probe 7c: corrupt the anchor and the whole thing is
refused), while the signature independently confirms the server vouches for
the anchor. Both checks are needed; neither substitutes for the other.

## What this gate does not settle

1. **Where a trusted anchor comes from.** Probe 7d shows the server *will*
   sign a state at a non-head transaction, but that signature was fetched
   from a live server over `client._stub` during the probe. How an auditor
   obtains, distributes, and pins an anchor without trusting a live server
   at audit time is untouched here. This is the same open thread as
   `docs/reports/spike-offline-verify.md`'s caveat, and it is the substance
   of D23 rather than a detail of it.
2. **Behaviour across an SDK upgrade.** Everything above ran against exactly
   one pinned version, `immudb-py==1.5.0` on `codenotary/immudb:1.9.5`. The
   seam is private surface (item 3); `call()`'s signature or `verify()`'s
   source/target ordering could change without a public-API break. No
   upgrade, no second SDK version, and no second server version was
   exercised.
3. **Scale and ledger shape.** A 12-transaction, single-database ledger with
   sequential writes and no deletions, expirations, or tenant separation.
   Nothing here bounds proof size, verification latency, or correctness over
   a large source-to-target gap, and the largest gap probed was 8
   transactions (record 3 to anchor 11).

## What blocked it

Nothing blocked the question. Two mechanical notes, neither affecting the
verdict:

- The scripts as originally run carried an absolute developer path for the
  repository root. The committed copies derive it as
  `Path(__file__).resolve().parent.parent.parent`, matching the convention
  in `spikes/offline-verify/export_material.py`. That one line is the only
  difference between the scripts as run and the scripts as committed; the
  probe table in item 2 was regenerated by running the committed copies.
- `keys/signing.pub` is gitignored and generated by `make keygen`, so the
  scripts require a key pair present and the same key mounted into the
  immudb container. They do not generate one themselves.

## Artifacts

`spikes/consistency-proof/`:
- `p3b1_gate.py`: probes 1-6. Writes six entries, then probes the arbitrary
  pair (source 2, target 5) below the head at 6, with a corrupt-source
  negative control and the public-API enumeration.
- `p3b1_gate2.py`: probes 7a-7d, the D23 direction. Extends the same ledger
  to 12 transactions and proves an old record against a newer, non-head
  anchor, with a corrupt-anchor negative control.

Run in that order against a fresh stack; `p3b1_gate2.py` assumes the ledger
`p3b1_gate.py` leaves behind. Neither writes anything outside the ledger,
and no exported material is retained.
