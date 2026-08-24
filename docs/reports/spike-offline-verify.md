# Spike: Offline Verification of ImmuDB Proof Material

Run id: spike-offline-verify

**Verdict: GO WITH CHANGES.** A record's tamper-evidence can be verified with
no live ImmuDB and no network, reusing immudb-py 1.5.0's own unmodified
verification code with zero hand-rolled crypto, but only after
`verifier/main.py` is changed to actually export the raw proof material it
currently discards, since nothing in this codebase persists that material
today.

## Question

Can a record's tamper-evidence be verified with no live ImmuDB and no
network, using only material exported at write or read time?

## 1. What immudb-py's verifiedGet/verifiedSet actually verify

Read directly from the installed `immudb-py==1.5.0` package (matching
`verifier/requirements.txt`), not from docs.

`immudb/handler/verifiedGet.py::call()` and `immudb/handler/verifiedSet.py::call()`
each make exactly one network call: `service.VerifiableGet(req)` /
`service.VerifiableSet(rawRequest)`, a single gRPC round trip. Everything
after that line is pure computation on the response message plus a locally
held prior `State`:

- `store.EntrySpecDigestFor(...)` (`immudb/embedded/store/verification.py`)
  recomputes the leaf digest of the (key, value, metadata) tuple.
- `store.VerifyInclusion(inclusionProof, digest, root)` walks the Merkle
  tree from that leaf to the transaction's entry-hash root (`eH`). Pure
  SHA-256 over the proof's `terms` list, no I/O.
- `store.VerifyDualProof(dualProof, sourceTxID, targetTxID, sourceAlh, targetAlh)`
  verifies the linear-hash chain between the previously trusted transaction
  and the new one, using `TxHeader.Alh()` / `innerHash()`
  (`immudb/embedded/store/tx.py`). Also pure SHA-256 and struct packing.
- `State.Verify(verifying_key)` (`immudb/rootService.py`) checks the
  server's ECDSA signature over `(db, txId, txHash)` using the `ecdsa`
  library, against a `VerifyingKey` loaded from a local PEM file
  (`ImmudbClient.loadKey()`, a plain file read).

None of `VerifyInclusion`, `VerifyDualProof`, `VerifyLinearProof`, or
`State.Verify` take a gRPC stub, a channel, or any network handle as an
argument. They take already-parsed protobuf messages and a `State`
dataclass. The gRPC stub only appears in the one-line RPC call at the top of
each handler. This is a materially different picture than ImmuDB's REST
surface: `docs/adr/0001-immudb-rest-migration.md` records that the REST
endpoints do not return inclusion/consistency proofs at all, which is why
this project moved to a process-isolated `immudb-py` verifier
(`verifier/main.py`) in the first place. The gRPC SDK's proof objects are
present in the response; they are simply thrown away by
`verifiedGet.call()`'s return value (`datatypes.SafeGetResponse`, which
carries only `verified: bool`, no proof bytes) and by `verifier/main.py`,
which reduces the whole call to `{verified, error_class, detail}` over
HTTP.

Conclusion for item 1: yes, these verification functions are separable from
a live connection, and are already separated in the SDK's own code, not
just in principle.

## 2. Exporting proof material for a real ledger entry

Brought up the minimal test stack (`docker-compose.test.yml`, which is the
only compose file that publishes ImmuDB's gRPC port 3322 to the host):

```
docker compose -f docker-compose.test.yml up -d immudb verifier
```

Wrote `spikes/offline-verify/export_material.py`, run against that live
stack with `immudb-py` directly (not through the `verifier` FastAPI
wrapper, to reach the raw proto response before `verifier/main.py` discards
it). It writes two entries, `spike-offline-verify:entry-1` and
`spike-offline-verify:entry-2`, then captures the material for entry-1
while the trust anchor is already at entry-2's transaction, so the read
exercises the "reading behind the current anchor" branch of
`verifiedGet.call()`, not the trivial same-tx case:

```
wrote entry-1: tx=1 verified=True
wrote entry-2: tx=2 verified=True
source state: db=defaultdb txId=2 txHash=9ade617c8ad399fca979dc2b1eb42877e13a4845200633df4bdd1cbea98efd3f
live verifiedGet: id=1 verified=True value=b'{"tool":"spike-offline-verify","note":"first entry, will be proven"}'

exported material to .../spikes/offline-verify/material
{
  "source_state": {
    "db": "defaultdb",
    "txId": 2,
    "txHash_hex": "9ade617c8ad399fca979dc2b1eb42877e13a4845200633df4bdd1cbea98efd3f",
    "publicKey_hex": "0426435c7e65ffbaafd972ea736789d553d42c1072f400231e715e89bfe11b665152d5c475205ce58b6fd6444cb2f0889c66baa2c51be199931595596125ba24dd",
    "signature_hex": "3044022051c005c5dd7581d97ef7c20b40be29301dfeb905f592fcee49c54145a2b5f72b022078cab97267a6da7d28a9c856db796fa5e6a316a666fd8fcb52f2167f71470824"
  },
  "entry1_tx": 1,
  "entry2_tx": 2,
  "ventry_serialized_len": 794,
  "live_verifiedGet": {"id": 1, "verified": true, "timestamp": 1787324205}
}
```

What a checker needs, enumerated from what the export script actually had
to capture to make offline verification succeed:

1. **The prior trust anchor** (`state_source.pkl`): a `rootService.State`
   with `db`, `txId`, `txHash`, `publicKey`, `signature`. This is whatever
   the verifier last persisted before this read/write, i.e. the
   `PersistentRootService` pickle file's per-database entry.
2. **The raw `VerifiableEntry` response** (`ventry.pb`, 794 bytes for this
   entry): the server's answer to `VerifiableGet`, containing the entry
   itself, the inclusion proof, the dual proof (source/target `TxHeader`s
   plus the ah-tree inclusion/consistency/linear sub-proofs), and the
   server's new state signature. Serialized with the proto's own
   `SerializeToString()`.
3. **The ECDSA public key** (`signing.pub`): already export-once material,
   not fetched per call. It is `keys/signing.pub` in this repo, mounted
   read-only into both `immudb` and `verifier` containers.
4. The raw key bytes being looked up, only needed so the offline checker
   knows what it is checking, not for the cryptography itself.

Nothing else. In particular, no second server round trip and no
certificate chain beyond the one already-static public key.

## 3. Offline verification attempt

`spikes/offline-verify/verify_offline.py` loads only files under
`spikes/offline-verify/material/` and the installed `immudb-py` package. It
calls `immudb.handler.verifiedGet.call()` **unmodified**, the exact function
the real client uses, by passing two small fake objects instead of a gRPC
stub and a `RootService`:

```python
class FakeStub:
    def VerifiableGet(self, req):
        return self._ventry          # pre-captured, no RPC

class FakeRootService:
    def get(self):
        return self._state           # pre-captured, no RPC
    def set(self, new_state):
        self.new_state = new_state   # nothing to persist offline
```

No line in `verify_offline.py` reimplements hashing, proof-walking, or
signature checking. `EntrySpecDigestFor`, `VerifyInclusion`,
`VerifyDualProof`, and `State.Verify` are imported straight from
`immudb.embedded.store.verification` and `immudb.rootService`.

To make "no live ImmuDB and no network" a tested condition rather than an
assumption, the entire test stack was torn down before running the offline
script, and `socket.socket.connect` was monkeypatched to raise after
imports complete (patched post-import because `ssl.py`, pulled in by
`grpc`, subclasses `socket.socket` at import time):

```
docker compose -f docker-compose.test.yml down
 Container compliance-ail-verifier-1 Removed
 Container compliance-ail-immudb-1 Removed
 Network compliance-ail_default Removed

docker ps -a --filter "name=compliance-ail" --format "{{.Names}}: {{.Status}}"
(no output - no containers exist)

python verify_offline.py
loading exported material from .../spikes/offline-verify/material
RESULT: verified=True id=1 value=b'{"tool":"spike-offline-verify","note":"first entry, will be proven"}' timestamp=1787324205
new trust anchor computed offline: txId=2 txHash=9ade617c8ad399fca979dc2b1eb42877e13a4845200633df4bdd1cbea98efd3f
EXIT: 0
```

The offline result matches the live `verifiedGet` captured during export
(`id=1`, `verified=True`, same value). This ran with every container for
the project removed, not merely stopped, and with `connect()` blocked at
the socket layer, so a hidden network dependency would have raised
`RuntimeError` rather than silently succeeding.

`ADR-0001` records that an earlier attempt to hand-roll `TxHeader.Alh()` in
Python (for the REST migration path) got the field order wrong and
substituted `eH` for `innerHash`. This spike does not repeat that: it does
not compute `Alh()`, `innerHash()`, or any digest itself anywhere in
`verify_offline.py` or `tamper_test.py`. Every cryptographic primitive
comes from the pinned SDK. The only code written for this spike is
marshaling (pickle/protobuf load, PEM load) and the two-method fake-object
shim shown above.

## 4. Tampering with the exported material

`spikes/offline-verify/tamper_test.py`, same offline conditions (stack torn
down, `connect()` blocked).

**Pass 1, full byte-by-byte sweep over `ventry.pb`** (794 bytes, each byte
XORed with `0xFF`, verified offline, then restored before the next byte):

```
Category counts across all 794 single-byte flips:
  corrupted_data           357  (e.g. offset 36: ErrCorruptedData (inclusion or dual/consistency proof rejected))
  no_effect                 251  (e.g. offset 6: verified=True id=1 value=b'{"tool":"spike-offline-verify",...}')
  decode_error              114  (e.g. offset 0: Wire format was corrupt)
  bad_signature              72  (e.g. offset 718: BadSignatureError: Malformed formatting of signature)

543/794 single-byte flips were caught (decode_error + corrupted_data + bad_signature).
```

The 251 "no_effect" offsets are not a bypass of the proof check. They land
in protobuf wire-format framing (tag bytes, varint length prefixes) or in
message fields that are not inputs to any digest or signature the checker
computes, so flipping them either still decodes to a self-consistent
message or changes an unhashed, uncompared field. Every byte that is part
of the hashed leaf content, the proof chain, or the signature was caught.

**Pass 2, targeted field-level tamper** (via the protobuf/dataclass APIs,
one byte flipped per field, so the exact mechanism is unambiguous):

```
[a] flip byte 0 of entry.value: corrupted_data - ErrCorruptedData (inclusion or dual/consistency proof rejected)
[b] flip byte 0 of verifiableTx.signature.signature: bad_signature - BadSignatureError (Malformed formatting of signature)
[c] flip byte 0 of the LOCAL trust anchor's txHash: corrupted_data - ErrCorruptedData (inclusion or dual/consistency proof rejected)
[d] flip byte 0 of the LOCAL state's cached publicKey field: no_effect - verified=True
```

[a] and [c] confirm the two things that actually matter for tamper
evidence: changing the stored value is caught (inclusion proof), and
corrupting the locally-held trust anchor itself is caught (dual proof no
longer matches the anchor's `Alh()`). This is the same vector
`docs/adr/0001-immudb-rest-migration.md` names as the one attacker-reachable
test in the existing suite (corrupting the verifier's own persisted state
file).

[d] is a genuine, worth-noting finding rather than a gap: `state.publicKey`
is never read by `verifiedGet.call()`. The signature check uses only the
externally loaded PEM `verifying_key`, not the copy of the public key
`State` happens to carry. An offline checker must ship the trusted PEM
file separately from whatever `State` blob it is checking; trusting a
`publicKey` field that arrived bundled with the material being verified
would be circular. `export_material.py` already does this correctly (it
copies `keys/signing.pub` as its own file, not extracted from `ventry.pb`
or `state_source.pkl`), and any production exporter needs to preserve that
separation.

## 5. Alternative if offline verification were not achievable

Not triggered. Offline verification of ImmuDB proofs is achievable without
hand-rolled crypto, reusing the SDK's own verification module.

## What could not be determined

- Only the read path (`verifiedGet`) was captured and replayed offline.
  `verifiedSet`'s proof (`immudb/handler/verifiedSet.py`, used by
  `ledger/immudb_ledger.py` at write time through `verifier/main.py`'s
  `/write`) calls the identical `store.VerifyInclusion` /
  `store.VerifyDualProof` functions on a `VerifiableTx` response instead of
  a `VerifiableEntry`, so the same separability argument applies by
  inspection of the source in item 1, but it was not independently
  exported and replayed offline in this spike. Low risk, same code path,
  but not directly tested.
- Signing-key rotation was not exercised. `docs/adr/0001-immudb-rest-
  migration.md`'s own backlog item notes the verifier does not detect a
  mismatch between the mounted public key and the key embedded in its
  persisted state; an offline checker would inherit the same failure mode
  (an opaque signature failure) if handed a stale key, and this spike did
  not attempt to reproduce that.
- History across many transactions (a long consistency-proof chain
  spanning dozens of transactions, or a database with deletions/expirations)
  was not exercised; this spike used a two-transaction database.

## What blocked it

Nothing blocked the core question. The one implementation snag was that
`socket.socket.connect` cannot be monkeypatched before importing `grpc`,
because `ssl.py` (imported transitively by `grpc`) subclasses
`socket.socket` at import time and a monkeypatched non-class object breaks
that subclassing. Fixed by patching `connect` after imports finish instead
of patching the class itself before importing; this has no bearing on the
verdict, it is a Python import-ordering detail in the test harness.

## Caveat behind "GO WITH CHANGES"

The capability exists in the SDK; nothing in this project exposes it today.
`verifier/main.py`'s `/verify` endpoint calls `verifiedGet`, discards the
proof material `ventry` in this spike had to capture by calling
`client._stub.VerifiableGet(req)` directly, and returns only
`{verified, tx_id, value, timestamp, state_id, error_class}`. Making
offline verification a real capability (e.g. for an air-gapped auditor, or
a long-term archival check independent of the live verifier) requires
changing `verifier/main.py` to export the raw proof bytes and the prior
`State` at write or read time, which is a scoped, separate implementation
task, not a research question. This spike deliberately did not build that;
per its own instructions, it stops at describing what would be needed.

## Artifacts

`spikes/offline-verify/`:
- `export_material.py`, `verify_offline.py`, `tamper_test.py`: runnable
  scripts, in that order, reproducing everything above.
- `material/`: the actual exported material from the run quoted in this
  report (`state_source.pkl`, `ventry.pb`, `signing.pub`, `key.txt`,
  `value.txt`, `manifest.json`). Not committed to git; regenerable by
  rerunning `export_material.py` against a fresh `docker-compose.test.yml`
  stack.
