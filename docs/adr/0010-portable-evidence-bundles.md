# ADR 0010: Portable Evidence Bundles and Offline Verification

## Status

Accepted

## Context

Every ledger record in this project can be verified, and until Phase 3a
verification was only possible from inside the system that produced it.
`GET /audit` calls the verifier, the verifier calls ImmuDB over gRPC, and
what comes back is a boolean plus a state id. An auditor who wanted to
confirm that a single record was committed and unaltered had to be given a
running stack, network reach to it, and credentials for it - which is a
larger grant than the question deserves, and impossible for anything
archival, air-gapped, or after the fact.

`docs/reports/spike-offline-verify.md` established that this was a plumbing
problem rather than a cryptographic one. Read directly from the installed
`immudb-py==1.5.0`, `immudb/handler/verifiedGet.py::call()` makes exactly
one network call (`service.VerifiableGet(req)`); every line after it is pure
computation over the response message and a locally held prior `State`.
`store.VerifyInclusion`, `store.VerifyDualProof` and
`rootService.State.Verify` take parsed protobuf and a dataclass, never a
channel or a stub. The spike drove that unmodified function offline, with
the whole test stack torn down and `socket.connect` patched to raise, and
got the same answer the live client had given.

What the spike also found is why nothing in this project could do that yet:
`verifier/main.py`'s `/verify` computed the boolean and discarded the
material. The `VerifiableEntry` protobuf and the prior `State` existed for
the duration of one function call and were never persisted or returned. The
capability was in the SDK; the project simply threw away its inputs.

One further finding shaped the design more than any other. The spike flipped
a byte in `State.publicKey` and nothing happened: `verifiedGet.call()` never
reads that field. The only key that decides anything is the `VerifyingKey`
loaded from a PEM file on disk. A verification package that carried its own
public key would therefore be checked against a key its own author supplied,
which is not verification.

`docs/adr/0001-immudb-rest-migration.md` records what happens when this
project writes its own proof code: an earlier REST-era attempt hand-rolled
`TxHeader.Alh()`, got the field order wrong, and substituted `eH` for
`innerHash`. That history is the reason D20 below is phrased as a
prohibition rather than a preference.

## Decision

### D18: the verifier exports proof material rather than discarding it

`POST /verify` returns a `proof_material` object alongside its existing
result. The result itself is unchanged; the material is additional.

The field list is derived from what the spike's `export_material.py`
actually had to capture before offline verification would succeed, not from
a guess about what might be useful:

| Spike item | Field |
| :--- | :--- |
| The prior trust anchor (`db`, `txId`, `txHash`) | `proof_material.source_state` |
| The raw `VerifiableEntry` response | `proof_material.verifiable_entry` (base64 of `SerializeToString()`) |
| The ECDSA public key | **not exported**, named by `signing_key_fingerprint` |
| The raw key bytes being looked up | the caller's own request input; the value comes back in `value` |

`prove_since_tx` and `entry_tx_id` are recorded so the request
`verifiedGet.call()` made can be reconstructed exactly.

The verifier now makes the `VerifiableGet` RPC itself, with the same request
the SDK would have built, and feeds the response back into the unmodified
`verifiedGet.call()` through a two-line stand-in stub. This is not a
reimplementation of the handler: it is the handler, called with its one I/O
dependency supplied from a variable instead of a socket. Doing it this way
rather than reading twice means the material a bundle carries is provably the
material the verifier's own verdict was computed from, rather than a second
read that could differ.

Material is exported only for a check that passed. There is no such thing as
material proving a failed check, and exporting the inputs of a rejected proof
would invite treating them as evidence of something that did not verify.

**The public key is not part of the material.** It is configuration the
checker holds independently. `State.publicKey` is not exported either: the
spike showed it is never read, so shipping it would add a key-shaped field
that no check consults, sitting next to material that is supposed to be
checked against an independently held key. Reconstructing the anchor with
`publicKey=b""` verifies identically, which
`tests/test_evidence_bundle.py` asserts rather than assumes.

### D19: a bundle is one file, self-describing, and verifies with no network

`GET /audit/bundle?key=<base64 ImmuDB key>` on the control plane returns one
JSON file per record: the record as stored, the D18 proof material, the
fingerprint of the key it expects, and a format version.

The identifier is the raw ImmuDB key rather than a `call_id`, because that is
the one identifier every record shape shares. `tool_call:` decisions
(`policy_allow`, `policy_deny`, `schema_deny`, `fault`), `content_erasure:`
tombstones and `tool_call_intent:` records all export through the same code
path, with no per-type branch that could be gotten wrong for one of them.
`GET /audit` now reports `ledger_key` for every entry so the two compose; the
key carries a random uuid (`ledger/immudb_ledger.py::log_tool_call`), so it
cannot be derived from a `call_id`.

Authorization is `Depends(_require_read_key)` - the same read-scoped
credential `GET /audit` requires (ADR-0007), not a third key and not a more
permissive path. A bundle contains a record and its proof; anyone who can
read the record through `/audit` can already see both, so export adds no
reach to that credential, while leaving it ungated would hand the audit trail
to an unauthenticated caller.

`tools/ail_verify_bundle.py` is the checker: two file paths in, a named
result out. It replaces `socket.socket.connect` with a raiser as soon as its
imports finish, so no network is a property of the process rather than a
claim about it. The patch lands after imports because `ssl.py`, pulled in
transitively by `grpc`, subclasses `socket.socket` at import time; the spike
hit and documented the same ordering constraint.

### D20: the checker reuses the SDK's verification functions unmodified

`store.EntrySpecDigestFor`, `store.VerifyInclusion`, `store.VerifyDualProof`
and `State.Verify` are reached through `immudb.handler.verifiedGet.call()`,
the exact function `ImmudbClient.verifiedGet()` calls. The shims the spike
used are the mechanism: a stub with one method returning the captured
`VerifiableEntry`, and a root service whose `get()` returns the captured
anchor and whose `set()` records what the SDK derived.

Nothing in `tools/ail_verify_bundle.py` computes a digest, walks a proof, or
checks a signature. `tests/test_offline_verify.py` asserts this against the
source: no cryptographic module may be imported, `hashlib` may appear only
inside `key_fingerprint()` (where it derives an identifier that no proof
result depends on), and `verifiedGet.call(` must still be there.

Failure reports which check failed. The closed set is:

| Result | Meaning |
| :--- | :--- |
| `verified` | Every check passed |
| `consistency_failure` | `ErrCorruptedData`: an inclusion or dual proof was rejected |
| `signature_failure` | `BadSignatureError`: an ECDSA signature was rejected |
| `record_mismatch` | The bundle's readable copy of the record is not the record the proof covers |
| `key_mismatch` | The supplied key is not the key the bundle names |
| `malformed_bundle` | The file is not a bundle this checker can read |

The first three are exactly the distinction `verifier/main.py` already draws
in its `error_class` and `docs/adr/0006-verification-states.md` already
draws in its five read-time states, so a bundle result and a live `/audit`
result mean the same thing by the same names. The last three name failures
that can only exist because a bundle is a file that travelled; there is no
bundle in the live read path, so the live verifier has no equivalent. They
are additions to the vocabulary, never substitutes: nothing that used to
report `consistency_failure` reports one of them instead.

### Two checks the live verifier does not perform

Both were added because a bundle's inputs arrive together in one file, where
online they arrive from separate places with separate trust.

**The trust anchor is verified before it is used.** `verifiedGet.call()`
verifies the state it derives and trusts the anchor it was handed, which is
correct online, where the anchor comes off the verifier's own protected
volume. A bundle's anchor arrived in the same file as the material it
anchors, so the checker runs `State.Verify` on it first, against the
independently held key. This is strictly additional: every anchor a real
verifier persists is a state the server signed, so nothing that verified
before stops verifying. It also closes a downgrade - `verifiedGet.call()`
runs `VerifyDualProof` only when `state.txId > 0`, so an anchor substituted
with the genesis state would skip the consistency proof entirely and still
return `verified=True`.

**The bundle's readable copy of the record is bound to the proven record.**
The SDK verifies the entry inside the protobuf and never sees
`record.value`, `record.tx_id`, `record.timestamp` or `record.record_type`.
Those exist so a person can read the bundle, and `tools/bundle_byte_sweep.py`
found that editing them left a bundle that still verified while displaying
something the ledger never held. The checker derives each from the proven
entry and compares. Every field the format defines is required rather than
optional for the same reason: a comparison that skips an absent claim is a
comparison an editor can delete their way past, and corrupting one byte of a
field *name* is enough to make a value unreachable.

## Consequences

Evaluating a record becomes opening a file. An auditor needs the bundle, the
public key, and `pip install immudb-py==1.5.0`. They do not need this
repository, this stack, credentials, or a network.

**A bundle proves less than it might appear to.** It proves the record was
committed to the ledger and has not been altered since. It does not prove the
policy that approved the record was correct - that distinction is drawn in
`readME.md` 3.4 and is not blurred by making the proof portable. It does not
prove the writer was honest: a bundle exported for a record forged by
something with the verifier's network position is a perfectly valid bundle of
a forged record. Portability does not fix provenance.

**The export-time metadata is not covered by anything.** `exported_at`,
`exported_by` and `proof.sdk` are claims the exporter makes about itself, and
no signature covers them. The byte sweep reports them as inert, and
`readME.md`'s Residual Limits says so plainly rather than leaving a reader to
assume that everything in a signed-looking file is signed.

**The checker is pinned to one SDK version.** The material is only meaningful
to code running `immudb-py==1.5.0`'s verification, and immudb-py's proof
handling carries no cross-version stability guarantee, so the version is
recorded in the material. A future upgrade needs the fixtures regenerated and
this ADR revisited.

**A bundle can outlive its key.** The fixtures under
`tests/fixtures/evidence_bundles/` carry their own `signing.pub` because
`make keygen` produces a different pair on a fresh checkout. Any long-term
archive of bundles has the same obligation, and signing-key rotation was not
exercised here (it was already open in ADR-0001's backlog).

**`tools/ail_verify_bundle.py` duplicates two small things on purpose.** The
stub shim and the `record_type` discrimination rule also exist in
`verifier/main.py` and `control_plane/main.py`. Sharing them would tie an
auditor's offline check to this project's Docker images or source layout,
which defeats the point of the tool. Tests hold the copies in agreement
instead: the fixtures are exported by the control plane and their labels are
checked against the tool's own derivation.

**A dependency can no longer end the checking process.** `immudb-py`'s
`embedded/store/tx.py` calls `sys.exit()` on an unrecognised transaction
header version, and one corrupted byte reaches it. `SystemExit` is a
`BaseException`, so it is caught explicitly and reported as
`malformed_bundle`. A file under examination must never be able to terminate
the process examining it.

## References

- `docs/reports/spike-offline-verify.md` - the go/no-go spike, including the `state.publicKey` finding
- `docs/reports/phase-3a.md` - the completion report, byte sweep table, and mutation results
- `docs/adr/0001-immudb-rest-migration.md` - the hand-rolled `Alh()` this decision exists to avoid repeating
- `docs/adr/0006-verification-states.md` - the five read-time states the result vocabulary aligns with
- `docs/adr/0007-two-tier-authorization.md` - the read credential the export route reuses
- `tools/ail_verify_bundle.py`, `tools/bundle_byte_sweep.py`, `tools/export_evidence_fixtures.py`
- `tests/test_evidence_bundle.py`, `tests/test_offline_verify.py`
