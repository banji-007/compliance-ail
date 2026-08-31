# ADR 0012: Writer Signing and External Anchoring

## Status

Accepted

## Context

Phase 3a made a record portable. `docs/adr/0010-portable-evidence-bundles.md`
ends by saying plainly what that did not buy:

> It does not prove the writer was honest: a bundle exported for a record
> forged by something with the verifier's network position is a perfectly
> valid bundle of a forged record. Portability does not fix provenance.

Two separate things were missing behind that sentence, and they are missing
in different directions.

**A record did not say who wrote it.** Every field in a decision record was
put there by the decision service, and nothing in the record bound it to
that service rather than to anything else holding a verifier write
credential. A reader could establish that ImmuDB committed the bytes and
that they have not changed; they could not establish who produced them.

**The trust anchor was inside the operator's control.** A bundle's dual
proof ran from whatever `verifier/`'s `PersistentRootService` happened to
hold at export time to the record's transaction. That anchor is a state on
a Docker volume in the deployment being audited. An external party has no
way to learn what it was, no way to know it was not chosen after the fact,
and no independent record that the ledger ever looked like that. The proof
was sound and the anchor was unfalsifiable.

Three spikes ran before this decision, and each of them constrained it.

`docs/reports/spike-signing-anchor.md` asked whether a SPIFFE SVID could
sign records (**NO-GO**) and whether Rekor v2 would accept a checkpoint from
a self-managed key (**GO**). Question A was answered from a real forced
rotation in both directions: a rotated-away SVID keeps verifying, and stops
the moment its own `not_valid_after` passes, which at this project's own
`default_x509_svid_ttl = 24h` is about a day. Question B produced live
submissions accepted on the first attempt, returning inclusion proofs and
checkpoints co-signed by three independent witnesses, verified offline with
`sigstore-python`'s own verification functions in 2 to 4 seconds, with
nothing but a hash, a signature and a public key reaching the log.

`docs/reports/spike-consistency-proof.md` established that immudb-py's own
verification is drivable over an arbitrary transaction pair, through the
injected `RootService` seam Phase 3a already depends on, and that the server
signs the state at an arbitrary transaction rather than only at the head
(probe 7d). It also established the constraint that shapes the API: the
older transaction is always the proof source and the newer always the
target, so the caller cannot invert the pair by argument order.

`docs/reports/spike-offline-verify.md` established that seam in the first
place, and found the `State.publicKey` result this project's key handling
has been built around since: immudb-py never reads it, so a bundle that
carried its own key would be checked against a key its own author chose.

## Decision

### D22: writer signing uses a dedicated long-lived key, not the SVID

Each service that writes a ledger record signs the canonical record bytes
before the write, and the signature is a **field in the record**. It
therefore goes into ImmuDB with everything else and is covered by the same
inclusion proof, rather than being attached by the exporter later.
`docs/adr/0010-portable-evidence-bundles.md` already records that a bundle's
export-time metadata is covered by nothing; a signature added at export time
would be one more such claim.

The canonical bytes are a deterministic JSON serialization of the record
with the signature field itself removed: sorted keys, no whitespace, ASCII
escapes. `writer_key_fingerprint` and `writer_signature_format` are **inside**
the signed bytes, so a forger cannot repoint a record at a key of their
choosing without breaking the signature. Signatures are RFC 6979
deterministic ECDSA, so signing the same record twice produces identical
bytes, which is what makes "sign it twice and compare" a test rather than a
coin flip.

**Why not the SVID.** SPIFFE answers *who is connecting right now*, with a
credential deliberately designed to expire. Durable evidence answers *who
wrote this*, checkable years later. Those are opposite key-lifetime
requirements, and `docs/plan/ail-roadmap.md` conflated them. The spike measured the
consequence rather than arguing it: a bundle whose only attribution is an
SVID signature becomes cryptographically uncheckable roughly one day after
it was created. `spikes/signing-anchor/leaf_cert.pem` is committed with that
property intact, so the finding re-runs itself on a clock.

**Two writer keys, not one.** `decision-service` signs decision and intent
records; `ail-control-plane` signs the erasure tombstone it writes directly.
Each is *configured* with its own pair, so a bundle's
`writer_key_fingerprint` names which key signed the record, and one writer
can be revoked without revoking the other. A single shared key would verify
every record identically and attribute nothing.

**Correction (Phase 3c-3c completion pass): "they hold separate pairs" was
false, and the sentence it supported claimed too much.** The paragraph above
said the fingerprint "names which service wrote the record". It does not.
Every service mounts the whole key directory read-only - `./keys:/keys:ro`
appears on `ail-control-plane`, `verifier`, `decision-service`,
`anchor-service` and `immudb` in `docker-compose.yml` - so each of them holds
every writer's private key and is separated from the others only by which
path its own `AIL_WRITER_SIGNING_KEY` points at. That is a configuration
convention, not a boundary: any of those services can read
`/keys/writer-decision.key` and produce a signature indistinguishable from
the decision service's own.

So the fingerprint names **a key**, and the key does not name a service. What
survives unchanged is per-key revocation, which is what the deny-list
mechanism actually operates on, and the refusal of an unsigned record. What
does not survive is reading a fingerprint as evidence of *which component*
wrote a record, which matters exactly when it would be relied on: after a
compromise of one of them.

Segregating the mounts so each service mounts only its own key is a D22 item
and is recorded in `TODO.md`; it is not done here, because it is a change to
the deployment topology rather than to this phase's subject, and doing it
without also deciding what `immudb` needs from that directory would be
guesswork.

#### Where the key is generated and stored, and how it reaches the service

The same custody mechanism `docs/adr/0010-portable-evidence-bundles.md` and
ADR-0001 already document for the ImmuDB signing key, deliberately, and this
ADR points at it rather than inventing a second one:

- Generated by `make keygen`, with the same `openssl ecparam -genkey -name
  prime256v1` invocation that produces `keys/signing.key`, into the same
  `keys/` directory. Idempotent: an existing key is reused, never
  regenerated.
- Never committed. `.gitignore` covers `keys/*.key` and `keys/*.pub` as a
  glob rather than name by name, so a key pair added later is ignored by
  default instead of committed by default. The **public** halves the tests
  need are committed deliberately, under
  `tests/fixtures/evidence_bundles/`, which that pattern does not reach.
- Reaches each service as a read-only bind mount of `keys/` plus one
  environment variable naming which file that service may sign with
  (`AIL_WRITER_SIGNING_KEY`). Each service is pointed at its own key; the
  mount is shared because it is the same mount ImmuDB and the verifier
  already use, and the separation that matters is which path a service is
  told to open.
- Loaded once at first use and held in the process. A missing or unreadable
  key raises, and the ledger write fails, and the middleware returns DENY.

This is a development-grade custody story, and it is the same one this
project already has for the ImmuDB key. It is stated here so that a
production deployment knows exactly what it is replacing: an operator-held
PEM on a mounted volume, not an HSM, not a KMS, and not anything that
prevents a host compromise from reading it.

#### What happens on suspected compromise

Long-lived does not mean no lifecycle. A compromised writer key signs
forgeries that are cryptographically indistinguishable from genuine records,
and re-signing history is not available - the records are in an immutable
ledger.

The revocation path is a **fingerprint deny-list the checker consults**:

```
python tools/ail_verify_bundle.py BUNDLE.json --key signing.pub \
  --writer-key writer-decision.pub \
  --writer-deny-list revoked-writers.json
```

`revoked-writers.json` is `{"revoked": [{"fingerprint": "sha256:...",
"reason": "...", "revoked_at": "..."}]}`. Anything a listed key signed is
refused with `writer_key_revoked`, **whether or not the signature checks
out** - it does, which is exactly why validity cannot be the whole test.

Three properties of that design are deliberate:

1. **The deny-list is held by the checker, out of band, like the keys.** A
   bundle that carried its own revocation status would be asserting that its
   own writer had not been compromised. Same reasoning as ADR-0010's rule
   about the key.
2. **A malformed deny-list is refused, not skipped.** A row the checker
   cannot read is a hole in a revocation list, and a hole is
   indistinguishable from not having revoked the key.
3. **Rotation and revocation are separate operations.** Rotating a writer
   key needs no volume deleted and no ledger change: records already written
   stay verifiable against the old public key, which is why a bundle names
   its writer by fingerprint and a checker takes `--writer-key` more than
   once. Rotation *after a compromise* additionally requires the deny-list
   entry, or every record the compromised key ever signed still verifies.

This treats compromise as an operational event with a documented response,
which is how this project already treats it elsewhere (`readME.md` §5's
tamper-evidence-is-not-forgery-resistance bullet), rather than as a design
gap.

#### SVID signing with trusted timestamping was considered and rejected

The obvious repair for Question A's NO-GO is to keep SVID signing and add an
RFC 3161 trusted timestamp, so a checker can establish that the signature
was made while the certificate was valid rather than requiring the
certificate to still be valid at checking time. It was considered and
rejected for this phase, for three reasons:

1. **It adds a second external dependency to fix a problem the first one
   already solves.** D23 already puts the ledger's own signed state into a
   public transparency log, which independently establishes that a state
   existed at a point in time. Adding a TSA to rescue SVID signing would
   mean two external services on the evidence path where one does the work.
2. **It moves trust rather than removing it.** A timestamp is only as good
   as the timestamp authority, and this project would then be trusting a TSA
   about *when*, a SPIRE CA about *who*, and a transparency log about
   *what* - three roots where a long-lived key plus a log is two.
3. **The chain still expires at the CA.** The spike's "What could not be
   determined" section records this: `ca_ttl = 720h` here, so the trust
   bundle a checker would need also goes stale, just on a longer cycle. A
   timestamp fixes the leaf's expiry and leaves the CA's.

**The condition that would reopen it:** an `attested` conformance profile
(`docs/adr/0005-outcome-taxonomy.md` reserves the term) in which the claim a
record makes is specifically *which attested workload* produced it, rather
than *which key*. A long-lived key cannot make that claim - it says a key
signed, and any process holding the key could have. At that point the SVID
is the right credential precisely because it is attested, the TTL problem
becomes unavoidable rather than self-inflicted, and trusted timestamping
becomes the cost of the claim instead of a patch on a design choice.

### D23: anchoring uses Rekor v2 over ImmuDB's own signed states

ImmuDB's transaction hash is already a Merkle root, and the server signs the
state at an arbitrary transaction, not only at the head (probe 7d). So there
is no second tree. A periodic job (`anchor_service/`) asks the verifier for
ImmuDB's current signed state, submits that state's canonical payload to a
Rekor v2 instance with a self-managed key, and records the accepted entry.

The bundle's chain becomes:

| Link | Established by |
| :--- | :--- |
| the record | `store.EntrySpecDigestFor` + `store.VerifyInclusion` |
| record's transaction to the anchored state | `store.VerifyDualProof` |
| that state is ImmuDB's | `State.Verify` against the out-of-band ImmuDB key |
| who wrote the record | the writer signature, against an out-of-band writer key (D22) |
| that state was published | the anchor payload's digest inside the log entry, signed by the out-of-band anchoring key |
| the log holds that entry | `verify_merkle_inclusion` + `verify_checkpoint`, sigstore-python's own |

**The anchor payload** is a canonical JSON object over `(anchor_payload_format,
db, tx_id, tx_hash, signature)` - the state's own ECDSA signature included,
not stripped. Anchoring an unsigned triple would anchor a claim about the
ledger rather than the ledger's own attestation of it. `sha256` of that
payload is the `hashedrekord` digest; the payload itself never leaves the
deployment.

**The log instance URL is discovered, never hardcoded.** B1 found the
current public v2 instance is scheduled for turndown and its URL rotates.
`provenance/rekor.py` reads it from Sigstore's own TUF-distributed
configuration, in two ordered sources: `SigningConfig.rekorTlogUrls`
filtered to `majorApiVersion >= 2` and a currently in-force `validFor`
window, falling back to `TrustedRoot.tlogs[]` excluding every `baseUrl`
SigningConfig itself advertises at `majorApiVersion < 2`. The fallback is
not hedging: as of 2026-08-24, live, the production SigningConfig lists only
the v1 instance under `rekorTlogUrls` while the TrustedRoot names the v2
instance, so today the second source is the one that answers. Which one did
is recorded on the anchor and travels in the bundle.
`tests/test_external_anchor.py` scans the product source for a Rekor URL,
including comments, which is why `provenance/rekor.py` describes the
instance rather than naming it.

**`/verify` takes an anchor.** The verifier reconstructs the supplied state,
**verifies its ImmuDB signature before using it** - it is caller-supplied
input, and without that check anyone holding the read credential could pin a
proof to a state of their own invention - and drives
`immudb.handler.verifiedGet.call()` through a `_PinnedRootService` whose
`set()` records rather than persists. Auditing an old record must not
advance the trust anchor every other proof is measured against.

**An anchor older than the record is refused by name.** Proof direction is
fixed by the ledger: the older transaction is always the source. So an
anchor that precedes a record does not fail, it quietly inverts, producing a
sound proof running forward from a checkpoint published before the record
existed - which says nothing about corroboration while looking exactly like
corroboration. `error_class: anchor_precedes_record` refuses it, and the
control plane falls back to an unanchored export.

#### This is the project's first deliberate fail-open subsystem

Stated as the named exception it is. OPA missing, ImmuDB missing, SPIRE
missing, the verifier missing, the content store missing, the writer key
missing: all DENY, by explicit project rule stated as universal in
`readME.md` §5 and in every ADR that touches a dependency. Anchoring does
not block writes if it fails.

That is correct for something off the hot path - blocking a policy decision
on a shared public service would be a worse failure than the one it
prevents - and it is an exception to a rule stated as universal elsewhere,
so it is written down as one rather than left for a reader to discover.

The precise form is **fail-open on the write path, fail-closed on the
claim**:

- If TUF is unreachable, if the log refuses the submission, if the anchor
  service is not deployed at all: writes continue, decisions continue,
  records are produced, bundles export.
- A bundle exported for a record no anchored checkpoint covers **cannot**
  claim external corroboration. It says so explicitly, in
  `external_anchor.state = "not_anchored"` with a `detail` in words, rather
  than by omitting a field. Absence of corroboration is visible rather than
  inferred - the same discipline `docs/adr/0006-verification-states.md`
  applies to the read-time states.
- The ordering enforces it: `anchor_service/` submits **first** and records
  **second**, so a row in the anchor store and "a public log holds this" are
  the same statement rather than two that can drift apart.
- A checker handed an anchored bundle with no trust root refuses it
  (`anchor_unchecked`) rather than printing the same "verified" a full check
  prints. The opt-out (`--skip-anchor-check`) exists and is explicit; it is
  never a default, and the result reports itself as unchecked.

#### The arbitrary-pair capability is a seam, not an API

This must be recorded, because it is a maintenance surface an API would not
be.

No public `ImmudbClient` method takes a source transaction. Probe 6 in
`docs/reports/spike-consistency-proof.md` enumerated every public method
under four plausible spellings (`proveSinceTx`, `provenSinceTx`, `sourceTx`,
`fromTx`) and returned the empty list. Every call site in immudb-py
hardcodes `proveSinceTx = state.txId`. The pair is selected entirely by the
`State` the injected `RootService` returns, and `rs` is a caller-supplied
object. `store.VerifyDualProof` and `State.Verify` still do all the work,
unmodified; nothing is patched and nothing is reimplemented.

This is the same seam Phase 3a already depends on - `verifier/`'s
`PersistentRootService` occupies it in production, and
`tools/ail_verify_bundle.py`'s `_BundleRootService` occupies it offline - so
Phase 3b adds no new class of coupling. What it adds is a *dependency on the
seam's exact shape*: an `immudb-py` upgrade past the pinned `1.5.0` can move
it, and if `proveSinceTx` were derived some other way, the verifier would
anchor at the wrong transaction and every anchored bundle would become
quietly meaningless while still reporting `verified`.

**What would detect it:**
`tests/test_anchored_export.py::test_the_proof_source_still_comes_from_the_injected_root_service`
asserts, against the installed SDK's own source, that
`verifiedGet.call()` still contains `state = rs.get()` and
`proveSinceTx=state.txId`, and re-runs probe 6's enumeration to assert the
seam has not become an API. An upgrade that moves it fails that test rather
than silently changing what a bundle means. The pin in
`verifier/requirements.txt` is load-bearing and should be treated as such.

## Consequences

**A bundle now answers a third question.** Phase 3a's bundle answered "was
this committed and is it unaltered". It now also answers "which key wrote
it" and "was the state it is proven against published outside this
deployment". Those are three different claims and the tool prints them
separately.

**It does not answer a fourth.** A Rekor anchor proves a state existed at a
point in a public log. It does not prove the policy was correct, and it does
not prove the writer was honest - only which key signed. A compromised
writer signs whatever it records, and the signature makes that forgery
attributable to a key, not false, and not attributable to a service - see
the correction above. `readME.md` §3.4 keeps that distinction and §5
states this one.

**The checker gained an optional dependency.** The base check still needs
nothing but `immudb-py==1.5.0`. Verifying an anchored bundle's log entry
additionally needs `sigstore==4.5.0`, imported lazily inside
`verify_external_anchor` and only when a bundle claims corroboration - and
imported *after* the socket block is installed, so the anchor check has to
prove it needs no network rather than be trusted not to use one.

**Entry permanence across a log turndown is unresolved.** The spike's own
"What could not be determined" says so: whether an entry in the current
public instance survives that instance's eventual turndown was not
established, and no documented migration guarantee was found. This is why
the local chain stays primary and Rekor corroborates, rather than the other
way round. `readME.md`'s Residual Limits says this.

**The anchor store's write route uses an existing credential.** `POST
/anchors` is gated by `CONTROL_PLANE_WRITE_KEY`. That is deliberately not a
new grant: anything holding that key can already write an erasure tombstone
the verifier treats as authentic. What stops a forged anchor from becoming a
forged claim is not the gate - it is that the verifier refuses a checkpoint
ImmuDB did not sign, and the offline checker re-verifies the whole Rekor
chain against a trust root it holds itself. A forged row yields a bundle
that fails offline, which is where a forgery should fail.

**Three canonicalization rules now exist in two copies each.** The record
rule and the anchor-payload rule live in `provenance/` for writers and again
in `tools/ail_verify_bundle.py` for auditors, for the reason ADR-0010 gives
for the stub shim and the `record_type` rule: an auditor checking a bundle
from a system they do not operate cannot be asked to obtain that system's
source. The copies are held in agreement by
`tests/test_writer_signing.py`, which signs through one and verifies through
the other, rather than by an import.

**The bundle format is now `ail-evidence-bundle/2` and the proof material
`ail-proof-material/2`.** No proof-material field was added or removed, but
`source_state` was reinterpreted: it used to be whatever the exporting
verifier held, and is now the published checkpoint whenever one covers the
record. A `/1` checker reading a `/2` bundle would draw the wrong conclusion
about what the proof is anchored at, and would skip the writer check and the
anchor section entirely, so the version strings refuse rather than guess.
The Phase 3a fixtures were regenerated rather than migrated.

## References

- `docs/reports/spike-signing-anchor.md` - Question A's NO-GO across a real forced rotation, Question B's live Rekor v2 submissions, and what actually becomes public
- `docs/reports/spike-consistency-proof.md` - the arbitrary-pair probes, the direction constraint, and probe 6's "seam, not an API"
- `docs/reports/spike-offline-verify.md` - the injected `RootService` seam and the `State.publicKey` finding
- `docs/reports/phase-3b.md` - the completion report, mutation results, and claim mapping
- `docs/adr/0010-portable-evidence-bundles.md` - the bundle this extends, and the key-stays-outside rule it reuses
- `docs/adr/0011-verifier-authentication.md` - the read credential `/state` reuses
- `docs/adr/0006-verification-states.md` - the state-your-answer discipline `external_anchor` follows
- `docs/adr/0005-outcome-taxonomy.md` - the `attested` profile that would reopen SVID signing
- `provenance/`, `anchor_service/`, `tools/ail_verify_bundle.py`
- `tests/test_writer_signing.py`, `tests/test_external_anchor.py`, `tests/test_anchored_export.py`
