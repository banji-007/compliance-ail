# Phase 3a: Portable evidence bundle and offline verifier

**Run id:** `p3a-bundle`
**Working directory:** `C:\Users\banji\OneDrive\Documents\compliance-ail\.claude\worktrees\agent-a582614fcd7624bfe` (a git worktree, not the primary working directory)
**Branch:** `phase-3a-evidence-bundle`, branched from `main`
**Compose project name:** `p3a-bundle` on every invocation, with `--no-cache` on every image rebuild
**CI run id:** _(filled in at the bottom of this report)_

Implements D18, D19 and D20 from `phase-3a-instruction.md`, grounded in
`docs/reports/spike-offline-verify.md`. Design record:
`docs/adr/0010-portable-evidence-bundles.md`.

---

## 1. Verdict per item

| Item | Verdict |
| :--- | :--- |
| P3a-1. The verifier exports proof material | **Met** |
| P3a-2. A bundle can be exported for any record | **Met** |
| P3a-3. A bundle verifies offline | **Met** |
| P3a-4. Tampering fails with a named error | **Met** |
| P3a-5. The key is independent of the bundle | **Met** |
| P3a-6. Documentation and claim mapping | **Met** |

Test totals at the end of the pass: `tests/test_evidence_bundle.py` (17,
needs the stack) and `tests/test_offline_verify.py` (35, needs nothing), both
green. CI on the PR: **199 passed, 9 skipped, 0 failed**. The full-suite
figure matters because of the defect recorded in section 8.1, which the two
new files alone would not have surfaced.

Two `tests/test_content_states.py` tests fail *locally* and pass on CI. They
shell out to `docker compose` under a project name derived from the repository
directory basename (`_default_compose_project_name()`), which in this worktree
is `agent-a582614fcd7624bfe`, while this phase's standing rule requires every
compose invocation to pass `-p p3a-bundle`. They therefore look for containers
in a project that does not exist and report `service "ail-control-plane" is not
running`. Confirmed unrelated to this changeset: both pass on CI (8/8 in
`test_content_states.py`), where the project name matches the checkout
directory. Recorded rather than silently attributed to the environment,
because "it passes on CI" is exactly the claim that needs evidence.

---

## 2. P3a-1. The verifier exports proof material

**Verdict: met.**

### Demonstration

A real entry on the live `p3a-bundle` stack, read through `POST /verify`.
The write of a second record before the read puts the trust anchor ahead of
the entry being proven (anchor at tx 312, entry at tx 309), so the response
exercises the "reading behind the current anchor" branch of
`verifiedGet.call()` rather than the trivial same-transaction case.

```
verified          : True tx_id: 309
format            : ail-proof-material/1
sdk               : immudb-py==1.5.0
source_state      : {"db": "defaultdb", "tx_id": 312, "tx_hash": "uhhD/o4fIiojNoVHdNdAuvEtNRyg3Y7tyX4BhDmEjDg=", "signature": "MEQCIFFDAeOd9tDgWNtzY2EsS1gRfE1JlS3Xgy...
verifiable_entry  : base64, 1836 chars -> 1377 bytes of VerifiableEntry protobuf
prove_since_tx    : 312
entry_tx_id       : 309
signing_key_fingerprint: sha256:cc837c537fe429fa4c565919004bd8a799a55e525aa639a669052647b719d6f8
PUBLIC KEY PRESENT?: False
```

The prior `State`, the raw `VerifiableEntry` protobuf and the transaction
identifiers are all present. The public key is not, in either of its two
possible hiding places: there is no top-level key field, and
`proof_material.source_state` carries no `publicKey`. D18 requires this
because the spike (item 4[d]) found `verifiedGet.call()` never reads
`state.publicKey`, so a bundle carrying its own key would be self-certifying.

`verifier/main.py` makes the `VerifiableGet` RPC itself with the request the
SDK would have built, then feeds the response back into the unmodified
`verifiedGet.call()` through a two-method stand-in stub. The material a
bundle carries is therefore the material the verifier's own verdict was
computed from, not a second read that could differ.

### Enforcing test

`tests/test_evidence_bundle.py`. The field list is transcribed into
`_SPIKE_REQUIRED_MATERIAL` from `docs/reports/spike-offline-verify.md` item 2
("What a checker needs, enumerated from what the export script actually had
to capture"), in the spike's own wording, with each row checked separately,
rather than from the phase instruction. Spike item 2.3, the ECDSA public
key, is deliberately excluded and the exclusion is commented in place.

The load-bearing test is
`test_exported_material_actually_completes_an_offline_check`: it assembles a
bundle from nothing but one `/verify` response and runs the standalone
checker over it with sockets blocked. Presence assertions alone would pass
against a field that was present but useless; this one fails if the exported
set is not sufficient.

### Mutation

Dropped `proof_material.source_state` from the response
(`verifier/main.py`, field made optional and no longer populated), rebuilt
the verifier image with `--no-cache`, restarted under `-p p3a-bundle`.

```
E           AssertionError: missing proof_material.source_state
E           assert ('source_state' in {'entry_tx_id': 125, 'format': 'ail-proof-material/1', 'prove_since_tx': 126, 'sdk': 'immudb-py==1.5.0', ...} and None is not None)
E           ail_verify_bundle.BundleCheckFailed: malformed_bundle: bundle is missing required field proof.source_state.db
FAILED tests/test_evidence_bundle.py::test_verify_response_carries_each_item_the_spike_enumerated[source_state]
FAILED tests/test_evidence_bundle.py::test_proof_material_source_state_carries_the_anchor_fields_the_sdk_reads
FAILED tests/test_evidence_bundle.py::test_exported_material_actually_completes_an_offline_check
3 failed, 2 passed, 12 deselected, 1 warning in 51.71s
```

Named assertion failures, not crashes or import errors. Reverted, image
rebuilt `--no-cache`, suite green again.

---

## 3. P3a-2. A bundle can be exported for any record

**Verdict: met.**

`GET /audit/bundle?key=<base64 ledger key>` on the control plane. The
identifier is the raw ImmuDB key because that is the one identifier every
record shape shares; `GET /audit` now reports `ledger_key` for every entry so
the two compose. The key carries a random uuid
(`ledger/immudb_ledger.py::log_tool_call`), so it cannot be derived from a
`call_id`.

### Demonstration

Exported live from the `p3a-bundle` stack through the real route with the
real read credential. The instruction asked for four record types; a fifth
(`schema_deny`) is included because the same code path serves it.

```
policy_allow     HTTP 200  tx=237   record_type=policy_allow     bytes=4220   disposition=attachment; filename="ail-evidence-tx237.json"
policy_deny      HTTP 200  tx=238   record_type=policy_deny      bytes=4543   disposition=attachment; filename="ail-evidence-tx238.json"
fault            HTTP 200  tx=304   record_type=fault            bytes=4097   disposition=attachment; filename="ail-evidence-tx304.json"
content_erasure  HTTP 200  tx=323   record_type=content_erasure  bytes=2731
schema_deny      HTTP 200  tx=247   record_type=schema_deny      bytes=4343
```

The `content_erasure` tombstone was produced by driving the control plane's
own `POST /content` then `DELETE /content/{call_id}` routes, not by writing a
tombstone directly.

### Authorization

`Depends(_require_read_key)` on line 928 of `control_plane/main.py`, the
identical dependency `GET /audit` uses on line 551. Not a new credential and
not a looser check. Probed live:

```
no header  -> 422
wrong key  -> 403
write key  -> 403
```

The write credential is refused, which is the point of the two-key split in
ADR-0007: the export is read-scoped, and holding the mutating credential
does not confer it.

### Enforcing test

`tests/test_evidence_bundle.py`: one test per record type
(`test_bundle_exported_for_a_policy_allow`, `..._policy_deny`, `..._fault`,
`..._content_erasure_tombstone`), plus
`test_bundle_export_requires_the_read_credential` and
`test_bundle_export_is_not_reachable_with_the_write_credential_alone`. The
second credential test exists because "requires a credential" and "requires
the *read* credential" are different claims.

### Mutation

Removed `_: None = Depends(_require_read_key)` from `get_audit_bundle`,
rebuilt the control plane `--no-cache`, restarted under `-p p3a-bundle`.

```
E       AssertionError: expected 422 with no header, got 200
E       assert 200 == 422
E       AssertionError: the write key must not authorize a read-scoped export, got 200
E       assert 200 == 403
FAILED tests/test_evidence_bundle.py::test_bundle_export_requires_the_read_credential
FAILED tests/test_evidence_bundle.py::test_bundle_export_is_not_reachable_with_the_write_credential_alone
2 failed, 15 deselected, 1 warning in 28.36s
```

Reverted, rebuilt `--no-cache`, green again.

---

## 4. P3a-3. A bundle verifies offline

**Verdict: met.**

`tools/ail_verify_bundle.py` is a standalone entry point: two file paths in,
a named result out. No Docker, no ImmuDB, no control plane, no network.

### D20 compliance, checked rather than asserted

Every check runs inside `immudb-py==1.5.0`, reached through
`immudb.handler.verifiedGet.call()` with the spike's `FakeStub` /
`FakeRootService` shim pattern (here `_BundleStub` / `_BundleRootService`).
`store.EntrySpecDigestFor`, `store.VerifyInclusion`, `store.VerifyDualProof`
and `State.Verify` are the SDK's own. The complete import list of the
checker contains no cryptographic module:

```
import argparse, base64, binascii, json, socket, sys
from pathlib import Path
import ecdsa
from ecdsa.keys import BadSignatureError
from google.protobuf.message import DecodeError
from immudb.exceptions import ErrCorruptedData
from immudb.grpc import schema_pb2
from immudb.handler import verifiedGet
from immudb.rootService import State
```

`hashlib` appears at exactly two lines, both inside `key_fingerprint()`,
where it derives an identifier that no proof result depends on. ADR-0001
records a hand-rolled `Alh()` in this project that got the field order wrong
and substituted `eH` for `innerHash`; not repeating that is why the tool is
built this way.

### Demonstration, with the stack torn down

See section 9. The four committed fixture bundles verify with every
`p3a-bundle` container removed and `socket.socket.connect` replaced by a
raiser, reproducing the spike's method.

### Enforcing test

`tests/test_offline_verify.py::test_fixture_bundle_verifies_offline_with_no_network`,
parametrized over all four record types. It installs the block and calls
`pytest.fail` explicitly if the checker attempts a connection, so an attempted
fetch is a named failure rather than an error that could be mistaken for an
environment problem. Two structural tests back it:
`test_the_checker_implements_no_cryptography_of_its_own` walks the checker's
AST for banned imports and stray `hashlib` use, and
`test_merely_importing_the_checker_blocks_the_network` asserts the block is a
property of the import rather than of a caller remembering to switch it on.

The fixtures are committed and never regenerated at test time. That is
deliberate: regenerating them would turn a portability test back into an
integration test. The whole offline suite runs in about 1.5 seconds with no
stack at all.

### Mutation

Added a live socket connection inside `verify_bundle`.

```
E       ail_verify_bundle.NetworkAccessAttempted: ail_verify_bundle.py attempted a live socket connection; offline verification must not touch the network
E           Failed: the offline checker attempted a network connection while verifying the content_erasure fixture: ...
E           Failed: the offline checker attempted a network connection while verifying the fault fixture: ...
E           Failed: the offline checker attempted a network connection while verifying the policy_allow fixture: ...
E           Failed: the offline checker attempted a network connection while verifying the policy_deny fixture: ...
```

All four parametrized cases fail with the named `NetworkAccessAttempted`
path. Reverted, green again.

---

## 5. P3a-4. Tampering fails with a named error

**Verdict: met.**

### The byte sweep

`tools/bundle_byte_sweep.py`, rerun against the bundle format rather than the
raw proto as the item requires. Baseline untampered bundle verifies.

**Pass 1, printable rotation over the bundle file (3513 bytes).** A rotation
that keeps the file valid UTF-8, so the sweep measures the format's own
coverage rather than JSON's:

| Result | Count | Example |
| :--- | ---: | :--- |
| `consistency_failure` | 1183 | offset 165: inclusion or dual proof rejected |
| `record_mismatch` | 700 | offset 298: `record.value` differs from the proven entry |
| `malformed_bundle` | 510 | offset 5: unsupported `bundle_format` |
| `no_effect` | 452 | offset 49 |
| `not_json` | 275 | offset 0 |
| `signature_failure` | 240 | offset 1114: trust anchor not signed by the supplied key |
| `key_mismatch` | 153 | offset 3317 |
| **Caught** | **3061 / 3513** | |

**Pass 1b, XOR 0xFF (the spike's own operator), same file.** 3513/3513
caught, all as `not_json`, because XOR on a UTF-8 text file breaks the
encoding before any semantic check runs. Reported separately rather than
headlined: a 100 percent figure here measures JSON's brittleness, not the
evidence format's strength, and quoting it as coverage would overstate the
result.

**Pass 2, sweep over the decoded `VerifiableEntry` (1406 bytes), re-encoded
into the bundle each time.** This is the honest measure of proof-material
coverage, directly comparable to the spike's 543/794:

| Result | Count |
| :--- | ---: |
| `consistency_failure` | 844 |
| `no_effect` | 280 |
| `malformed_bundle` | 124 |
| `record_mismatch` | 86 |
| `signature_failure` | 72 |
| **Caught** | **1126 / 1406** |

### Which bytes are semantically meaningful, and which are not

**Not every byte of a bundle is protected, and the format does not claim
otherwise.** The 452 inert bytes in pass 1 break down by field as follows,
and each group has a specific reason:

| Field | Inert bytes | Why |
| :--- | ---: | :--- |
| `proof.verifiable_entry` | 364 | Protobuf wire framing (tag bytes, varint length prefixes) and message fields that are not inputs to any digest or signature. Same finding as the spike's 251 no-effect offsets. |
| `exported_at` | 38 | Export-time metadata. Nothing signs it. |
| `exported_by` | 28 | Export-time metadata. Nothing signs it. |
| `proof.sdk` | 19 | A claim the exporter makes about itself. |
| `record.ledger_key` | 1 | Base64 trailing-bit artifact, see below. |
| `proof.source_state.tx_hash` | 1 | Base64 trailing-bit artifact, see below. |
| `proof.source_state.signature` | 1 | Base64 trailing-bit artifact, see below. |

The three single-byte entries are not gaps. A 32-byte value base64-encodes
to 44 characters, and the last data character carries only 2 significant
bits; the other 4 are unused. Verified directly for
`proof.source_state.tx_hash`: position 42 of 44 is the only position where a
different base64 character decodes to identical bytes. The decoded bytes do
not change, so there is nothing for a proof to catch. This is a property of
base64, not of the evidence format.

`exported_at`, `exported_by` and `proof.sdk` are the genuinely unprotected
semantic fields. They are export-time metadata that no signature covers, and
rewriting them leaves a bundle that still verifies. This is stated in
`readME.md`'s Residual Limits and in ADR-0010's Consequences rather than
left for a reader to discover, because a file that verifies cryptographically
invites the assumption that everything in it was verified.

Everything a proof or signature actually covers is bound and checked: the
record bytes, the ledger key, the transaction id, the timestamp, the
record-type label, the proof material, and the trust anchor.

### Three checks the byte sweep found rather than confirmed

The sweep was run as a discovery tool, not a victory lap, and it found three
real holes that are now closed:

1. Relabelling `record.record_type` from `policy_allow` to `policy_deny` left
   a bundle that still verified. The label is not an input to any proof. The
   checker now derives it from the proven bytes and compares.
2. Every byte of `proof.signing_key_fingerprint` was inert, because only the
   outer `signing_key.fingerprint` copy was read. The two copies must now
   agree.
3. Treating `tx_id`, `timestamp` and `record_type` as optional was a bypass:
   corrupting one byte of a field *name* makes the value unreachable, and a
   check that skips an absent claim then passes. Every field the format
   defines is now required.

A fourth finding was a robustness bug rather than a coverage hole:
`immudb-py`'s `embedded/store/tx.py::Alh()` calls `sys.exit()` on an
unrecognised transaction header version, and one corrupted byte reaches it.
`SystemExit` is a `BaseException`, so the checker would have terminated
rather than reported. It is now caught explicitly and reported as
`malformed_bundle`. A file under examination must never be able to end the
process examining it.

### Pass 3, targeted field-level tamper

```
record.value, byte 0 flipped                   -> record_mismatch
record.ledger_key, byte 0 flipped              -> consistency_failure
record.tx_id, incremented                      -> record_mismatch
record.record_type, relabelled                 -> record_mismatch
record.timestamp, incremented                  -> record_mismatch
exported_at, rewritten                         -> no_effect
exported_by, rewritten                         -> no_effect
proof.verifiable_entry entry.value, byte 0     -> consistency_failure
proof.source_state.tx_hash, byte 0 flipped     -> signature_failure
proof.source_state.signature, byte 0 flipped   -> signature_failure
proof.source_state.tx_id, set to 0 (genesis)   -> signature_failure
proof.source_state.db, renamed                 -> signature_failure
proof.prove_since_tx, incremented              -> record_mismatch
proof.entry_tx_id, incremented                 -> record_mismatch
proof.sdk, rewritten                           -> no_effect
signing_key.fingerprint, byte flipped          -> key_mismatch
```

### Enforcing tests

The four the item names, each asserting a specific `result_class` and never a
broad exception:

| Case | Test | Asserts |
| :--- | :--- | :--- |
| Flipped record byte | `test_flipped_record_byte_fails_as_record_mismatch` | `RECORD_MISMATCH` |
| Flipped proof byte | `test_flipped_proof_byte_fails_as_consistency_failure` | `CONSISTENCY_FAILURE` |
| Substituted state | `test_substituted_state_fails_as_signature_failure` | `SIGNATURE_FAILURE` |
| Wrong key fingerprint | `test_wrong_key_fingerprint_fails_as_key_mismatch` | `KEY_MISMATCH` |

Plus `test_anchor_substituted_with_an_unsigned_genesis_state_is_refused`,
which closes a downgrade the SDK alone would not catch: `verifiedGet.call()`
runs `VerifyDualProof` only when `state.txId > 0`, so an anchor substituted
with the genesis state would skip the consistency proof entirely and still
return `verified=True`.

`test_no_tamper_test_accepts_a_broad_exception` enforces the "no broad
exception" property over the module's own AST: every `pytest.raises` must
name `BundleCheckFailed` or `NetworkAccessAttempted`, and every test using
the former must assert on `result_class`. The property is enforced rather
than asserted, so widening any assertion is caught mechanically.

### Mutation

Widened `test_flipped_record_byte_fails_as_record_mismatch` to
`pytest.raises(Exception)` and dropped its `result_class` assertion.

```
E       AssertionError: tamper tests must name the specific failure they expect, never a broad exception: ['test_flipped_record_byte_fails_as_record_mismatch: pytest.raises(Exception)']
E       assert not ['test_flipped_record_byte_fails_as_record_mismatch: pytest.raises(Exception)']
FAILED tests/test_offline_verify.py::test_no_tamper_test_accepts_a_broad_exception
1 failed, 1 passed, 32 deselected, 1 warning in 3.19s
```

The mutated test itself still passed, which is exactly why the meta-test
exists. Reverted, green again.

---

## 6. P3a-5. The key is independent of the bundle

**Verdict: met.**

`--key` is a required command-line argument. `load_key()` is the only
function that constructs a verifying key, and it reads the path it was
handed. No bundle field is consulted.

### Demonstration

Both cases the item names, distinguished:

- **A bundle naming a key the checker does not hold** is refused as
  `key_mismatch`, *before any proof runs*. Byte sweep pass 3:
  `signing_key.fingerprint, byte flipped -> key_mismatch`. This is
  deliberately a different result class from a tampered bundle, because "you
  are holding the wrong key" and "this evidence was altered" call for
  different responses from whoever reads the result.
- **A bundle verified against the wrong key** fails as `signature_failure`.
  An attacker who rewrites the fingerprint to name a key the checker does
  hold gets past the identity comparison and then fails ECDSA verification of
  material the real key signed. This is what stops the fingerprint from
  becoming a self-certifying substitute for the key.

### Enforcing tests

- `test_a_bundle_carrying_its_own_key_still_cannot_certify_itself` builds a
  bundle with every field a self-certifying bundle would need (a PEM of the
  real key, its DER, and a `public_key` on the source state), checks it while
  holding a *different* key, and requires `KEY_MISMATCH`.
- `test_a_refingerprinted_bundle_fails_at_the_signature_not_the_fingerprint`
  requires `SIGNATURE_FAILURE`, not `KEY_MISMATCH`, so the two failures
  cannot be collapsed.
- `test_no_fixture_bundle_contains_key_material` scans the committed
  artifacts for PEM armour, the DER encoding, and the raw point encoding.
- `test_the_checker_loads_a_key_only_from_the_path_it_was_given` walks the
  AST and requires that `from_pem` / `from_der` / `from_string` /
  `from_public_point` appear in `load_key` and nowhere else, and that
  `load_key` never references `bundle`.

`tests/fixtures/evidence_bundles/other-signing.pub` is a genuinely unrelated
P-256 key pair, so "the checker was handed the wrong key" is a real different
key rather than a corrupted copy of the right one. Only the public half is
committed.

### Mutation

Made `verify_bundle` prefer a PEM embedded in the bundle when one is present.

```
E       Failed: DID NOT RAISE <class 'ail_verify_bundle.BundleCheckFailed'>
E       AssertionError: a verifying key is constructed outside load_key(), in ['load_key', 'verify_bundle']; load_key is the only function that reads a key, and it reads it from the --key path, never from the bundle
E       assert ['load_key', 'verify_bundle'] == ['load_key']
FAILED tests/test_offline_verify.py::test_a_bundle_carrying_its_own_key_still_cannot_certify_itself
FAILED tests/test_offline_verify.py::test_the_checker_loads_a_key_only_from_the_path_it_was_given
2 failed, 32 deselected, 1 warning in 3.81s
```

Both halves fail: the behavioural test (the self-certifying bundle verified,
so nothing was raised) and the structural one. Reverted, green again.

---

## 7. P3a-6. Documentation and claim mapping

**Verdict: met.**

`docs/adr/0010-portable-evidence-bundles.md` covers D18 through D20, records
the `state.publicKey` finding and why the key stays out of the bundle, and
documents the two checks the offline checker performs that the live verifier
does not.

`readME.md` gains §3.4.1, which states what a bundle proves and what it does
not, and preserves rather than blurs the §3.4 distinction: a bundle proves a
record was committed and unaltered, not that the policy which approved it was
correct. Residual Limits gains two entries.

### Mapping

Every new or changed claim, derived per row.

| Location | Claim | Maps to |
| :--- | :--- | :--- |
| README §3.4.1, "one JSON file for one ledger record" | Bundle is a single self-describing file | `tests/fixtures/evidence_bundles/*.json`; `control_plane/main.py::get_audit_bundle` |
| README §3.4.1, `GET /audit/bundle` route and parameter | Export endpoint exists and takes a base64 ledger key | Section 3 above (live, five record types); `tests/test_evidence_bundle.py::test_bundle_exported_for_a_policy_allow` |
| README §3.4.1, "behind the same read credential `GET /audit` already requires" | Authorization is not new or looser | `tests/test_evidence_bundle.py::test_bundle_export_requires_the_read_credential`, `..._not_reachable_with_the_write_credential_alone`; live probe in section 3 |
| README §3.4.1, "every record shape exports the same way" | No per-type branch | Five types exported live, section 3; four enforcing tests, one per type |
| README §3.4.1, "`GET /audit` reports each entry's `ledger_key`" | The two routes compose | `control_plane/main.py` `get_audit` entry dict; exercised by every export test, which reads the key from `/audit` |
| README §3.4.1, the `ail_verify_bundle.py` command block | Reproducible command | `tests/test_offline_verify.py::test_readme_command_block_is_exactly_reproducible` (P3a-9, Phase 3a completion pass - extracts and runs the literal command as a subprocess; previously live-transcript-only, see `docs/reports/phase-3a-completion.md`) |
| README §3.4.1, "No Docker, no ImmuDB, no control plane, no network" | Offline verification | `tests/test_offline_verify.py::test_fixture_bundle_verifies_offline_with_no_network`; section 9 |
| README §3.4.1, "replaces `socket.socket.connect` ... property of the process" | The block is structural, not incidental | `tests/test_offline_verify.py::test_the_network_block_is_actually_installed`, `..._merely_importing_the_checker_blocks_the_network` |
| README §3.4.1, "No cryptography is implemented in the checker" | D20 compliance | `tests/test_offline_verify.py::test_the_checker_implements_no_cryptography_of_its_own` (AST); import list in section 4 |
| README §3.4.1, "the key is never inside the bundle" | D18 key exclusion | `tests/test_offline_verify.py::test_no_fixture_bundle_contains_key_material`, `..._the_checker_loads_a_key_only_from_the_path_it_was_given` |
| README §3.4.1, `key_mismatch` distinct from a checked-and-failed bundle | Two situations stay distinguishable | `test_wrong_key_fingerprint_fails_as_key_mismatch` vs `test_a_refingerprinted_bundle_fails_at_the_signature_not_the_fingerprint` |
| README §3.4.1, the five-result closed set | Failure names which check failed | `tools/ail_verify_bundle.py::RESULT_CLASSES`; every tamper test asserts one member |
| README §3.4.1, "the same distinction `/audit` already draws in `error_class`" | Vocabulary aligns, nothing renamed | `docs/adr/0006-verification-states.md`; `verifier/main.py`'s `error_class`, unchanged this phase |
| README §3.4.1, "what a bundle proves is exactly what §3.4 says" | The §3.4 distinction is not blurred | README §3.4, unchanged this phase; Residual Limits §5 bullet added this phase |
| README §5 Residual Limits, "a bundle of a forged record" | Portability does not fix provenance | Residual Limits entry (this is the claim's own home); `docs/adr/0010-portable-evidence-bundles.md` Consequences |
| README §5 Residual Limits, "export metadata not covered by any proof" | `exported_at`, `exported_by`, `proof.sdk` are inert | Byte-sweep table, section 5 above (per-field counts); `tools/bundle_byte_sweep.py` pass 3 |
| README §6, ADR-0010 summary paragraph | Summary matches the ADR | `docs/adr/0010-portable-evidence-bundles.md` |
| ADR-0010 D18, the spike-item-to-field table | Field list derived from the spike, not invented | `tests/test_evidence_bundle.py::_SPIKE_REQUIRED_MATERIAL`, transcribed from spike item 2 |
| ADR-0010 D18, "material exported only for a check that passed" | No material for a failed check | `tests/test_evidence_bundle.py::test_no_proof_material_is_exported_for_a_record_that_did_not_verify` |
| ADR-0010 D18, "reconstructing the anchor with `publicKey=b""` verifies identically" | The dropped field is genuinely unread | `tools/ail_verify_bundle.py` sets `publicKey=b""`; all 4 fixtures verify, `test_fixture_bundle_verifies_offline_with_no_network` |
| ADR-0010 D19, "raw ImmuDB key rather than a `call_id`" | One identifier for every record shape | Five record types through one code path, section 3 |
| ADR-0010 D20, the shim mechanism | Spike's `FakeStub`/`FakeRootService` reused, not reimplemented | `tools/ail_verify_bundle.py::_BundleStub`, `_BundleRootService`; `spikes/offline-verify/verify_offline.py` |
| ADR-0010, "trust anchor is verified before it is used" | A check the live verifier does not perform | `test_substituted_state_fails_as_signature_failure`, `test_anchor_substituted_with_an_unsigned_genesis_state_is_refused` |
| ADR-0010, "the readable copy is bound to the proven record" | Editing the display copy is caught | `test_flipped_record_byte_fails_as_record_mismatch`, `test_relabelled_record_type_fails_as_record_mismatch`, `test_relabelled_timestamp_fails_as_record_mismatch` |
| ADR-0010, "every field the format defines is required" | An absent claim is a refusal, not a bypass | `test_deleting_any_required_field_is_refused` (parametrized) |
| ADR-0010, "a dependency can no longer end the checking process" | `SystemExit` from `Alh()` is caught | `test_a_corrupted_transaction_header_is_reported_not_fatal` |
| ADR-0010, "the checker is pinned to one SDK version" | Version recorded in the material | `proof_material.sdk` in the live response, section 2; `verifier/main.py::SDK_IDENTIFIER` |
| ADR-0010, "a bundle can outlive its key" | Fixtures carry their own `signing.pub` | `tests/fixtures/evidence_bundles/README.md`; `PROVENANCE.json`; Residual Limits (rotation not exercised) |
| ADR-0010, "duplicates two small things on purpose" | Copies are held in agreement by tests | `test_fixture_bundle_verifies_offline_with_no_network` compares the tool's derived label against the control-plane-exported fixture's label |
| `tests/fixtures/.../README.md`, "regenerating" command block | Reproducible command | `tools/export_evidence_fixtures.py`; `PROVENANCE.json` |

---

## 8. What had to be fixed in the staged work

The changeset was inherited already staged and largely correct. Four defects
were found and fixed; each is recorded because the report is worth less if it
only lists what worked.

### 8.1 The offline suite disabled the network for the whole pytest session

**The most serious defect, and one neither new test file would have caught.**
`tools/ail_verify_bundle.py` blocks `socket.socket.connect` at import, which
is correct and is the D19 property. But `tests/test_offline_verify.py`
imported it at module scope and never lifted the block, and pytest imports
every test module during collection, before running any test. The block was
therefore still in force when the rest of the suite ran.

Running the full `tests/` directory the way CI does:

```
51 failed, 113 passed, 43 skipped in 219.29s
FAILED tests/test_verification.py::test_parity - ail_verify_bundle.NetworkAcc...
FAILED tests/test_verification.py::test_tamper_state - ail_verify_bundle.Netw...
... 49 more across test_dashboard_auth, test_epic_2, test_outcome_types, ...
```

This would have failed CI immediately. Fixed by containing the side effect
rather than weakening it: the real `connect` is captured before the checker
is loaded and restored immediately after, and an autouse fixture reinstalls
the block for every test in that module and restores it afterwards. The tool
itself is unchanged, so the D19 property is intact.

To make sure the containment did not silently remove the property being
tested, a new test was added:
`test_merely_importing_the_checker_blocks_the_network` loads the module afresh
with a real `connect` in place and asserts the import alone replaced it. Net
assertions went up, not down.

### 8.2 The live suite could not reach the stack it drives

`tests/test_evidence_bundle.py` loads the decision service in-process on the
host but only pointed `OPA_URL` at the published loopback port.
`ledger/immudb_ledger.py` and `ledger/content_store.py` default to the compose
service names (`http://verifier:8003`, `http://ail-control-plane:8002`), which
do not resolve from the host, so three tests got a fault record with
`fault_class: content_store_unreachable` or `verifier_unreachable` instead of
the decision they asked for: a real fail-closed response to a real outage,
just not the outage under test. Fixed with `os.environ.setdefault` for
`VERIFIER_URL`, `CONTROL_PLANE_URL` and `CONTROL_PLANE_WRITE_KEY`.
`setdefault`, so CI's own `make test-integration` environment still wins.

The same latent gap was fixed in `tools/export_evidence_fixtures.py`, which
`tests/fixtures/evidence_bundles/README.md` documents as the reproducible
regeneration command.

### 8.3 A synthetic test record claimed a label it did not support

`_fresh_record` wrote `{"record_type": "decision", ...}`, but `decision` is
not in the closed set `record_type_of` recognises, so the checker correctly
derived `unknown` and
`test_exported_material_actually_completes_an_offline_check` failed with
`record_mismatch`. The checker was right and the test's claim was wrong.
Fixed by writing a record that genuinely is one of the closed-set shapes
(`outcome_type: policy_allow`) and claiming that label literally, which also
makes the round trip exercise a real derivation instead of `unknown`.

### 8.4 One em dash

`control_plane/main.py`'s endpoint list. Replaced with a hyphen. The staged
changeset contained exactly one, verified by scanning every added line.

### Not a defect: a stale container token

The first run of the live suite failed all 16 stack tests with
`PERMISSION_DENIED: token has expired`. The `p3a-bundle` containers had been
up for two days and the verifier's ImmuDB session token had expired. A
restart cleared it. This is a pre-existing property of the verifier's session
handling, unrelated to D18 through D20, and is noted here rather than fixed
because fixing it would be a design change outside this phase's scope.

---

## 9. P3a-3 demonstration: verification with the stack torn down

Reproducing the spike's method. The stack was removed, not merely stopped:

```
docker compose -p p3a-bundle -f docker-compose.test.yml down -v
 Volume p3a-bundle_test-control-plane-data Removed
 Volume p3a-bundle_test-immudb-data Removed
 Volume p3a-bundle_test-verifier-state Removed
 Network p3a-bundle_default Removed

docker ps -a --filter "name=p3a-bundle" --format "{{.Names}}"
(no output, no containers exist)
```

All four fixture bundles then verified, with `socket.socket.connect`
replaced by a raiser inside the checking process:

```
--- policy_allow ---
OK [verified]
  ledger key   : tool_call:p3a_fixture_96d87a2f:199954d3aedf4c86aede93da9da23fe8:provision_cloud_server
  record type  : policy_allow
  transaction  : 1 (proven against trust anchor at tx 4)
  signing key  : sha256:cc837c537fe429fa4c565919004bd8a799a55e525aa639a669052647b719d6f8
EXIT=0
--- policy_deny ---
OK [verified]  record type: policy_deny   transaction: 2 (anchor tx 4)   EXIT=0
--- fault ---
OK [verified]  record type: fault         transaction: 3 (anchor tx 4)   EXIT=0
--- content_erasure ---
OK [verified]  record type: content_erasure  transaction: 4 (anchor tx 4)  EXIT=0

### offline suite, stack removed ###
35 passed, 1 warning in 4.46s
```

Each record is proven against a trust anchor at a later transaction, so the
dual consistency proof is exercised rather than skipped. The whole suite runs
in under five seconds with no stack in existence.

The CLI also prints the scope of what it just proved, so a reader of the
output cannot come away with a larger claim than the evidence supports:

```
This bundle proves the record above was committed to the ledger and has
not been altered since. It does not prove the policy that produced the
record was correct, nor that the writer was honest. See readME.md 3.4.
```

---

## 10. The eight pre-registered negatives

Each confirmed individually, with its own evidence.

### N1. Any reimplemented cryptographic primitive: **false**

`tools/ail_verify_bundle.py`'s complete import list (section 4) contains
`ecdsa`, `immudb.*` and `google.protobuf` only. No `hmac`, `Crypto`,
`cryptography`, `nacl`, or `hashes`. `hashlib` appears at two lines, both
inside `key_fingerprint()`, deriving an identifier no proof result depends
on. Enforced mechanically by
`test_the_checker_implements_no_cryptography_of_its_own`, which also requires
`verifiedGet.call(` to still be present, so verification cannot be quietly
replaced. `verifier/main.py`'s only added hash is the same fingerprint
derivation.

### N2. Any network access during verification: **false**

`block_network()` runs at import of the checker. The offline suite verifies
all four fixtures with the block live, and section 9 repeats it with every
container removed. The M3 mutation confirms an attempted connection is
caught rather than tolerated. Evidence that the block is real and not a
no-op: `test_the_network_block_is_actually_installed` opens a socket and
requires `NetworkAccessAttempted`.

### N3. Any key material inside a bundle: **false**

Scanned all four committed bundles for PEM armour, the DER SubjectPublicKeyInfo
encoding, and the raw point encoding of the key they were exported against:
zero matches in every file. No bundle's `source_state` carries a `publicKey`
or `public_key` field. The live `/verify` response carries no key either
(section 2). Enforced by `test_no_fixture_bundle_contains_key_material`.

### N4. Any tamper test asserting a broad exception: **false**

Scanned both new test files: the only `except Exception` occurrences are the
three service-availability probes in `tests/test_evidence_bundle.py` (lines
113, 120, 128), which decide whether to skip and assert nothing. Every
`pytest.raises` in `tests/test_offline_verify.py` names `BundleCheckFailed`
or `NetworkAccessAttempted`, and every tamper test asserts on `result_class`.
Enforced over the module's own AST by
`test_no_tamper_test_accepts_a_broad_exception`, and the M4 mutation confirms
that enforcement bites.

### N5. Any bundle export reachable without the read credential: **false**

Live probes against the running control plane: `422` with no header, `403`
with a wrong key, `403` with the *write* key. The route declares
`Depends(_require_read_key)`, the same dependency `GET /audit` uses. The M2
mutation confirms removing it is caught by two named tests.

### N6. Any claim not in the mapping: **false**

The mapping in section 7 has a row per new or changed claim, derived per row
rather than asserted over the set. Coverage was determined by reading the
complete diff of `readME.md` (three added blocks: §3.4.1, two Residual Limits
bullets, and the ADR-0010 summary in §6) and of
`docs/adr/0010-portable-evidence-bundles.md`, and giving each substantive
claim its own row.

### N7. Any assertion weakened: **false**

No assertion in any pre-existing test was changed. Within this phase's own
new tests, the only assertion-affecting edit was §8.3, which made a test's
claim *match* the closed set instead of asserting a label the data did not
support, and made the comparison exercise a real derivation rather than
`unknown`. Section 8.1 added an assertion rather than removing one. All five
mutations were reverted and verified absent by grepping for `MUTATION` across
every touched file.

### N8. Any item met by live evidence alone with no test enforcing it: **false**

Each of P3a-1 through P3a-5 has both halves, and each enforcing test was
proven to bite by its own named mutation:

| Item | Live demonstration | Enforcing test | Mutation confirmed |
| :--- | :--- | :--- | :--- |
| P3a-1 | §2, tx 309 behind anchor 312 | `test_exported_material_actually_completes_an_offline_check` and 5 others | Yes, M1 |
| P3a-2 | §3, five record types | 4 per-type tests, 2 credential tests | Yes, M2 |
| P3a-3 | §9, stack torn down | `test_fixture_bundle_verifies_offline_with_no_network` (x4) | Yes, M3 |
| P3a-4 | §5, byte sweep | 4 named tamper tests plus the AST meta-test | Yes, M4 |
| P3a-5 | §6, both key cases | 4 tests, behavioural and structural | Yes, M5 |

---

## 11. Could not verify

Honest limits of this pass.

- **`verifiedSet`'s write-path proof was not exported or replayed offline.**
  The spike left this open and this phase did not close it. `/verify` and the
  bundle cover the read path (`verifiedGet` / `VerifiableEntry`). The write
  path calls the identical `store.VerifyInclusion` and
  `store.VerifyDualProof` on a `VerifiableTx`, so the same separability
  argument applies by inspection, but it was not independently exercised.
- **Signing-key rotation was not exercised.** Inherited from ADR-0001's own
  backlog and from the spike. A checker handed a stale key gets an opaque
  signature failure. `key_mismatch` improves on this when the fingerprint
  differs, but rotation itself was not tested.
- **Long consistency-proof chains were not exercised.** The fixtures span a
  four-transaction database, and the live demonstration a few hundred. A
  chain spanning a large archive, or a database with expirations, was not
  tested.
- **The byte sweep is single-byte only.** Coordinated multi-byte edits, in
  particular an edit that adjusts a protobuf length prefix along with its
  payload, were not swept. The field-level pass 3 partially covers this by
  tampering through the protobuf API, but no multi-byte sweep was run.
- **The fixtures' provenance is evidenced, not independently reproduced from
  scratch this pass.** `PROVENANCE.json` records generation at
  2026-08-21T15:56:43Z by `tools/export_evidence_fixtures.py`, the file
  mtimes agree, and the bundles pass real cryptographic verification against
  real captured proofs, which fabricated bytes could not. The
  `--no-cache` rebuild plus regeneration cycle was not rerun from a clean
  database this pass; the existing fixtures were verified rather than
  replaced.
- **CI runs on Linux; this pass ran on Windows.** The `os.memfd_create`
  divergence noted in project memory does not touch this phase, but the
  offline checker was only exercised on one platform locally.

---

## 12. CI

**PR:** https://github.com/banji-007/compliance-ail/pull/9
**CI run id:** `32718536458`
(https://github.com/banji-007/compliance-ail/actions/runs/32718536458)
**Result: green.** `199 passed, 9 skipped, 1 warning in 37.36s`

The run exercises both new files against a stack built from scratch
(`make test-integration` does `down -v`, `make keygen`, `up -d --build
--wait`), so the fixtures are verified against a signing key CI generated
fresh and which is *not* the key the fixtures were exported against. That is
the point of committing `tests/fixtures/evidence_bundles/signing.pub`
alongside them: the offline tests use the fixture key, and the live tests use
`keys/signing.pub`, and the two never have to be the same. A bundle
outliving the key of the system that is running today is the ordinary case
for an auditor, not an edge case.

The PR is left open for human review and was not merged.
