# Phase 3b: Writer Signing and External Anchoring

Run id: `p3b-provenance`
Branch: `phase-3b-provenance`
Working directory: a `git worktree` under this session's scratchpad, not the
primary working directory. Removed after this report; see Cleanup.

**Verdict: all six items met.** Every record now says which key wrote it, and
a bundle's dual proof runs to a checkpoint that exists in a public
transparency log rather than to a state on a volume inside the deployment
being audited. Both are checkable offline, in one command, against keys the
checker holds and a bundle never carries.

Design decisions are recorded in
`docs/adr/0012-writer-signing-and-external-anchoring.md`, including all three
statements D22 requires and both D23 requires.

---

## Item verdicts

### P3b-1. The export anchors at the checkpoint, not at whatever the verifier held

**Met.**

**Demonstrate.** `POST /verify` takes an optional `anchor`. The verifier
reconstructs it as an `immudb.rootService.State`, verifies its ECDSA
signature against the ImmuDB public key on its own volume, and drives
`immudb.handler.verifiedGet.call()` through a `_PinnedRootService` pinned at
that state, so `proveSinceTx` is the checkpoint's transaction. All three
shapes the item names are in the committed fixtures, produced by a real run
rather than constructed:

| Fixture | Record tx | Proof runs to | Shape |
| :--- | ---: | ---: | :--- |
| `policy_allow.json` | 1 | 2 | record older than the anchor |
| `policy_deny.json` | 2 | 2 | record at the anchor itself |
| `fault.json` | 3 | 4 | no anchor covers it; falls back to the verifier's state |
| `content_erasure.json` | 4 | 4 | same |

```
$ python tools/ail_verify_bundle.py tests/fixtures/evidence_bundles/policy_allow.json \
    --key .../signing.pub --writer-key .../writer-decision.pub \
    --writer-key .../writer-control-plane.pub \
    --trusted-root .../trusted_root.json --anchor-key .../anchor-signing.pub
OK [verified]
  ledger key   : tool_call:...:provision_cloud_server
  record type  : policy_allow
  transaction  : 1 (proven against trust anchor at tx 2)
  written by   : sha256:c770706648326c5c1d13656e63a4de08c1020fcbddd332e978c75655be30560f
  corroboration: anchored in https://log2025-1.rekor.sigstore.dev at index 79224227,
                 inclusion proof and checkpoint verified
```

`policy_deny` is the boundary case (`transaction : 2 ... trust anchor at tx 2`).

**Enforce.**
`tests/test_anchored_export.py::test_the_proof_runs_to_the_supplied_anchor_and_not_the_verifiers_own_state`
constructs the one situation that distinguishes the two anchors - a
checkpoint strictly between the record and the verifier's own state - and
asserts `prove_since_tx` and `source_state.tx_id` are the checkpoint's and
not the held state's.
`tests/test_external_anchor.py::test_an_anchored_bundles_proof_runs_to_the_anchored_checkpoint`
asserts the same property offline against the committed artifacts, where the
anchored fixtures and the unanchored ones name provably different
transactions.

The rejected direction has two tests, at two layers.
`test_a_dual_proof_is_rejected_when_the_source_is_newer_than_the_target`
drives the SDK's own `store.VerifyDualProof` over a real captured proof with
the ends swapped and asserts it returns `False`.
`test_an_anchor_older_than_the_record_is_refused_by_name` asserts the
endpoint refuses that pair with `error_class: anchor_precedes_record` rather
than letting it silently invert into a proof that says nothing about
corroboration. `test_an_anchor_immudb_never_signed_is_refused_before_any_proof_runs`
and `test_verifying_against_an_anchor_does_not_move_the_verifiers_own_state`
cover the two other ways a supplied anchor could do harm.

**Mutation.** In `verifier/main.py`, replaced `root_service =
_PinnedRootService(source_state)` with `root_service = client._rs;
source_state = client._rs.get()` - reverting to anchoring at the verifier's
held state - and rebuilt the container.
`test_the_proof_runs_to_the_supplied_anchor_and_not_the_verifiers_own_state`
**failed**, along with four others as collateral (the mutation also lets an
anchored read advance the persisted state, which the fallback and unanchored
paths then observe). Reverted, rebuilt, 17/17 green.

### P3b-2. The decision service signs records

**Met.**

**Demonstrate.** `provenance/record_signature.py` canonicalizes a record -
sorted keys, no whitespace, ASCII escapes, signature field excluded - and
signs it with RFC 6979 deterministic ECDSA over P-256.
`ledger/immudb_ledger.py` calls it immediately before `json.dumps`, so the
signature is a field inside the record and goes to ImmuDB with everything
else. A real committed record:

```json
{"record_type":"decision","agent_id":"...","tool_name":"provision_cloud_server",
 "outcome_type":"policy_allow", ...,
 "writer_signature_format":"ail-record-signature/1",
 "writer_key_fingerprint":"sha256:c770706648326c5c1d13656e63a4de08c1020fcbddd332e978c75655be30560f",
 "writer_signature":"MEUCIQCtHc27UOqUavM1dFHs/a/o+RnkIxl57H8IJSEe4Kuy9AIgRVCF5yFrJ4ut331AGshgKbLe0GOLVgmkDQJto0uoxVg="}
```

Determinism is shown by signing the same record twice, in two different key
orders, and comparing bytes -
`tests/test_writer_signing.py::test_signing_the_same_record_twice_produces_identical_bytes`.
Two things have to hold for that comparison to mean anything and both are
asserted separately: the canonical bytes are stable across dict ordering,
and the ECDSA signature over them is deterministic. Plain ECDSA is
randomised, so without `sign_deterministic` the second signature would differ
while still being valid and "identical" would be the wrong test to write.

**Enforce.**
`test_the_signature_covers_the_recorded_bytes_and_not_some_other_sequence`
recomputes the canonical bytes through the **checker's** independent copy of
the rule and verifies the recorded signature against them - the two
implementations are held in agreement by that assertion rather than by an
import.
`test_a_modified_record_fails_the_writer_signature` and
`test_adding_a_field_to_a_record_fails_the_writer_signature` cover
modification in both directions.
`test_a_record_with_no_writer_signature_is_refused_not_accepted` and
`test_a_record_with_no_fingerprint_is_refused` cover the
unsigned-and-fine case, and
`tests/test_anchored_export.py::test_an_unsigned_record_committed_to_the_ledger_is_refused_not_accepted`
covers it against a record that really is in the ledger and really does pass
every ImmuDB proof.
`test_the_decision_service_refuses_to_write_a_record_it_cannot_sign` covers
the fail-closed half at the writer.

**Mutation.** In `provenance/record_signature.py::sign_record`, signed
`canonical_record_bytes(signed) + b"-not-the-recorded-bytes"`.
`tests/test_anchored_export.py::test_a_record_written_through_the_real_path_carries_a_verifiable_signature`
**failed**, with `writer_signature_failure: the writer signature does not
verify against sha256:c7707066...`. Reverted, both tests green.

### P3b-3. The checker verifies the writer, and the key stays out of the bundle

**Met.**

**Demonstrate.** `tools/ail_verify_bundle.py` takes `--writer-key`
(repeatable) and an optional `--writer-deny-list`. The bundle carries the
signature and the fingerprint; the checker holds the keys. Four distinct
refusals, because they call for four different responses:

| Situation | Result class |
| :--- | :--- |
| Correct key held, signature verifies | `verified`, and the result names the writer |
| Key held, signature does not verify | `writer_signature_failure` |
| Fingerprint names a key not supplied | `writer_key_unknown` |
| Fingerprint is on the deny-list | `writer_key_revoked` |
| Record carries no signature at all | `writer_signature_missing` |

The deny-list refusal happens **whether or not the signature checks out** -
it does, in that test. That is the point: a revoked key's signatures remain
cryptographically valid, which is precisely why validity cannot be the whole
test.

**Enforce.** One test per row, each asserting a specific `result_class`:
`test_a_bundle_verifies_against_the_correct_writer_key`,
`test_repointing_the_fingerprint_at_a_key_you_hold_fails_at_the_signature`,
`test_a_record_naming_a_writer_key_the_checker_does_not_hold_is_refused`,
`test_a_record_signed_by_a_revoked_writer_key_is_refused`,
`test_a_record_with_no_writer_signature_is_refused_not_accepted`. Plus
`test_the_deny_list_is_refused_rather_than_skipped_when_malformed` (a hole in
a revocation list is indistinguishable from not revoking) and
`test_the_two_writers_are_distinguishable_by_the_key_that_signed` (two keys
rather than one is what makes the attribution say anything).
`test_no_test_in_this_file_accepts_a_broad_exception` enforces over the file
itself that no refusal test names a broad exception, the same way
`tests/test_offline_verify.py` does for Phase 3a.

**Mutation.** In `verify_writer_signature`, added a fallback that loads a key
from `record["writer_public_key_pem"]` when the fingerprint is not held.
`test_the_writer_check_reads_its_keys_from_the_supplied_map_only` **failed**,
and so did the static
`test_the_checker_still_loads_every_key_only_from_a_path_it_was_given`, which
detects the new `from_pem` call outside `load_key`. Reverted, 26/26 green.

### P3b-4. States are anchored in Rekor

**Met.**

**Demonstrate - live, command-backed, not a test.** One real submission to
the public instance, made by `tools/export_evidence_fixtures.py` during
fixture regeneration:

```
$ python tools/export_evidence_fixtures.py     # with the compose stack up
anchoring: building the one-shot image
anchoring: submitting to a Rekor v2 instance (network p3b-bundle_default)
INFO HTTP Request: GET http://verifier:8003/state "HTTP/1.1 200 OK"
INFO Anchoring tx=2 in https://log2025-1.rekor.sigstore.dev (discovered via trusted_root.tlogs)
INFO HTTP Request: POST https://log2025-1.rekor.sigstore.dev/api/v2/log/entries "HTTP/1.1 201 Created"
INFO HTTP Request: POST http://ail-control-plane:8002/anchors "HTTP/1.1 201 Created"
INFO Anchored tx=2 at log index 79224227 (store: {"recorded":true,"checkpoint_tx_id":2})
```

Self-managed key (`keys/anchor-signing.key`, never Fulcio), the
`hashedrekord` v0.0.2 mapping the spike used, and a URL discovered from
Sigstore's own TUF-distributed configuration. The returned inclusion proof
and witnessed checkpoint are persisted verbatim in the control plane's
anchor store and travel in the bundle.

**This row is a command-backed claim, not a test.** `anchor-service` is
deliberately absent from `docker-compose.test.yml`, and nothing in the suite
submits to a public log: doing so would make CI depend on a shared public
service and on CI having egress. Re-running the command above makes a real
entry in a real public log, and should not be run in a loop.

**Demonstrate - offline verification.** The entry that submission returned is
committed and is verified offline with `sigstore-python`'s own
`verify_merkle_inclusion` and `verify_checkpoint`, reached through
`TransparencyLogEntry._verify`, against the TUF-fetched `trusted_root.json`
committed beside it. `sigstore` is imported inside `verify_external_anchor`,
**after** the socket block is already installed, so the anchor check has to
prove it needs no network rather than be trusted not to use one.

**Enforce.**
`tests/test_external_anchor.py::test_an_anchored_bundle_verifies_its_log_entry_offline`
is the fixture-proof test, and
`test_the_checker_attempts_no_network_while_checking_an_anchored_bundle`
asserts the block is live in the process (a socket raises) before checking
anything, so a pass cannot be explained by a machine that happened to have
no route out.

Two further tests cover the binding that makes an entry mean anything for
*this* bundle.
`test_a_real_log_entry_about_a_different_state_does_not_corroborate_this_one`
pastes a genuine, fully verifiable entry into a bundle it has nothing to do
with - every signature valid, inclusion proof sound, checkpoint witnessed -
and it is refused, because the checker recomputes the anchored payload from
`proof.source_state` and requires the log's digest to be that payload's.
`test_an_anchor_naming_a_key_the_checker_does_not_hold_is_refused` keeps
"you do not hold this key" distinct from "this evidence was altered".
`test_an_anchored_bundle_is_not_quietly_passed_when_nothing_can_check_it`
asserts that an anchored bundle checked without a trust root is refused
(`anchor_unchecked`) rather than printed as `verified`, and that the explicit
opt-out reports itself as unchecked.

**Mutation.** Tampered the persisted root hash in the committed fixture
(`policy_allow.json`'s `inclusionProof.rootHash`, first byte flipped).
`test_an_anchored_bundle_verifies_its_log_entry_offline[policy_allow]`
**failed** with the specific error the item names:

```
anchor_failure: the transparency log's inclusion proof or signed checkpoint
was rejected by sigstore-python's own verification: inclusion proof contains
invalid root hash: expected ... root_hash=b'\x02K\xa1\xb1...' ...
calculated fd4ba1b17a9a47fb2849c11a2cc23c58991346b8dcf587e0453c895e044a1a96
```

Reverted, 27/27 green.

### P3b-5. Fail-open on the write path, fail-closed on the claim

**Met.**

**Demonstrate.** Anchoring is broken in the strongest available sense for the
whole integration suite: `anchor-service` is not in
`docker-compose.test.yml` at all. Under that condition writes succeed,
records are produced, and bundles export - two of the four committed
fixtures were produced that way. A bundle for a record no checkpoint covers
carries:

```json
"external_anchor": {
  "state": "not_anchored",
  "detail": "no checkpoint covering this record has been submitted to a public
             transparency log, so this bundle makes no claim of external
             corroboration. The local proof chain above is unaffected."
}
```

and an anchored one carries `"state": "anchored"` with the log URL, the log
index, the anchoring key fingerprint, and the entry. The two are
distinguishable by a **value**, not by a missing key: both bundles have the
same top-level key set and the same `state` key inside the section.

**Enforce.**
`tests/test_anchored_export.py::test_writes_continue_and_records_are_produced_with_anchoring_broken`
asserts the write path, and asserts `anchor-service`'s absence from the test
compose file directly, so a future edit that quietly added it turns this into
a test of nothing rather than passing anyway.
`test_a_bundle_for_an_unanchored_record_says_so_rather_than_omitting_it`
asserts the claim side live.
`tests/test_external_anchor.py::test_an_unanchored_bundle_states_its_lack_of_corroboration_in_a_field`,
`test_the_two_states_are_distinguishable_without_reading_an_absence`,
`test_a_bundle_that_omits_the_anchor_section_entirely_is_refused`, and
`test_an_unanchored_bundle_cannot_claim_corroboration_by_relabelling` cover
both states offline.
`test_the_anchor_loop_does_not_stop_on_a_failed_cycle` covers the fail-open
rule where it is actually implemented - the loop - by making a cycle raise
and asserting the next one still runs.

**Mutation.** In `control_plane/main.py::get_audit_bundle`, made the bundle
include `external_anchor` only when anchored, omitting it otherwise.
`test_a_bundle_for_an_unanchored_record_says_so_rather_than_omitting_it`
**failed** (plus two collateral, because the checker refuses a bundle with no
section at all). Reverted, rebuilt, 17/17 green.

### P3b-6. Documentation and claim mapping

**Met.** `docs/adr/0012-writer-signing-and-external-anchoring.md` covers D22
and D23. The required statements are present and are the substance of their
sections, not asides:

| Required statement | Where |
| :--- | :--- |
| D22: where the key is generated and stored, how it reaches the service | "Where the key is generated and stored, and how it reaches the service" - and it points explicitly at ADR-0010/ADR-0001's ImmuDB-key custody as the same mechanism, plus what a production deployment is replacing |
| D22: what happens on suspected compromise | "What happens on suspected compromise" - a fingerprint deny-list the checker consults, with the three properties that make it work and the rotation/revocation distinction |
| D22: SVID + trusted timestamping considered and rejected, why, and what reopens it | "SVID signing with trusted timestamping was considered and rejected" - three reasons, and the `attested` profile as the reopening condition |
| D23: named fail-open exception | "This is the project's first deliberate fail-open subsystem", with the fail-open/fail-closed split spelled out |
| D23: the arbitrary-pair capability is a seam, not an API, and what would detect it | "The arbitrary-pair capability is a seam, not an API", naming the test that asserts the seam's shape against the installed SDK |

`readME.md` gains §3.4.2 ("Provenance: Who Wrote It, and Who Else Saw the
Ledger"), which states what the chain proves as a table and then states what
it does not: a Rekor anchor proves a state existed at a point in a public
log; it does not prove the policy was correct, and it does not prove the
writer was honest, only which key signed. §5's fail-closed table gains the
one row that is not fail-closed, marked as such, with the exception written
out beneath it.

Residual Limits gains the three entries the item names: entry permanence
across a log turndown, that a compromised writer signs whatever it records,
and that the arbitrary-pair capability rests on a library seam. Phase 3a's
"provenance is Phase 3b's subject" bullet is closed rather than left
dangling.

---

## Claim mapping

Derived per row. Every new or changed claim maps to a test, a reproducible
command, or a Residual Limits entry.

| Claim | Backed by | Kind |
| :--- | :--- | :--- |
| Every record carries a writer signature over its own canonical bytes | `test_every_committed_record_carries_a_writer_signature`, `test_the_signature_covers_the_recorded_bytes_and_not_some_other_sequence` | test |
| The signature is inside the record, so the inclusion proof covers it | Byte sweep pass 3: every writer-field tamper returns `consistency_failure` from `store.VerifyInclusion` | test + command |
| Signing is deterministic | `test_signing_the_same_record_twice_produces_identical_bytes` | test |
| The signer's and the checker's canonicalization rules agree without sharing code | `test_the_signer_and_the_checker_hold_the_same_rule_without_sharing_code` | test |
| A modified record fails the signature | `test_a_modified_record_fails_the_writer_signature`, `test_adding_a_field_to_a_record_fails_the_writer_signature` | test |
| An unsigned record is refused, not accepted | `test_a_record_with_no_writer_signature_is_refused_not_accepted`, `test_an_unsigned_record_committed_to_the_ledger_is_refused_not_accepted` | test |
| A writer that cannot sign refuses to write | `test_the_decision_service_refuses_to_write_a_record_it_cannot_sign` | test |
| Two writers are distinguishable by key | `test_the_two_writers_are_distinguishable_by_the_key_that_signed` | test |
| A wrong key is a named signature failure | `test_repointing_the_fingerprint_at_a_key_you_hold_fails_at_the_signature` | test |
| An unheld key is distinct from a tamper | `test_a_record_naming_a_writer_key_the_checker_does_not_hold_is_refused` | test |
| A deny-listed key is refused | `test_a_record_signed_by_a_revoked_writer_key_is_refused` | test |
| No key material is in any bundle | `test_no_fixture_bundle_contains_writer_or_anchor_key_material` | test |
| The checker never takes a key from the bundle | `test_the_checker_still_loads_every_key_only_from_a_path_it_was_given`, `test_the_writer_check_reads_its_keys_from_the_supplied_map_only` | test |
| The proof runs to the anchored checkpoint | `test_the_proof_runs_to_the_supplied_anchor_and_not_the_verifiers_own_state`, `test_an_anchored_bundles_proof_runs_to_the_anchored_checkpoint` | test |
| A record at the anchor itself verifies | `test_a_record_at_the_anchor_itself_verifies_against_it`, and `policy_deny.json` | test |
| The rejected proof direction is rejected | `test_a_dual_proof_is_rejected_when_the_source_is_newer_than_the_target`, `test_an_anchor_older_than_the_record_is_refused_by_name` | test |
| A forged anchor is refused before any proof runs | `test_an_anchor_immudb_never_signed_is_refused_before_any_proof_runs` | test |
| Auditing does not move the verifier's trust anchor | `test_verifying_against_an_anchor_does_not_move_the_verifiers_own_state` | test |
| `/state` returns a state ImmuDB signed, behind the read credential | `test_the_state_endpoint_returns_a_state_immudb_actually_signed`, `test_the_state_endpoint_requires_the_read_credential` | test |
| A real submission is accepted by the public log | `python tools/export_evidence_fixtures.py` transcript above (201 Created, index 79224227) | **command, marked: no test covers this** |
| The returned proof verifies offline with no network | `test_an_anchored_bundle_verifies_its_log_entry_offline`, `test_the_checker_attempts_no_network_while_checking_an_anchored_bundle` | test |
| Tampering the log entry is refused by name | `test_a_tampered_root_hash_is_refused_with_the_invalid_root_hash_error` and three siblings | test |
| An entry about another state does not corroborate this bundle | `test_a_real_log_entry_about_a_different_state_does_not_corroborate_this_one` | test |
| The bundle's `log_url`/`log_index` describe the actual entry | `test_a_rewritten_log_index_is_refused`, `test_a_rewritten_log_url_is_refused` | test |
| Nothing but a hash, a signature and a key reaches the log | `test_nothing_but_a_hash_a_signature_and_a_key_reached_the_public_log` | test |
| The log URL is discovered, never hardcoded | `test_no_log_instance_url_is_hardcoded_anywhere_in_the_product`, `test_the_log_url_is_discovered_and_the_bundle_records_which_source_answered` | test |
| Writes continue with anchoring broken | `test_writes_continue_and_records_are_produced_with_anchoring_broken` | test |
| An unanchored bundle says so rather than omitting | `test_an_unanchored_bundle_states_its_lack_of_corroboration_in_a_field`, `test_a_bundle_for_an_unanchored_record_says_so_rather_than_omitting_it` | test |
| The two states differ by value, not by absence | `test_the_two_states_are_distinguishable_without_reading_an_absence` | test |
| An unanchored bundle cannot claim corroboration by relabelling | `test_an_unanchored_bundle_cannot_claim_corroboration_by_relabelling` | test |
| A failed anchoring cycle does not stop the loop | `test_the_anchor_loop_does_not_stop_on_a_failed_cycle` | test |
| The seam has not become an API and has not moved | `test_the_proof_source_still_comes_from_the_injected_root_service` | test |
| The README §3.4.1 command block still runs | `test_readme_command_block_is_exactly_reproducible` (a real subprocess, the README's own text) | test |
| A Rekor anchor does not prove the policy was correct | readME.md §3.4.2 and §5 | Residual Limits |
| A compromised writer signs whatever it records | readME.md §5, writer-signature bullet | Residual Limits |
| Entry permanence across a log turndown is unresolved | readME.md §5, anchor-permanence bullet | Residual Limits |
| The arbitrary-pair capability rests on a library seam | readME.md §5, seam bullet (and the test above) | Residual Limits + test |
| `external_anchor.state` can be downgraded to `not_anchored` undetectably | Byte sweep pass 3; readME.md §5 | Residual Limits + command |

---

## Byte sweep

`python tools/bundle_byte_sweep.py`, extended this phase to run the full
check (writer keys, anchoring key, trust root) rather than the Phase 3a
subset, and to name the new fields.

**Pass 1, printable rotation, over the whole 7450-byte bundle file**
(`policy_allow.json`, the anchored fixture). The rotation operator rather
than XOR 0xFF, for the reason Phase 3a recorded: XORing a printable ASCII
byte produces an invalid UTF-8 start byte, so that pass reports "caught" for
everything and says nothing about which fields matter. The XOR pass is still
run and still reports 7450/7450.

```
  anchor_failure          1933
  consistency_failure     1390
  record_mismatch         1022
  no_effect                967
  not_json                 933
  malformed_bundle         736
  signature_failure        245
  key_mismatch             153
  anchor_key_unknown        71

  6483/7450 single-byte flips were caught.
  967 had no detectable effect, by field:
      json_structure                       484
      proof.verifiable_entry               360
      exported_at                           38
      external_anchor.log_url_source        32
      exported_by                           28
      proof.sdk                             19
      external_anchor.entry.treeSize         2
      record.ledger_key                      1
      record.value                           1
      external_anchor.entry.integratedTime     1
      external_anchor.entry.rootHash         1
```

Pass 2 (the decoded `VerifiableEntry`, 1571 bytes, re-encoded each time)
reports 1291/1571 caught, unchanged in character from Phase 3a: 1016
`consistency_failure`, 118 `malformed_bundle`, 86 `record_mismatch`, 71
`signature_failure`, 280 with no effect - protobuf padding and unused
submessage bytes, the same shape `docs/reports/spike-offline-verify.md` item
4 reported for the raw proto.

Two numbers are worth comparing directly. Before the two fixes below, the
same pass reported **6379/7450 caught and 1071 inert**, with
`external_anchor.log_url` (43 bytes) and `external_anchor.log_index` (17)
in the inert list. After: 6483 and 967.

**Two findings, both from the sweep rather than anticipated.**

`external_anchor.log_index` (17 bytes) and `external_anchor.log_url`
(43 bytes) were **inert** on the first run - exactly the shape of the Phase
3a `record_type` finding. Neither is an input to any proof, so a bundle could
have pointed a reader at a different index in a different log and still
verified, and those two fields are precisely what a person acts on when they
go and look the entry up. Both are now bound: `log_index` against the entry's
own `logIndex`, and `log_url` against the TrustedRoot entry for the log key
id that signed the checkpoint. `test_a_rewritten_log_index_is_refused` and
`test_a_rewritten_log_url_is_refused` are the enforcing tests, and the second
sweep run reports both as `anchor_failure`.

`external_anchor.state` **remains inert in the downgrade direction**: a
holder can change `anchored` to `not_anchored` and the bundle still verifies.
This is reported rather than fixed, because it cannot be fixed at the bundle
layer - an unanchored bundle and a downgraded one are the same bytes by
construction - and because the direction that matters is refused: relabelling
`not_anchored` to `anchored` is `malformed_bundle`, and a fabricated section
is `anchor_failure`. Downgrading only ever *removes* a claim. It is in
Residual Limits.

The writer-signature rows are worth reading carefully. Every attempt to
tamper a writer field inside a bundle returns `consistency_failure` from
immudb-py's own `store.VerifyInclusion`, not `writer_signature_failure` -
because the signature is a field **inside** `record.value`, and `record.value`
is what the Merkle leaf commits to. That is the finding, not a limitation of
the sweep: a writer signature cannot be edited inside a bundle at all. The
D22 check catches a bad signature that was committed to the ledger in the
first place, which no bundle-level tamper can produce, and that case is
exercised live against a real ledger in
`test_a_record_signed_over_different_bytes_is_refused_end_to_end`.

`exported_at`, `exported_by`, `proof.sdk` and
`external_anchor.log_url_source` remain inert, as Phase 3a already recorded
for the first three: they are claims the exporter makes about itself, no
signature covers them, and readME.md §5 says so.

---

## Pre-registered negatives

All false. Confirmed individually, derived per row.

| Negative | Confirmation |
| :--- | :--- |
| Any reimplemented cryptographic primitive | **False.** `test_the_checker_implements_no_cryptography_of_its_own` asserts against the source: no crypto toolkit imported, `hashlib` confined to three named functions, and the verification itself must go through `verifiedGet.call(`, `TransparencyLogEntry(raw_entry)._verify(keyring)` and `sigdecode=sigdecode_der`. The `hashlib` allowlist widened from one name to three this phase; that widening is recorded in the test with the reason for each name, and two assertions were added alongside it rather than in place of it. |
| Any key material inside a bundle | **False.** `test_no_fixture_bundle_contains_writer_or_anchor_key_material` scans every committed bundle for PEM armour and for the DER and raw-point encodings of all four public keys. `test_no_fixture_bundle_contains_key_material` (Phase 3a) still covers the ImmuDB key. |
| Any trust derived from `state.publicKey` | **False.** The checker reconstructs the anchor with `publicKey=b""` and always has; the anchored checkpoint's authenticity comes from `State.Verify` against the out-of-band ImmuDB key and from the Rekor entry. `test_a_bundle_carrying_its_own_key_still_cannot_certify_itself` is unchanged and still passes, and `verifier/main.py`'s `AnchorState` deliberately has no `publicKey` field for the same reason `SourceState` does not. |
| Any network access during offline verification | **False.** `test_the_checker_attempts_no_network_while_checking_an_anchored_bundle` asserts the block is live in the process, then runs the full anchored check; `test_merely_importing_the_checker_blocks_the_network` (Phase 3a) is unchanged. The `sigstore` import happens after the block is installed. |
| Any hardcoded log instance URL | **False.** `test_no_log_instance_url_is_hardcoded_anywhere_in_the_product` scans the raw text of every `.py` under `provenance/`, `anchor_service/`, `control_plane/`, `verifier/`, `ledger/`, `decision_service/`, `tools/`, plus both compose files and the Makefile, for `rekor.sigstore.dev`, `log2025-1` and `log2026-1`. It found one on its first run - in `provenance/rekor.py`'s own comment - which is why that comment now describes the instance rather than naming it. |
| Any record content, key name, or identifier beyond a hash reaching the public log | **False.** `test_nothing_but_a_hash_a_signature_and_a_key_reached_the_public_log` decodes the `canonicalizedBody` of the real committed entry, asserts its key set is exactly `{data:{algorithm,digest}, signature:{content,verifier:{keyDetails,publicKey}}}`, and separately asserts that no `agent_id`, `tool_name`, `call_id`, `input_sha256` or `policy_revision` from the anchored record appears anywhere in the entry. |
| Any unanchored bundle indistinguishable from an anchored one by absence | **False.** `test_the_two_states_are_distinguishable_without_reading_an_absence` asserts both have the same key set and differ by a value; `test_a_bundle_that_omits_the_anchor_section_entirely_is_refused` refuses the omission. |
| Any fail-open path other than the one D23 names | **False.** The writer key is fail-closed at both writers (`test_the_decision_service_refuses_to_write_a_record_it_cannot_sign`; `control_plane/main.py::get_writer_keys` raises identically and `_write_tombstone`'s caller already treats a raise as a refused erasure). `/state` returns 503 with no configured key or an unverifiable state. `/verify` refuses an unverifiable anchor. The anchor store's write route is credential-gated. The only path that continues on failure is `anchor_service.run_forever`'s cycle, which is D23's named exception and is asserted by `test_the_anchor_loop_does_not_stop_on_a_failed_cycle`. |
| Any assertion weakened | **False, with one recorded exception that is not a weakening on net.** No test's `pytest.raises` was broadened, no `result_class` assertion was removed, and the two "no broad exception" meta-tests were replicated into both new offline test files. The one relaxation is the `hashlib` allowlist in `test_the_checker_implements_no_cryptography_of_its_own`, from `{key_fingerprint}` to three named functions, each with its reason written into the test; two new assertions (`_verify(keyring)` and `sigdecode_der` must be present) were added in the same test at the same time, so the net effect is stricter. Stated here rather than left to be noticed. |
| Any item met by live evidence alone with no test enforcing it, except the live submission row, which is marked | **False.** Every item has at least one enforcing test listed above. The single live-only claim is P3b-4's submission, marked as a command in both the item and the claim-mapping table. |

---

## Could not verify

- **Whether a Rekor entry survives its log instance's turndown.** Unchanged
  from `docs/reports/spike-signing-anchor.md`'s own open item, and the reason
  the local chain stays primary. Nothing in this phase tested a turndown, and
  no documented migration guarantee for entries across one was found.
- **Behaviour across an `immudb-py` upgrade.** Everything here ran against
  the pinned `immudb-py==1.5.0` and `codenotary/immudb:1.9.5`. The seam test
  asserts the shape the pin currently has; it does not establish that a later
  version keeps it, and no second version was exercised.
- **Behaviour across a `sigstore-python` upgrade.** Same shape of gap, one
  layer out. `TransparencyLogEntry._verify` and `TrustedRoot.rekor_keyring`
  are `sigstore._internal` surface, pinned at `4.5.0` in
  `requirements-test.txt` and `anchor_service/requirements.txt`. Nothing
  asserts their shape the way the immudb seam test does; an upgrade would
  surface as an import or attribute error in the anchor tests rather than as
  a silently wrong answer, but that is inference from how the calls are
  written, not something this phase demonstrated.
- **Sustained anchoring against the public log.** Two submissions were made
  in total this phase. No rate limit was probed and no long-running
  `anchor-service` deployment was observed over multiple cycles; the interval
  loop is exercised only by the fail-open unit test.
- **Whether the anchoring key's custody is adequate for production.** It is
  an operator-held PEM on a mounted volume, exactly like the ImmuDB signing
  key, and the ADR says so plainly. Nothing here evaluates an HSM or KMS
  path.
- **`charts/ail-gateway/`.** Untouched and still pre-ADR-001; it has no
  verifier workload, so it also has no writer keys and no anchor service. It
  was already documented as not deployable (`readME.md` §4.7) and this phase
  does not change that in either direction.

---

## Cleanup

**Working directory.** A `git worktree` of this repository at
`<scratchpad>/p3b-provenance`, on branch `phase-3b-provenance` - not the
primary working directory. Everything below was done from there and pushed
from there; the worktree itself is removed with `git worktree remove` as the
last action of this phase, after this report is committed and pushed. The
branch and its commits live in the repository, not in the scratch directory.

**Scratch directory.** Removed in full. It held, and no longer holds:

- `tuf-out/` and `tuf-out;C/` - the first TUF fetch of `trusted_root.json`
  and `signing_config.json`, plus an empty directory created by a
  mis-quoted Docker bind-mount path on the first attempt. The trust root
  that matters is committed under `spikes/signing-anchor/` and
  `tests/fixtures/evidence_bundles/`; these were the scratch copies.
- `insert.md` and `patch_sweep.py` - two throwaway scripts used to splice
  text into `docs/reports/spike-signing-anchor.md` and
  `tools/bundle_byte_sweep.py`. Their output is committed; the scripts were
  never part of the deliverable.
- `sweep-full.txt` and `full-suite.txt` - captured stdout from the byte
  sweep and the local suite run. The numbers that matter are transcribed
  into this report; both are reproducible with the commands quoted above.

**Docker.** The `p3b-bundle` compose project (used to generate the fixtures,
including the live anchoring run) and the `p3b-provenance` compose project
(used for the CI-equivalent suite run) were both torn down with `down -v`,
removing their containers, volumes and networks. A third, `p3b-cfgcheck`,
was only ever used for `docker compose config` and created nothing. Ten
images were removed: the four per-service images of each compose project,
plus `p3b-sigstore` (a throwaway image for running the spike's offline
checkers) and `ail-anchor-oneshot` (built by the fixture exporter to make
the live submission). `docker ps -a` and `docker images` both report zero
matching entries afterwards.

**Host Python environment.** This session installed `sigstore==4.5.0` into
the host's global environment to run the offline anchor checks outside a
container, which upgraded `cryptography` from 46.0.5 to 50.0.0 and broke
`spiffe==0.2.5`'s own pin (`cryptography<47,>=45`) while it was installed.
Both were reverted: `sigstore` and `sigstore-models` uninstalled,
`cryptography` reinstalled at 46.0.5. `import spiffe, immudb, ecdsa`
succeeds afterwards. This is the same detour and the same repair
`docs/reports/spike-signing-anchor.md` records for the same reason.

One `pip check` complaint remains and is **not** claimed as clean:
`pyopenssl 26.4.0 has requirement cryptography<51,>=49.0.0, but you have
cryptography 46.0.5`. Nothing in this project imports pyOpenSSL (the only
`OpenSSL` string in the source is `cryptography`'s own
`PrivateFormat.TraditionalOpenSSL` enum), and nothing requires it other than
as an optional extra of `google-auth` and `pem`. Whether that version
pre-dates this session or arrived with a sigstore install is not something
this session can distinguish - the earlier spike made the same install and
the same revert - so it is reported rather than guessed at, and nothing was
uninstalled on a guess. The second `pip check` line
(`sse-starlette` wanting a newer `starlette` than `requirements-test.txt`
pins) is pre-existing and documented in that file's own comments.

---

## CI

**Green.** Run id `32785456278`, job `97616336081`, conclusion `success`,
3m9s, on `6fc2f9f71926ca96c10562f80ac2f41ac0cca4c4`. That commit carries all
of this phase's code, tests and fixtures, so it is the run that establishes
the work. PR [#10](https://github.com/banji-007/compliance-ail/pull/10).

```
$ gh run list --branch phase-3b-provenance --limit 1 --json status,conclusion,databaseId
[{"conclusion":"success","databaseId":32785456278,"status":"completed"}]
```

Run `32786753257` is green as well, on `52a3702939eeb47e991736375f3fcd8e02216f77`,
the documentation-only commit that filled in this report's sweep, CI and
cleanup sections. A report cannot contain the id of the run triggered by the
commit that adds that id, so the last such run is linked from the PR rather
than transcribed here; both ids above are stated so the chain is followable
rather than ending in a claim about itself.

CI runs `make test-integration`, which brings up `docker-compose.test.yml`
and runs the whole suite. Two things about that are worth stating rather
than leaving implicit.

`requirements-test.txt` gained `sigstore==4.5.0`, so the offline anchor
checks run in CI rather than only locally. The combined install was checked
before adding it (`pip install -r requirements-test.txt && pip install
immudb-py==1.5.0 && pip check` in a clean `python:3.11-slim`, reporting "No
broken requirements found"), because that file is installed alongside
`immudb-py` and a resolver conflict there would have been a wall of
unrelated failures.

`anchor-service` is not in that compose file, so **CI never touches a public
transparency log**. The entire suite runs with external anchoring broken,
which is what makes P3b-5's fail-open demonstration a property of every
green run rather than something staged once.

The same suite was also run locally against a fresh stack under an explicit
`-p p3b-provenance`, matching CI's own conditions:

```
$ docker compose -p p3b-provenance -f docker-compose.test.yml down -v
$ docker compose -p p3b-provenance -f docker-compose.test.yml up -d --build --wait
$ COMPOSE_PROJECT_NAME=p3b-provenance ... python -m pytest tests/ -q
286 passed, 9 skipped, 1 warning in 755.50s (0:12:35)
```

295 tests collected, up from 206 before this phase; the 9 skips are the same
9 that were skipping before it (environment-gated tests that name their own
condition), and no test this phase added is among them.

`COMPOSE_PROJECT_NAME` has to be set for that local run and is worth
recording, because getting it wrong looks exactly like a regression.
`tests/test_content_states.py` derives the project it shells out to from
Compose's own default, which is the *directory name* - and this phase's work
happened in a `git worktree` whose directory is not the one the stack was
brought up under. Two tests then fail with `service "ail-control-plane" is
not running`, which reads as a broken erasure path rather than as a
mismatched project name. CI is unaffected: it runs `make test-integration`
from the repository root with no `-p`, so the default and the actual project
are the same string.
