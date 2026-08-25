# Evidence bundle fixtures

Four real evidence bundles, one per record shape the audit trail holds, plus
every public key and trust anchor the tests need. Committed on purpose:
`tests/test_offline_verify.py`, `tests/test_writer_signing.py` and
`tests/test_external_anchor.py` check them with no Docker, no ImmuDB, and no
network, which is the property Phase 3a exists to establish and Phase 3b
extends. Regenerating them at test time would quietly turn a portability
test back into an integration test.

| File | What it holds |
| :--- | :--- |
| `policy_allow.json` | A `provision_cloud_server` call OPA approved. **Anchored** |
| `policy_deny.json` | The same tool denied by the FinOps pack. **Anchored** |
| `fault.json` | A `fault` record, `fault_class: opa_unreachable`. Not anchored |
| `content_erasure.json` | A D11 erasure tombstone, the only remaining evidence after an Article 17 deletion. Not anchored |
| `signing.pub` | The ImmuDB state-signing key these four bundles were exported against |
| `writer-decision.pub` | The decision service's writer key (D22) - signed the first three |
| `writer-control-plane.pub` | The control plane's writer key (D22) - signed the tombstone |
| `anchor-signing.pub` | The key the Rekor submission was made under (D23) |
| `trusted_root.json` | Sigstore's TrustedRoot, fetched via TUF, for checking the log entry |
| `other-signing.pub` | An unrelated P-256 public key, for the wrong-key tests |
| `PROVENANCE.json` | When these were generated, by what, which keys they name, and which are anchored |

## Two anchor states, both real

`policy_allow` and `policy_deny` were written before the export run's single
anchoring cycle; `fault` and `content_erasure` after it. So the first two are
covered by a checkpoint that really is in a public transparency log and the
last two are not, and the difference between them is a fact about
transaction ordering rather than a flag anything set. Neither state is
hand-edited into place, and `tools/export_evidence_fixtures.py` refuses to
finish if the set does not contain both - a fixture set that was entirely
one or the other would let every anchor test pass while exercising half the
rule.

`tests/test_external_anchor.py` reads which is which out of `PROVENANCE.json`
rather than hardcoding it, so a regeneration that ordered things differently
fails loudly instead of passing for the wrong reason.

## Two writer keys, deliberately

`decision-service` and `ail-control-plane` sign with separate long-lived
pairs, so a bundle's `writer_key_fingerprint` names which of them wrote the
record. A single shared key would verify all four fixtures identically and
attribute nothing. It also means one writer can be put on a checker's
deny-list without revoking the other - see
`docs/adr/0012-writer-signing-and-external-anchoring.md`.

## Every key is a separate file, deliberately

No bundle contains any key it is checked against - not the ImmuDB key, not
either writer key, not the anchoring key. `immudb-py` never reads
`State.publicKey` during verification
(`docs/reports/spike-offline-verify.md`, item 4[d]), so a bundle carrying its
own key would be checked against a key its own author chose, and the same
reasoning applies unchanged to the two kinds Phase 3b added. A bundle names
each key it expects by fingerprint; the checker holds the keys.
`tests/test_writer_signing.py` asserts no bundle embeds key material in any
encoding, for every key in this directory.

`trusted_root.json` plays the same role one level out: an independently
obtained trust anchor, fetched from Sigstore's TUF repository rather than
supplied by the log entry it is used to check. It can be re-fetched and
diffed:

```python
from sigstore._internal.tuf import TrustUpdater, DEFAULT_TUF_URL
u = TrustUpdater(DEFAULT_TUF_URL, offline=False)
print(open(u.get_trusted_root_path()).read())
```

`other-signing.pub` is an arbitrary unrelated key pair. Only its public half
is committed; the private half was generated in a scratch directory and
discarded. It exists so "the checker was handed the wrong key" is a real
different key rather than a corrupted copy of the right one.

## Regenerating

These bundles were signed by whatever keys were mounted when they were
exported, so every `.pub` here has to travel with them. `make keygen`
generates *different* key pairs on a fresh checkout, and `keys/*.pub` will
not verify these fixtures. That is not a defect in the fixtures, it is the
same constraint an auditor faces with any bundle from a system they do not
operate.

To regenerate all of it together:

```
docker compose -p p3b-bundle -f docker-compose.test.yml up -d --build --wait
python tools/export_evidence_fixtures.py
docker compose -p p3b-bundle -f docker-compose.test.yml down -v
```

`tools/export_evidence_fixtures.py` drives the real routes: it produces each
record through the decision service or the control plane's own erasure
endpoint, then exports each bundle through `GET /audit/bundle` with the read
credential. It never assembles a bundle itself, so a fixture cannot drift
from what the product actually emits.

**One step of that reaches the public internet.** Between writing the first
two records and the last two, the script runs one real anchoring cycle - a
genuine submission to a Rekor v2 instance discovered from Sigstore's own TUF
configuration - in a one-shot container built from `anchor_service/Dockerfile`
and attached to the compose project's network. It runs in a container
because `sigstore-python`'s TUF client calls `os.symlink`, which Windows
refuses without elevated privileges (`WinError 1314`,
`docs/reports/spike-signing-anchor.md`, "What blocked it"). Regenerating
therefore needs network access and writes one entry to a shared public log;
do not run it in a loop.

## Checking one by hand

```
python tools/ail_verify_bundle.py tests/fixtures/evidence_bundles/policy_allow.json \
  --key tests/fixtures/evidence_bundles/signing.pub \
  --writer-key tests/fixtures/evidence_bundles/writer-decision.pub \
  --writer-key tests/fixtures/evidence_bundles/writer-control-plane.pub \
  --trusted-root tests/fixtures/evidence_bundles/trusted_root.json \
  --anchor-key tests/fixtures/evidence_bundles/anchor-signing.pub
```

The base check needs nothing but `immudb-py==1.5.0`. `--trusted-root`
additionally needs `sigstore==4.5.0`, and is required for a bundle that
claims corroboration: without it the checker refuses with `anchor_unchecked`
rather than printing the same "verified" a full check prints.
