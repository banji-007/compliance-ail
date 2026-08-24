# Evidence bundle fixtures

Four real evidence bundles, one per record shape the audit trail holds, plus
the two public keys the tests need. Committed on purpose: `tests/test_offline_verify.py`
checks them with no Docker, no ImmuDB, and no network, which is the property
Phase 3a exists to establish. Regenerating them at test time would quietly
turn a portability test back into an integration test.

| File | What it holds |
| :--- | :--- |
| `policy_allow.json` | A `provision_cloud_server` call OPA approved |
| `policy_deny.json` | The same tool denied by the FinOps pack |
| `fault.json` | A `fault` record, `fault_class: opa_unreachable` |
| `content_erasure.json` | A D11 erasure tombstone, the only remaining evidence after an Article 17 deletion |
| `signing.pub` | The ECDSA public key these four bundles were exported against |
| `other-signing.pub` | An unrelated P-256 public key, for the wrong-key tests |
| `PROVENANCE.json` | When these were generated, by what, and which key they name |

## The key is a separate file, deliberately

No bundle contains the key it is checked against. `immudb-py` never reads
`State.publicKey` during verification (`docs/reports/spike-offline-verify.md`,
item 4[d]), so a bundle carrying its own key would be checked against a key
its own author chose. A bundle names the key it expects by fingerprint; the
checker holds the key. `signing.pub` sits here rather than inside the JSON
for exactly that reason, and `tests/test_offline_verify.py` asserts no
bundle embeds key material in any encoding.

`other-signing.pub` is an arbitrary unrelated key pair. Only its public half
is committed; the private half was generated in a scratch directory and
discarded. It exists so "the checker was handed the wrong key" is a real
different key rather than a corrupted copy of the right one.

## Regenerating

These bundles were signed by whatever ImmuDB signing key was mounted when
they were exported, so `signing.pub` has to travel with them. `make keygen`
generates a *different* key pair on a fresh checkout, and `keys/signing.pub`
will not verify these fixtures. That is not a defect in the fixtures, it is
the same constraint an auditor faces with any bundle from a system they do
not operate.

To regenerate all of it together:

```
docker compose -p p3a-bundle -f docker-compose.test.yml up -d --build --wait
python tools/export_evidence_fixtures.py
docker compose -p p3a-bundle -f docker-compose.test.yml down -v
```

`tools/export_evidence_fixtures.py` drives the real routes: it produces each
record through the decision service or the control plane's own erasure
endpoint, then exports each bundle through `GET /audit/bundle` with the read
credential. It never assembles a bundle itself, so a fixture cannot drift
from what the product actually emits.

## Checking one by hand

```
python tools/ail_verify_bundle.py tests/fixtures/evidence_bundles/policy_allow.json \
  --key tests/fixtures/evidence_bundles/signing.pub
```
