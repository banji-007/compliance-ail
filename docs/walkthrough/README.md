# Verify one record yourself, without running the system

This directory holds one real evidence bundle and the public keys it names.
You can check it on your own machine with Python and one dependency. No
Docker, no ImmuDB, no credentials, no network, and no part of this project
running anywhere.

The record is a prompt injection being refused by policy.

## What you need

```
Python 3.11 or newer
pip install immudb-py==1.5.0
```

That is the whole list for the check below. The optional anchor step at the
end needs one more package and says so.

## The files

| file | what it is |
| :--- | :--- |
| `injection-denied.json` | the evidence bundle: one ledger record, the proof material ImmuDB returned for it, and the fingerprints of the keys it expects |
| `signing.pub` | the ImmuDB state-signing public key the bundle names |
| `writer-decision.pub` | the public key of the service that wrote the record |
| `anchor-signing.pub` | the public key that signed the transparency-log submission (optional step only) |
| `trusted_root.json` | Sigstore's trusted root, held out of band (optional step only) |

**No key is inside the bundle.** A bundle that carried its own key would be
checked against a key its own author chose. The bundle names the keys it
expects by fingerprint; you supply them. That is why they are separate files
here.

## Step 1: verify the record

Clone this repository and run the command below **from the repository root**.
Nothing else in the clone is used, and nothing is built or started:

```bash
git clone https://github.com/banji-007/compliance-ail.git
cd compliance-ail

python tools/ail_verify_bundle.py docs/walkthrough/injection-denied.json \
  --key docs/walkthrough/signing.pub \
  --writer-key docs/walkthrough/writer-decision.pub \
  --skip-anchor-check
```

`tools/ail_verify_bundle.py` is a single file that imports nothing from the
rest of the repository, so copying it and the five files in this directory
somewhere else and running it there works identically. Both forms were run
when this page was written.

Expected output:

```
OK [verified]
  ledger key   : tool_call:langgraph_agent:12688b3fc9524b4db7778b9df015a514:provision_cloud_server
  record type  : policy_deny
  transaction  : 2 (proven against trust anchor at tx 7)
  signing key  : sha256:d948681d5ee14890ed8eadc1930dec1fc2e8796581adc27b5204a31450e32c30
  written by   : sha256:b6c8e73b141d09401ea5b6e33915cd951ecdd6cedd467048661b014af8c35d4f
  corroboration: anchored, NOT CHECKED (--skip-anchor-check)
  record bytes : b'{"record_type":"decision", ... }'

This bundle proves the record above was committed to the ledger, has not
been altered since, and was signed by the writer key named. It does not
prove the policy that produced the record was correct, and it does not
prove that writer was honest - only which key signed. See readME.md 3.4.
```

`--skip-anchor-check` says deliberately that you are not checking the
external anchor in this step. **What ran without it:** the inclusion proof
and the consistency proof, verified against the ImmuDB state signed by
`signing.pub`, plus the writer signature over the record. **What did not
run:** the check that this ledger's state was also published outside the
deployment that produced it. The bundle says it was anchored; this step took
its word for that and checked nothing about it. Step 2 is where you stop
taking its word.

Leave `--skip-anchor-check` off and the tool refuses rather than quietly
skipping:

```
FAILED [anchor_unchecked] this bundle claims external corroboration, but no
--trusted-root and --anchor-key were supplied to test that claim against.
Supply them, or pass --skip-anchor-check to say deliberately that you are
not checking it
```

That refusal is the point. There is no way to get a pass here without having
said which of the two you meant.

## What the record actually says

The bundle's `record bytes` carry the decision in full. This one is the
README's prompt-injection test: a request that told the agent to ignore its
guardrails, which the language model complied with and which the gateway
refused anyway, on four independent policy grounds:

```
DENIED: GDPR Data Residency Violation. Unclassified data defaults to highly
        sensitive and must run in an approved region. Approved:
        eu-central-1, us-east-1
DENIED: Instance type p4d.24xlarge is restricted. 'project' tag must be
        'ml-training'.
DENIED: Production environments must include a valid 'cost_center' tag.
        Approved values: engineering, finance, marketing, operations.
DENIED: SOC2 Violation. Production environments must have
        'encryption_at_rest' set to 'true'.
```

`outcome_type` is `policy_deny`, not `schema_deny`. The payload was
well-formed, so it reached the policy engine and was refused there, and the
reasons name the injected values directly. That distinction is the whole
claim: the injection was not filtered out as malformed text, it was
evaluated and denied.

## Step 2 (optional): check the anchor too

The ledger state this record is proven against was also submitted to a public
transparency log. Checking that claim needs Sigstore's own client:

```bash
pip install sigstore==4.5.0

python tools/ail_verify_bundle.py docs/walkthrough/injection-denied.json \
  --key docs/walkthrough/signing.pub \
  --writer-key docs/walkthrough/writer-decision.pub \
  --trusted-root docs/walkthrough/trusted_root.json \
  --anchor-key docs/walkthrough/anchor-signing.pub
```

The `corroboration` line changes:

```
  corroboration: anchored in https://log2025-1.rekor.sigstore.dev at index 108407026, inclusion proof and checkpoint verified
```

Everything else is identical. What this adds: the state the record was proven
against was published somewhere this project does not control, so the
deployment cannot have quietly rewritten its own history after the fact
without that being visible in a log it does not own.

If `sigstore` is not installed, the tool says so rather than passing:

```
FAILED [anchor_unchecked] checking an anchored bundle needs sigstore-python
installed (pip install sigstore==4.5.0): No module named 'sigstore'
```

## What this does not prove

Stated at the same resolution as what it does.

- **It does not prove the policy was right.** It proves a decision was
  recorded and has not changed since. Whether denying that request was the
  correct call is a question about the Rego, not about the ledger.
- **It does not prove the writer was honest.** It proves which key signed.
  Every service in the deployment currently mounts every writer key, so the
  signature attributes a record to a key and not to a component. That is a
  recorded limit, not a subtlety we are glossing.
- **It does not prove the call was intercepted at all.** For tools the
  gateway does not hold exclusive authority over, a bypassed call produces no
  record, and a record that does not exist cannot be bundled.
- **It does not carry the record's ledger fault, if it has one.** The bundle
  format has no section for one. A record whose write-time proof failed
  exports a clean-looking bundle; the fault lives on the audit row and under
  its own ledger key. Recorded in readME.md section 5.
- **Offline is a property of the process, not a promise in prose.** The
  checker replaces `socket.socket.connect` with a raiser as soon as its
  imports finish. If it tried to reach the network, it would fail rather than
  succeed quietly.

## Where this bundle came from

Exported with `GET /audit/bundle` from a real stack brought up from a clean
clone, from the record the README's own section 4.4 Test 2 produces. The
transparency-log submission was made by that same stack during the same
session. Nothing here was hand-assembled.

The four-record fixture set under `tests/fixtures/evidence_bundles/` is a
different thing for a different purpose: it is what `tests/test_offline_verify.py`
checks the verifier against, it covers four record types, and it is signed by
that export's own keys. This directory is the one meant to be read.
