# Spike: SPIFFE SVID Signing and Rekor v2 as Evidence Anchors

Run id: spike-signing-anchor

**Verdict, Question A: NO-GO.** An SVID-signed record only remains offline
verifiable until the signing certificate's own short TTL expires (24 hours
by default in this project's own SPIRE server config, confirmed empirically
across a real rotation), so it cannot back evidence that must stay
verifiable indefinitely, and the decision service does not hold an SVID for
this purpose today in the first place.

**Verdict, Question B: GO.** Rekor v2's public instance accepts a
self-managed key, returns a Merkle inclusion proof bound to a signed
checkpoint, verifies fully offline with the official client's own
verification code, costs 2 to 4 seconds per submission, and stores nothing
but a hash, a signature, and a public key, never the content anchored.

---

## Question A: can a record be signed with the decision service's SPIFFE SVID private key such that a bundle stays verifiable offline after that SVID has rotated?

### A1. How the decision service obtains its SVID private key today

It does not. Read `decision_service/main.py` in full: zero references to
`spiffe`, `SPIFFE`, `X509Source`, `WorkloadApiClient`, or `svid` anywhere in
the file, one comment only. Read `docker-compose.yml`'s `decision-service`
service definition: no `SPIFFE_ENDPOINT_SOCKET` environment variable, no
`spire-sockets` volume mount, nothing SPIRE-related at all. `envoy/envoy.yaml`
confirms why: Envoy holds `spiffe://ail.internal/workload/envoy` via SDS
(`tls_certificate_sds_secret_configs`) and terminates mTLS in front of
`decision-service`, validating the caller against
`spiffe://ail.internal/workload/agent`. `decision-service` itself is not a
SPIFFE workload with its own identity in the current architecture; Envoy is.

The one place in this codebase that fetches an SVID's private key into
Python-accessible memory is `interceptor/middleware.py::_get_spiffe_ssl_context()`,
used by the agent (`langgraph-demo`) for its own outbound mTLS to Envoy, not
by the decision service, and not for signing.

Read `spiffe==0.2.5`'s own source
(`spiffe/svid/x509_svid.py::X509Svid`), the library this project already
pins: `private_key` is typed `PRIVATE_KEY_TYPES`, a plain union of
`cryptography.hazmat.primitives.asymmetric` key classes (EC, RSA, Ed25519,
etc.), returned as a real object with no restriction to TLS use. The leaf
certificate's own `KeyUsage` extension requires `digitalSignature=True` and
forbids `keyCertSign`/`cRLSign` (`_validate_leaf_certificate`, same file) -
consistent with signing, not merely key exchange. The key is usable for
signing arbitrary bytes; nothing in the library or the certificate's own
constraints prevents it.

**Finding, stated plainly:** the premise of this question does not hold
architecturally today. There is no "the decision service's SVID" to sign
with, because the decision service does not have one. The rest of this
question was answered anyway, using the same mechanism
(`spiffe==0.2.5` against this project's own SPIRE server and agent, an
existing registered workload entry) as a stand-in for whichever service
would eventually hold this responsibility, since the cryptographic
properties of SVID rotation are a property of SPIRE and the `spiffe`
library, not of which service calls them. Extending this mechanism to
decision-service itself, or registering it as a new SPIFFE workload, would
be a design change and is out of this spike's scope.

**Method:** `docker-compose.yml`'s existing `scripts/register-workloads-container.sh`
already registers `spiffe://ail.internal/workload/test` with selector
`unix:uid:0`, used by the `python-mtls-test` diagnostic service. A
standalone container, run with `--pid container:<spire-agent container>`
(the same PID-namespace sharing `python-mtls-test` already uses, without
which SPIRE's `unix` WorkloadAttestor cannot resolve caller credentials
over the shared socket volume - confirmed by reproducing the failure
without it: `"could not resolve caller information"`), fetched this SVID.

### A2. Signing a real record's bytes

```
$ docker exec sig-anchor-spike-workload python3 -c "..."
record bytes length: 459
signing key type: ECPrivateKey
curve: secp256r1
algorithm used: ECDSA with SHA-256 over the NIST P-256 (secp256r1) curve
signature length (DER-encoded ECDSA): 70 bytes
self-check: signature verifies against the leaf cert public key: OK
```

The record bytes are the actual `record.value` field, base64-decoded, from
`tests/fixtures/evidence_bundles/policy_allow.json` - a real committed
fixture, not synthetic data. The algorithm is not a preference: SPIRE issues
secp256r1 (P-256) keys by default for X509-SVIDs, and ECDSA/SHA-256 is what
that key type supports. This happens to match this project's own existing
ImmuDB signing key (also P-256, confirmed via
`openssl ecparam -genkey -name prime256v1`, the same curve).

### A3. What a checker needs to verify this signature with no network

Enumerated by building the checker and confirming it needs exactly these
five inputs, nothing else:

1. **The record bytes** that were signed.
2. **The signature bytes** (DER-encoded ECDSA).
3. **The leaf certificate** (the SVID that signed it), as PEM. Unlike the
   current ImmuDB-key approach, this cannot be assumed pre-held by the
   checker, because a fresh one is issued on every rotation - it must
   travel with the bundle.
4. **The trust bundle** (the SPIRE trust domain's CA root certificate(s)),
   as PEM.
5. **The expected SPIFFE ID** of the signer, as a string. Chain validation
   alone proves only "issued by our CA," not "issued to the specific
   workload this bundle claims signed it" - a policy decision the checker
   must make explicitly, the same way `tools/ail_verify_bundle.py` takes
   `--key` explicitly rather than trusting a key the bundle supplies about
   itself.

Built `spikes/signing-anchor/offline_check.py`: blocks `socket.socket.connect`
at import (the same pattern `tools/ail_verify_bundle.py` and
`spikes/offline-verify/verify_offline.py` use), checks the SPIFFE ID against
the leaf's URI SAN, path-validates the leaf against the trust bundle using
`cryptography.x509.verification` (`PolicyBuilder`/`Store`/`build_client_verifier`
- the `cryptography` library's own webpki-backed validator, not a hand-rolled
chain walk), then verifies the ECDSA signature over the record bytes using
the leaf's own public key.

```
$ docker run --rm --network none -v <isolated dir>:/app -w /app <image> \
    python3 offline_check.py record_bytes.bin signature.bin leaf_cert.pem \
    trust_bundle.pem spiffe://ail.internal/workload/test
OK {'signer_spiffe_id': 'spiffe://ail.internal/workload/test',
    'leaf_not_before': '2026-08-24T19:28:01+00:00',
    'leaf_not_after': '2026-08-25T19:28:11+00:00',
    'chain_length': 2, ...}
```

Run with `--network none` at the Docker level, not merely a socket patch
inside the process, matching the strongest form of the offline-verify
spike's own no-network standard.

### A4. Rotation, the crux

Updated the registered entry's TTL live
(`spire-server entry update -x509SVIDTTL 60`), which caused SPIRE to
proactively reissue a new leaf certificate for the same workload identity
almost immediately - a real rotation, not a simulated one. Confirmed by
serial number: the leaf used for A2's signature (serial
`70666634272067232057706086118914953585`, 24-hour TTL, the server's
default) was fully replaced by a new leaf (serial
`44746775641259936324230155699101003188`, ~70-second TTL) before this test
ran.

**Immediately after rotation**, re-fetched the trust bundle fresh (not
reused from before rotation) and re-ran the offline checker against the
*original, now-rotated-away* leaf certificate and signature from A2:

```
$ diff trust_bundle.pem trust_bundle_after_rotation.pem && echo "trust bundle UNCHANGED after leaf rotation"
trust bundle UNCHANGED after leaf rotation

$ python3 offline_check.py record_bytes.bin signature.bin leaf_cert.pem \
    trust_bundle_after_rotation.pem spiffe://ail.internal/workload/test
OK {...}
```

**The old, rotated-away certificate still verifies.** The CA did not
rotate (`ca_ttl = 720h`, 30 days, versus `default_x509_svid_ttl = 24h` for
leaves - the CA outlives many leaf rotations by design), and SPIRE performs
no revocation of superseded leaf certificates; rotation is purely additive,
the old certificate simply stops being what the workload currently
presents. Nothing invalidates it before its own `not_valid_after`.

**But that window is bounded, not indefinite.** Signed a second record with
the newly-issued 70-second-TTL leaf, then polled until 9 seconds past its
own `not_valid_after` (2026-08-24T19:39:44Z) and re-ran the identical
offline checker, same trust bundle, same code path:

```
$ python3 offline_check.py record_bytes_shortlived.bin signature_shortlived.bin \
    leaf_cert_shortlived.pem trust_bundle_after_rotation.pem spiffe://ail.internal/workload/test
FAILED chain validation failed: validation failed: cert is not valid at
validation time (encountered processing <Certificate(subject=<Name(C=US,O=SPIRE)>...)
```

Refused with a specific, named reason from `cryptography.x509.verification`
itself (expired-certificate, not a broad exception), the moment the leaf's
own validity window closed. Both directions of the crux question are now
answered from direct observation, not inference: **yes, a rotated-away SVID
remains offline-verifiable, but only until its own original expiry** -
which, at this project's default `default_x509_svid_ttl = 24h`, is far
shorter than what "durable evidence" implies. A bundle whose only anchor is
an SVID signature becomes cryptographically unverifiable roughly one day
after it was created, unless the checker happens to run before then. This
is the finding that drives the NO-GO verdict.

### A5. What the bundle would have to carry, and how much larger it gets

Compared against the current D18/D19 format, which needs no certificate at
all because the checker independently holds the ImmuDB signing key
out-of-band (`--key`, matching `docs/adr/0010-portable-evidence-bundles.md`'s
own reasoning for why the key stays outside the bundle):

| Field | Size |
| :--- | :--- |
| Leaf certificate, DER | 544 bytes |
| Leaf certificate, base64 (as it would sit in a JSON bundle) | 728 bytes |
| Signature, raw | 70 bytes |
| Signature, base64 | 96 bytes |
| **Total added, base64-in-JSON** | **824 bytes** |
| Current fixture bundle size for comparison (`tests/fixtures/evidence_bundles/policy_allow.json`) | 3513 bytes |

An added 824 bytes is roughly a 23% increase over that example bundle - a
real but not extreme cost by itself. The leaf certificate must be embedded
(unlike the ImmuDB key, it is not stable enough to hold out-of-band); the
trust bundle (CA root) could plausibly still be held out-of-band by the
checker the same way `signing.pub` is today, since it changes far less
often, but that reintroduces exactly the same durability problem one level
up: the CA itself is not permanent either (720h TTL by default here), so an
out-of-band-held CA would eventually go stale relative to old bundles too,
just on a longer cycle. Sizing this second-order cost was not attempted;
see What could not be determined.

---

## Question B: will Rekor v2 accept a checkpoint from a key we control and return an inclusion proof we can persist and verify offline?

### B1. The current public Rekor v2 API, verified against source and the live service

Read `CLIENTS.md` directly from `sigstore/rekor-tiles` at its current
`main` (via `gh api repos/sigstore/rekor-tiles/contents/CLIENTS.md`), not
from memory or a cached description:

- **One write API:** `POST /api/v2/log/entries`.
- **Entry type:** `hashedrekord` (`HashedRekordLogEntryV002`) only. Rekor v2
  dropped `rekord`, `intoto`, `dsse`, `jar`, `alpine`, `rpm`, and others.
- **DSSE is explicitly not a native entry type.** CLIENTS.md's own words:
  clients should "extract the DSSE Pre-Authentication Encoding (PAE) and
  signature from the DSSE envelope, including the hash of the PAE and the
  signature in a `hashedrekord` request." The question's premise
  ("submit a DSSE checkpoint") does not map onto a literal API call; it
  maps onto this documented workaround, which was implemented rather than
  skipped (see B2).
- **Self-managed keys are explicitly permitted, not just Fulcio keyless.**
  CLIENTS.md shows both request shapes side by side; Fulcio's certificate
  and a caller-supplied raw public key are both first-class `verifier`
  options in the same request schema.
- **What an upload returns:** a `TransparencyLogEntry` - `logIndex`,
  `logId.keyId`, `kindVersion`, `integratedTime` (always `"0"` now - Rekor
  v2 no longer timestamps entries itself), `inclusionPromise` (`null` for
  v2), `inclusionProof` (`logIndex`, `rootHash`, `treeSize`, `hashes`, and a
  `checkpoint.envelope` - a signed, C2SP-format checkpoint), and
  `canonicalizedBody`.

Verified live against the public instance, not only from source:

```
$ curl -s -o /dev/null -w "%{http_code}\n" https://log2025-1.rekor.sigstore.dev/api/v2/log/entries
501   {"code":12, "message":"Method Not Allowed", "details":[]}
```

(GET correctly refused on a POST-only route - the endpoint exists and is
live.) The exact public URL was confirmed from the Sigstore blog
(`blog.sigstore.dev/rekor-v2-ga`) rather than assumed from the CLIENTS.md
example, since the blog explicitly states this URL rotates over time
("we will eventually turn down this 2025 Rekor v2 instance") - a real
integration must discover it via `SigningConfig`, not hardcode it. This is
a genuine, documented constraint, not a spike-specific inconvenience.

### B2. Submitting a DSSE checkpoint over a synthetic Merkle root, self-managed key

Built `spikes/signing-anchor/submit_dsse_checkpoint.py`: constructs a real
DSSE envelope (`payloadType`, base64 `payload`, and a real ECDSA signature
in `signatures[0].sig`) over a synthetic Merkle root
(`{"merkle_root": "<sha256 hex>", "tree_size": 1, ...}`, explicitly labeled
synthetic and not derived from any real AIL tree), computes the DSSE PAE
per the DSSE spec (a length-prefixed string format, not a cryptographic
primitive), signs the PAE with a freshly generated P-256 key (self-managed,
never touching Fulcio), and submits `sha256(PAE)` as the hashedrekord
digest with the DSSE signature as the hashedrekord signature - exactly the
CLIENTS.md-documented mapping.

```
$ python3 submit_dsse_checkpoint.py
=== POST https://log2025-1.rekor.sigstore.dev/api/v2/log/entries ===
status: 201
body: {"logIndex":"78978396", "logId":{"keyId":"zxGZFVvd0FEmjR8WrFwMdcAJ9vtaY/QXf44Y1wUeP6A="},
       "kindVersion":{"kind":"hashedrekord","version":"0.0.2"}, ...
       "inclusionProof":{"logIndex":"78978396","rootHash":"...","treeSize":"78978442",
       "hashes":[...18 hashes...],
       "checkpoint":{"envelope":"log2025-1.rekor.sigstore.dev\n78978442\n...\n
         — log2025-1.rekor.sigstore.dev <sig>\n
         — witness.stagemole.eu <sig>\n
         — staging.witness.transparency.goog/ring-any-bells <sig>\n
         — witness.navigli.sunlight.geomys.org <sig>\n"}}, "canonicalizedBody":"..."}
```

Accepted (HTTP 201) on the first attempt, no refusal to report. One thing
this run found that the source documentation, read the same session, did
not lead me to expect: the checkpoint came back **co-signed by three
independent witnesses** (`witness.stagemole.eu`,
`staging.witness.transparency.goog/ring-any-bells`,
`witness.navigli.sunlight.geomys.org`), in addition to the log operator's
own signature. CLIENTS.md, current at the time it was read this session,
states "In the initial launch of Rekor v2, checkpoints will not be
witnessed, while we wait for the launch of a public witness network."
Witnessing is evidently live now against the public instance, ahead of what
the client-facing docs described - confirmed by observing the live
response, not by re-reading the docs more carefully.

Independently confirmed, separately from parsing my own submission, that
`logId.keyId` (`zxGZFV...`) matches the `log2025-1.rekor.sigstore.dev`
entry in Sigstore's own published TrustedRoot (`tlogs[].logId.keyId`,
fetched via TUF) - the response is from the log it claims to be from.

### B3. Persisting and verifying the inclusion proof offline

Rather than reimplement Merkle inclusion or checkpoint-signature
verification, fetched `sigstore` (the official Python client, 4.5.0) and
reused its own internal functions directly:
`sigstore._internal.merkle.verify_merkle_inclusion` (a straight
RFC 6962 Merkle audit-path recomputation, explicitly credited in its own
docstring to Google's Trillian implementation) and
`sigstore._internal.rekor.checkpoint.verify_checkpoint` (parses the C2SP
signed-note checkpoint, verifies the log operator's signature against a
`Keyring` built from Sigstore's TrustedRoot, and cross-checks that the
inclusion proof's claimed root hash matches the *signed* checkpoint's root
hash - closing exactly the gap CLIENTS.md warns about: "Do not use the
unverified root hash and tree size... unless the client compares these
values to the values in the verified checkpoint").

The TrustedRoot itself was fetched once, ahead of time, via TUF
(`sigstore._internal.tuf.TrustUpdater`, the client's own mechanism) and
saved to a local file - the same role `signing.pub` plays for
`tools/ail_verify_bundle.py`: an independently obtained trust anchor, not
something the entry response supplies about itself.

```
$ docker run --rm --network none -v <isolated dir>:/app -w /app <image> \
    python3 offline_verify_rekor.py trusted_root.json submit_response.json
OK: Merkle inclusion proof and checkpoint signature both verified, offline
log_index: 78978396
tree_size (from inclusion proof, cross-checked against signed checkpoint): 78978442
root_hash: cff52a501f7752b477ed8fae4309d9970be71d985dc7d8bf592b3a15e87285b1
```

`--network none` at the Docker level (stronger than an in-process socket
patch, though the script also blocks `socket.socket.connect` after its one
local-file read, before importing the verification code, the same ordering
`tools/ail_verify_bundle.py` uses and for the same reason - some imports
transitively subclass `socket.socket`).

**Negative control**, matching this project's own established rigor: tampered
the response's claimed `rootHash` field and re-ran the identical checker.

```
$ python3 offline_verify_rekor.py trusted_root.json submit_response_tampered.json
FAILED: inclusion proof contains invalid root hash: expected ... calculated
cff52a501f7752b477ed8fae4309d9970be71d985dc7d8bf592b3a15e87285b1
```

Refused by name (`VerificationError`, the specific "invalid root hash"
case), not a broad exception, and not a silent pass - the library
recomputes the actual root from the leaf and proof hashes rather than
trusting the claimed field.

### B4. Latency, submission to verifiable inclusion proof

Rekor v2 blocks the HTTP response until a checkpoint covering the new entry
is published (CLIENTS.md: "Rekor now blocks on returning a response until
a checkpoint has been published... increase request timeouts to at least
20 seconds"). Measured wall-clock time from `POST` to a response already
containing a complete, verifiable inclusion proof and signed checkpoint,
across four separate live submissions:

```
3.782s, 3.453s, 1.922s, 2.906s
```

All four completed in 2 to 4 seconds, well under the documented 20-second
guidance - that guidance reads as a conservative upper bound for clients to
configure, not the typical observed latency against the live public
instance at the time of this spike.

### B5. What becomes public

Decoded a real `canonicalizedBody` from a live response
(`base64.b64decode` then `json.loads`, not inference from the schema):

```json
{
  "apiVersion": "0.0.2",
  "kind": "hashedrekord",
  "spec": {
    "hashedRekordV002": {
      "data": {"algorithm": "SHA2_256", "digest": "L2JI3SPJxtrFnigtn9TVpynHb73GeDY6RMoRusL/2nI="},
      "signature": {
        "content": "MEQCICrIU+vTRz...",
        "verifier": {"keyDetails": "PKIX_ECDSA_P256_SHA_256",
                      "publicKey": {"rawBytes": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..."}}
      }
    }
  }
}
```

Exactly four kinds of thing are present: a hash algorithm label, a SHA-256
digest (of the DSSE PAE, not of the underlying merkle-root payload
directly, and never of the payload itself), a signature, and a raw public
key. **The actual payload - the synthetic Merkle root value and the rest of
the DSSE envelope's JSON body - was never sent to Rekor at all.** The B2
submission script only ever transmits `digest` and `signature`; grepping
the request body constructed and sent (`submit_request.json`, saved before
the POST) confirms no `payload` field, no raw Merkle root string, and no
human-readable key name or label anywhere in either the request or the
response. This is the same shape of guarantee this project's own bundle
format already relies on for `input_sha256` (`docs/adr/0010-portable-
evidence-bundles.md`): the log holds a one-way function of the content, not
the content, and the public key is an inherent identity, not an assigned
name string.

---

## What could not be determined

- **Question A, the second-order CA-durability cost.** Whether holding the
  SPIRE trust domain's CA root out-of-band (rather than embedding it) is
  actually viable long-term was not sized or tested against a real CA
  rotation - this project's `ca_ttl = 720h` (30 days) was not forced to
  rotate live in this session, only observed as unchanged across a leaf
  rotation. The size and mechanics of *that* rotation, and what a checker
  holding a now-superseded CA root would need to do about older bundles,
  is a real open question this spike surfaces but does not answer.
- **Question A, whether SPIRE supports CRL/OCSP for X.509-SVIDs at all** -
  not exhaustively confirmed against SPIRE's own source, only inferred from
  the observed behavior (a rotated-away certificate was not revoked, only
  naturally expired) and the absence of any revocation-related plugin in
  `spire/server/server.conf`.
- **Question B, entry permanence.** Whether an entry submitted to the
  public `log2025-1.rekor.sigstore.dev` instance is retained indefinitely,
  or only until that instance is eventually turned down in favor of a 2026
  instance (which the Sigstore blog says will happen), was not established.
  The transparency-log model is designed around durability and monitoring,
  but this spike did not find or test a documented migration guarantee for
  entries across a log-instance turndown.
- **Question B, sustained throughput/rate limits.** Only five submissions
  were made total across B2 and B4; no attempt was made to find a rate
  limit or sustained-load behavior on the public instance, which would be
  irresponsible to probe aggressively against a shared public service.

## What blocked it

- **Windows symlink permissions blocked `sigstore-python`'s own TUF client
  on the host directly** (`TrustUpdater`, which calls `os.symlink` for its
  root-history cache and fails with `WinError 1314` without elevated
  privileges - the same class of Windows/UAC limitation encountered
  earlier this session during unrelated disk-space work). Worked around by
  running the TUF fetch and all offline verification inside Linux
  containers instead, which was already the plan for proving "no network"
  at the OS level via `--network none`, so this did not cost the spike
  anything beyond the detour.
- **SPIRE's `unix` WorkloadAttestor could not resolve caller credentials**
  for a standalone container that did not share the SPIRE agent's PID
  namespace (`"could not resolve caller information"`), until
  `--pid container:<spire-agent>` was added, matching the pattern this
  project's own `python-mtls-test` service already uses. Not a genuine
  blocker once found, but worth recording since it cost real time to
  diagnose and is not obvious from the compose file alone.

## Cleanup

Scratch clone: a fresh `git clone` of this repository into an unused
directory under this session's scratchpad, per this spike's own run
instructions. Removed in full after this report and the `spikes/signing-
anchor/` outputs were copied back into the primary working directory.

Docker: `sig-anchor-spike-workload`, `sig-anchor-b3-checker` containers
removed; `sig-anchor-checker-image`, `sig-anchor-b3-image` custom images
removed; the `sig-anchor` compose project (SPIRE server, agent, watchdog,
workload-registrar, token-generator) torn down with `down -v`, removing its
containers, volumes, and networks.

Host: this session installed `sigstore` (and its dependency chain,
including a `cryptography` upgrade from 46.0.5 to 50.0.0) directly into the
host's global Python environment to reach its TUF client and verification
code from outside a container for initial exploration. Uninstalled after
use; `cryptography` reinstalled at its original pinned version (46.0.5) to
leave the host environment as it was found.
