# Phase 3d-share: The front door

**Run id:** `p3dshare`.
**Working directory:** a fresh clone at `AppData\Local\Temp\ail-p3dshare`,
never the primary working directory. Compose project `p3dshare`, named
explicitly with `-p` on every invocation.
**Branch:** `p3dshare`, PR #15, base `main` at `86f32dc`.
**Keys** generated in the clone with the raw openssl commands before any
baseline, since `make` is not on PATH here.
**`.env`** copied from the primary working directory as instructed. Its
contents are unreadable in this environment by policy, so it was never
inspected; what it holds was established from the containers instead, which
mattered (see P3dshare-3, finding 1).

**Baseline after keys**, before anything was touched:

```
tests/test_route_parity.py + tests/test_committed_is_a_fact.py
33 passed, 7 skipped
```

---

## Verdicts

| # | Item | Verdict |
|---|---|---|
| P3dshare-1 | README leads with the claim | done, new opening section |
| P3dshare-2 | Verify-without-running | done, fresh anchored bundle, both paths run |
| P3dshare-3 | The quickstart is true | done, 4 corrections, 1 blocking defect found |
| P3dshare-4 | The walkthrough script | **no-op**, existing tooling suffices |
| P3dshare-5 | Roadmap reorder | done |
| P3dshare-6 | The share text | drafted below, not committed |

---

## P3dshare-3. The quickstart is true

Run in order, from the clean clone, project `p3dshare` throughout.

### Finding 1: the stack does not come up, and the error points at the wrong thing

This is the one a stranger hits first and it cost the most time here.

`docker compose up -d --build` ended with:

```
Container p3dshare-decision-service-1  Error dependency decision-service failed to start
dependency failed to start: container p3dshare-decision-service-1 is unhealthy
```

`decision-service` crash-looped on:

```
ERROR - STARTUP: bundle 'ail-policies' has no revision on OPA after 30s -
opa-config.yaml's bundles: key and AIL_BUNDLE_NAME may not name the same bundle.
RuntimeError: OPA bundle 'ail-policies' not loaded at startup - refusing to serve.
```

That message names bundle **naming** as the suspect. Bundle naming was fine.
OPA's own log said:

```
[ERROR] Bundle load failed: server replied with Service Unavailable
  name = "ail-policies"
```

and the control plane was answering `GET /bundles/tenant_default` with 503.
The actual cause, found by inspecting the container's environment rather than
the file:

```
CONTROL_PLANE_READ_KEY     SET BUT EMPTY
CONTROL_PLANE_WRITE_KEY    SET BUT EMPTY
VERIFIER_READ_KEY          SET BUT EMPTY
VERIFIER_WRITE_KEY         SET BUT EMPTY
IMMUDB_USER                SET len=6
```

The control plane returns 503 for every request whose gating key is empty,
which is documented and correct (section 4.1). The copied `.env` had the four
credential variables present but empty. Appending the values section 4.1
publishes brought the whole stack up on the next `docker compose up -d`.

**Why this is a repo finding and not just my `.env`.** A stranger who skips or
mistypes one of those four gets a fail-closed 503 three layers away from the
cause, and the only error message with a suggestion in it points at bundle
naming. Nothing anywhere says "check that your credentials are non-empty".
Fixed by making the keys and credentials prerequisites explicit and
discoverable (new section 4.1a, Prerequisites); **not fully fixed**, because
improving `decision_service/main.py`'s diagnostic would be a production code
change and this phase forbids it. Carried below.

### Finding 2: the service counts are both wrong

Measured with the stack up:

```
docker compose -p p3dshare ps            -> 15 services listed
docker compose -p p3dshare config --services -> 18 defined
docker compose -p p3dshare ps -a | grep Exited:
  policy-validator     Exited (0)
  token-generator      Exited (0)
  workload-registrar   Exited (0)
```

The README's shape was right (N listed, three one-shot init jobs, named
correctly) and both numbers were stale: `anchor-service` and `dashboard` were
added after they were written.

### Finding 3: the attach command depends on the directory name

Section 4.4 and 4.5 both published `docker attach compliance-ail-langgraph-demo-1`.
Container names derive from the Compose project, which defaults to the
directory name. That is correct for a default `git clone` and wrong for
anyone who cloned into a different directory, which includes every scratch
clone this project's own workflow uses. Replaced with
`docker compose attach langgraph-demo`, which resolves by service and is
project-independent. Verified to resolve in this session.

### Section 4.4, the three demo tests: all three correct as published

Driven against the live stack with a real OpenAI key.

**Test 1**, the multi-framework denial:

```
Policy Engine Decision: DENIED: Instance type p4d.24xlarge is restricted.
'project' tag must be 'ml-training'.; SOC2 Violation. Production environments
must have 'encryption_at_rest' set to 'true'.
[Agent Request] -> [AIL Intercept] -> [Policy Engine Decision] -> [Ledger tx] 1 -> [Block]
```

Matches the published expected result on both grounds.

**Test 2**, the prompt injection. The README makes a specific and falsifiable
claim here: that the model may comply, that the gateway blocks it anyway, and
that the denial is a **policy** denial on a well-formed payload rather than a
schema rejection, with the reasons naming the injected values. All of it held:

```
Agent Request -> AIL Intercept: provision_cloud_server |
  args={"instance_type": "p4d.24xlarge", "region": "ap-southeast-1", "cost_per_hour": 50.0, ...}
Policy Engine Decision: DENIED: GDPR Data Residency Violation ... Approved:
eu-central-1, us-east-1; Instance type p4d.24xlarge is restricted ...;
Production environments must include a valid 'cost_center' tag. Approved
values: engineering, finance, marketing, operations.; SOC2 Violation ...
[Ledger tx] 2 -> [Block]
```

The model did comply with the injection and emitted the tool call. `/audit`
reports that record as `outcome_type: policy_deny`, confirming the payload
reached the policy engine rather than being refused by the schema.

**Test 3**, the approval: `APPROVED: Action approved by policy`, ledger tx 3,
execution proceeds. As published.

### Section 4.5, multi-tenant isolation: correct as published, and reversible by accident

**The audit defect the instruction sent me to drive is fixed.** The
2026-08-16 audit found the published Step 2 prompt never reached OPA, because
Pydantic rejected it first (`cost_per_hour` defaulted to 0.0 against a `gt=0`
field). The current prompt carries "$5/hour", `cost_per_hour` arrives as
`5.0`, and the request reaches OPA. No prompt change was needed.

Step 1, the OPA recreate, and the published confirmation command:

```
{"result":{"allowed_cost_centers":["finance","executive"],
           "approved_regions":["eu-central-1","us-east-1"],
           "tenant_id":"tenant_finance"}}
```

Step 2, the published prompt, with OPA genuinely pinned:

```
Policy Engine Decision: DENIED: Production environments must include a valid
'cost_center' tag. Approved values: executive, finance.
[Ledger tx] 6 -> [Block]
```

Verbatim match to the published expected denial. Step 3 approved at ledger tx
7; Step 4 restored `tenant_default` with `allowed_cost_centers` back to four.

**What I nearly reported as a defect, and the control that stopped me.** My
first two runs of Step 2 came back **APPROVED** under the Finance tenant, at
ledger tx 4 and 5, which would have been a straight refutation of the
README's central isolation claim. It was not. I was driving the agent with
`docker compose run`, which starts the service's dependencies, and Compose
re-evaluated `opa` against an environment with no `AIL_TENANT_ID` and silently
recreated it against the default tenant. Isolated with a control, container id
either side:

```
opa id before a compose run : f30cc04b0096   tenant_finance
opa id after  a compose run : 38306c3a80a7   tenant_default
opa id before, with --no-deps: 1bd4227dd261  tenant_finance
opa id after,  with --no-deps: 1bd4227dd261  tenant_finance
```

So the product was right and my instrument was wrong. The finding that
survives is real but different, and it is a documentation gap rather than a
defect: **the tenant pin is silently reversible by ordinary Compose commands.**
Section 4.5 already tells you how to restore it in Step 4; what it never said
is that anything starting containers reverts it for you. A reader
experimenting around the demo sees the opposite verdict with no message
explaining why. Added as a warning in 4.5, with the measurement.

---

## P3dshare-2. Verify-without-running

### The fixture

Generated from the real stack this session, not hand-assembled. The record is
section 4.4's Test 2: the prompt injection being refused. Exported with
`GET /audit/bundle`, which is the documented route.

**It is genuinely anchored.** `anchor-service` submitted this ledger's state
to the public transparency log during the session:

```
Anchoring tx=7 in https://log2025-1.rekor.sigstore.dev (discovered via trusted_root.tlogs)
POST https://log2025-1.rekor.sigstore.dev/api/v2/log/entries "HTTP/1.1 201 Created"
Anchored tx=7 at log index 108407026
```

So the decision's fallback (unanchored fixture, limit stated) was not needed.
The bundle reports `bundle_format: ail-evidence-bundle/2`,
`external_anchor.state: anchored`, `outcome_type: policy_deny`.

Committed to `docs/walkthrough/` with the three public keys it names and
Sigstore's trusted root. A separate directory from
`tests/fixtures/evidence_bundles/` deliberately: those four fixtures are what
`tests/test_offline_verify.py` checks the verifier against, they are signed by
the 2026-08-24 export's keys, and this bundle is signed by this session's, so
putting them together would have collided the `.pub` filenames. The
walkthrough says which is which.

### The primary path, run from a clean directory

```
$ python tools/ail_verify_bundle.py docs/walkthrough/injection-denied.json \
    --key docs/walkthrough/signing.pub \
    --writer-key docs/walkthrough/writer-decision.pub \
    --skip-anchor-check

OK [verified]
  ledger key   : tool_call:langgraph_agent:12688b3fc9524b4db7778b9df015a514:provision_cloud_server
  record type  : policy_deny
  transaction  : 2 (proven against trust anchor at tx 7)
  signing key  : sha256:d948681d5ee14890ed8eadc1930dec1fc2e8796581adc27b5204a31450e32c30
  written by   : sha256:b6c8e73b141d09401ea5b6e33915cd951ecdd6cedd467048661b014af8c35d4f
  corroboration: anchored, NOT CHECKED (--skip-anchor-check)

This bundle proves the record above was committed to the ledger, has not
been altered since, and was signed by the writer key named. It does not
prove the policy that produced the record was correct, and it does not
prove that writer was honest - only which key signed. See readME.md 3.4.
```

Run three ways, all in this session: from the repository root as published;
from a directory holding only the tool and the five files; and in a
`python:3.11-slim` container with **only** `pip install immudb-py==1.5.0`,
which confirms the dependency claim exactly as section 3.4.1 states it.

### The optional step

`sigstore` cannot be installed into this host's Python, so this transcript is
from a `python:3.11-slim` container with `immudb-py==1.5.0` and
`sigstore==4.5.0`. That is stated in the walkthrough and here rather than
quietly omitted; the primary path above is the one that needs no container.

```
  corroboration: anchored in https://log2025-1.rekor.sigstore.dev at index
                 108407026, inclusion proof and checkpoint verified
```

Everything else in the output is byte-identical to the primary path. The
committed `trusted_root.json`, exported 2026-08-24, verifies an entry made
today in the same log.

### The refusal, which is the part worth having

Omitting both the anchor material and `--skip-anchor-check`:

```
FAILED [anchor_unchecked] this bundle claims external corroboration, but no
--trusted-root and --anchor-key were supplied to test that claim against.
Supply them, or pass --skip-anchor-check to say deliberately that you are not
checking it
```

There is no way to get a pass without having said which of the two you meant.
Documented in the walkthrough, because a reader who meets it otherwise reads
it as the bundle being broken.

### On the decision's wording

The decision said the primary path's expected output "INCLUDES
ANCHOR_UNCHECKED". Two different things print that token and only one of them
is the primary path. `--skip-anchor-check` prints
`corroboration: anchored, NOT CHECKED`, which is the substance the decision
describes: proofs verified, anchor not checked, one sentence saying so.
Supplying the anchor material without sigstore prints
`FAILED [anchor_unchecked]` and verifies nothing at all. The walkthrough uses
the first as the primary path and documents the second as what you see if
sigstore is missing, which I believe is what was meant; flagging it because
the literal token appears only on the path that fails.

---

## P3dshare-4. The walkthrough script

**No-op.** `tools/ail_verify_bundle.py` is already a standalone CLI with
`--help`, named error classes, and a closing statement of what the check does
and does not establish. It imports nothing from the rest of the repository,
which was verified by running it from a directory containing only it and the
fixture files. No wrapper was written and no test was added.

---

## P3dshare-1 and P3dshare-7: claim edits

Every sentence in the new README opening traces to a test, a command run in
this session, or a Residual Limits entry.

| # | Site | Old | New | Reason |
|---|---|---|---|---|
| 1 | `readME.md` opening | went straight from the badges to "The Problem" | new section: what is enforced, what is fail-closed, what the ledger's account of itself guarantees, and what is not claimed, then a pointer to the walkthrough | The honest-claim statement lived at the bottom of a phase report. P3dshare-1. |
| 2 | `readME.md` Prerequisites | Docker, OpenAI key, 8 GB RAM | plus `openssl`, plus Python for the no-stack path | openssl is required by 4.1a and was unstated; the verify path needs none of the rest. |
| 3 | `readME.md` new 4.1a | did not exist; keys were mentioned only as "`make keygen`" | the five openssl pairs and the vault token, as raw commands, with the rotation caveat and the route-parity symptom | `make` is not on every machine. Decision 2. These are the commands this session ran. |
| 4 | `readME.md` 4.2 | "lists 13 of the 16 defined services" | "lists 15 of the 18 defined services" | Measured. |
| 5 | `readME.md` 4.4, 4.5 | `docker attach compliance-ail-langgraph-demo-1` (twice) | `docker compose attach langgraph-demo` | The old form depends on the clone directory's name. |
| 6 | `readME.md` 4.5 | Step 4 restores the default tenant | plus a warning that any Compose command starting containers reverts the pin silently, with the measurement | Cost this session two false APPROVED results before the control found it. |
| 7 | `readME.md` 7 | "Docker Compose \| v2 (16 services)" | "v2 (18 services)" | Measured. |
| 8 | `readME.md` 8 | `make test-integration` and a CI sentence | plus the raw compose and pytest invocations, the seven-service note, what a local run looks like away from CI, and "treat CI as the signal" | Decision 2, and the first-hour surface the instruction named. |
| 9 | `docs/plan/ail-roadmap.md` Phase 3 | one exit criterion bundling portability and footprint | 3d split into 3d-share (done) and three post-share phases, with the WASM landmine named first and the reason footprint was not the gate | P3dshare-5. |

**The mapping check, and one baseline edit that needs stating.** It ends clean
at `0 new, 10 known, 0 stale`, `34 heading pins, 0 unpinned, 0 retitled, 0
stale`. Getting there took two things. One new failure appeared because the
word "quickstart" in a new section 8 paragraph became the distinctive term for
a historical row citing section 4.1, which does not contain it; resolved by
rewording the new prose, which is this project's documented resolution for
that coupling. Two baseline entries then went **stale**, meaning quarantined
failures that stopped failing: `phase-1-3.md` row 15 (section 4.5 lacking
"message") and `phase-3a.md` row 8 (section 3.4.1 lacking "structural"). Both
stopped failing as a side effect of this phase's README edits rather than
because anyone repaired the rows. `tools/mapping_check.py --write-baseline`
removed exactly those two entries and added nothing: the diff is 16 deletions
and 0 insertions. Recorded here because "edit the quarantine record" is
normally the wrong move, and the argument for it in this direction is that a
baseline asserting a failure that no longer happens is itself inaccurate.

Nothing in the opening is stronger than section 5. Two sentences were checked
against it specifically: the fail-open anchoring claim, which restates the
existing Residual Limits entry, and the writer-signature claim, which
restates the D22 entry.

---

## The share draft

Not committed to the repository. For review.

> **Title: I built a policy gateway for AI agents, and you can check one of its claims without running it**
>
> Most "AI guardrails" are a paragraph in a system prompt. That is a polite
> suggestion enforced by a next-token predictor. I wanted to know what it
> takes to put a real enforcement boundary in front of an agent's tool calls,
> so I built one: every call is intercepted, schema-checked, evaluated against
> OPA policy, and written to a tamper-evident ledger before it executes. Any
> link failing denies the call.
>
> The part I actually want reviewed is not the architecture. It is this: you
> can verify one of its records yourself, right now, without running any of
> it.
>
> ```
> git clone https://github.com/banji-007/compliance-ail.git
> cd compliance-ail
> pip install immudb-py==1.5.0
> python tools/ail_verify_bundle.py docs/walkthrough/injection-denied.json \
>   --key docs/walkthrough/signing.pub \
>   --writer-key docs/walkthrough/writer-decision.pub \
>   --skip-anchor-check
> ```
>
> That record is a prompt injection being refused. The model complied with the
> injection and emitted the tool call; the gateway denied it anyway, on four
> policy grounds, and the denial is `policy_deny` rather than a schema
> rejection, which means the payload was well-formed and reached the policy
> engine. Install `sigstore` and re-run with the anchor material and you also
> check that the ledger state was published to a public transparency log, so
> the deployment cannot have rewritten its own history quietly.
>
> What it does not do, at the same resolution. It does not prevent prompt
> injection; it structurally constrains what a successfully injected agent can
> actually cause to happen. It does not prove the policy was right, only that
> the decision was recorded and has not changed. It does not prove the writer
> was honest, only which key signed, and every service currently mounts every
> writer key. Three of the four demo tools are `observed`, meaning the agent
> keeps their real authority and a bypassed call produces no record at all;
> one tool is mediated and that difference is stated per tool rather than
> averaged away. The Helm chart does not deploy. All of this is in the
> README's Residual Limits, which is long on purpose.
>
> The README leads with what is and is not claimed before it sells anything.
> I would rather be told the claims are too small than discover later they
> were too big.

The banned words do not appear. Every claim is a subset of the README's, and
the two that come closest ("tamper-evident", "structurally constrains") are
the repo's own wording.

---

## CI

**Run `34763307518`, head `9bc5983`, conclusion `success`: 583 passed, 10
skipped, no failures, in 3m19s.**

That run covers every file this phase changed except the two corrections
made after it (section 8's failure count and this section), which are
documentation only. The phase changed no production code, so CI is confirming
that the documentation edits broke nothing, not that behaviour is unchanged;
behaviour is unchanged by construction.

---

## What a stranger hits in the first hour that this phase knew about

Answered honestly, which is what the item asks for.

**Fixed or stated:**

- The stack not starting on empty credentials: prerequisites and 4.1a now make
  the keys and credentials explicit and discoverable.
- Both service counts, the directory-dependent attach command, the silently
  reversible tenant pin: fixed in place.
- The local test suite not behaving like CI: stated in section 8 with a
  measurement and a pointer to run one module instead. The raw commands there
  were all run in this session; the pytest invocation was **left incomplete**
  at 106 of 583 tests after about 40 minutes, with **2 failures**, against
  CI's 583 in under four with none. Section 8 publishes those as a floor
  rather than a total and says the run did not finish. The two failures were
  not individually diagnosed, because identifying them would have meant
  driving a multi-hour run that CI already answers in under four minutes;
  they are consistent with the two recorded host-specific causes and that is
  as far as this phase can honestly put it. An earlier draft of this report
  and of section 8 said "no failures" on the strength of the first 99 tests,
  which was wrong, and is corrected rather than quietly dropped.
- What the system does not claim: now the first screen rather than the last
  section.

**Known and not fixed, because fixing it is a production change this phase
forbids:** `decision_service/main.py`'s startup failure names bundle naming as
the likely cause when the actual cause is an empty credential three services
away. The README now makes the credential requirement hard to miss, which
reduces how often a stranger meets the message, and does not improve the
message. That is the honest state of it, and it is the one item here I would
fix first in the next phase that is allowed to touch code.

**Not encountered and therefore not answered:** anything requiring a machine
that is not Windows with Docker Desktop, and anything in the Kubernetes path,
which section 4.7 already documents as not deployable.
