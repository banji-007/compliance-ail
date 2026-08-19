# AIL v2: gap closure, pivot, and hosted architecture

> **Status: partly superseded.** `docs/plan/ail-roadmap.md` replaces the
> phasing in section 4 (Phasing) and section 6 (What to share, and when) —
> follow the roadmap's phases, not this document's. Section 3 (Target
> architecture) still stands, with the changes established by
> `docs/reports/spike-wasm-parity.md`: the bundle-revision digest cannot be
> read under WASM and is replaced by a module+data hash computed in the
> isolate, four Rego rules' `sprintf("%v", ...)` set-formatting diverges from
> the WASM evaluator's output, and the corpus is 13 deny rules, not 12
> (GDPR has 3). Section 3's MCP-mediation assumption is also refuted by
> `docs/reports/spike-mcp-mediation.md`: mediation is not a configuration
> change but a function of authority exclusivity — see the roadmap's
> section 2. This document is not deleted because it is cited elsewhere;
> read it for architecture context, not for phase sequencing or the MCP
> claim.

Baseline: HEAD `1ba5d05`, audit report `docs/audit/2026-08-16-verification.md`.

---

## 1. The pivot

**From:** a compliance gateway you deploy.
**To:** a verifiable record of agent governance that anyone can check without deploying anything.

Enforcement is now a commodity. agentgateway is Linux Foundation hosted with Cedar authorization per tool invocation; Kong, Cloudflare, Solo, and MintMCP all ship a variant. Nothing in AIL's current enforcement path is defensible against that.

The verifiable record is not commodity. The state of practice for agent audit is a hash chain with per-row HMAC in a database the vendor operates. Nobody is producing a portable evidence artifact a third party can verify offline. EU AI Act Article 12 tamper-evident logging obligations took effect 2 August 2026 with no finalized technical standard, so the slot is open and the deadline is live.

The consequence for scope: the gateway becomes one producer of records. The record format, the verifier, and the anchor are the product. That reframing is also what makes the trajectory work coherent later, because a stateful decision is only auditable if the state that drove it is in the record.

Blocking problem: the audit proved the record is not currently trustworthy. A decision evaluated against `tenant_default` was committed to the ledger stamped with the digest of `tenant_finance`'s bundle. The proof chain is intact and the claim it protects is false. Nothing in this plan is worth building until that is structurally impossible.

---

## 2. The root defect

Three audit findings are one bug:

| Finding | What happens | Collapse |
| :--- | :--- | :--- |
| V4 | Policy version unknown, recorded as `bundle-hash-unavailable`, entry written | unknown to "fine" |
| V2 | Policy version wrong, recorded as definite | unknown never detected |
| V6 | Entry not checked after verifier error, reported `verified: false` | unknown to "bad" |

The system has no representation for "unknown." An evidence layer needs four states: **asserted** (claimed, not yet checked), **verified** (proof passed), **unverifiable** (could not check), **failed** (proof rejected). Every record field and every UI surface carries one of the four. Collapsing them in either direction is the defect; the direction of collapse is incidental.

This is the single abstraction the rest of the plan depends on.

---

## 3. Target architecture

Five planes. No long-running containers in the hosted path.

**Decision plane, Cloudflare Worker.** Rego packs compiled with `opa build -t wasm`, evaluated through `@open-policy-agent/opa-wasm`. This is an officially supported integration; OPA ships a Cloudflare Worker example in `open-policy-agent/contrib`. The bundle for a tenant is fetched from Workers KV per request, not fixed per process, so multi-tenancy becomes real rather than one OPA process per tenant.

The policy digest is `sha256` of the wasm module plus the data document actually loaded into the isolate for that evaluation. It is computed from the artifact in memory, not by asking another service which bundle it thinks is active. The V2 class of bug becomes unrepresentable.

The OPA input document extends to `{tool_call, identity, tenant, session}`. V8 confirmed no current rule can reference identity, tenant, session, or history, which is why tenant isolation is architecturally impossible today.

**Session plane, Durable Objects.** One object per session, keyed by a gateway-minted session id bound to the workload identity. Single-threaded and consistent by construction, which is exactly the semantics a trajectory monitor needs. Holds accumulators and taint labels. The session id is minted at session open and returned as an opaque token; a bare string supplied by the agent is never accepted, or "start a new session" is a one-line taint bypass.

**Record plane, D1.** Each decision produces a canonical record: identity, tenant, tool, input hash, redacted field list, policy digest, session state digest, decision, reason, timestamp, previous record hash. Payload is hashed, never stored. That retires the Article 17 contradiction V9 demonstrated live, where a marker string in a `query` field was redacted in stdout and retrievable verbatim from the immutable ledger.

**Anchor plane, Sigstore Rekor v2.** A Merkle tree is maintained per tenant over the record hashes. Every N records or T seconds the root is signed and submitted as a DSSE checkpoint, and the inclusion proof returned on upload is persisted with the checkpoint, which is what Rekor's own client guidance requires now that the read API serves tiles rather than per-index proofs.

Anchoring is asynchronous by necessity: Rekor v2 batches submissions and integration takes seconds, so it cannot sit on the decision hot path. Only roots are published, never records, so the public metadata exposure is "a root hash exists at time T."

Two things this buys beyond parity with ImmuDB. First, the trust anchor moves from a volume you control to an append-only log with a third-party witness network, which is a strictly stronger answer to "who watches the ledger" than an ECDSA-signed state file on a separate Docker volume. Second, with Fulcio keyless signing the long-lived signing key disappears, and with it the README's only Known Limitation, the one where rotating `keys/signing.key` requires deleting the verifier state volume.

**Verification plane.** `npx @ail/verify bundle.json`: recompute the record hash, walk the Merkle path to the root, verify the checkpoint signature, verify the Rekor inclusion proof. Pure TypeScript, no Docker, no account, no network unless the user wants a fresh checkpoint. Plus a static drag-and-drop page on Vercel.

**Identity.** One interface, two backends. Hosted: Cloudflare mTLS client certificate via `request.cf.tlsClientAuth`, or an OIDC workload token (GitHub Actions, Kubernetes projected service account). Self-hosted: SPIFFE SVID, unchanged. In both modes the actor is derived from the presented credential and never from the request body, which fixes the `agent_id="langgraph_agent"` string literal that currently populates a cryptographically verified audit field.

### What gets deleted from the hosted path

ImmuDB, the verifier container, SPIRE server, SPIRE agent, the watchdog, the workload registrar, Envoy, the OPA container, Prometheus, Grafana, token-generator, policy-validator. Sixteen services and eleven volumes go to zero. Local development is `wrangler dev` plus `next dev`.

The full Docker stack survives as the `self-hosted` profile for buyers who need SPIFFE mTLS and an on-premises ledger. It stops being the way anyone evaluates the project.

### Cost

Workers and D1 free tiers cover a demo. Durable Objects require the $5/month Workers paid plan. Rekor public instance is free. Vercel hobby is free.

---

## 4. Phasing

### Phase 0. Truth pass. Nothing new is built.

Non-negotiable and first. Building on a demo that lies costs more than it saves.

- Policy digest is derived from what OPA actually evaluated, or the call fails closed. No HEAD request to a bundle nobody loaded.
- README section 4.5 and section 3.3's "same OPA process, two isolated policy brains" corrected to the truth: isolation is per OPA process, which is what the Helm chart already does.
- Root-cause the demo agent reporting "audit ledger write failed" on all four runs where the ledger verified. The user-visible output of the demo is currently wrong on the happy path every time.
- Test gate collects what it claims: five methods in three files are silently dropped because their classes define `__init__`.
- `make test-integration` stops failing for anyone with a root `.env`; Compose auto-loads it regardless of `-f`.
- README's "five acceptance tests including tamper detection" scoped to the one realistic tamper test, or a second realistic one written. `test_tamper_pubkey` overwrites `_vk` on an object the test constructed, which is a misconfiguration, not an attack.
- Helm chart either gains the verifier or is marked unsupported. It currently deploys the architecture ADR-001 abandoned.

**Acceptance:** every claim in the README maps to a passing test or a reproducible command; `pytest tests/` collects 34 items; a clean clone plus a documented command produces a demo whose output matches its documentation.

### Phase 1. Evidence bundle and offline verifier.

Ships against today's ImmuDB records. No migration required. This is the first thing that is actually shareable, because it turns evaluation from "run sixteen containers" into "open a link."

- Canonical record schema with the four-state field model from section 2.
- `@ail/verify` npm package plus the static verification page.
- ADR-005 recording the evidence bundle format.

**Acceptance:** a bundle downloaded from the dashboard verifies on a machine with no AIL code, no Docker, and no network; a single flipped byte in the record makes verification fail with a named error, not a generic one; a record whose policy digest is `unverifiable` reports as unverifiable, distinctly from `failed`.

### Phase 2. Edge decision plane spike.

- Compile the four packs to wasm; build a golden corpus of inputs covering all thirteen deny rules.

**Acceptance:** wasm and OPA-server decisions are identical across the corpus, including message strings. If any builtin fails to compile, report it rather than rewriting the rule to fit.

### Phase 3. Hosted gateway.

Identity backends, extended input document, D1 records, per-tenant Merkle tree, Rekor checkpointing. Python interceptor becomes a thin client SDK against the hosted decision endpoint so the LangGraph demo keeps working unchanged.

**Acceptance:** two tenants served concurrently by one deployment with different verdicts on the same input, proven live; actor field in every record traceable to a presented credential; checkpoint anchored in Rekor and independently verifiable via `rekor-cli`.

### Phase 4. Trajectory.

Durable Object session state, declared-label taint, gateway-minted session identity, windowing or declassification.

**Acceptance:** the honest self-inflicted demo, an injection that reads PII through an approved `query_database` call and exfiltrates through an approved egress tool, both individually policy-compliant. v1 approves it. v2 denies the second call and the record shows the session state digest that caused the denial. Session laundering by restart or by supplying a new session id is denied.

### Phase 5. MCP integration.

Second framework integration. Retires the "LangGraph reference only" caveat and puts the interception point where the standards work is happening.

---

## 5. Risks

- **Rego builtin coverage under wasm.** Not all builtins compile. The rules use `contains`, `sprintf`, set membership. Phase 2 exists to find out before anything depends on the answer.
- **Losing SPIFFE in hosted mode** weakens the "off-host enforcement bound to cryptographic workload identity" position, which is the one thing the current design has that CaMeL, Progent, and IsolateGPT do not. Mitigated by keeping SPIFFE in the self-hosted profile and by treating identity as an interface, but it is a real trade and should be stated in an ADR rather than glossed.
- **Rewrite cost.** Control plane and decision path move from Python to TypeScript. The interceptor SDK staying in Python contains the blast radius.
- **Rekor is public.** Only roots are published. Any design that would put record contents in the log is out of scope. An enterprise profile needs a private Trillian or an ImmuDB fallback, and that should be a documented deployment option, not an afterthought.
- **Durable Objects are Cloudflare-specific.** The session store should sit behind an interface with a Postgres or Redis implementation for the self-hosted profile.

---

## 6. What to share, and when

Not before Phase 0. After Phase 1 there is a link that demonstrates the differentiated claim in under a minute with no install, and that is the right moment.
