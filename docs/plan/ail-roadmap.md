# AIL roadmap

Status: current. Supersedes the phasing in `docs/plan/ail-v2-plan.md` sections 4 and 6; that document's architecture section survives with the changes the WASM parity spike established.

Written after the Phase 1.2 red-team report, revised after `docs/reports/spike-mcp-mediation.md` and the Phase 1.3 completion pass. Profile definitions live in `docs/adr/0005-outcome-taxonomy.md` and are summarized here rather than restated.

---

## 1. Where the remediation arc ended, and why it ended

Six phases of correction ran from Phase 0 through Phase 1.3. Two things caused that, and only one of them is fixed.

**Criteria described mechanisms rather than properties.** An acceptance criterion that names a fix can be satisfied by a change that does not address the finding, which is exactly what P11-7 did to S2. From Phase 1.2 onward, any item remediating a red-team finding is accepted only when the original attack, re-run verbatim, stops working, and the attack becomes a test. That is fixed.

**Every refutation was treated as blocking.** A false sentence in the README and a denial-of-service against a local demo were handled identically. That is what turned a two-phase correction into six. The triage rule in section 3 fixes it.

The thing that is not fixed, and cannot be fixed by process, is that the trust boundary sits inside the process it constrains. `intercept_tool_call` runs in the agent's own interpreter. A compromised container holds every credential the interceptor holds and can call the tool directly without asking. Prompt injection is genuinely constrained, because an injected LLM can only emit tool calls and every emitted call passes the hook. Container compromise is not constrained at all. README section 1 and section 3.1 now say this plainly. Phase 2 is where it changes.

---

## 2. What the MCP spike established

The spike tested the claim that an MCP proxy makes enforcement non-bypassable. It refuted it, and in doing so found the actual principle.

Under stdio, the network bypasses are impossible, because there is no address and the proxy owns the subprocess. But the agent self-spawned an off-the-shelf filesystem server pointed at a volume the proxy also used, and wrote to it unmediated. Under HTTP, bypass was blocked from a segmented container and succeeded from a container sharing the upstream's network.

**Mediation is a property of authority exclusivity, not of MCP, a proxy, or a transport.** Enforcement is non-bypassable for a given tool if and only if the gateway holds that tool's authority and the agent does not. The filesystem case failed because the authority was an ambient shared mount. The HTTP case failed because the upstream accepted unauthenticated connections, so there was no authority to hold.

Two consequences. First, **profile is a property of the tool, not the deployment**: one installation can be Mediated for a tool whose credentials live only in the gateway and Observed for a tool the agent can reach directly, and the record declares which applied to that call. Second, **Mediated is not a configuration change.** I said it was; that was wrong. It requires removing the agent's independent authority, which is real least-privilege work: no shared mounts, credentials only in the proxy, no ambient network reach.

Attribution ceiling, from the same spike: the gateway attributes a call to a session or process, and under Attested to a workload. It cannot attribute to intent, so a compromised agent's calls carry the same identity as its legitimate ones.

---

## 3. The triage rule

Every red-team finding gets one disposition, decided when the report lands.

**Blocking.** It falsifies a claim in the README, an ADR, the dashboard, or a test name. Fixed in the current phase, or the claim is scoped down in the current phase.

**Next phase.** It breaks an invariant a later phase already establishes. Backlogged with the phase named. It does not spawn a phase.

**Known and unfixed.** Real, not a false claim, no scheduled phase closes it. Goes to the README's Residual Limits and ships disclosed.

A red-team pass is warranted when new design lands, not when prose and decorators change.

---

## 4. Definition of done

Done is **shareable**: a stranger can verify a claim about a governed agent action without running anything, and every claim the repository makes is backed by a passing test, a reproducible command, or a Residual Limits entry.

| Invariant | Today | Made true by |
| :--- | :--- | :--- |
| 1. Every action intercepted before execution | False against a non-cooperating agent | Phase 2, per-tool, where authority is exclusive |
| 2. Schema-validated | True | done |
| 3. Policy-evaluated fail-closed | True for cooperating agents | Phase 2 |
| 4. Independently verifiable tamper-evidence | Partial: host exposure closed, but any party at the agent's network position can write a record that verifies | Phase 3 |

Plus: a working deployment in minutes, and a claim verifiable without deploying anything.

---

## 5. Phases

### Phase 2: Move the boundary

Two parts, both in the existing stack. This is not the hosted move; boundary and edge are separate problems and conflating them was an earlier error.

**The decision leaves the agent process.** A decision service evaluates policy and writes the record. The agent holds no credential that can write a record and no path to the ledger. This closes the class containing U1's manifest forgery, U5's forged tombstone, and U8's unauthenticated policy replacement, by making them unrepresentable rather than patched.

**Authority exclusivity becomes declarable and achievable per tool.** The tool registry records whether the gateway holds a tool's authority exclusively. Records carry the resulting profile. MCP over stdio is one delivery mechanism and the strongest available today; MCP over HTTP requires network segmentation the adopter must supply, and the registry must not claim Mediated where that segmentation is absent.

Also here: the SPIRE-absent exit currently exists only as a side effect of `verify_bundle_at_startup`, so reordering that function silently removes a documented security property. Give it a dedicated guard and a test in the gate.

**Exit criterion:** for at least one tool whose authority is exclusive, an agent with arbitrary code execution in its own container attempts the action directly, fails, and the attempt is recorded. Demonstrated live, enforced by a test. Its red-team pass matters more than any previous one, because "a compromised agent cannot reach the tool" is the strongest claim this project would ever make.

### Phase 3: Make the record portable, and the footprint small

- Evidence bundle plus a standalone verifier: recompute the hash, walk the inclusion path, check the signature. No Docker, no account, no network.
- Records signed by their writer, so provenance travels in the record rather than being inferred from which port accepted the write. This is what closes invariant 4.
- Anchoring to an external transparency log, retiring the signing-key rotation limitation by construction.
- `/audit`'s per-entry verification is O(n) and now takes about 39 seconds at 200 entries, timing out tests during the Phase 1.3 red-team run. It is a flakiness generator whose trigger grows every session. Lazy verification, as ADR-0001 anticipated.
- **Minimum footprint as an exit criterion.** The WASM spike measured a 144KB module evaluating in fractions of a millisecond, so policy embeds rather than running as a service. With periodic anchoring instead of ImmuDB, the minimum deployment is one process plus a record sink; SPIRE, Envoy, Prometheus, Grafana, ImmuDB, and the dashboard become optional.

**Exit criterion:** a bundle verifies on a machine with no AIL code; one flipped byte fails with a named error; an unverifiable digest reports unverifiable, not failed. And an Observed deployment running in minutes without Docker, with `docker compose up` remaining the full-stack path.

This is where the project becomes shareable.

### Phase 4: Hosted deployment. Optional.

Workers with the packs compiled to WASM, Durable Objects for session state, D1 for records, Rekor for anchoring. The spike returned GO WITH CHANGES: Rego stops carrying the revision, the host hashes module and data in the isolate, and the tenant id is bound into the data document with the policy asserting the match, so a concurrency mistake cannot decide one tenant's call against another's config.

Because Phase 2 fixes the boundary in place and Phase 3 fixes the footprint, this can slip without blocking anything.

---

## 6. After the roadmap

Trajectory policy is the first work that is a contribution rather than a correction: taint over declared labels, accumulators, gateway-minted session identity. It needs Phase 2 for a session-scoped enforcement point and Phase 3 for a record carrying the session state digest. Capability-token egress gating for non-MCP tools lands here too.

Backlog stays in `TODO.md`, plus: OPA management hardening for the agent-reachable case, Basic Auth requiring TLS, erasure attribution to a person rather than a key, and Helm, unsupported until Phase 4 decides whether it survives.

---

## 7. What would change this plan

**If authority exclusivity turns out to be unachievable for realistic tools**, invariant 1 is out of reach, Observed is the only honest profile, and the position becomes that AIL constrains cooperating agents and prompt injection. That is what everything else in this space actually offers, and it would have to be stated rather than implied.

**If a red-team pass finds the decision service bypassable**, that is Blocking, because it falsifies Phase 2's own exit criterion.

**If the enforcement-gateway category ships portable evidence bundles before Phase 3 lands**, the differentiation narrows, and the response is to say so.
