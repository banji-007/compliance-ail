# ADR 0003: Trust Profiles (Observed, Mediated, Attested)

## Status

Proposed (P13-8)

## Context

The MCP mediation spike (`docs/reports/spike-mcp-mediation.md`) tested the assumption that placing a proxy in an agent's tool-call path is sufficient for a "Mediated" trust guarantee. It found that topology does not decide the outcome, authority does. Under stdio, a proxy that owns its own subprocess blocks every network-based bypass, but a compromised agent that can independently reach the tool's authority (a shared filesystem, a reachable socket, the server binary itself) simply runs its own unmediated copy of the same server (spike report, M2, attempts A5/A5b). Under HTTP, an agent on the same network as the upstream reaches the tool directly regardless of the proxy's presence, the proxy's place in the path is unenforced without independent network segmentation (spike report, M2, HTTP bypass table).

A profile defined by deployment topology, "a proxy sits between the agent and the tool," describes something that can be true of the wiring diagram and false of the actual guarantee. This amendment redefines the three trust profiles by authority instead, and states the attribution ceiling the same spike established.

## Decision

Profiles are per-tool, not per-deployment. A single deployment can serve some tool calls at one profile and other calls at a different profile within the same session. The ledger record's `profile` field describes the call, not the deployment it ran in.

- **Observed** - the gateway evaluates and records the call. The agent independently holds the tool's authority, so a bypass is possible and undetectable.
- **Mediated** - the gateway holds the tool's authority exclusively and the agent cannot exercise it independently. A bypass fails rather than going unrecorded. Requires a least-privilege agent runtime, not merely a proxy in the path.
- **Attested** - Mediated, plus a workload identity bound to the record and an external anchor.

## Attribution ceiling

The gateway attributes a call to a session or a process, and in the Attested profile to a workload. It cannot attribute to intent: a compromised agent's calls attribute to the same identity as its legitimate ones.

This bound comes directly from the spike (`docs/reports/spike-mcp-mediation.md`, M5). Under HTTP the proxy attributes a call to an MCP session id and the TCP peer captured at session init. Under stdio, to the OS parent-child process relationship between the client and the proxy it spawned. Neither transport gives the gateway a way to distinguish a legitimate call from a compromised one issued under the same, already-attributed identity. The identity is real; it says nothing about whether the call reflects the operator's intent.

## Consequences

**Gained:**

- The profile recorded against every call is now falsifiable against a concrete authority test (does the agent independently hold the tool's authority, yes or no), instead of a topology description that can hold on the diagram and fail in practice.
- The attribution ceiling is stated once, here, instead of being implied differently wherever a record's identity field is read.

**Constraints:**

- Mediated requires a least-privilege agent runtime as a precondition, not just a proxy wired into the call path. Where that precondition does not hold (spike report M2, A5/A5b: a shared filesystem, a reachable socket, an executable server binary the agent can also run), a tool call is Observed even if a proxy sits in its configured path.
- No profile substitutes for a containment control the gateway does not itself enforce. Mediated over HTTP depends on network segmentation the adopter's infrastructure provides (spike report M2, M6). Mediated over stdio depends on OS-principal isolation the adopter's runtime provides (spike report M4, M6). The gateway can only report which profile a call actually achieved, not guarantee the precondition that profile requires.
- Attested's workload-identity claim is bounded by what the transport actually exposes (spike report M5: session or process identity). It is not intent attribution and must not be represented as such in the audit UI or in compliance reporting derived from these records.

## References

- `docs/reports/spike-mcp-mediation.md` - M2 (bypass evidence per transport), M4 (credential isolation), M5 (attribution ceiling), M6 (adoption cost and preconditions)
- `docs/plan/ail-v2-plan.md` §4, Phase 5 (MCP integration)
