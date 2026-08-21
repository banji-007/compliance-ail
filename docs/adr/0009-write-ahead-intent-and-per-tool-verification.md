# ADR 0009: Write-Ahead Intent Visibility and Per-Tool Exclusivity Verification

## Status

Accepted

## Context

ADR-0008 (D12) moved policy evaluation, schema validation, and the ledger
write out of the agent process into `decision_service/`, and made that
service the one thing on the network that also executes the one mediated
tool (D14, `read_vault_secret`) on the agent's behalf. Before this pass, the
completion record for that execution - `outcome_type`, `fault_class`, the
result - was written once, after execution, the same way every other tool
call's record has always been written.

Two gaps followed directly from that shape, both surfaced by review of the
Phase 2 build rather than by a red-team exercise:

**The recording gap.** Execution and its own durable recording are two
separate operations against two separate systems (this process, and ImmuDB
via the verifier), and nothing can make two operations against two systems
atomic. If decision-service executes the vault tool and then the ledger
write for the completion record fails - the verifier becomes unreachable in
the window between execution finishing and that write starting, for
example - the tool ran, a real secret was returned to the agent, and
nothing durable says so. Before this ADR, that call is simply absent from
`/audit`: indistinguishable from a call that was never attempted at all.

**The verification-keying gap.** `decision_service/schemas.py`'s
`_MECHANISM_VERIFIED` (ADR-0008, D13) was a boolean keyed on the mechanism
string, populated once at startup by running `mcp_stdio_secret_mount`'s own
check. `resolve_exclusivity_for` read that boolean by mechanism name, not by
tool name. With exactly one tool declaring that mechanism today, the
distinction was latent, not exploitable - but the design as written meant a
second tool later declaring the identical mechanism string would inherit
the first tool's verification result without its own check ever running in
its own name. That is precisely what D13 forbids: recording `demonstrated`
on the strength of something the gateway did not itself check for *this*
tool.

## Decision

### D16: write-ahead intent, then completion

Before `decision_service/main.py::decide()` calls `_execute_vault_tool`, it
now calls `ledger/immudb_ledger.py::log_tool_intent`, writing a distinct
`record_type: "decision_intent"` entry (key prefix `tool_call_intent:`,
scanned separately from `tool_call:` - the same partition-by-prefix,
classify-by-field discipline `content_erasure:` keys already established,
ADR-0005 D11) carrying `agent_id`, `tool_name`, `call_id`, the policy
revision that approved the call, `input_sha256`, `content_state`, and
`profile`. This is the record of "approved, under this policy revision,
about to execute" - written before execution, not after.

**If the intent write fails, execution is refused outright.** This is
enforced in `decide()`'s own control flow (`try` the intent write; only the
`else` branch calls `_execute_vault_tool`), not by a convention a future
change could silently drop. The response the agent receives is
`outcome_type: fault`, `fault_class: intent_write_failed` - and, per the
existing fail-closed ledger-guard discipline, the completion record
documenting that refusal is still written normally, because content storage
and policy resolution already succeeded by that point.

Execution and the completion write still cannot be made atomic. What
changes is what happens when they diverge: a successful intent write
followed by a completion write that fails leaves an intent record with no
matching completion record for the same `call_id`. `control_plane/main.py::
get_audit` now performs a third scan (`tool_call_intent:`, joined by
`call_id` against the completion entries the same way tombstones are
already joined) and surfaces this at read time as `execution_state:
"unknown"` - a synthesized entry built from the intent record's own fields,
carrying `outcome_type: "policy_allow"` (what was approved, not a claim
about what happened next) and no fabricated completion data. Every other
record gets `execution_state: "completed"` (an intent and a completion both
exist) or `"n/a"` (no intent record exists at all - every `observed` record,
and any `read_vault_secret` call denied or faulted before reaching the
intent write).

This is the same principle ADR-0006 and ADR-0005 already apply to
verification state and `payload_state`: a gap in what the system can
guarantee is not closed by pretending it doesn't exist. It is computed at
read time, from what was actually written, and rendered as its own distinct
state.

### D17: exclusivity verification is keyed by tool, not by mechanism

`decision_service/schemas.py` now keys verification results by tool name
(`_TOOL_VERIFIED: Dict[str, bool]`), not by mechanism string. A new
`run_verification_pass()`, called once from `decision_service/main.py`'s
`lifespan`, iterates every tool in `TOOL_REGISTRY` whose mechanism is in
`_VERIFIABLE_MECHANISMS` and invokes that mechanism's registered check
(`register_mechanism_verifier`) independently for each one, storing the
result under that tool's own name. Two tools sharing an identical mechanism
string each trigger their own call to the check - proven in
`tests/test_exclusivity_verification.py` by call count, since the one real
check today (`_verify_mcp_stdio_secret_mount`) takes no tool-specific
parameter and so cannot be distinguished by differing return values alone.

`resolve_exclusivity_for` now takes the tool's own name and looks up
exactly that key. A tool absent from `_TOOL_VERIFIED` - including,
structurally, a tool that could be added to `TOOL_REGISTRY` after
`run_verification_pass()` has already completed, since there is no runtime
registration path in this codebase and so no way to re-run the pass for it
- resolves to `declared`, never `demonstrated`, by the same "absent means
unverified" logic D13 already established. This holds without a special
case for lateness; it follows from the dict lookup itself.

This does not make the underlying check tool-aware - `_verify_mcp_stdio_
secret_mount` still checks one hardcoded path regardless of which tool
triggered it, so two tools sharing the mechanism today would still get
identical results if both existed. What D17 closes is narrower and
specific: the *inheritance* of a result one tool's check never actually
produced for another tool's own name. Making the check itself
parameterizable per tool (e.g. a per-tool secret path) is a natural
follow-on if a second verifiable mechanism is ever added, and is out of
scope here - D17 fixes the caching bug, not the check's granularity.

## Consequences

**Gained:**

- A mediated call's outcome is now either known (`completed`, including a
  documented fault) or honestly unknown (`unknown`) - never silently absent
  from `/audit` the way an executed-but-unrecorded call was before this ADR.
- `demonstrated` can no longer be inherited by a tool the gateway never
  itself checked, closing a gap in D13's own guarantee that was latent
  (one verifiable tool today) but structural.

**Constraints:**

- `execution_state` is a new closed-set field on every `/audit` entry
  (`"completed" | "unknown" | "n/a"`) - `dashboard/lib/types.ts::AuditEntry`
  and `audit-table.tsx` must stay in sync with it, the same discipline
  ADR-0005 already requires for `outcome_type`/`fault_class`.
- `intent_write_failed` is a new fault class, reachable from `/audit` (the
  completion record documenting the refusal is written normally) - added to
  the closed sets in `decision_service/main.py`,
  `dashboard/lib/types.ts::FaultClass`, and ADR-0005's Documented Boundary
  section.
- A second verifiable mechanism, when one is added, must register its own
  check via `register_mechanism_verifier` and rely on `run_verification_
  pass()`'s per-tool iteration - reintroducing a mechanism-keyed cache
  anywhere in that path reopens exactly the gap D17 closes.

## References

- `ledger/immudb_ledger.py::log_tool_intent`, `log_tool_call`
- `decision_service/main.py::decide`, `FAULT_INTENT_WRITE_FAILED`
- `decision_service/schemas.py::run_verification_pass`,
  `resolve_exclusivity_for`, `_TOOL_VERIFIED`
- `control_plane/main.py::get_audit` - the third scan and the
  `execution_state` synthesis
- `docs/adr/0005-outcome-taxonomy.md` - the taxonomy and Documented Boundary
  section this ADR extends
- `docs/adr/0008-decision-service-boundary.md` - D12-D15, which this ADR
  builds directly on
- `tests/test_intent_completion_visibility.py` - D16's write-side gate
  (mocked, no live stack) and read-side surfacing (live, including the
  forged-orphan-intent reproduction)
- `tests/test_exclusivity_verification.py` - D17's per-tool independence
  and late-registration refusal
- `docs/reports/phase-2-completion.md` - Demonstrate/Enforce/Mutation
  evidence for both items
