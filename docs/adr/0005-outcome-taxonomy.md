# ADR 0005: Outcome Taxonomy and the Record Schema

## Status

Accepted

## Context

Before Phase 1, a ledger entry was a single free-text `decision` string
(`"APPROVED"`, `"DENIED: <reasons> (policy: <revision>)"`, or, for an
infrastructure fault, the exact same shape as a real policy denial -
`"DENIED: Compliance engine unavailable. Fail-closed policy enforced."`).
Every consumer - the dashboard, Prometheus labeling, the agent's reply text
- either re-parsed this string or read an ad hoc, inconsistently-present key
(`fault: "infrastructure"` on some paths, absent on others). Red-team R4
(`docs/reports/phase-0-1-redteam.md`) showed this directly: an OPA-down
denial produced a real, ledger-verified entry with no fault marker anywhere,
indistinguishable from a genuine GDPR/SOC2/FinOps violation on every surface
- the agent's reply, the ledger, `/audit`, the dashboard, and Prometheus.

## Decision

Every intercepted call is assigned exactly one `outcome_type`, from a closed
set, at exactly one point in the code (`interceptor/middleware.py::query_opa_policy`,
finalized in `intercept_tool_call`):

| `outcome_type` | Meaning | `fault_class` | `policy_revision` |
| :--- | :--- | :--- | :--- |
| `policy_allow` | OPA evaluated and permitted | `null` | set |
| `policy_deny` | OPA evaluated and refused | `null` | set |
| `schema_deny` | Rejected by the schema registry before OPA was queried | `null` | `null` |
| `fault` | The call could not be evaluated | one of four below | `null` |

`fault_class` is one of: `opa_unreachable`, `revision_unavailable`,
`verifier_unreachable`, `spiffe_unavailable`, `malformed_policy_response`
(Phase 1.1, P11-3), `content_store_unreachable` (Phase 1.1, D7). Nothing
downstream re-derives `outcome_type` or `fault_class` from message text -
`_render_message` in `interceptor/middleware.py` goes the other direction,
from the already-decided type to presentational text.

`malformed_policy_response` covers a 200 response from OPA's `/evaluation`
whose body is missing or mistyping `allow`, `reasons`, or `revision` - red-
team S3 found a body with only `allow` present was read as `policy_allow`
with a null revision, contradicting this ADR's own table. Validated in
`query_opa_policy` immediately after the existing `result is None` check
(which stays `revision_unavailable` - that is a *structurally* undefined
result, not a malformed one).

`content_store_unreachable` covers a failed content-store write (D7,
`docs/adr/0005-outcome-taxonomy.md` continues to apply here: this fault
still follows the same closed-set discipline). Unlike the other four fault
classes, this one is checked for *before* the ledger write is attempted -
see the Documented boundary section below, which this phase extends.

The ledger entry itself carries this taxonomy directly - no free-text
`decision` string. `call_id` and `content_state` (D7, Phase 1.1) join the
entry to its erasable content-store row - see `docs/adr/0006-verification-
states.md` for the read-time inference this enables (`payload_state`),
which follows the same pattern D2 uses for verification:

```json
{
  "record_type": "decision",
  "agent_id": "...", "timestamp": "...", "tool_name": "...",
  "call_id": "<uuid4 hex, minted at intercept>",
  "input_sha256": "...",
  "outcome_type": "policy_deny",
  "fault_class": null,
  "policy_revision": "<bundle revision>",
  "reasons": ["..."],
  "content_state": "present",
  "profile": "observed"
}
```

### `record_type` and erasure as a recorded event (D11, Phase 1.2)

Every ledger record now carries an explicit `record_type`: `"decision"` for
the shape above, or `"content_erasure"` for the tombstone `DELETE
/content/{call_id}` writes directly (via the same verifier the interceptor
uses, `control_plane/main.py::_write_tombstone`) before it deletes a
content-store row:

```json
{
  "record_type": "content_erasure",
  "call_id": "<the call_id whose content-store row was deleted>",
  "timestamp": "...",
  "actor": "control-plane-write-key",
  "profile": "observed"
}
```

A tombstone carries no personal data - just enough to prove an erasure
happened, when, and under which authorization boundary. It is written
*before* the row is deleted, not after: if the tombstone write fails, the
erasure is refused and the row survives - the same fail-closed ordering D7
already established for content-before-ledger. `record_type` exists so a
consumer scanning a broader key range discriminates on this field, not on
key shape (`control_plane/main.py::get_audit`'s own content_erasure: scan
still checks the field, not just the prefix, before trusting an entry as a
tombstone). A tombstone is never rendered as a decision in `/audit` and is
never counted in `ail_policy_decisions_total` - it is written entirely
inside the control plane, a different process from the interceptor that
owns that metric.

Read-time inference of the erasable payload's own state (`payload_state`,
computed by `control_plane/main.py::_payload_state`, same read-time
pattern D2/D8 use for verification) is now five states (P13-4 adds the
fifth):

| `payload_state` | Meaning |
| :--- | :--- |
| `present` | The content-store row still exists and no tombstone exists for this `call_id`. |
| `unavailable` | `content_state` was already `"unavailable"` at write time (nothing dict-shaped to store) - always wins over the rest. |
| `erased` | A `content_erasure` tombstone exists for this `call_id` and the row is gone - the real endpoint always writes the tombstone first. |
| `lost` | `content_state` was `"present"`, the row is gone, and no tombstone exists - the row disappeared some other way (e.g. a direct SQL delete bypassing the endpoint). |
| `erasure_conflict` | A `content_erasure` tombstone exists for this `call_id` **and the row still exists anyway** - never rendered as `present` (payload is withheld) and never silently collapsed into `erased` (a real row is a real problem the CISO needs to see, not just the fact that an erasure was once requested). |

Red-team T5 (`docs/reports/phase-1-1-redteam.md`) found `erased` and what
is now `lost` rendering byte-for-byte identically - a GDPR Article 17
request honored through the real endpoint was indistinguishable from an
operational data-loss incident. `lost` exists specifically so those two
are never conflated again. Red-team U4 combination 1
(`docs/reports/phase-1-2-redteam.md`) found the same conflation on the
opposite side - a tombstone coexisting with a still-present row rendered
as plain `present`, discarding the tombstone. `erasure_conflict` (P13-4)
closes that: `write_content` now also refuses to write to a tombstoned
`call_id` at all (`control_plane/main.py::_has_tombstone`), so this state
should not arise through this control plane's own routes going forward -
it remains reachable from a tombstone forged directly against the
verifier (P13-2's residual limit) or an operational failure between a real
tombstone write and the row delete that should follow it.

Metrics follow the same closed set (Phase 1, D3): `ail_policy_decisions_total`
is labeled by `outcome_type` and `fault_class`, not by a substring of a Rego
deny message - a policy author changing denial wording cannot reshape metric
cardinality.

### Conformance profile (P13-8, Phase 1.3)

Every record now carries `profile`, from a closed set of three. `"observed"`
is the only value any record in this codebase has ever carried or can carry
today; `mediated` and `attested` are defined here so that reaching them
later is a value change, not a schema change.

A profile describes a **call**, not a deployment. It is defined by where the
tool's authority sits relative to the gateway, not by which components are
wired into the topology - a proxy sitting on the path between an agent and
a tool does not, by itself, change which profile applies to the calls that
cross it. This distinction exists because it is the one the go/no-go spike
at `docs/reports/spike-mcp-mediation.md` found the roadmap's own topology-
based framing failed to preserve: adding a mediation proxy is a
configuration change; taking the tool's authority away from the agent is
not.

| Profile | Authority | Bypass |
| :--- | :--- | :--- |
| `observed` | The agent independently holds the tool's authority (its own credentials, its own reachable copy of the tool, or both). The gateway evaluates and records the call, but nothing stops the agent from exercising that authority without going through the gateway. | Possible, and undetectable - a bypassed call leaves no record at all, because the record is only ever produced by the gateway path the agent chose not to take. |
| `mediated` | The gateway holds the tool's authority exclusively. The agent cannot exercise it independently, by construction. | Fails rather than going unrecorded - there is no unmediated path to the tool's authority left for a bypass attempt to reach. |
| `attested` | Mediated, plus a workload identity bound to the record and an external anchor. | Same as `mediated`, with the added guarantee that the record names *which* workload the call came from, cryptographically, and that guarantee is checked against something outside the gateway's own process. |

This gateway, as built, is `observed`. Section 1's own correction (the
interceptor is an in-process hook, not an out-of-band gateway) is the same
finding stated architecturally: `interceptor/middleware.py` runs inside the
same process and under the same OS principal as the agent code that calls
it, and the actual tool execution - the cloud API call, the database query,
the deploy - is something the agent's own runtime is capable of performing
directly, with or without calling `intercept_tool_call` first. Nothing in
this codebase takes that capability away from the agent. P13-1's and
P13-2's residual limits describe two concrete instances of exactly this: a
party with the agent's network position can act on OPA's or the verifier's
own APIs directly, because that position is never exclusively the
gateway's.

**Reaching `mediated` is not a proxy-placement exercise.** The spike
demonstrated this concretely, on the MCP path a future mediation layer
would likely use: with a real mediation proxy in place and no other
change, a compromised agent still reached the tool's underlying authority
unmediated - by spawning its own copy of the tool server against a stdio
transport (M2/A5, A5b), or by reaching the same upstream directly over a
shared network under HTTP (M2, `internal`-network row). Both bypasses
required no cooperation from the proxy and left no ledger entry. Closing
either one is a property of the deployment's process/OS isolation (stdio)
or its network segmentation and upstream authentication (HTTP), not of the
proxy's own policy logic - which is why `mediated` is defined here by what
the agent can no longer do, not by which component sits in the request
path. This codebase does not implement a least-privilege agent runtime by
either mechanism, so `mediated` is not reachable from the current
architecture without that runtime work, independent of any change to AIL
itself.

**Attribution ceiling.** A record attributes a call to a session or a
process; in the `attested` profile, to a workload. It never attributes to
*intent*. The spike's own attribution finding (M5) is the concrete basis
for this: what a mediation layer can actually name is a connection/session
identity plus a network address (HTTP) or a spawning-process relationship
(stdio) - never a cryptographic workload identity, and never anything
about what the caller meant to do. A workload identity, where one exists
(this gateway's own SPIFFE SVID, in the `attested` profile), narrows *who*
issued a call; it does not and cannot establish *why*. A compromised
agent's calls carry the same workload identity as its legitimate ones,
because the credential does not know the difference - it authenticates the
process, not the process's current loyalty. No profile changes this; it is
a ceiling on what attribution can ever mean here, not a gap particular to
`observed`.

## Documented boundary

Four of the six fault classes (`opa_unreachable`, `revision_unavailable`,
`spiffe_unavailable`, `malformed_policy_response`) still produce a ledger
record - the call could not be evaluated, but the fact of that failure can
still be durably recorded. The other two cannot, for the same underlying
reason: each is discovered in a path that itself precedes, or is, the write
that would record it, and a fault in the recording path cannot be recorded
through that same path.

`verifier_unreachable` is discovered when the ledger write itself fails.
`content_store_unreachable` (D7, Phase 1.1) is discovered one step earlier -
the content write, which now happens *before* the ledger write, fails - and
`intercept_tool_call` skips the ledger write entirely rather than record an
entry whose `content_state` it cannot yet describe. Both cases: `outcome_type:
fault` and the fault class are returned to the caller and to Prometheus, but
`ledger_tx_id` is omitted entirely - there is no ledger entry to point to, in
either case. This is a structural limit, not an oversight: nothing can write
a durable record of "the durable-record writer is down," or of "the store
this record's content_state would name is itself down."

This is the one place in the whole system where "the record tells the
truth" cannot mean "there is always a record." It means the caller and the
metrics are never lied to about what happened, even when nothing could be
written down.

## Consequences

**Gained:**

- A real GDPR/SOC2/FinOps violation, a malformed payload, and an
  infrastructure fault are structurally distinct everywhere: the ledger,
  `/audit`, the dashboard, Prometheus, and the agent's reply text.
- A test written against the response contract
  (`tests/test_response_contract.py`) fails if a producer renames or drops
  one of these keys, closing the gap red-team R1 found (a rename was
  previously caught only by an unrelated test's incidental assertion).

**Constraints:**

- Adding a new fault class means touching the closed set in
  `interceptor/middleware.py`, the ledger schema, the dashboard's switch
  statements, and this ADR together - it is deliberately not something a
  single file's change can do silently.
- `reasons` is always a list, even for a single-message denial or an empty
  allow - consumers must not assume a specific length.

## References

- `interceptor/middleware.py::_outcome`, `query_opa_policy`, `intercept_tool_call`
- `ledger/immudb_ledger.py::log_tool_call`
- `docs/reports/phase-0-1-redteam.md`, R4 - the conflation this closes
- `docs/reports/phase-1-redteam.md`, S1 #2/#4, S3, S4/S5 - the gaps Phase 1.1 closes
- `tests/test_outcome_types.py` - automated coverage of every type and fault class
- `tests/test_response_contract.py` - the contract test this taxonomy's key set feeds
- `tests/test_policy_response_shape.py` - `malformed_policy_response` (P11-3)
- `tests/test_content_states.py` - `content_state`/`content_store_unreachable` (D7); `lost` vs `erased`, refused erasure on tombstone-write failure, and tombstone exclusion from the decision view/metric (D11, Phase 1.2); `erasure_conflict` and the resurrection refusal (P13-4, Phase 1.3)
- `tests/test_raw_ledger_fields.py` - the raw-stored-value checks S1 #2/#4 named
- `tests/test_record_profile.py` - every record carries `profile` from the closed set (P13-8, Phase 1.3)
- `docs/reports/phase-1-1-redteam.md`, T5 - the erased/lost conflation D11 closes
- `docs/reports/phase-1-2-redteam.md`, U4 - the resurrection and the erasure_conflict-shaped combination P13-4 closes
- `docs/reports/spike-mcp-mediation.md` - the go/no-go spike whose findings ground the `mediated`/`attested` profile definitions and the attribution ceiling (P13-8, Phase 1.3)
