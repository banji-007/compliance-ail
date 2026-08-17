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
  "content_state": "present"
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
  "actor": "control-plane-write-key"
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
pattern D2/D8 use for verification) is now four states, not three:

| `payload_state` | Meaning |
| :--- | :--- |
| `present` | The content-store row still exists. |
| `unavailable` | `content_state` was already `"unavailable"` at write time (nothing dict-shaped to store) - always wins over the other three. |
| `erased` | `content_state` was `"present"`, the row is gone, and a `content_erasure` tombstone exists for this `call_id` - the real endpoint always writes one first. |
| `lost` | `content_state` was `"present"`, the row is gone, and no tombstone exists - the row disappeared some other way (e.g. a direct SQL delete bypassing the endpoint). |

Red-team T5 (`docs/reports/phase-1-1-redteam.md`) found `erased` and what
is now `lost` rendering byte-for-byte identically - a GDPR Article 17
request honored through the real endpoint was indistinguishable from an
operational data-loss incident. `lost` exists specifically so those two
are never conflated again.

Metrics follow the same closed set (Phase 1, D3): `ail_policy_decisions_total`
is labeled by `outcome_type` and `fault_class`, not by a substring of a Rego
deny message - a policy author changing denial wording cannot reshape metric
cardinality.

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
- `tests/test_content_states.py` - `content_state`/`content_store_unreachable` (D7); `lost` vs `erased`, refused erasure on tombstone-write failure, and tombstone exclusion from the decision view/metric (D11, Phase 1.2)
- `tests/test_raw_ledger_fields.py` - the raw-stored-value checks S1 #2/#4 named
- `docs/reports/phase-1-1-redteam.md`, T5 - the erased/lost conflation D11 closes
