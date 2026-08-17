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
`verifier_unreachable`, `spiffe_unavailable`. Nothing downstream re-derives
`outcome_type` or `fault_class` from message text - `_render_message` in
`interceptor/middleware.py` goes the other direction, from the already-decided
type to presentational text.

The ledger entry itself carries this taxonomy directly - no free-text
`decision` string:

```json
{
  "agent_id": "...", "timestamp": "...", "tool_name": "...",
  "input_sha256": "...",
  "outcome_type": "policy_deny",
  "fault_class": null,
  "policy_revision": "<bundle revision>",
  "reasons": ["..."]
}
```

Metrics follow the same closed set (Phase 1, D3): `ail_policy_decisions_total`
is labeled by `outcome_type` and `fault_class`, not by a substring of a Rego
deny message - a policy author changing denial wording cannot reshape metric
cardinality.

## Documented boundary

Three of the four fault classes (`opa_unreachable`, `revision_unavailable`,
`spiffe_unavailable`) still produce a ledger record - the call could not be
evaluated, but the fact of that failure can still be durably recorded. The
fourth, `verifier_unreachable`, cannot: it is discovered only when the
ledger write itself fails, and a fault in the recording path cannot be
recorded through that same path. `intercept_tool_call` denies and returns
`outcome_type: fault, fault_class: verifier_unreachable` to the caller and to
Prometheus, but omits `ledger_tx_id` entirely - there is no ledger entry to
point to. This is a structural limit, not an oversight: nothing can write a
durable record of "the durable-record writer is down."

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
- `tests/test_outcome_types.py` - automated coverage of every type and fault class
- `tests/test_response_contract.py` - the contract test this taxonomy's key set feeds
