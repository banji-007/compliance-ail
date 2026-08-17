# ADR 0004: Pydantic Schema Validation Before OPA

## Status

Accepted

## Context

OPA is a general-purpose policy engine, not an input validator. Running a
full Rego evaluation on a structurally invalid payload (a missing required
key, a wrong type, an LLM-hallucinated field) wastes an evaluation cycle
and network round trip, and produces a Rego-shaped error rather than a
precise, actionable one an agent's retry logic can parse.

## Decision

Every registered tool has a strict Pydantic v2 schema
(`interceptor/schemas.py`), validated in-process before any network call to
OPA. `TOOL_VALIDATORS` is the single routing table: an unregistered tool
name is rejected at the lookup itself, fail-closed, before OPA is ever
queried. A registered tool whose arguments fail validation is rejected with
the specific field-level error.

Both cases produce `outcome_type: schema_deny` (Phase 1, D1) - structurally
before, and independent of, any policy evaluation. Phase 1's `evaluation`
query is never sent for a schema-denied call, which is also why the deny is
provably zero-cost against OPA: see `docs/reports/phase-0-1-redteam.md`, R8,
for the live round-trip count confirming this.

## Consequences

**Gained:**

- Sub-millisecond, in-process rejection of malformed or hallucinated
  payloads, with no OPA round trip.
- Precise, structured error messages (`pydantic.ValidationError`'s
  field/message pairs) instead of a generic policy-engine failure.
- A closed, auditable registry (`TOOL_VALIDATORS`) - adding a tool requires
  an explicit schema, so there is no code path where an unrecognized tool
  name reaches OPA by omission.

**Constraints:**

- Schemas must be kept in sync with each tool's actual parameter set by
  hand; there is no single source shared with the tool definitions passed
  to the LLM (`agent/base_agent.py`, `framework_integration/langgraph_demo.py`).
- A schema that is stricter than the underlying policy intent produces a
  `schema_deny`, not a `policy_deny` - operators reading `outcome_type`
  (Phase 1, D1) can tell these apart, but a schema that is too strict
  still blocks a request policy itself would have allowed.

## References

- `interceptor/schemas.py` - per-tool Pydantic schemas and the
  `TOOL_VALIDATORS` registry
- `interceptor/middleware.py::query_opa_policy` - the pre-flight gate
