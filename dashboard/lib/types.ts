// ---------------------------------------------------------------------------
// Tenant / Settings
// ---------------------------------------------------------------------------

export interface Tenant {
  id: string;
  name: string;
  enable_gdpr: boolean;
  enable_soc2: boolean;
  enable_finops: boolean;
  enable_hipaa: boolean;
  /** Comma-separated, e.g. "engineering,marketing,finance" */
  allowed_cost_centers: string;
  /** Comma-separated, e.g. "eu-central-1,us-east-1" — injected as data.ail.config.approved_regions */
  approved_regions: string;
  /** Comma-separated, e.g. "customer_support,billing" — injected as data.ail.config.approved_purposes */
  approved_purposes: string;
}

export type TenantUpdate = Partial<Omit<Tenant, "id">>;

// ---------------------------------------------------------------------------
// Audit Ledger
// ---------------------------------------------------------------------------

/** Closed set (D1) — never inferred from message text. */
export type OutcomeType = "policy_allow" | "policy_deny" | "schema_deny" | "fault";

/**
 * The fault classes /audit can actually send, not the full closed set
 * (docs/adr/0005-outcome-taxonomy.md). verifier_unreachable and
 * content_store_unreachable are documented as never producing a ledger
 * record - each is discovered in a path that itself precedes, or is, the
 * write that would record it - so they can never reach this API. R5 (Phase
 * 1.3 completion pass, red-team V1 finding 3): this type previously
 * included verifier_unreachable (which cannot reach here) and omitted
 * malformed_policy_response (which does - live-forced through the real
 * interceptor and confirmed to produce a ledger entry with fault_class:
 * "malformed_policy_response").
 *
 * spiffe_unavailable and decision_service_unreachable (Phase 2, D12) are
 * now the agent's own client-leg faults (interceptor/middleware.py) - the
 * decision service (where mTLS used to be checked, before OPA) is never
 * even reached when either fires, so there is nothing for it to have
 * written a ledger entry about. Same category as verifier_unreachable:
 * never reaches here, deliberately omitted. Before Phase 2,
 * spiffe_unavailable belonged to this set; it does not any more, because
 * the fault now happens strictly before the network call this API's data
 * comes from.
 *
 * tool_execution_failed (Phase 2, D14) is different: the decision service
 * did reach the point of writing a ledger entry (schema validated, policy
 * allowed, content stored) before the mediated tool call itself failed, so
 * this one DOES reach /audit - included here for that reason.
 */
export type FaultClass =
  | "opa_unreachable"
  | "revision_unavailable"
  | "malformed_policy_response"
  | "tool_execution_failed"
  | null;

/**
 * The five read-time verification states (D2, D8). A ledger entry cannot
 * assert its own verification status — this is computed by /audit at
 * request time, never stored in the entry. See
 * docs/adr/0006-verification-states.md.
 *
 *   verified     - a verifiedGet ran and every proof passed.
 *   failed       - a verifiedGet ran and a proof/signature was rejected
 *                  (the tamper signal) — error_class distinguishes which.
 *   unverifiable - a verifiedGet was attempted and could not complete
 *                  (verifier unreachable, timeout, transport error).
 *   asserted     - no verifiedGet was attempted for this entry at all.
 *                  Not a problem by itself — it means "we did not look".
 *   not_found    - a verifiedGet was attempted and the underlying gRPC call
 *                  returned NOT_FOUND: no entry was ever written for this
 *                  key. Not a tamper signal (no proof was ever rejected —
 *                  there was never a proof to check) and not "failed" — a
 *                  bug/race signal, distinct from both.
 */
export type VerificationState = "verified" | "failed" | "unverifiable" | "asserted" | "not_found";

export interface Verification {
  state: VerificationState;
  /** tx_id of the latest verified state the verifier held, when state is "verified" */
  state_id: number | null;
  /** Populated for "failed", "unverifiable", and "not_found" */
  detail: string | null;
  /**
   * "consistency_failure" | "signature_failure" when state is "failed" -
   * these are the only two positively-identified tamper conditions (D10).
   * "not_found" when state is "not_found". "unknown", or any other value
   * the verifier has never classified, means state is "unverifiable" - it
   * is never promoted to "failed" by default.
   */
  error_class: string | null;
}

export interface AuditEntry {
  tx_id: number;
  /** Minted at intercept, independent of ImmuDB's tx numbering (D7). The key
   *  GDPR erasure targets: DELETE /content/{call_id}. */
  call_id: string | null;
  agent_id: string | null;
  timestamp: string | null;
  tool_name: string | null;
  outcome_type: OutcomeType | null;
  fault_class: FaultClass;
  /** Bundle revision that produced the decision; null for schema_deny and fault (D1) */
  policy_revision: string | null;
  /** Deny reasons; empty for an allow */
  reasons: string[];
  /** SHA-256 of the canonically serialized tool arguments (D5) */
  input_sha256: string | null;
  /**
   * Original tool arguments, joined from the control plane's erasable
   * content store by call_id (D5, D7). Null unless payload_state is
   * "present" — the ledger entry's hash and verification state are
   * unaffected either way.
   */
  payload: Record<string, unknown> | null;
  /**
   * Read-time inference (D7, D11 - Phase 1.1/1.2), same pattern as
   * `verification`:
   *   present     - content_state was "present" at write time and the
   *                 content-store row still exists.
   *   erased      - content_state was "present" at write time, the row is
   *                 gone now, and a content_erasure tombstone exists for
   *                 this call_id (GDPR Article 17 erasure via the real
   *                 DELETE /content/{call_id} endpoint, which always
   *                 writes the tombstone before deleting the row).
   *   lost        - content_state was "present" at write time and the row
   *                 is gone now, but no tombstone exists - the row
   *                 disappeared some other way (e.g. a direct SQL delete
   *                 bypassing the endpoint). Never rendered the same as
   *                 "erased": one is a request honored, the other is an
   *                 operational incident.
   *   unavailable - content_state was already "unavailable" at write time
   *                 (nothing dict-shaped to store, e.g. malformed
   *                 tool_args) — never rendered as erased or lost.
   */
  /**
   * P13-4: a content_erasure tombstone now wins over a present row. A row
   * that outlived its own tombstone renders as "erasure_conflict", not
   * "present" — the payload is withheld either way and this needs
   * investigation, not silent display.
   */
  payload_state: "present" | "erased" | "lost" | "unavailable" | "erasure_conflict";
  verification: Verification;
  /**
   * Conformance profile this record was produced under (P13-8), now
   * per-tool rather than a single deployment constant (D13, Phase 2):
   * "observed" for the three Python-function tools, "mediated" for the one
   * D14 tool whose authority the gateway holds exclusively. See
   * docs/adr/0005-outcome-taxonomy.md and
   * docs/adr/0008-decision-service-boundary.md.
   *
   * "unknown" (R3, Phase 1.3 completion pass) is not a profile - it is
   * what /audit renders for a record that structurally lacks the field,
   * so that case is never confused with a genuine "observed" record.
   */
  profile: "observed" | "mediated" | "attested" | "unknown";
  /**
   * D13 (Phase 2): only ever set for a "mediated" record, and only ever
   * the gateway's own verified answer, never a tool's config claim (see
   * decision_service/schemas.py::resolve_exclusivity_for). null for every
   * "observed" record - not "not applicable" rendered as a string, an
   * actual absence of the key.
   */
  exclusivity: "demonstrated" | "declared" | null;
}

export interface AuditResponse {
  entries: AuditEntry[];
  total: number;
}
