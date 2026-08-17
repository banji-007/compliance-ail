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

/** Closed set (D1). Null unless outcome_type is "fault". */
export type FaultClass =
  | "opa_unreachable"
  | "revision_unavailable"
  | "verifier_unreachable"
  | "spiffe_unavailable"
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
  /** Populated for "failed" and "unverifiable" */
  detail: string | null;
  /** "consistency_failure" | "signature_failure" | "unknown"; only meaningful when state is "failed" */
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
   * Read-time inference (D7, Phase 1.1), same pattern as `verification`:
   *   present     - content_state was "present" at write time and the
   *                 content-store row still exists.
   *   erased      - content_state was "present" at write time but the row
   *                 is gone now (GDPR Article 17 erasure via
   *                 DELETE /content/{call_id}).
   *   unavailable - content_state was already "unavailable" at write time
   *                 (nothing dict-shaped to store, e.g. malformed
   *                 tool_args) — never rendered as erased.
   */
  payload_state: "present" | "erased" | "unavailable";
  verification: Verification;
}

export interface AuditResponse {
  entries: AuditEntry[];
  total: number;
}
