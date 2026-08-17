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
 * The four read-time verification states (D2). A ledger entry cannot assert
 * its own verification status — this is computed by /audit at request time,
 * never stored in the entry. See docs/adr/0006-verification-states.md.
 *
 *   verified     - a verifiedGet ran and every proof passed.
 *   failed       - a verifiedGet ran and a proof/signature was rejected
 *                  (the tamper signal) — error_class distinguishes which.
 *   unverifiable - a verifiedGet was attempted and could not complete
 *                  (verifier unreachable, timeout, transport error).
 *   asserted     - no verifiedGet was attempted for this entry at all.
 *                  Not a problem by itself — it means "we did not look".
 */
export type VerificationState = "verified" | "failed" | "unverifiable" | "asserted";

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
   * content store by tx_id (D5). Null if never stored or erased — the
   * ledger entry's hash and verification state are unaffected either way.
   */
  payload: Record<string, unknown> | null;
  verification: Verification;
}

export interface AuditResponse {
  entries: AuditEntry[];
  total: number;
}
