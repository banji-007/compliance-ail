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
   * Conformance profile this record was produced under (P13-8). "observed"
   * is the only value that exists today — the agent independently holds
   * every tool's authority, so a bypass of this gateway is possible and
   * would leave no record at all. See docs/adr/0005-outcome-taxonomy.md.
   */
  profile: "observed" | "mediated" | "attested";
}

export interface AuditResponse {
  entries: AuditEntry[];
  total: number;
}
