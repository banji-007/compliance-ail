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

export interface AuditEntry {
  tx_id: number;
  agent_id: string | null;
  timestamp: string | null;
  tool_name: string | null;
  /** Original tool arguments as stored by the interceptor */
  payload: Record<string, unknown> | null;
  /** OPA verdict, e.g. "APPROVED" or "DENIED: gdpr.pii_masking_required" */
  decision: string | null;
  /** SHA-256(key:serialized_entry:tx_id) — recomputed server-side for verification */
  ledger_hash: string | null;
}

export interface AuditResponse {
  entries: AuditEntry[];
  total: number;
}
