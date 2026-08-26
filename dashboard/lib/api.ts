import type {
  AuditResponse,
  RecordVerification,
  Tenant,
  TenantUpdate,
} from "./types";
import { AUDIT_PAGE_SIZE } from "./constants";

// Same-origin only (D4): every dashboard request goes through this app's own
// Next.js Route Handlers under app/api/, which hold CONTROL_PLANE_READ_KEY /
// CONTROL_PLANE_WRITE_KEY server-side and attach the appropriate one. The
// browser never learns the control plane's address or either key - it only
// ever holds its own dashboard-level credential (D6, middleware.ts).
const DEFAULT_TENANT = process.env.NEXT_PUBLIC_TENANT_ID ?? "tenant_default";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, {
    headers: { "Content-Type": "application/json", ...init?.headers },
    ...init,
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`API ${res.status}: ${body}`);
  }
  return res.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Tenant
// ---------------------------------------------------------------------------

export function fetchTenant(tenantId = DEFAULT_TENANT): Promise<Tenant> {
  return request<Tenant>(`/tenants/${tenantId}`);
}

export function updateTenant(
  update: TenantUpdate,
  tenantId = DEFAULT_TENANT
): Promise<Tenant> {
  return request<Tenant>(`/tenants/${tenantId}`, {
    method: "PUT",
    body: JSON.stringify(update),
  });
}

// ---------------------------------------------------------------------------
// Audit Ledger
// ---------------------------------------------------------------------------

export function fetchAudit(limit = AUDIT_PAGE_SIZE): Promise<AuditResponse> {
  return request<AuditResponse>(`/audit?limit=${limit}`);
}

// P3c2-1 (Phase 3c-2): one record's verification, on demand. /audit
// defers (D29), so this is the only call that actually asks the verifier
// for a proof check, and the audit table's row-expand control is its only
// caller. Named here rather than inside the component so there is one
// place the route is spelled.
export function fetchRecordVerification(
  ledgerKey: string
): Promise<RecordVerification> {
  return request<RecordVerification>(
    `/audit/verify?key=${encodeURIComponent(ledgerKey)}`
  );
}
