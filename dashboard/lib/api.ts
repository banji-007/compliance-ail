import type { AuditResponse, Tenant, TenantUpdate } from "./types";

const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8002";
const DEFAULT_TENANT = process.env.NEXT_PUBLIC_TENANT_ID ?? "tenant_default";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
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

export function fetchAudit(limit = 200): Promise<AuditResponse> {
  return request<AuditResponse>(`/audit?limit=${limit}`);
}
