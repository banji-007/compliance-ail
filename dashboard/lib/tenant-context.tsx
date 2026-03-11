"use client";

import { createContext, useContext, useState } from "react";

export const TENANTS = [
  { id: "tenant_default", label: "Default Tenant" },
  { id: "tenant_finance", label: "Finance Tenant" },
] as const;

export type TenantId = (typeof TENANTS)[number]["id"];

interface TenantContextValue {
  tenantId: TenantId;
  setTenantId: (id: TenantId) => void;
  tenants: typeof TENANTS;
}

const TenantContext = createContext<TenantContextValue | null>(null);

export function TenantProvider({ children }: { children: React.ReactNode }) {
  const defaultId =
    (process.env.NEXT_PUBLIC_TENANT_ID as TenantId | undefined) ??
    "tenant_default";
  const [tenantId, setTenantId] = useState<TenantId>(defaultId);

  return (
    <TenantContext.Provider value={{ tenantId, setTenantId, tenants: TENANTS }}>
      {children}
    </TenantContext.Provider>
  );
}

export function useTenant() {
  const ctx = useContext(TenantContext);
  if (!ctx) throw new Error("useTenant must be used inside TenantProvider");
  return ctx;
}
