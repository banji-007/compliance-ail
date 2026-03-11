"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ShieldCheck, BookOpen, Settings2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { useTenant } from "@/lib/tenant-context";
import type { TenantId } from "@/lib/tenant-context";

const links = [
  { href: "/settings", label: "Policy Settings", icon: Settings2 },
  { href: "/audit", label: "Audit Ledger", icon: BookOpen },
];

export function Nav() {
  const pathname = usePathname();
  const { tenantId, setTenantId, tenants } = useTenant();

  return (
    <nav className="flex h-screen w-60 flex-col border-r bg-card px-4 py-6 shrink-0">
      {/* Wordmark */}
      <div className="mb-8 flex items-center gap-2 px-2">
        <ShieldCheck className="h-6 w-6 text-primary" />
        <span className="text-base font-semibold tracking-tight">
          AIL Control Plane
        </span>
      </div>

      {/* Links */}
      <ul className="flex flex-col gap-1">
        {links.map(({ href, label, icon: Icon }) => (
          <li key={href}>
            <Link
              href={href}
              className={cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                pathname === href
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
              )}
            >
              <Icon className="h-4 w-4" />
              {label}
            </Link>
          </li>
        ))}
      </ul>

      {/* Tenant Switcher */}
      <div className="mt-6 px-2">
        <p className="mb-1.5 text-xs font-medium text-muted-foreground">
          Active Tenant
        </p>
        <select
          value={tenantId}
          onChange={(e) => setTenantId(e.target.value as TenantId)}
          className="w-full rounded-md border bg-background px-2 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          aria-label="Switch active tenant"
        >
          {tenants.map((t) => (
            <option key={t.id} value={t.id}>
              {t.label}
            </option>
          ))}
        </select>
      </div>

      {/* Footer badge */}
      <div className="mt-auto px-2 text-xs text-muted-foreground">
        <p className="font-medium">Phase 5 — Enterprise Ready</p>
        <p className="mt-0.5 opacity-60">v5.0.0</p>
      </div>
    </nav>
  );
}
