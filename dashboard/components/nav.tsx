"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ShieldCheck, BookOpen, Settings2 } from "lucide-react";
import { cn } from "@/lib/utils";

const links = [
  { href: "/settings", label: "Policy Settings", icon: Settings2 },
  { href: "/audit", label: "Audit Ledger", icon: BookOpen },
];

export function Nav() {
  const pathname = usePathname();

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

      {/* Footer badge */}
      <div className="mt-auto px-2 text-xs text-muted-foreground">
        <p className="font-medium">Phase 3 — CISO Dashboard</p>
        <p className="mt-0.5 opacity-60">v3.0.0</p>
      </div>
    </nav>
  );
}
