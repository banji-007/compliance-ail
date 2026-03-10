"use client";

import { useState, useMemo } from "react";
import { Copy, Check, Search } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { formatTimestamp, truncateHash } from "@/lib/utils";
import type { AuditEntry } from "@/lib/types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function decisionVariant(
  decision: string | null
): "approved" | "denied" | "secondary" {
  if (!decision) return "secondary";
  const upper = decision.toUpperCase();
  if (upper.startsWith("APPROVED")) return "approved";
  if (upper.startsWith("DENIED")) return "denied";
  return "secondary";
}

/**
 * Renders a compact verdict badge ("APPROVED" / "DENIED") with the full
 * policy reason displayed as smaller muted text beneath it.
 */
function DecisionCell({ decision }: { decision: string | null }) {
  if (!decision) return <span className="text-muted-foreground text-xs">—</span>;

  // Split "DENIED: gdpr.data_residency_required" into verdict + reason
  const colonIdx = decision.indexOf(":");
  const verdict = colonIdx === -1 ? decision : decision.slice(0, colonIdx).trim();
  const reason = colonIdx === -1 ? null : decision.slice(colonIdx + 1).trim();

  return (
    <div className="flex flex-col gap-1">
      <Badge variant={decisionVariant(decision)} className="w-fit text-xs">
        {verdict}
      </Badge>
      {reason && (
        <span className="text-xs text-muted-foreground break-words leading-tight">
          {reason}
        </span>
      )}
    </div>
  );
}

function CopyHash({ hash }: { hash: string | null }) {
  const [copied, setCopied] = useState(false);
  if (!hash) return <span className="text-muted-foreground">—</span>;

  function copy() {
    if (!hash) return;
    navigator.clipboard.writeText(hash).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }

  return (
    <div className="flex items-center gap-1.5 font-mono text-xs">
      <span className="text-muted-foreground">{truncateHash(hash)}</span>
      <button
        onClick={copy}
        className="rounded p-0.5 hover:bg-accent"
        aria-label="Copy full hash"
      >
        {copied ? (
          <Check className="h-3.5 w-3.5 text-emerald-500" />
        ) : (
          <Copy className="h-3.5 w-3.5 text-muted-foreground" />
        )}
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Table
// ---------------------------------------------------------------------------

interface Props {
  entries: AuditEntry[];
}

const COLUMNS = [
  { key: "timestamp", label: "Timestamp", width: "w-40" },
  { key: "agent_id", label: "Agent ID", width: "w-48" },
  { key: "tool_name", label: "Tool Name", width: "w-44" },
  { key: "decision", label: "Decision", width: "w-48" },
  { key: "ledger_hash", label: "Ledger Hash (SHA-256)", width: "w-52" },
] as const;

export function AuditTable({ entries }: Props) {
  const [search, setSearch] = useState("");

  const filtered = useMemo(() => {
    const q = search.toLowerCase().trim();
    if (!q) return entries;
    return entries.filter((e) => {
      const haystack = [
        e.agent_id,
        e.tool_name,
        e.decision,
        e.timestamp,
        e.ledger_hash,
        JSON.stringify(e.payload ?? {}),
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(q);
    });
  }, [entries, search]);

  return (
    <div className="flex flex-col gap-4">
      {/* Search bar */}
      <div className="relative max-w-sm">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Search agent, tool, decision, hash…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="pl-9"
        />
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-md border">
        <table className="w-full text-sm">
          <thead className="border-b bg-muted/50">
            <tr>
              {COLUMNS.map((col) => (
                <th
                  key={col.key}
                  className={cn(
                    "px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-muted-foreground",
                    col.width
                  )}
                >
                  {col.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td
                  colSpan={COLUMNS.length}
                  className="py-12 text-center text-sm text-muted-foreground"
                >
                  {search
                    ? "No entries match your search."
                    : "No ledger entries found."}
                </td>
              </tr>
            ) : (
              filtered.map((entry, idx) => (
                <tr
                  key={`${entry.tx_id}-${idx}`}
                  className="border-b last:border-0 hover:bg-muted/30 transition-colors"
                >
                  <td className="px-4 py-3 text-xs text-muted-foreground whitespace-nowrap">
                    {formatTimestamp(entry.timestamp)}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs max-w-[12rem] truncate">
                    {entry.agent_id ?? "—"}
                  </td>
                  <td className="px-4 py-3 font-medium text-xs">
                    {entry.tool_name ?? "—"}
                  </td>
                  <td className="px-4 py-3 max-w-[14rem]">
                    <DecisionCell decision={entry.decision} />
                  </td>
                  <td className="px-4 py-3">
                    <CopyHash hash={entry.ledger_hash} />
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <p className="text-xs text-muted-foreground">
        Showing {filtered.length} of {entries.length} ledger entries — newest
        first. Hashes are SHA-256(key:entry:tx_id) and verifiable offline.
      </p>
    </div>
  );
}
