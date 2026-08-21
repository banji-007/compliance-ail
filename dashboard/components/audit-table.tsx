"use client";

import { useState, useMemo } from "react";
import { Search, ShieldCheck, ShieldAlert, ShieldQuestion, CircleDashed, HelpCircle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { BadgeProps } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { formatTimestamp } from "@/lib/utils";
import type { AuditEntry, OutcomeType } from "@/lib/types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const OUTCOME_LABEL: Record<OutcomeType, string> = {
  policy_allow: "APPROVED",
  policy_deny: "POLICY DENIED",
  schema_deny: "SCHEMA REJECTED",
  fault: "INFRASTRUCTURE FAULT",
};

const OUTCOME_VARIANT: Record<OutcomeType, NonNullable<BadgeProps["variant"]>> = {
  policy_allow: "approved",
  policy_deny: "denied",
  schema_deny: "warning",
  fault: "fault",
};

/**
 * Renders a badge distinguishing all four outcome_types (P1-7) — a policy
 * denial (a real compliance violation), a schema rejection (the LLM's
 * payload was malformed, never reached policy), and an infrastructure
 * fault (no decision was made at all) must never look alike. Reasons/
 * fault_class render as smaller text beneath, same as the policy revision.
 */
function DecisionCell({ entry }: { entry: AuditEntry }) {
  if (!entry.outcome_type) return <span className="text-muted-foreground text-xs">—</span>;

  const detail =
    entry.outcome_type === "fault"
      ? entry.fault_class
      : entry.reasons.length > 0
      ? entry.reasons.join("; ")
      : null;

  return (
    <div className="flex flex-col gap-1">
      <Badge variant={OUTCOME_VARIANT[entry.outcome_type]} className="w-fit text-xs">
        {OUTCOME_LABEL[entry.outcome_type]}
      </Badge>
      {detail && (
        <span className="text-xs text-muted-foreground break-words leading-tight">
          {detail}
        </span>
      )}
      {entry.policy_revision && (
        <span className="text-[10px] text-muted-foreground/70 font-mono">
          policy: {entry.policy_revision}
        </span>
      )}
      {/* P13-8/D13: every record declares the conformance profile it was
          produced under, now per-tool (Phase 2) rather than a single
          deployment constant. */}
      <span className="text-[10px] text-muted-foreground/70 font-mono uppercase">
        profile: {entry.profile}
        {entry.exclusivity ? ` (${entry.exclusivity})` : ""}
      </span>
      {/* D16: "unknown" is the one execution_state worth calling out visually
          - it means a mediated call executed but its outcome was never
          durably recorded. "n/a" and "completed" are the ordinary cases and
          stay in the same quiet, low-emphasis style as profile/exclusivity. */}
      {entry.execution_state === "unknown" ? (
        <span className="text-[10px] font-mono uppercase text-amber-600 dark:text-amber-400">
          execution: unknown outcome
        </span>
      ) : (
        <span className="text-[10px] text-muted-foreground/70 font-mono uppercase">
          execution: {entry.execution_state}
        </span>
      )}
    </div>
  );
}

/**
 * Renders one of the five verification states distinctly (P1-7, D2, D8).
 * "asserted" is deliberately the quiet, neutral one — it is not a problem,
 * it means no check was attempted for this entry. "unverifiable" and
 * "failed" are both problems, but different ones: one is "we could not
 * check", the other is the actual tamper signal. "not_found" (D8, Phase
 * 1.1) is neither - no entry was ever written for this key, so there was
 * never a proof to check in the first place.
 */
function VerificationCell({ entry }: { entry: AuditEntry }) {
  const v = entry.verification;

  if (v.state === "verified") {
    return (
      <div className="flex items-center gap-1.5 text-xs">
        <ShieldCheck className="h-3.5 w-3.5 text-emerald-500 shrink-0" />
        <span className="text-muted-foreground">
          Verified{v.state_id != null ? ` · state ${v.state_id}` : ""}
        </span>
      </div>
    );
  }

  if (v.state === "failed") {
    return (
      <div className="flex items-center gap-1.5 text-xs">
        <ShieldAlert className="h-3.5 w-3.5 text-red-500 shrink-0" />
        <div className="flex flex-col gap-0.5">
          <Badge variant="denied" className="w-fit">
            FAILED{v.error_class ? `: ${v.error_class.toUpperCase()}` : ""}
          </Badge>
        </div>
      </div>
    );
  }

  if (v.state === "unverifiable") {
    return (
      <div className="flex items-center gap-1.5 text-xs">
        <ShieldQuestion className="h-3.5 w-3.5 text-amber-500 shrink-0" />
        <div className="flex flex-col gap-0.5">
          <Badge variant="warning" className="w-fit">
            UNVERIFIABLE
          </Badge>
          {v.detail && (
            <span className="text-[10px] text-muted-foreground break-words leading-tight">
              {v.detail}
            </span>
          )}
        </div>
      </div>
    );
  }

  if (v.state === "not_found") {
    // Distinct from "failed" (D8): no proof was ever rejected because there
    // was never a proof to check — a bug/race signal, not a tamper signal.
    return (
      <div className="flex items-center gap-1.5 text-xs">
        <HelpCircle className="h-3.5 w-3.5 text-amber-500 shrink-0" />
        <div className="flex flex-col gap-0.5">
          <Badge variant="warning" className="w-fit">
            NO RECORD
          </Badge>
          {v.detail && (
            <span className="text-[10px] text-muted-foreground break-words leading-tight">
              {v.detail}
            </span>
          )}
        </div>
      </div>
    );
  }

  // asserted — quiet by design: we simply did not look.
  return (
    <div className="flex items-center gap-1.5 text-xs">
      <CircleDashed className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
      <Badge variant="muted" className="w-fit">
        NOT CHECKED
      </Badge>
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
  { key: "verified", label: "Verification", width: "w-52" },
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
        e.outcome_type,
        e.fault_class,
        e.reasons.join(" "),
        e.timestamp,
        e.verification.state,
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
          placeholder="Search agent, tool, decision, verification…"
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
                    <DecisionCell entry={entry} />
                  </td>
                  <td className="px-4 py-3">
                    <VerificationCell entry={entry} />
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <p className="text-xs text-muted-foreground">
        Showing {filtered.length} of {entries.length} ledger entries — newest
        first. Verification is a cryptographic inclusion/consistency proof
        check against ImmuDB's signed state, performed server-side per entry.
      </p>
    </div>
  );
}
