"use client";

import { Fragment, useState, useMemo } from "react";
import {
  Search,
  ShieldCheck,
  ShieldAlert,
  ShieldQuestion,
  CircleDashed,
  HelpCircle,
  ChevronRight,
  ChevronDown,
  Loader2,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { BadgeProps } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { formatTimestamp } from "@/lib/utils";
import { fetchRecordVerification } from "@/lib/api";
import type { AuditEntry, OutcomeType, Verification } from "@/lib/types";

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
 * P2-10 (Phase 2 completion pass B, red-team W7): a record's `profile` used
 * to render as plain, uniform, muted text regardless of value - a forged
 * `profile: "unknown"` (or any value) looked identical to a genuine
 * `observed`/`mediated` record, unlike the rich per-state treatment
 * VerificationCell already gives verification.state. "unknown" is the one
 * value that must never be mistaken for a normal one: it means the record
 * structurally lacks a profile key at all (R3, Phase 1.3 completion pass) -
 * exactly what a forger supplying a plausible-looking payload would produce.
 * "attested" is defined (docs/adr/0005-outcome-taxonomy.md) but not yet
 * producible by any code path; included here so the map stays exhaustive
 * over AuditEntry["profile"] rather than needing a runtime fallback.
 */
const PROFILE_LABEL: Record<AuditEntry["profile"], string> = {
  observed: "OBSERVED",
  mediated: "MEDIATED",
  attested: "ATTESTED",
  unknown: "UNKNOWN",
};

const PROFILE_VARIANT: Record<AuditEntry["profile"], NonNullable<BadgeProps["variant"]>> = {
  observed: "muted",
  mediated: "approved",
  attested: "approved",
  unknown: "warning",
};

/**
 * P3c2-2 (Phase 3c-2): the state of this row's on-demand verification.
 *
 * /audit defers verification (D29), so every row arrives `asserted` and the
 * check for one record happens when a reader expands it. "idle" is not the
 * same thing as `asserted`: `asserted` is what the server says about the
 * record, "idle" is what this browser has not yet asked about it.
 */
type CheckState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "done"; verification: Verification }
  | { status: "error"; message: string };

const IDLE: CheckState = { status: "idle" };

/**
 * Renders a badge distinguishing all four outcome_types (P1-7) - a policy
 * denial (a real compliance violation), a schema rejection (the LLM's
 * payload was malformed, never reached policy), and an infrastructure
 * fault (no decision was made at all) must never look alike. Reasons/
 * fault_class render as smaller text beneath, same as the policy revision.
 */
function DecisionCell({ entry }: { entry: AuditEntry }) {
  if (!entry.outcome_type) return <span className="text-muted-foreground text-xs">-</span>;

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
          deployment constant. P2-10: badged, not plain text - see
          PROFILE_LABEL/PROFILE_VARIANT above. */}
      <div className="flex items-center gap-1">
        <Badge variant={PROFILE_VARIANT[entry.profile]} className="w-fit text-[9px] px-1.5 py-0">
          {PROFILE_LABEL[entry.profile]}
        </Badge>
        {entry.exclusivity && (
          <span className="text-[10px] text-muted-foreground/70 font-mono uppercase">
            ({entry.exclusivity})
          </span>
        )}
      </div>
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
 * "asserted" is deliberately the quiet, neutral one - it is not a problem,
 * it means no check was attempted for this entry. "unverifiable" and
 * "failed" are both problems, but different ones: one is "we could not
 * check", the other is the actual tamper signal. "not_found" (D8, Phase
 * 1.1) is neither - no entry was ever written for this key, so there was
 * never a proof to check in the first place.
 *
 * D29 (Phase 3c-2): `asserted` is now what almost every row carries on a
 * freshly loaded page, because /audit defers verification rather than
 * running it for the whole page. `check` is this row's on-demand result
 * once a reader has expanded it, and supersedes the deferred state when
 * present - the row then shows what was actually checked, rather than what
 * the page declined to check.
 */
function VerificationCell({ entry, check }: { entry: AuditEntry; check: CheckState }) {
  if (check.status === "loading") {
    return (
      <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
        <Loader2 className="h-3.5 w-3.5 animate-spin shrink-0" />
        Checking
      </div>
    );
  }

  if (check.status === "error") {
    // The check did not complete, which is not the same as the record
    // failing one. Rendered as a problem with the check, never as a
    // verdict on the record.
    return (
      <div className="flex items-center gap-1.5 text-xs">
        <ShieldQuestion className="h-3.5 w-3.5 text-amber-500 shrink-0" />
        <div className="flex flex-col gap-0.5">
          <Badge variant="warning" className="w-fit">
            CHECK FAILED
          </Badge>
          <span className="text-[10px] text-muted-foreground break-words leading-tight">
            {check.message}
          </span>
        </div>
      </div>
    );
  }

  const v: Verification = check.status === "done" ? check.verification : entry.verification;

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
    // was never a proof to check - a bug/race signal, not a tamper signal.
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

  // asserted - quiet by design: nobody has looked at this record. Since D29
  // that is the ordinary state of a freshly loaded page rather than an
  // outage artifact, so the badge says what it has always said and the row
  // beside it carries the control that changes it.
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
  { key: "expand", label: "", width: "w-10" },
  { key: "timestamp", label: "Timestamp", width: "w-40" },
  { key: "agent_id", label: "Agent ID", width: "w-48" },
  { key: "tool_name", label: "Tool Name", width: "w-44" },
  { key: "decision", label: "Decision", width: "w-48" },
  { key: "verified", label: "Verification", width: "w-52" },
] as const;

export function AuditTable({ entries }: Props) {
  const [search, setSearch] = useState("");
  // P3c2-2: which row is open, and what its on-demand check has produced.
  // Keyed by ledger_key, the identifier the per-record route takes - not by
  // row index, which changes under the 30s refetch.
  //
  // The footer below no longer claims "newest first". It is not true and was
  // not true before this phase: control_plane/main.py's ImmuDB scan passes
  // desc: true, which orders by KEY descending, and a tool_call: key leads
  // with the agent id. The page is therefore the lexicographically-largest
  // keys, not the most recent decisions, and once the ledger holds more than
  // `limit` of them a record written seconds ago can be absent entirely.
  // Pre-existing and out of this phase's scope - see TODO.md and
  // docs/reports/phase-3c2.md - but not restated as fact in a line this
  // phase was already rewriting.
  const [expanded, setExpanded] = useState<string | null>(null);
  const [checks, setChecks] = useState<Record<string, CheckState>>({});

  async function runCheck(ledgerKey: string) {
    setChecks((prev) => ({ ...prev, [ledgerKey]: { status: "loading" } }));
    try {
      const result = await fetchRecordVerification(ledgerKey);
      setChecks((prev) => ({
        ...prev,
        [ledgerKey]: { status: "done", verification: result.verification },
      }));
    } catch (err) {
      setChecks((prev) => ({
        ...prev,
        [ledgerKey]: { status: "error", message: (err as Error).message },
      }));
    }
  }

  function toggleRow(entry: AuditEntry) {
    const ledgerKey = entry.ledger_key;
    if (!ledgerKey) return;
    if (expanded === ledgerKey) {
      setExpanded(null);
      return;
    }
    setExpanded(ledgerKey);
    const current = checks[ledgerKey];
    // Re-run a check that errored; never re-run one that answered. A
    // verification is a statement about a committed record, so repeating it
    // on every open buys nothing and multiplies the cost this phase exists
    // to remove.
    if (!current || current.status === "error") {
      void runCheck(ledgerKey);
    }
  }

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
          placeholder="Search agent, tool, decision, verification..."
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
              filtered.map((entry, idx) => {
                const ledgerKey = entry.ledger_key;
                const isOpen = ledgerKey != null && expanded === ledgerKey;
                const check: CheckState = ledgerKey ? checks[ledgerKey] ?? IDLE : IDLE;
                return (
                  <Fragment key={`${entry.tx_id}-${idx}`}>
                    <tr className="border-b last:border-0 hover:bg-muted/30 transition-colors">
                      <td className="px-2 py-3">
                        {/* P3c2-2: the expand affordance. Verification is
                            deferred (D29), so this is what actually asks
                            for one record to be checked. */}
                        <button
                          type="button"
                          onClick={() => toggleRow(entry)}
                          disabled={!ledgerKey}
                          aria-expanded={isOpen}
                          aria-label={isOpen ? "Collapse record" : "Expand and verify record"}
                          className="rounded p-1 text-muted-foreground hover:bg-muted disabled:opacity-30"
                        >
                          {isOpen ? (
                            <ChevronDown className="h-4 w-4" />
                          ) : (
                            <ChevronRight className="h-4 w-4" />
                          )}
                        </button>
                      </td>
                      <td className="px-4 py-3 text-xs text-muted-foreground whitespace-nowrap">
                        {formatTimestamp(entry.timestamp)}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs max-w-[12rem] truncate">
                        {entry.agent_id ?? "-"}
                      </td>
                      <td className="px-4 py-3 font-medium text-xs">
                        {entry.tool_name ?? "-"}
                      </td>
                      <td className="px-4 py-3 max-w-[14rem]">
                        <DecisionCell entry={entry} />
                      </td>
                      <td className="px-4 py-3">
                        <VerificationCell entry={entry} check={check} />
                      </td>
                    </tr>
                    {isOpen && (
                      <tr className="border-b bg-muted/20">
                        <td colSpan={COLUMNS.length} className="px-4 py-3">
                          <div className="flex flex-col gap-1 text-xs">
                            <span className="font-mono text-[10px] text-muted-foreground break-all">
                              ledger_key: {ledgerKey}
                            </span>
                            {check.status === "done" && (
                              <>
                                <span className="text-muted-foreground">
                                  state: {check.verification.state}
                                  {check.verification.state_id != null
                                    ? ` (ledger state ${check.verification.state_id})`
                                    : ""}
                                </span>
                                {check.verification.detail && (
                                  <span className="text-muted-foreground break-words">
                                    {check.verification.detail}
                                  </span>
                                )}
                              </>
                            )}
                            {check.status === "loading" && (
                              <span className="text-muted-foreground">
                                Asking the verifier for this record.
                              </span>
                            )}
                            {check.status === "error" && (
                              <span className="text-amber-600 dark:text-amber-400 break-words">
                                {check.message}
                              </span>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      <p className="text-xs text-muted-foreground">
        Showing {filtered.length} of {entries.length} ledger entries.
        Verification is a cryptographic inclusion/consistency proof
        check against ImmuDB&apos;s signed state, performed server-side for one
        record at a time when you expand it (D29). A page that has not been
        expanded has checked nothing, which is what NOT CHECKED means.
      </p>
    </div>
  );
}
