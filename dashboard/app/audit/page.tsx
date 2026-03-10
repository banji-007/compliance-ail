"use client";

import { useQuery } from "@tanstack/react-query";
import { RefreshCw, AlertCircle, ShieldAlert, RefreshCcw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { AuditTable } from "@/components/audit-table";
import { fetchAudit } from "@/lib/api";

export default function AuditPage() {
  const { data, isLoading, isError, error, refetch, isFetching, dataUpdatedAt } =
    useQuery({
      queryKey: ["audit"],
      queryFn: () => fetchAudit(200),
      // Refresh every 30 s automatically — ledger grows as agents run.
      refetchInterval: 30_000,
    });

  const updatedAt = dataUpdatedAt
    ? new Date(dataUpdatedAt).toLocaleTimeString()
    : null;

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Audit Ledger</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Cryptographically immutable log of all AI agent tool-call decisions
            stored in ImmuDB. Hashes are SHA-256(key:entry:tx_id) and
            verifiable offline.
            {updatedAt && (
              <span className="ml-2 text-xs opacity-60">
                Last fetched {updatedAt}
              </span>
            )}
          </p>
        </div>

        <Button
          variant="outline"
          size="sm"
          onClick={() => refetch()}
          disabled={isFetching}
        >
          <RefreshCcw
            className={`mr-2 h-3.5 w-3.5 ${isFetching ? "animate-spin" : ""}`}
          />
          Refresh
        </Button>
      </div>

      {/* Loading */}
      {isLoading && (
        <div className="flex items-center gap-2 py-16 text-sm text-muted-foreground">
          <RefreshCw className="h-4 w-4 animate-spin" />
          Fetching ledger entries from ImmuDB…
        </div>
      )}

      {/* Error */}
      {isError && (
        <div className="flex items-start gap-3 rounded-md border border-destructive/40 bg-destructive/10 px-4 py-4 text-sm text-destructive">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
          <div>
            <p className="font-semibold">Failed to load audit ledger</p>
            <p className="mt-1 text-xs opacity-80">
              {(error as Error).message}
            </p>
            <p className="mt-2 text-xs opacity-60">
              Ensure ImmuDB is running and the control-plane has{" "}
              <code>IMMUDB_USER</code> / <code>IMMUDB_PASSWORD</code> set.
            </p>
          </div>
        </div>
      )}

      {/* Summary stats */}
      {data && (
        <div className="grid grid-cols-3 gap-4">
          <StatCard
            label="Total Decisions"
            value={data.total}
            color="text-foreground"
          />
          <StatCard
            label="Approved"
            value={
              data.entries.filter((e) =>
                e.decision?.toUpperCase().startsWith("APPROVED")
              ).length
            }
            color="text-emerald-600"
          />
          <StatCard
            label="Denied"
            value={
              data.entries.filter((e) =>
                e.decision?.toUpperCase().startsWith("DENIED")
              ).length
            }
            color="text-red-600"
          />
        </div>
      )}

      {/* Table */}
      {data && <AuditTable entries={data.entries} />}

      {/* Empty state after load */}
      {data && data.total === 0 && (
        <div className="flex flex-col items-center gap-3 py-20 text-center text-muted-foreground">
          <ShieldAlert className="h-10 w-10 opacity-30" />
          <p className="text-sm font-medium">No ledger entries yet.</p>
          <p className="max-w-xs text-xs opacity-70">
            Run the LangGraph demo or send tool calls through the interceptor —
            every decision will appear here in real time.
          </p>
        </div>
      )}
    </div>
  );
}

function StatCard({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color: string;
}) {
  return (
    <div className="rounded-lg border bg-card p-4">
      <p className="text-xs font-medium text-muted-foreground">{label}</p>
      <p className={`mt-1 text-3xl font-bold tabular-nums ${color}`}>
        {value.toLocaleString()}
      </p>
    </div>
  );
}
