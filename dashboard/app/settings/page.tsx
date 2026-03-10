"use client";

import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Save, RefreshCw, CheckCircle2, AlertCircle } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { ComplianceToggles } from "@/components/compliance-toggles";
import { CostCenterInput } from "@/components/cost-center-input";
import { fetchTenant, updateTenant } from "@/lib/api";
import { parseCostCenters, serializeCostCenters } from "@/lib/utils";
import type { Tenant } from "@/lib/types";

const TENANT_ID =
  process.env.NEXT_PUBLIC_TENANT_ID ?? "tenant_default";

// ---------------------------------------------------------------------------
// Local form state type — mirrors Tenant but cost_centers as array for UI
// ---------------------------------------------------------------------------
type FormState = {
  enable_gdpr: boolean;
  enable_soc2: boolean;
  enable_finops: boolean;
  enable_hipaa: boolean;
  cost_centers: string[];
};

function tenantToForm(t: Tenant): FormState {
  return {
    enable_gdpr: t.enable_gdpr,
    enable_soc2: t.enable_soc2,
    enable_finops: t.enable_finops,
    enable_hipaa: t.enable_hipaa,
    cost_centers: parseCostCenters(t.allowed_cost_centers),
  };
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function SettingsPage() {
  const qc = useQueryClient();

  const {
    data: tenant,
    isLoading,
    isError,
    error,
  } = useQuery({
    queryKey: ["tenant", TENANT_ID],
    queryFn: () => fetchTenant(TENANT_ID),
  });

  const [form, setForm] = useState<FormState | null>(null);

  // Sync local form state whenever the server data (re-)loads
  useEffect(() => {
    if (tenant && !form) {
      setForm(tenantToForm(tenant));
    }
  }, [tenant, form]);

  const mutation = useMutation({
    mutationFn: (update: Parameters<typeof updateTenant>[0]) =>
      updateTenant(update, TENANT_ID),
    onSuccess: (updated) => {
      qc.setQueryData(["tenant", TENANT_ID], updated);
      setForm(tenantToForm(updated));
    },
  });

  function handleToggle(
    key: keyof Pick<
      FormState,
      "enable_gdpr" | "enable_soc2" | "enable_finops" | "enable_hipaa"
    >,
    value: boolean
  ) {
    setForm((prev) => (prev ? { ...prev, [key]: value } : prev));
  }

  function handleCostCenters(values: string[]) {
    setForm((prev) => (prev ? { ...prev, cost_centers: values } : prev));
  }

  function handleSave() {
    if (!form) return;
    mutation.mutate({
      enable_gdpr: form.enable_gdpr,
      enable_soc2: form.enable_soc2,
      enable_finops: form.enable_finops,
      enable_hipaa: form.enable_hipaa,
      allowed_cost_centers: serializeCostCenters(form.cost_centers),
    });
  }

  const isDirty =
    tenant && form
      ? form.enable_gdpr !== tenant.enable_gdpr ||
        form.enable_soc2 !== tenant.enable_soc2 ||
        form.enable_finops !== tenant.enable_finops ||
        form.enable_hipaa !== tenant.enable_hipaa ||
        serializeCostCenters(form.cost_centers) !==
          tenant.allowed_cost_centers
      : false;

  // ---------------------------------------------------------------------------
  // Render states
  // ---------------------------------------------------------------------------

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24 text-sm text-muted-foreground">
        <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
        Loading tenant configuration…
      </div>
    );
  }

  if (isError) {
    return (
      <div className="flex items-center gap-2 rounded-md border border-destructive/50 bg-destructive/10 px-4 py-3 text-sm text-destructive">
        <AlertCircle className="h-4 w-4 shrink-0" />
        Failed to load tenant: {(error as Error).message}
      </div>
    );
  }

  if (!form) return null;

  // ---------------------------------------------------------------------------
  // Main UI
  // ---------------------------------------------------------------------------

  return (
    <div className="mx-auto max-w-2xl space-y-8">
      {/* Page header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Policy Settings</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {tenant?.name ?? TENANT_ID}
          {" · "}
          Changes trigger a new OPA bundle on the next poll cycle.
        </p>
      </div>

      {/* Compliance packs card */}
      <Card>
        <CardHeader>
          <CardTitle>Compliance Packs</CardTitle>
          <CardDescription>
            Toggle which regulatory frameworks are enforced by OPA. Disabling a
            pack removes its Rego rules from the active bundle immediately.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ComplianceToggles
            values={form}
            onChange={handleToggle}
            disabled={mutation.isPending}
          />
        </CardContent>
      </Card>

      <Separator />

      {/* Allowed cost centers card */}
      <Card>
        <CardHeader>
          <CardTitle>Allowed Cost Centers</CardTitle>
          <CardDescription>
            Cloud provisioning requests with a{" "}
            <span className="font-mono text-xs">cost_center</span> not in this
            list will be denied by the FinOps policy pack. Type a value and
            press <kbd className="rounded border px-1 font-mono text-xs">Enter</kbd>{" "}
            or{" "}
            <kbd className="rounded border px-1 font-mono text-xs">,</kbd> to
            add. Click{" "}
            <kbd className="rounded border px-1 font-mono text-xs">✕</kbd> to
            remove.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <CostCenterInput
            values={form.cost_centers}
            onChange={handleCostCenters}
            disabled={mutation.isPending}
          />
        </CardContent>
      </Card>

      {/* Save footer */}
      <div className="flex items-center justify-between">
        {mutation.isSuccess && (
          <span className="flex items-center gap-1.5 text-sm text-emerald-600">
            <CheckCircle2 className="h-4 w-4" />
            Configuration saved — OPA bundle updated.
          </span>
        )}
        {mutation.isError && (
          <span className="flex items-center gap-1.5 text-sm text-destructive">
            <AlertCircle className="h-4 w-4" />
            Save failed: {(mutation.error as Error).message}
          </span>
        )}
        {!mutation.isSuccess && !mutation.isError && <span />}

        <Button
          onClick={handleSave}
          disabled={!isDirty || mutation.isPending}
        >
          {mutation.isPending ? (
            <>
              <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
              Saving…
            </>
          ) : (
            <>
              <Save className="mr-2 h-4 w-4" />
              Save Configuration
            </>
          )}
        </Button>
      </div>
    </div>
  );
}
