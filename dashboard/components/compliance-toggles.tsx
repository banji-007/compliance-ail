"use client";

import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import type { Tenant } from "@/lib/types";

interface Pack {
  key: keyof Pick<
    Tenant,
    "enable_gdpr" | "enable_soc2" | "enable_finops" | "enable_hipaa"
  >;
  label: string;
  description: string;
  /** Whether this pack ships with the policy directory */
  available: boolean;
}

const PACKS: Pack[] = [
  {
    key: "enable_gdpr",
    label: "GDPR",
    description:
      "EU General Data Protection Regulation — PII handling and data residency controls.",
    available: true,
  },
  {
    key: "enable_soc2",
    label: "SOC 2",
    description:
      "AICPA Service Organisation Controls — access management and availability policies.",
    available: true,
  },
  {
    key: "enable_finops",
    label: "FinOps",
    description:
      "Cloud cost governance — validates cost centers and blocks unapproved spend.",
    available: true,
  },
  {
    key: "enable_hipaa",
    label: "HIPAA",
    description:
      "Health Insurance Portability and Accountability Act — PHI data controls.",
    available: true,
  },
];

interface Props {
  values: Pick<
    Tenant,
    "enable_gdpr" | "enable_soc2" | "enable_finops" | "enable_hipaa"
  >;
  onChange: (
    key: Pack["key"],
    value: boolean
  ) => void;
  disabled?: boolean;
}

export function ComplianceToggles({ values, onChange, disabled }: Props) {
  return (
    <div className="grid gap-5">
      {PACKS.map((pack) => (
        <div key={pack.key} className="flex items-start justify-between gap-4">
          <div className="space-y-0.5">
            <Label
              htmlFor={pack.key}
              className="text-sm font-semibold"
            >
              {pack.label}
            </Label>
            <p className="text-xs text-muted-foreground max-w-sm">
              {pack.description}
            </p>
          </div>
          <Switch
            id={pack.key}
            checked={values[pack.key]}
            onCheckedChange={(v) => onChange(pack.key, v)}
            disabled={disabled || !pack.available}
            aria-label={`Toggle ${pack.label}`}
          />
        </div>
      ))}
    </div>
  );
}
