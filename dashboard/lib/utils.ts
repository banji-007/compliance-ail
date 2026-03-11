import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/** Format an ISO-8601 UTC string into a human-readable local datetime. */
export function formatTimestamp(iso: string | null): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString(undefined, {
      dateStyle: "medium",
      timeStyle: "medium",
    });
  } catch {
    return iso;
  }
}

/** Truncate a hash string to first 16 chars + "…" for display. */
export function truncateHash(hash: string | null): string {
  if (!hash) return "—";
  return `${hash.slice(0, 16)}…`;
}

/** Parse a comma-separated cost centers string into a sorted array. */
export function parseCostCenters(csv: string): string[] {
  return csv
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

/** Serialize a cost centers array back to comma-separated string. */
export function serializeCostCenters(arr: string[]): string {
  return arr.join(",");
}
