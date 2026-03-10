"use client";

import { useState, KeyboardEvent } from "react";
import { X } from "lucide-react";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

interface Props {
  values: string[];
  onChange: (values: string[]) => void;
  disabled?: boolean;
  className?: string;
}

export function CostCenterInput({ values, onChange, disabled, className }: Props) {
  const [draft, setDraft] = useState("");

  function add() {
    const trimmed = draft.trim().toLowerCase().replace(/\s+/g, "_");
    if (trimmed && !values.includes(trimmed)) {
      onChange([...values, trimmed]);
    }
    setDraft("");
  }

  function remove(target: string) {
    onChange(values.filter((v) => v !== target));
  }

  function handleKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      add();
    } else if (e.key === "Backspace" && draft === "" && values.length > 0) {
      remove(values[values.length - 1]);
    }
  }

  return (
    <div
      className={cn(
        "flex flex-wrap items-center gap-1.5 rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-within:ring-2 focus-within:ring-ring focus-within:ring-offset-2 min-h-[2.5rem]",
        disabled && "opacity-50 cursor-not-allowed",
        className
      )}
    >
      {values.map((v) => (
        <span
          key={v}
          className="inline-flex items-center gap-1 rounded-full bg-secondary px-2.5 py-0.5 text-xs font-medium text-secondary-foreground"
        >
          {v}
          {!disabled && (
            <button
              type="button"
              onClick={() => remove(v)}
              aria-label={`Remove ${v}`}
              className="ml-0.5 rounded-full hover:bg-muted-foreground/20 focus:outline-none"
            >
              <X className="h-3 w-3" />
            </button>
          )}
        </span>
      ))}
      {!disabled && (
        <Input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={handleKeyDown}
          onBlur={add}
          placeholder={values.length === 0 ? "Type a cost center, press Enter…" : "Add…"}
          className="h-auto flex-1 border-0 bg-transparent p-0 text-xs shadow-none focus-visible:ring-0 focus-visible:ring-offset-0 min-w-[8rem]"
          disabled={disabled}
        />
      )}
    </div>
  );
}
