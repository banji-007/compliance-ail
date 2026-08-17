import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
  {
    variants: {
      variant: {
        default:
          "border-transparent bg-primary text-primary-foreground hover:bg-primary/80",
        secondary:
          "border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80",
        destructive:
          "border-transparent bg-destructive text-destructive-foreground hover:bg-destructive/80",
        outline: "text-foreground",
        approved:
          "border-transparent bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-100",
        denied:
          "border-transparent bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-100",
        // schema_deny and "unverifiable" — distinct from a policy denial /
        // proof failure, so a real violation is never confused with a
        // rejection or a check that could not complete (P1-7).
        warning:
          "border-transparent bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-100",
        // Infrastructure fault — deliberately not red (a policy denial) or
        // green (an allow); this is neither, it is "no decision was made".
        fault:
          "border-transparent bg-violet-100 text-violet-800 dark:bg-violet-900 dark:text-violet-100",
        // "asserted" — not a problem, just "no check was attempted".
        muted:
          "border-transparent bg-muted text-muted-foreground",
      },
    },
    defaultVariants: { variant: "default" },
  }
);

export interface BadgeProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?:
    | "default"
    | "secondary"
    | "destructive"
    | "outline"
    | "approved"
    | "denied"
    | "warning"
    | "fault"
    | "muted";
}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}

export { Badge, badgeVariants };
