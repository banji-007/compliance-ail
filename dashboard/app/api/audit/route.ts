import { NextRequest, NextResponse } from "next/server";
import { AUDIT_PAGE_SIZE } from "@/lib/constants";

// Server-side only (D4). CONTROL_PLANE_READ_KEY never carries a NEXT_PUBLIC_
// prefix and is never read from a client component - the browser only ever
// talks to this same-origin route, never to the control plane directly. The
// caller reaching this handler at all has already passed dashboard
// middleware.ts's own auth check (D6) - this key is a second, independent
// credential the control plane itself enforces.
const CONTROL_PLANE_URL = process.env.CONTROL_PLANE_URL ?? "http://ail-control-plane:8002";

export async function GET(req: NextRequest) {
  const apiKey = process.env.CONTROL_PLANE_READ_KEY;
  if (!apiKey) {
    return NextResponse.json(
      { detail: "CONTROL_PLANE_READ_KEY not configured on the dashboard server" },
      { status: 503 }
    );
  }

  // P3c2-5: the page size has one definition (lib/constants.ts). This
  // file, lib/api.ts and app/audit/page.tsx each carried the number
  // independently before, three literals that had to agree with nothing
  // making them agree.
  const limit =
    req.nextUrl.searchParams.get("limit") ?? String(AUDIT_PAGE_SIZE);
  const res = await fetch(`${CONTROL_PLANE_URL}/audit?limit=${encodeURIComponent(limit)}`, {
    headers: { "X-API-Key": apiKey },
    cache: "no-store",
  });
  const body = await res.text();
  return new NextResponse(body, {
    status: res.status,
    headers: { "Content-Type": "application/json" },
  });
}
