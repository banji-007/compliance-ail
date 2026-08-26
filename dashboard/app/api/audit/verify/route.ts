import { NextRequest, NextResponse } from "next/server";

// P3c2-1 (Phase 3c-2): the browser's route to a single record's
// verification. Same shape, and same reasoning, as the /api/audit handler
// beside it (D4): CONTROL_PLANE_READ_KEY is held server-side, never carries
// a NEXT_PUBLIC_ prefix, and is never read from a client component. The
// browser talks only to this same-origin route and never learns the control
// plane's address or its credential.
//
// The control plane requires the read credential on GET /audit/verify for
// the same reason GET /audit/bundle requires it: a caller who can read the
// record through /audit can already see its verification, so gating the
// per-record route with the same read-scoped key adds no reach, while
// leaving it open would hand the audit trail's proof surface to an
// unauthenticated caller.
const CONTROL_PLANE_URL = process.env.CONTROL_PLANE_URL ?? "http://ail-control-plane:8002";

export async function GET(req: NextRequest) {
  const apiKey = process.env.CONTROL_PLANE_READ_KEY;
  if (!apiKey) {
    return NextResponse.json(
      { detail: "CONTROL_PLANE_READ_KEY not configured on the dashboard server" },
      { status: 503 }
    );
  }

  const key = req.nextUrl.searchParams.get("key");
  if (!key) {
    return NextResponse.json({ detail: "key is required" }, { status: 400 });
  }

  const res = await fetch(
    `${CONTROL_PLANE_URL}/audit/verify?key=${encodeURIComponent(key)}`,
    { headers: { "X-API-Key": apiKey }, cache: "no-store" }
  );
  const body = await res.text();
  return new NextResponse(body, {
    status: res.status,
    headers: { "Content-Type": "application/json" },
  });
}
