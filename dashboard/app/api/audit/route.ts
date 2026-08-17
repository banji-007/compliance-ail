import { NextRequest, NextResponse } from "next/server";

// Server-side only (D4). CONTROL_PLANE_API_KEY never carries a NEXT_PUBLIC_
// prefix and is never read from a client component - the browser only ever
// talks to this same-origin route, never to the control plane directly.
const CONTROL_PLANE_URL = process.env.CONTROL_PLANE_URL ?? "http://ail-control-plane:8002";

export async function GET(req: NextRequest) {
  const apiKey = process.env.CONTROL_PLANE_API_KEY;
  if (!apiKey) {
    return NextResponse.json(
      { detail: "CONTROL_PLANE_API_KEY not configured on the dashboard server" },
      { status: 503 }
    );
  }

  const limit = req.nextUrl.searchParams.get("limit") ?? "200";
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
