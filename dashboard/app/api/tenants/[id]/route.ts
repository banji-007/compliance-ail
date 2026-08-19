import { NextRequest, NextResponse } from "next/server";

// Server-side only (D4). Neither key carries a NEXT_PUBLIC_ prefix and
// neither is read from a client component - the browser only ever talks to
// this same-origin route, never to the control plane directly. The caller
// reaching this handler has already passed dashboard middleware.ts's own
// auth check (D6); these are the control plane's own, independent
// credentials - GET forwards the read key, PUT forwards the write key, so a
// bug here can leak reads but cannot forward a write with only a read key
// available in scope.
const CONTROL_PLANE_URL = process.env.CONTROL_PLANE_URL ?? "http://ail-control-plane:8002";

type RouteContext = { params: Promise<{ id: string }> };

async function proxy(id: string, apiKey: string | undefined, missingKeyName: string, init?: RequestInit) {
  if (!apiKey) {
    return NextResponse.json(
      { detail: `${missingKeyName} not configured on the dashboard server` },
      { status: 503 }
    );
  }

  const res = await fetch(`${CONTROL_PLANE_URL}/tenants/${encodeURIComponent(id)}`, {
    ...init,
    headers: { "Content-Type": "application/json", "X-API-Key": apiKey, ...init?.headers },
    cache: "no-store",
  });
  const body = await res.text();
  return new NextResponse(body, {
    status: res.status,
    headers: { "Content-Type": "application/json" },
  });
}

export async function GET(req: NextRequest, { params }: RouteContext) {
  const { id } = await params;
  return proxy(id, process.env.CONTROL_PLANE_READ_KEY, "CONTROL_PLANE_READ_KEY");
}

export async function PUT(req: NextRequest, { params }: RouteContext) {
  const { id } = await params;
  const body = await req.text();
  return proxy(id, process.env.CONTROL_PLANE_WRITE_KEY, "CONTROL_PLANE_WRITE_KEY", { method: "PUT", body });
}
