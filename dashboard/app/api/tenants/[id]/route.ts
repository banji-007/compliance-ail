import { NextRequest, NextResponse } from "next/server";

// Server-side only (D4). CONTROL_PLANE_API_KEY never carries a NEXT_PUBLIC_
// prefix and is never read from a client component - the browser only ever
// talks to this same-origin route, never to the control plane directly.
const CONTROL_PLANE_URL = process.env.CONTROL_PLANE_URL ?? "http://ail-control-plane:8002";

type RouteContext = { params: Promise<{ id: string }> };

async function proxy(req: NextRequest, id: string, init?: RequestInit) {
  const apiKey = process.env.CONTROL_PLANE_API_KEY;
  if (!apiKey) {
    return NextResponse.json(
      { detail: "CONTROL_PLANE_API_KEY not configured on the dashboard server" },
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
  return proxy(req, id);
}

export async function PUT(req: NextRequest, { params }: RouteContext) {
  const { id } = await params;
  const body = await req.text();
  return proxy(req, id, { method: "PUT", body });
}
