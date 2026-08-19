import { NextRequest, NextResponse } from "next/server";

// D6 (Phase 1.1): the dashboard's own route handlers must authenticate the
// caller (browser or curl) before they ever attach CONTROL_PLANE_READ_KEY /
// CONTROL_PLANE_WRITE_KEY and proxy to the control plane. Without this,
// anyone who can reach this app's port reads the full audit log and mutates
// tenant policy with zero credentials - the control plane's own key was
// never the thing protecting this app; nothing was (docs/reports/
// phase-1-redteam.md, S6).
//
// HTTP Basic Auth, not a custom header: two independent credential pairs
// (read, write - never a hierarchy), checked here in middleware before any
// route handler runs. The browser's native auth dialog collects and caches
// credentials per origin; curl uses `-u user:pass`. No client-side code or
// session storage needed.
const READ_USER = process.env.DASHBOARD_READ_USER;
const READ_PASSWORD = process.env.DASHBOARD_READ_PASSWORD;
const WRITE_USER = process.env.DASHBOARD_WRITE_USER;
const WRITE_PASSWORD = process.env.DASHBOARD_WRITE_PASSWORD;

function unauthorized(realm: string): NextResponse {
  return new NextResponse(JSON.stringify({ detail: "Authentication required" }), {
    status: 401,
    headers: {
      "Content-Type": "application/json",
      "WWW-Authenticate": `Basic realm="${realm}"`,
    },
  });
}

function matchesCredentials(
  req: NextRequest,
  user: string | undefined,
  password: string | undefined
): boolean {
  if (!user || !password) return false;
  const header = req.headers.get("authorization");
  if (!header || !header.startsWith("Basic ")) return false;

  let decoded: string;
  try {
    // atob, not Buffer - Buffer is not reliably available in the Edge
    // runtime middleware.ts executes in.
    decoded = atob(header.slice("Basic ".length));
  } catch {
    return false;
  }

  const sep = decoded.indexOf(":");
  if (sep < 0) return false;
  const suppliedUser = decoded.slice(0, sep);
  const suppliedPassword = decoded.slice(sep + 1);
  return suppliedUser === user && suppliedPassword === password;
}

// Any method other than a plain read (GET/HEAD) is treated as a write - this
// covers the existing PUT /api/tenants/{id} and any future mutating route
// added under /api/ without needing a per-route allowlist here.
const READ_METHODS = new Set(["GET", "HEAD"]);

export function middleware(req: NextRequest): NextResponse {
  if (!READ_USER || !READ_PASSWORD || !WRITE_USER || !WRITE_PASSWORD) {
    return NextResponse.json(
      { detail: "Dashboard authentication not configured (DASHBOARD_READ_USER/PASSWORD or DASHBOARD_WRITE_USER/PASSWORD missing)" },
      { status: 503 }
    );
  }

  const isWrite = !READ_METHODS.has(req.method);
  const writeAuthed = matchesCredentials(req, WRITE_USER, WRITE_PASSWORD);

  if (isWrite) {
    // Read credentials never authorize a write route - a caller holding
    // only the read pair is rejected here, not silently upgraded.
    if (!writeAuthed) return unauthorized("ail-dashboard-write");
    return NextResponse.next();
  }

  const readAuthed = writeAuthed || matchesCredentials(req, READ_USER, READ_PASSWORD);
  if (!readAuthed) return unauthorized("ail-dashboard-read");
  return NextResponse.next();
}

export const config = {
  matcher: ["/api/:path*"],
};
