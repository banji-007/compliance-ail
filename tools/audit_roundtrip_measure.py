"""Round-trip measurement for Phase 3c-2, item P3c2-6.

Counts the verifier round trips one GET /audit costs, from the verifier's
own uvicorn access log, at four ledger sizes. Run against a stack whose
ledger has at least 200 tool_call: records.
"""
import base64, json, os, re, subprocess, sys, time, uuid
import httpx

CP = os.getenv("CONTROL_PLANE_URL", "http://localhost:8002")
RK = os.getenv("CONTROL_PLANE_READ_KEY", "test-read-key")
VU = os.getenv("VERIFIER_URL", "http://localhost:8003")
VW = os.getenv("VERIFIER_WRITE_KEY", "test-verifier-write-key")
PROJ = os.getenv("COMPOSE_PROJECT_NAME", "ail-p3c2")

ACCESS = re.compile(r'\s(?P<client>[0-9a-fA-F:.]+):\d+ - "(?P<method>[A-Z]+) (?P<path>\S+) [^"]*"')


def b64(s): return base64.b64encode(s.encode()).decode()


def vlog():
    r = subprocess.run(["docker", "compose", "-p", PROJ, "-f", "docker-compose.test.yml",
                        "logs", "--no-log-prefix", "verifier"],
                       capture_output=True, text=True, timeout=120)
    return r.stdout


def count(log, method, path, exclude_loopback=False):
    n = 0
    for m in ACCESS.finditer(log):
        if m.group("method") != method or m.group("path") != path:
            continue
        if exclude_loopback and m.group("client") in ("127.0.0.1", "::1"):
            continue
        n += 1
    return n


def seed(target):
    """Write tool_call: records until the ledger holds at least `target`."""
    have = len(httpx.get(f"{CP}/audit", params={"limit": 1000}, headers={"X-API-Key": RK},
                         timeout=600).json()["entries"])
    while have < target:
        key = f"tool_call:measure-agent:{uuid.uuid4().hex}:measure_tool"
        value = json.dumps({"agent_id": "measure-agent", "timestamp": "2026-08-26T00:00:00",
                            "tool_name": "measure_tool", "outcome_type": "policy_allow",
                            "reasons": [], "content_state": "unavailable"})
        r = httpx.post(f"{VU}/write", json={"key": b64(key), "value": b64(value)},
                       headers={"X-API-Key": VW}, timeout=30)
        r.raise_for_status()
        have += 1
    return have


def measure(limit, extra_params=None):
    params = {"limit": limit}
    if extra_params:
        params.update(extra_params)
    before = vlog()
    v0 = count(before, "POST", "/verify")
    h0 = count(before, "GET", "/health", exclude_loopback=True)
    t0 = time.time()
    r = httpx.get(f"{CP}/audit", params=params, headers={"X-API-Key": RK}, timeout=600)
    elapsed = time.time() - t0
    r.raise_for_status()
    body = r.json()
    after = vlog()
    return {
        "limit": limit,
        "params": params,
        "entries": len(body["entries"]),
        "verify_calls": count(after, "POST", "/verify") - v0,
        "health_calls": count(after, "GET", "/health", exclude_loopback=True) - h0,
        "seconds": round(elapsed, 2),
        "verifier_reachable": body.get("verifier_reachable", "<absent>"),
    }


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "before"
    total = seed(200)
    print(f"ledger holds {total} tool_call entries", flush=True)
    rows = []
    for limit in (10, 50, 100, 200):
        row = measure(limit)
        rows.append(row)
        print(json.dumps(row), flush=True)
    if mode == "after":
        for limit in (10, 200):
            row = measure(limit, {"verify": "true"})
            rows.append(row)
            print(json.dumps(row), flush=True)
    with open(f"measure-{mode}.json", "w") as f:
        json.dump(rows, f, indent=2)
