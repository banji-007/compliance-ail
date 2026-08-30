"""tools/ail_ordering_cost_probe.py - Phase 3c-3b (P3c3b-8).

What the ordering costs, on both paths.

Write path. Three single-writer cases and one concurrent case:

  /write              the pre-3c-3b path: verifiedSet, no position
  /write-ordered      cached: ExecAll + verifiedGet, counter from the
                      writer's own last commit
  /write-ordered      uncached (AIL_SEQUENCE_CACHE=0): the same, reading
                      the counter from the ledger every write
  /write-ordered      8 concurrent writers, which is what D34's
                      serialisation ceiling is about

Read path. The ordered page against the key walk it replaces, timed as the
ImmuDB calls each one makes, plus the end-to-end GET /audit.

Medians with the full observed range, never a single figure: host noise has
been larger than the effect in every prior measurement on this project
(docs/reports/phase-3c3a.md section 7.1 is the worked example).

Usage, against a docker-compose.test.yml stack:

    python tools/ail_ordering_cost_probe.py

Writes throwaway records under its own agent-id prefix and does not clean
up. Run it against a stack you are about to tear down.
"""

from __future__ import annotations

import base64
import json
import os
import statistics
import subprocess
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import httpx

VERIFIER_URL       = os.getenv("VERIFIER_URL", "http://localhost:8003")
VERIFIER_WRITE_KEY = os.getenv("VERIFIER_WRITE_KEY", "test-verifier-write-key")
CONTROL_PLANE_URL  = os.getenv("CONTROL_PLANE_URL", "http://localhost:8002")
READ_API_KEY       = os.getenv("CONTROL_PLANE_READ_KEY", "test-read-key")
IMMUDB_URL         = os.getenv("IMMUDB_URL", "http://localhost:8080")
COMPOSE_PROJECT    = os.getenv("COMPOSE_PROJECT_NAME", "p3c3b")

SAMPLES = 25
PAGE_LIMIT = 200
VIEW_DECISION = "ail_view:decision:v1"

_client = httpx.Client(timeout=120.0)


def b64(value) -> str:
    return base64.b64encode(value if isinstance(value, bytes) else value.encode()).decode()


def stats(xs: list[float]) -> dict:
    return {"median_ms": round(statistics.median(xs), 1),
            "min_ms": round(min(xs), 1),
            "max_ms": round(max(xs), 1),
            "n": len(xs)}


def record(agent: str) -> tuple[str, str]:
    key = f"tool_call:{agent}:{uuid.uuid4().hex}:query_database"
    value = json.dumps({
        "record_type": "decision", "call_id": uuid.uuid4().hex, "agent_id": agent,
        "timestamp": "2026-08-30T00:00:00", "tool_name": "query_database",
        "outcome_type": "policy_allow", "fault_class": None,
        "policy_revision": "cost-probe", "reasons": [],
        "input_sha256": uuid.uuid4().hex, "content_state": "unavailable",
        "profile": "observed",
    }, separators=(",", ":"))
    return key, value


def write_once(ordered: bool) -> tuple[float, int]:
    key, value = record(f"costprobe-{uuid.uuid4().hex[:8]}")
    body = {"key": b64(key), "value": b64(value)}
    route = "/write"
    if ordered:
        route = "/write-ordered"
        body["view"] = "decision"
    t0 = time.perf_counter()
    resp = _client.post(f"{VERIFIER_URL}{route}", json=body,
                        headers={"X-API-Key": VERIFIER_WRITE_KEY})
    elapsed = (time.perf_counter() - t0) * 1000
    resp.raise_for_status()
    body = resp.json()
    assert body.get("verified"), body
    return elapsed, body.get("attempts", 0)


def set_cache(enabled: bool) -> None:
    """Restart the verifier with the cache on or off. The toggle is read at
    import, so this is a restart rather than a request-level switch."""
    env = "1" if enabled else "0"
    subprocess.run(
        ["docker", "compose", "-p", COMPOSE_PROJECT, "-f", "docker-compose.test.yml",
         "up", "-d", "--no-deps", "verifier"],
        env={**os.environ, "AIL_SEQUENCE_CACHE": env},
        check=True, capture_output=True,
    )
    for _ in range(60):
        try:
            if _client.get(f"{VERIFIER_URL}/health").status_code == 200:
                return
        except Exception:
            pass
        time.sleep(1)
    raise SystemExit("verifier did not come back")


def immudb_headers() -> dict:
    resp = _client.post(f"{IMMUDB_URL}/api/v2/login", json={
        "user": b64("immudb"), "password": b64("immudb"), "database": b64("defaultdb")})
    resp.raise_for_status()
    return {"Authorization": f"Bearer {resp.json()['token']}"}


def timed(fn) -> dict:
    for _ in range(3):
        fn()
    return stats([(lambda: (lambda t0: (fn(), (time.perf_counter() - t0) * 1000)[1])(time.perf_counter()))()
                  for _ in range(SAMPLES)])


def main() -> None:
    out: dict = {}

    print("A. write path, one writer")
    # Baseline first, so a cold JIT/connection is not charged to the new path.
    for _ in range(3):
        write_once(ordered=False)
    out["write_unordered_verifiedSet"] = stats([write_once(False)[0] for _ in range(SAMPLES)])
    print("   /write (verifiedSet, no position):", out["write_unordered_verifiedSet"])

    for _ in range(3):
        write_once(ordered=True)
    out["write_ordered_cached"] = stats([write_once(True)[0] for _ in range(SAMPLES)])
    print("   /write-ordered cached:            ", out["write_ordered_cached"])

    print("   restarting verifier with AIL_SEQUENCE_CACHE=0 ...")
    set_cache(False)
    for _ in range(3):
        write_once(ordered=True)
    out["write_ordered_uncached"] = stats([write_once(True)[0] for _ in range(SAMPLES)])
    print("   /write-ordered uncached:          ", out["write_ordered_uncached"])
    set_cache(True)

    print()
    print("B. write path, 8 concurrent writers")
    per_writer = 8

    def burst(_w: int) -> list[tuple[float, int]]:
        return [write_once(ordered=True) for _ in range(per_writer)]

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = [r for chunk in pool.map(burst, range(8)) for r in chunk]
    wall = (time.perf_counter() - t0)
    latencies = [r[0] for r in results]
    attempts = [r[1] for r in results]
    out["write_ordered_concurrent_8"] = {
        **stats(latencies),
        "writers": 8, "writes": len(results),
        "wall_seconds": round(wall, 2),
        "writes_per_second": round(len(results) / wall, 1),
        "attempts_median": statistics.median(attempts),
        "attempts_max": max(attempts),
        "attempts_total": sum(attempts),
        "rejected_attempts": sum(attempts) - len(attempts),
        "gave_up": 0,
    }
    print("   concurrent:", json.dumps(out["write_ordered_concurrent_8"]))

    print()
    print("C. read path, the ImmuDB call each selection makes")
    headers = immudb_headers()

    def key_walk():
        _client.post(f"{IMMUDB_URL}/api/v2/db/scan", json={
            "prefix": b64("tool_call:"), "desc": True, "limit": PAGE_LIMIT + 1,
        }, headers=headers).raise_for_status()

    def ordered_select():
        _client.post(f"{IMMUDB_URL}/api/v2/db/zscan", json={
            "set": b64(VIEW_DECISION), "desc": True, "limit": PAGE_LIMIT + 1,
        }, headers=headers).raise_for_status()

    out["select_key_walk_scan"] = timed(key_walk)
    out["select_ordered_zscan"] = timed(ordered_select)
    print("   scan  (key walk, replaced):", out["select_key_walk_scan"])
    print("   zscan (ordered, current):  ", out["select_ordered_zscan"])

    print()
    print("D. read path, end to end")

    def audit():
        _client.get(f"{CONTROL_PLANE_URL}/audit", params={"limit": PAGE_LIMIT},
                    headers={"X-API-Key": READ_API_KEY}).raise_for_status()

    out["audit_end_to_end"] = timed(audit)
    page = _client.get(f"{CONTROL_PLANE_URL}/audit", params={"limit": PAGE_LIMIT},
                       headers={"X-API-Key": READ_API_KEY}).json()
    out["ledger_records"] = page["total"]
    out["page_rows"] = len(page["entries"])
    print("   GET /audit:", out["audit_end_to_end"], "over", out["ledger_records"], "records")

    print()
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
