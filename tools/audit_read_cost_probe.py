"""tools/audit_read_cost_probe.py - Phase 3c-3a (P3c3a-4).

Component cost breakdown for GET /audit as a function of ledger size.

The end-to-end GET /audit timings at limit=200 came back inside host noise at
every ledger size (see the report), so they cannot say which call grows. This
times the individual ImmuDB calls each version of the endpoint makes, against
the same ledger, so the growth curve of the one that grows is visible.

  before, per request: scan(tool_call:, 200)
                       scan(content_erasure:, 200)   <- deleted by P3c3a-3
                       scan(tool_call_intent:, 200)

  after,  per request: scan(tool_call:, 201)
                       scan(tool_call_intent:, 201)
                       count(tool_call:)             <- added by P3c3a-1
                       getall(<= 207 tombstone keys) <- added by P3c3a-3

Usage, against a freshly started docker-compose.test.yml stack:

    python tools/audit_read_cost_probe.py

Seeds the ledger to 2k, 10k and 40k `tool_call:` keys in turn and prints one
JSON line per size. **It seeds tens of thousands of throwaway records and
does not clean up** - run it against a stack you are about to tear down with
`docker compose down -v`, never against one another test session needs.

Output transcribed in docs/reports/phase-3c3a.md section 7.2.
"""
import base64
import json
import statistics
import sys
import time
import urllib.parse
import uuid

import httpx

IMMUDB = "http://localhost:8080"
LIMIT = 200
SAMPLES = 15


def b64(s):
    return base64.b64encode(s if isinstance(s, bytes) else s.encode()).decode()


def login(c):
    r = c.post(f"{IMMUDB}/api/v2/login", json={
        "user": b64("immudb"), "password": b64("immudb"), "database": b64("defaultdb")})
    r.raise_for_status()
    return {"Authorization": f"Bearer {r.json()['token']}"}


def timed(fn):
    for _ in range(3):
        fn()                       # warm
    xs = []
    for _ in range(SAMPLES):
        t0 = time.perf_counter()
        fn()
        xs.append((time.perf_counter() - t0) * 1000)
    return {"median_ms": round(statistics.median(xs), 1),
            "min_ms": round(min(xs), 1),
            "max_ms": round(max(xs), 1)}


def seed(c, h, target):
    r = c.get(f"{IMMUDB}/api/v2/db/count/{urllib.parse.quote(b64('tool_call:'), safe='')}", headers=h)
    have = int(r.json().get("count", 0))
    need = target - have
    if need <= 0:
        return
    batch = []
    for _ in range(need):
        key = f"tool_call:seed-{uuid.uuid4().hex}:{uuid.uuid4().hex}:query_database"
        value = json.dumps({"record_type": "decision", "call_id": uuid.uuid4().hex,
                            "agent_id": "seed", "timestamp": "2026-08-26T00:00:00",
                            "tool_name": "query_database", "outcome_type": "policy_allow",
                            "fault_class": None, "policy_revision": "seed", "reasons": [],
                            "input_sha256": uuid.uuid4().hex,
                            "content_state": "unavailable", "profile": "observed"},
                           separators=(",", ":"))
        batch.append({"key": b64(key), "value": b64(value)})
        if len(batch) == 250:
            c.post(f"{IMMUDB}/api/v2/db/set", json={"KVs": batch}, headers=h).raise_for_status()
            batch = []
    if batch:
        c.post(f"{IMMUDB}/api/v2/db/set", json={"KVs": batch}, headers=h).raise_for_status()


def seed_tombstones(c, h, n):
    batch = []
    for _ in range(n):
        k = f"content_erasure:{uuid.uuid4().hex}"
        v = json.dumps({"record_type": "content_erasure", "call_id": uuid.uuid4().hex},
                       separators=(",", ":"))
        batch.append({"key": b64(k), "value": b64(v)})
        if len(batch) == 250:
            c.post(f"{IMMUDB}/api/v2/db/set", json={"KVs": batch}, headers=h).raise_for_status()
            batch = []
    if batch:
        c.post(f"{IMMUDB}/api/v2/db/set", json={"KVs": batch}, headers=h).raise_for_status()


def main():
    with httpx.Client(timeout=300.0) as c:
        h = login(c)
        # A realistic tombstone population, so the deleted scan is not timed
        # against an empty prefix.
        seed_tombstones(c, h, 200)

        # The keys the new getall asks for: one per call_id on the page.
        getall_keys = [b64(f"content_erasure:{uuid.uuid4().hex}") for _ in range(207)]

        def scan(prefix, limit):
            return lambda: c.post(f"{IMMUDB}/api/v2/db/scan", json={
                "prefix": b64(prefix), "desc": True, "limit": limit}, headers=h).raise_for_status()

        def count(prefix):
            enc = urllib.parse.quote(b64(prefix), safe="")
            return lambda: c.get(f"{IMMUDB}/api/v2/db/count/{enc}", headers=h).raise_for_status()

        def getall():
            c.post(f"{IMMUDB}/api/v2/db/getall", json={"keys": getall_keys},
                   headers=h).raise_for_status()

        for target in (2000, 10000, 40000):
            seed(c, h, target)
            row = {
                "tool_call_keys": target,
                "scan_tool_call_200": timed(scan("tool_call:", LIMIT)),
                "scan_tool_call_201": timed(scan("tool_call:", LIMIT + 1)),
                "scan_content_erasure_200_DELETED": timed(scan("content_erasure:", LIMIT)),
                "scan_intent_201": timed(scan("tool_call_intent:", LIMIT + 1)),
                "count_tool_call_ADDED": timed(count("tool_call:")),
                "getall_207_keys_ADDED": timed(getall),
            }
            print(json.dumps(row))


main()
