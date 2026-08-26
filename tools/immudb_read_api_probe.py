"""tools/immudb_read_api_probe.py - Phase 3c-3a (P3c3a-1, P3c3a-3).

Re-derives, live, the ImmuDB REST facts GET /audit's read path is built on,
so they are a re-runnable claim rather than a remembered one:

  count/{prefix} routes, and what its response looks like
  countall routes
  count counts distinct keys, not versions
  getall omits missing keys silently, and returns {} when all are missing
  getall has no scan-sized ceiling
  scan does have one, and where it is

Committed because docs/reports/phase-3c3a.md cites its output, and a
command-backed claim in this project has to be re-runnable from a checkout
(the same reason tools/audit_roundtrip_measure.py is here).

Usage, against a docker-compose.test.yml stack:

    python tools/immudb_read_api_probe.py

Writes a handful of throwaway keys under its own uuid-suffixed prefixes.
"""
import base64
import json
import urllib.parse
import uuid

import httpx

IMMUDB = "http://localhost:8080"
USER = "immudb"
PW = "immudb"


def b64(s):
    return base64.b64encode(s if isinstance(s, bytes) else s.encode()).decode()


c = httpx.Client(timeout=30.0)
r = c.post(f"{IMMUDB}/api/v2/login", json={
    "user": b64(USER), "password": b64(PW), "database": b64("defaultdb")})
r.raise_for_status()
tok = r.json()["token"]
H = {"Authorization": f"Bearer {tok}"}

# --- seed: 3 tool_call: keys, 2 tool_call_intent: keys, 1 tombstone -------
marker = uuid.uuid4().hex[:8]
written = []
for i in range(3):
    k = f"tool_call:probe-{marker}:{uuid.uuid4().hex}:probe_tool"
    v = json.dumps({"record_type": "decision", "call_id": f"cid-{marker}-{i}"})
    c.post(f"{IMMUDB}/api/v2/db/set", json={"KVs": [{"key": b64(k), "value": b64(v)}]},
           headers=H).raise_for_status()
    written.append(k)
for i in range(2):
    k = f"tool_call_intent:probe-{marker}:{uuid.uuid4().hex}:probe_tool"
    v = json.dumps({"record_type": "decision_intent", "call_id": f"icid-{marker}-{i}"})
    c.post(f"{IMMUDB}/api/v2/db/set", json={"KVs": [{"key": b64(k), "value": b64(v)}]},
           headers=H).raise_for_status()
tomb_cid = f"cid-{marker}-0"
c.post(f"{IMMUDB}/api/v2/db/set", json={"KVs": [{
    "key": b64(f"content_erasure:{tomb_cid}"),
    "value": b64(json.dumps({"record_type": "content_erasure", "call_id": tomb_cid})),
}]}, headers=H).raise_for_status()

print("=" * 70)
print("FACT 1: GET /api/v2/db/count/{prefix_b64} routes, and its shape")
for prefix in ["tool_call:", "tool_call", "tool_call_intent:", "content_erasure:"]:
    enc = urllib.parse.quote(b64(prefix), safe="")
    resp = c.get(f"{IMMUDB}/api/v2/db/count/{enc}", headers=H)
    print(f"  prefix={prefix!r:24} status={resp.status_code} body={resp.text[:120]}")

print()
print("FACT 2: GET /api/v2/db/countall routes")
resp = c.get(f"{IMMUDB}/api/v2/db/countall", headers=H)
print(f"  status={resp.status_code} body={resp.text[:120]}")

print()
print("FACT 3: count counts distinct KEYS, not versions")
k = f"tool_call:probe-{marker}-versioned:{uuid.uuid4().hex}:probe_tool"
enc = urllib.parse.quote(b64("tool_call:"), safe="")
before = c.get(f"{IMMUDB}/api/v2/db/count/{enc}", headers=H).json()
for n in range(3):
    c.post(f"{IMMUDB}/api/v2/db/set", json={"KVs": [{"key": b64(k), "value": b64(f"v{n}")}]},
           headers=H).raise_for_status()
after = c.get(f"{IMMUDB}/api/v2/db/count/{enc}", headers=H).json()
print(f"  before={before}  after 3 writes to ONE new key={after}")
print(f"  -> delta should be 1 if distinct-key, 3 if versions")

print()
print("FACT 4: POST /api/v2/db/getall omits missing keys silently")
present = f"content_erasure:{tomb_cid}"
missing = f"content_erasure:{uuid.uuid4().hex}-does-not-exist"
resp = c.post(f"{IMMUDB}/api/v2/db/getall",
              json={"keys": [b64(present), b64(missing)]}, headers=H)
print(f"  status={resp.status_code}")
body = resp.json()
ents = body.get("entries", [])
print(f"  requested 2 keys (1 present, 1 missing) -> got {len(ents)} entries")
for e in ents:
    print(f"    key={base64.b64decode(e['key']).decode()!r} tx={e.get('tx')}")

print()
print("FACT 4b: getall with ALL keys missing")
resp = c.post(f"{IMMUDB}/api/v2/db/getall",
              json={"keys": [b64(f"content_erasure:{uuid.uuid4().hex}") for _ in range(3)]},
              headers=H)
print(f"  status={resp.status_code} entries={len(resp.json().get('entries', []))} body={resp.text[:200]}")

print()
print("FACT 5: getall has no 2500 ceiling (scan does)")
many = [b64(f"content_erasure:{uuid.uuid4().hex}") for _ in range(3000)]
many[0] = b64(present)
resp = c.post(f"{IMMUDB}/api/v2/db/getall", json={"keys": many}, headers=H)
print(f"  3000 keys -> status={resp.status_code} entries={len(resp.json().get('entries', []))}"
      if resp.status_code == 200 else f"  3000 keys -> status={resp.status_code} body={resp.text[:200]}")

print()
print("FACT 6: scan ceiling")
for lim in [2500, 2501, 5000]:
    resp = c.post(f"{IMMUDB}/api/v2/db/scan",
                  json={"prefix": b64("tool_call:"), "desc": True, "limit": lim}, headers=H)
    print(f"  scan limit={lim} -> status={resp.status_code} {resp.text[:100] if resp.status_code != 200 else 'ok'}")
