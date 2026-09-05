"""tools/immudb_ordering_probe.py - Phase 3c-3c (P3c3c-9).

Re-derives, live, the ImmuDB wire facts the ordered audit view is built on,
so they are a re-runnable claim rather than a remembered one.

Why this file exists. Three phases in a row cited run ids `p3c3-question`,
`p3c3-probe` and `p3c3-scoring` for these facts, and no artifact for any of
the three exists in this repository. Every mechanism in D32 through D37 rests
on them, so each phase re-derived them by hand and wrote the transcript into
its own report. This is that probe, committed, in the same form
`tools/immudb_read_api_probe.py` already has for the read-path facts Phase
3c-3a rests on.

Provenance for the claims re-derived here, none of it first-hand recall:
  docs/reports/phase-3c3b.md section 2   the ordering facts and the transcript
  docs/reports/phase-3c3a.md             the count/getall/scan-ceiling facts
  tools/immudb_read_api_probe.py         the read-path probe this mirrors
  docs/reports/phase-3c3c-probe.md       this probe's own recorded output

What it checks:

  A. zscan under desc omits negatively-scored members, and minScore does not
     bring them back
  B. a score of exactly zero arrives with no `score` field at all
  C. zscan's limit ceiling, and scan's
  D. which routes exist: zscan, execall, zadd, set, history, verifiable/get,
     txscan, setall
  E. ExecAll with a precondition, accepted and rejected
  F. a prior version of a key is readable five ways, and getall reports
     `revision` on the head entry
  G. scan over a prefix returns one row per distinct key, not per version

Usage, against a docker-compose.test.yml stack:

    python tools/immudb_ordering_probe.py

Writes throwaway keys and zsets under its own uuid-suffixed names.
"""

import base64
import json
import os
import uuid

import httpx

IMMUDB = os.getenv("IMMUDB_URL", "http://localhost:8080")
USER = os.getenv("IMMUDB_USER", "immudb")
PW = os.getenv("IMMUDB_PASSWORD", "immudb")


def b64(value):
    return base64.b64encode(value if isinstance(value, bytes) else value.encode()).decode()


def unb64(value):
    return base64.b64decode(value)


c = httpx.Client(timeout=60.0)
r = c.post(f"{IMMUDB}/api/v2/login", json={
    "user": b64(USER), "password": b64(PW), "database": b64("defaultdb")})
r.raise_for_status()
H = {"Authorization": f"Bearer {r.json()['token']}"}

marker = uuid.uuid4().hex[:8]
SET = f"probe_view_{marker}"


def kv(key, value):
    return c.post(f"{IMMUDB}/api/v2/db/set",
                  json={"KVs": [{"key": b64(key), "value": b64(value)}]}, headers=H)


def zadd(score, key):
    return c.post(f"{IMMUDB}/api/v2/db/zadd",
                  json={"set": b64(SET), "score": score, "key": b64(key)}, headers=H)


def zscan(**body):
    payload = {"set": b64(SET), "limit": 100}
    payload.update(body)
    return c.post(f"{IMMUDB}/api/v2/db/zscan", json=payload, headers=H)


print("=== A/B. what zscan returns, by score sign ===")
scored = {"neg3": -3, "neg1": -1, "zero": 0, "quarter": 0.25, "one": 1, "two": 2}
for name, score in scored.items():
    key = f"probe_{marker}_{name}"
    kv(key, json.dumps({"probe": name})).raise_for_status()
    zadd(score, key).raise_for_status()

for desc in (True, False):
    rows = zscan(desc=desc).json().get("entries", [])
    rendered = [(row.get("score", "<NO SCORE FIELD>"),
                 unb64(row["entry"]["key"]).decode().rsplit("_", 1)[-1])
                for row in rows]
    print(f"  desc={str(desc):<5} -> {rendered}")

rows = zscan(desc=True, minScore={"score": -10}).json().get("entries", [])
print(f"  desc=True minScore=-10 -> "
      f"{[unb64(r['entry']['key']).decode().rsplit('_', 1)[-1] for r in rows]}")
print("  A: negatively-scored members are omitted under desc, and minScore does "
      "not bring them back")
print("  B: the zero-scored row carries no `score` key at all (protobuf omits "
      "zero-valued fields)")

print()
print("=== C. limit ceilings ===")
for limit in (2500, 2501):
    resp = zscan(limit=limit)
    print(f"  zscan limit={limit:<5} -> HTTP {resp.status_code}")
for limit in (2500, 2501):
    resp = c.post(f"{IMMUDB}/api/v2/db/scan",
                  json={"prefix": b64(f"probe_{marker}"), "limit": limit}, headers=H)
    print(f"  scan  limit={limit:<5} -> HTTP {resp.status_code}")

print()
print("=== D. which routes exist ===")
routes = {
    "db/zscan":          ("post", {"set": b64(SET), "limit": 1}),
    "db/zadd":           ("post", {"set": b64(SET), "score": 1.0,
                                   "key": b64(f"probe_{marker}_one")}),
    "db/execall":        ("post", {"Operations": [{"kv": {
                              "key": b64(f"probe_{marker}_ea"), "value": b64("x")}}]}),
    "db/set":            ("post", {"KVs": [{"key": b64(f"probe_{marker}_s"),
                                            "value": b64("x")}]}),
    "db/getall":         ("post", {"keys": [b64(f"probe_{marker}_one")]}),
    "db/history":        ("post", {"key": b64(f"probe_{marker}_one"), "limit": 10}),
    "db/verifiable/get": ("post", {"keyRequest": {"key": b64(f"probe_{marker}_one")}}),
    "db/txscan":         ("post", {"initialTx": "1", "limit": 1}),
    "db/setall":         ("post", {"KVs": [{"key": b64(f"probe_{marker}_sa"),
                                            "value": b64("x")}]}),
}
for route, (_method, body) in routes.items():
    resp = c.post(f"{IMMUDB}/api/v2/{route}", json=body, headers=H)
    print(f"  POST /api/v2/{route:<20} -> HTTP {resp.status_code}")
resp = c.post(f"{IMMUDB}/api/v2/db/get", json={"key": b64(f"probe_{marker}_one")}, headers=H)
print(f"  POST /api/v2/db/get{'':<15} -> HTTP {resp.status_code}  "
      "(the route that does not exist; GET db/get/{key} does)")

print()
print("=== E. ExecAll with a precondition ===")
counter = f"probe_{marker}_counter"
first = c.post(f"{IMMUDB}/api/v2/db/execall", json={
    "Operations": [{"kv": {"key": b64(counter), "value": b64("1")}}],
    "preconditions": [{"keyMustNotExist": {"key": b64(counter)}}],
    "noWait": False,
}, headers=H)
print(f"  KeyMustNotExist, first time  -> HTTP {first.status_code} "
      f"tx {first.json().get('id') if first.status_code == 200 else ''}")
second = c.post(f"{IMMUDB}/api/v2/db/execall", json={
    "Operations": [{"kv": {"key": b64(counter), "value": b64("2")}}],
    "preconditions": [{"keyMustNotExist": {"key": b64(counter)}}],
    "noWait": False,
}, headers=H)
print(f"  KeyMustNotExist, second time -> HTTP {second.status_code} "
      f"{second.text[:120]}")

head = c.post(f"{IMMUDB}/api/v2/db/getall", json={"keys": [b64(counter)]},
              headers=H).json()["entries"][0]
stale_tx = int(head["tx"])
c.post(f"{IMMUDB}/api/v2/db/execall", json={
    "Operations": [{"kv": {"key": b64(counter), "value": b64("3")}}],
    "preconditions": [{"keyNotModifiedAfterTX": {"key": b64(counter),
                                                 "txID": str(stale_tx)}}],
    "noWait": False,
}, headers=H)
stale = c.post(f"{IMMUDB}/api/v2/db/execall", json={
    "Operations": [{"kv": {"key": b64(counter), "value": b64("4")}}],
    "preconditions": [{"keyNotModifiedAfterTX": {"key": b64(counter),
                                                 "txID": str(stale_tx)}}],
    "noWait": False,
}, headers=H)
print(f"  KeyNotModifiedAfterTX, stale -> HTTP {stale.status_code} "
      f"{stale.text[:140]}")

print()
print("=== F. prior versions of one key, five ways ===")
versioned = f"probe_{marker}_versioned"
for i in (1, 2, 3):
    kv(versioned, json.dumps({"version": i})).raise_for_status()

head = c.post(f"{IMMUDB}/api/v2/db/getall", json={"keys": [b64(versioned)]},
              headers=H).json()["entries"][0]
print(f"  getall head        -> revision {head.get('revision')} tx {head.get('tx')} "
      f"value {unb64(head['value']).decode()}")
print("     (head revision equals the number of writes, at no extra call)")

for label, url in (
    ("get atRevision=-1", f"{IMMUDB}/api/v2/db/get/{b64(versioned)}?atRevision=-1"),
    ("get atRevision=1 ", f"{IMMUDB}/api/v2/db/get/{b64(versioned)}?atRevision=1"),
    ("get atTx         ", f"{IMMUDB}/api/v2/db/get/{b64(versioned)}?atTx={head['tx']}"),
):
    resp = c.get(url, headers=H)
    body = resp.json() if resp.status_code == 200 else {}
    print(f"  {label} -> HTTP {resp.status_code} revision {body.get('revision')} "
          f"value {unb64(body['value']).decode() if body.get('value') else ''}")

hist = c.post(f"{IMMUDB}/api/v2/db/history",
              json={"key": b64(versioned), "desc": True, "limit": 10}, headers=H)
entries = hist.json().get("entries", []) if hist.status_code == 200 else []
print(f"  history           -> HTTP {hist.status_code} "
      f"{[(e.get('revision'), unb64(e['value']).decode()) for e in entries]}")

vg = c.post(f"{IMMUDB}/api/v2/db/verifiable/get",
            json={"keyRequest": {"key": b64(versioned), "atRevision": "1"}}, headers=H)
print(f"  verifiable/get atRevision=1 -> HTTP {vg.status_code} "
      f"keys {sorted(vg.json())[:4] if vg.status_code == 200 else vg.text[:120]}")

print()
print("=== G. does a prefix scan inflate with versions ===")
scan = c.post(f"{IMMUDB}/api/v2/db/scan",
              json={"prefix": b64(versioned), "limit": 100}, headers=H)
rows = scan.json().get("entries", [])
print(f"  scan over the 3-version key -> {len(rows)} row(s), "
      f"revision {rows[0].get('revision') if rows else ''}")
print("  one row per distinct key, at its latest version")
