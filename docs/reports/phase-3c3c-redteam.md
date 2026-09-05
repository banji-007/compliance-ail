# Red-team report: Phase 3c-3c, run `p3c3c-red`

**Target:** PR #14 at `5bfc097`, branch `p3c3b-order`. Not merged, nothing fixed.
**Environment:** scratch clone under the session scratchpad, Compose project `p3c3cred`, stated explicitly on every invocation. Images built `--no-cache`. Keys generated on this machine (`make keygen` equivalent, run as its openssl commands since `make` is not on PATH here), which A10 requires.
**Baseline:** `tests/test_ledger_faults.py` + `tests/test_audit_ordering.py` = 36 passed, 1 failed (that failure is the "Also" item, explained below).

Nine of ten claims refuted (A1, A2, A3, A4, A5, A6, A8, A9, A10); A7 not refuted. The unexplained failure from `p3c3b-order` is reproduced, diagnosed, and demonstrated causally.

The two weakest points the build session named were both real. But the most serious finding is not on the list: any holder of the verifier write key can kill the entire `/audit` page with two ordinary, fully-verified writes.

## Checks I established could fail before trusting them

Every check below has a recorded control in the same session.

| Check | How I established it can fail |
| :--- | :--- |
| `test_image_contents.py` | dropped the two `.dockerignore` rules, rebuilt: `AssertionError: p3c3cred-decision-service carries key material ... ['/app/secrets/vault_api_token.txt']`, 1 failed |
| `test_ledger_vocabulary.py` | pointed the backfill at `ail_view:decision:v2`: 1 failed, 5 passed |
| the A3 parse test | added a plainly-named second caller: 1 failed before the alias made it pass |
| the cut proxy (A1, A8) | control writes through the same proxy with no marker: tx 149 and tx 151, both `verified: true`, `committed: true` |
| the erasure path (A8) | control erasure with no cut: DELETE gave 204, tombstone at tx 154, re-POST refused 409 |
| the reconciler (A5, A6) | it reported `state: findings` with `foreign_count: 1` and with `missing_count: 3` for other conditions in the same session |
| the `/audit` fault join (A2, A4) | the row read `ledger_fault: None` before the forged write |
| the keep-alive diagnosis | the failure window moved when I moved the server setting (below) |

## A1 - Refuted. The most serious of the listed claims.

The fix was demonstrated against one corruption. It covers exactly that one. The ordered route splits the commit from the proof; the plain route does not, and it wraps a second call in the same `try`:

```
resp   = client.verifiedSet(key, value)
state  = client.currentState()          # verifier/main.py:792
...
except (ErrCorruptedData, BadSignatureError):   # honest: committed: true
except Exception as exc:                         # verifier/main.py:800-802
    return WriteResponse(tx_id=None, verified=False, committed=False, ...)
```

Attack: a TCP proxy between verifier and immudb that relays the whole write request (so it commits and its response returns) and then stalls the client's next RPC. That is "connection reset after commit" from the brief's own list.

```
=== ATTACK: connection reset after commit (plain /write) ===
WRITE -> (200, {'tx_id': None, 'verified': False, 'committed': False,
                'error_class': None, 'fault_record': None,
                'detail': 'StatusCode.UNAVAILABLE ... Connection reset by peer (104)'})
LEDGER-> {"probe:ZZCUTZZ-a1": {"tx": "150", "revision": "1", ...}}
```

That is the exact shape `ledger/immudb_ledger.py` reads as "the write did not happen". No fault record was written.

**Decisive form.** Re-run as the last operation, reading the verifier's own persisted trust anchor before and after:

```
STATE BEFORE: {"immudb:3322/b'defaultdb'": 148, "cutproxy:3399/b'defaultdb'": 151}
WRITE -> (200, {'tx_id': None, 'verified': False, 'committed': False, ...})
LEDGER-> {"probe:ZZCUTZZ-a1-final": {"tx": "153", "revision": "1", ...}}
STATE AFTER : {"immudb:3322/b'defaultdb'": 148, "cutproxy:3399/b'defaultdb'": 153}
```

The anchor advanced to 153, the transaction the response says never happened. So this is not merely a committed-unverified write reported as uncommitted: `verifiedSet` completed, the proof passed, the client persisted the new state, and then `currentState()` raised. The route reported the whole thing as never having occurred.

The ordered route holds under the same attack, because it splits the two:

```
ORDERED WRITE -> {'tx_id': 152, 'seq': 1000000133, 'verified': False, 'committed': True,
                  'detail': 'verification could not be attempted: ... UNAVAILABLE ...'}
counter AFTER : 1000000133      IN LEDGER: tx 152      TOP OF VIEW: (1000000133, ...)
```

So the claim is false on one of the two routes, and it is the route the erasure tombstone uses.

## A2 - Refuted

Not through `_fault_key`'s fallback, which is real but bounded. Through the join itself.

`/write` refuses the `ledger_fault:` prefix. `/write-ordered` performs no refusal at all (`_refuse_reason_for_plain_write` is called from one place, `verifier/main.py:757`). So a caller holding only `VERIFIER_WRITE_KEY` writes its own fault record:

```
1. real decision record via /write-ordered -> tx 160, seq 1000000134, verified True
2. /audit row ledger_fault BEFORE: None
3. POST /write with a ledger_fault  -> (400, "key prefix 'ledger_fault:' does not belong ...")
4. SAME record via /write-ordered   -> (200, tx 161, seq 1000000135, verified True)
5. /audit row ledger_fault AFTER :
   {"fault_class": "FORGED-BY-CALLER", "error_class": "signature_failure",
    "committed_tx_id": 999999, "committed_position": 123,
    "timestamp": "2026-01-01T00:00:00", "count": 1, ...}
```

The page presents a caller-authored record as the ledger's own account of that record's standing, with an attacker-chosen fault class, transaction, position and timestamp. The verifier never wrote it. Nothing on the read path checks the writer signature or the writer key fingerprint before rendering it.

## A3 - Refuted, on both bounds

**The parse, defeated the way C8 was.** The test counts lines containing `_set_without_verification(` with the paren. A binding has no paren:

```
_unverified_write = _set_without_verification
def _aliased_second_caller(client, key, value, record):
    return _unverified_write(client, key, value, record)

=== MUTATION A: a plainly-named second caller ===  1 failed      (the test can fail)
=== MUTATION B (clean): alias caller ===           1 passed
caller lines found by the parse: 1
actual callers in the file: 2
```

**The runtime bound, defeated by driving it.** The guard inspects the `record` dict; the bytes written are `value`. They are different objects and nothing requires them to agree:

```
if record.get("record_type") != FAULT_RECORD_TYPE: raise RuntimeError(...)
resp = client.set(key, value)
```

Driven live through a route added to the verifier (rebuilt, then reverted):

```
== CONTROL: guard sees a non-fault record argument ==
  -> 500 Internal Server Error                      (the guard does refuse)
== ATTACK: record argument claims ledger_fault, value IS a decision record ==
  -> 200 {"tx":159}
== what is in the ledger ==
   tool_call:a3probe001 tx=159 rev=1 record_type=decision outcome=policy_allow
```

A decision record, written through the one path that requires no proof, with no position and no index entry. What this shows is that the path is not structurally unable to write one, and that the parse is not a second line. An external caller cannot reach it today; the guard and the parse are what were claimed to make that a property rather than a coincidence, and neither does.

## A4 - Refuted

`count` is `revision` on the head entry, and revision counts writes to the key, not faults. Via the unguarded ordered route, a caller advances it at will:

```
6. second forged fault -> (200, tx 162, seq 1000000136, verified True)
fault key ledger_fault:a2479b9302be65  tx 162  revision 2  head fault_class FORGED-2
```

Two forged faults, count follows. The verifier wrote neither.

## A5 - Refuted. A fourth condition that reads clean.

The three from the previous pass are genuinely fixed. C6a re-tested: a decision record indexed into the intent view is now reported (`foreign_count: 1`, naming position, key and expected prefix), pagination uses a `minScore` cursor, and a missing score is a reported finding rather than a `KeyError`.

The fourth: any score below the reserve is assumed to be history and is never checked for duplicating a live position. On a virgin ledger, three normal writes plus one injection giving an already-indexed record a second position at score 42:

```
=== reconciliation verdict (virgin ledger, this injection only) ===
{"state": "clean", "allocated": 3, "indexed": 3, "backfilled": 1,
 "missing": [], "unallocated": [], "foreign": [], "shared": [],
 "malformed": [], "views": {"ail_view:decision:v1": 4, "ail_view:intent:v1": 0}}
```

`clean`, every finding category empty. The page disagrees:

```
HTTP 200  rows 4  total 3
   a5c1-e0bc06  x2
call_ids appearing more than once on ONE page: ['a5c1-e0bc06']
```

This is C2's duplication defect wearing history's clothes, and the fault body's own remediation points the operator at this reconciliation.

## A6 - Refuted. A third limit.

`validate_reserve` bounds the reserve below and not above: "a positive integer" is the whole rule. `zscan` scores are float64, so a reserve at or above 2^53 makes allocated positions unrepresentable as distinct scores. All four readers agreed; the binding worked exactly as D36 says. What it bound was a number that cannot work.

`AIL_RESERVED_POSITIONS=9007199254740993` on verifier, control plane and anchor service, virgin ledger, six writes:

```
  write 0: tx=6  seq=9007199254740994 verified=True
  ...
  write 5: tx=11 seq=9007199254740999 verified=True
bound reserve: {'ail_seq:reserve': 9007199254740993}

view index as the ledger actually stored it:
   score=9007199254741000  tx=11
   score=9007199254740998  tx=10
   score=9007199254740996  tx=9
   score=9007199254740996  tx=8
   score=9007199254740996  tx=7
   score=9007199254740994  tx=6

scores holding MORE THAN ONE record: {"9007199254740996": [3 records]}
```

Six positions, four scores. Note also that write 5 was told `seq=...999` and stored at `...1000`: the response names a position the index does not hold. `/audit` is then dead at every limit from the sixth write on a virgin ledger:

```
HTTP 500 {"error": "audit_ordering_fault", "message": "... position 9007199254740996.0
 resolves to transaction 9 and position 9007199254740996.0 resolves to transaction 8 ..."}
```

Reconciliation does catch this one (`missing_count: 3`, `unallocated_count: 1`).

## A7 - Not refuted

The two conditions genuinely cover each other. Twelve shapes; nothing that a consumer reads as a decision got through:

```
record_type=decision, benign key                 -> 400
record_type OMITTED, tool_call: key              -> 400
record_type OMITTED, benign key                  -> 200 (no consumer reads it as a decision)
record_type=ledger_fault (any key)               -> 400
ledger_fault: key prefix                         -> 400
record_type='Decision' (case)                    -> 200 (consumers compare == "decision")
record_type='decision ' (trailing space)         -> 200 (same)
record_type=['decision'] (non-string)            -> 500  <-- see below
decision dict wrapped in a JSON ARRAY            -> 200 (not a dict; unreadable as a decision)
decision record, NOT valid JSON                  -> 400
decision record with a NUL appended              -> 200 (json.loads fails for consumers too)
key ' tool_call:' (leading space)                -> 400
```

`/audit` served rows 0 total 0 afterwards, so none of the accepted shapes reached a page.

## A8 - Refuted. GDPR path.

A1 lands here. `_write_tombstone` raises on not committed, and `erase_content` turns that into a 503 without deleting. So a tombstone that commits while the response says `committed: false` produces exactly the `erasure_conflict` P3c3c-12 says it removes.

Control first (no cut): DELETE gave 204, tombstone tx 154, re-POST 409, row gone. Then the attack:

```
##### ATTACK 7: erasure, cut only on the >=600B write frame #####
== 2. DELETE /content (the GDPR erasure) ==
DELETE -> 503 {"detail":"Tombstone write failed; erasure refused: timed out"}
== 3. is the tombstone in the ledger? ==
ledger: {"content_erasure:a8ZZCUTZZ007": {"tx": "158", "rev": "1", "call_id": "a8ZZCUTZZ007"}}
== control-plane DB ==
a8ZZCUTZZ007 -> [('a8ZZCUTZZ007', 22)]
a8control001 -> []
```

The ledger says this `call_id` was erased. The store still holds the payload. The caller was told the erasure was refused. Content writes for it are now frozen at 409, so the subject's data sits in the store, unerasable through the documented route and unwritable.

On the other two directions the brief asked about: a tombstone committed for a different `call_id` does not satisfy the check (it matches the exact key and `record_type == "content_erasure"` and the body's `call_id`), and `_has_tombstone` fails closed correctly (I confirmed this accidentally: with the verifier unreachable it returned 409, which is the documented behaviour and not a finding). The stale-version direction is real but narrow: `_tombstone_present_in_ledger` reads the head and asks only "does a tombstone exist", never "is this the one this call just wrote", so a pre-existing tombstone satisfies a later confirmation.

## A9 - Refuted. The stated scope is wider than the actual scope.

The report states the blind spots as "a rename, or a sixth module hardcoding a string". A fifth module defining a named constant is also invisible, and the completion report's own table counts that copy (`ail_view:decision:v1` | Copies: 5, while `_modules()` loads four).

The fifth copy is `tools/ail_ordering_cost_probe.py:52`: `VIEW_DECISION = "ail_view:decision:v1"`, a named constant in the same `tools/` directory as `ail_backfill_index.py`, which is compared.

```
=== BASELINE === 6 passed
=== MUTATION 1 (control): a COMPARED module drifts ===
FAILED tests/test_ledger_vocabulary.py::test_the_view_index_names_agree_everywhere
=== MUTATION 2: the FIFTH module's named constant drifts ===
52:VIEW_DECISION = "ail_view:decision:v2"
6 passed
```

## A10 - Refuted

The test can fail, and it caught the real defect when I recreated it. But it is a filename blacklist with directory prunes: it matches only `*.key` and `vault_api_token`, and it prunes site-packages, `/usr/share` and `/usr/lib`. On a machine that has run keygen, with `.dockerignore` untouched at `5bfc097`:

```
=== what the image actually carries ===
-rwxr-xr-x 1 root root 232 /app/deploy_credential.pem
-rwxr-xr-x 1 root root 232 /app/id_rsa
-rwxr-xr-x 1 root root 232 /usr/local/lib/python3.11/site-packages/leaked.key
--- head of the baked key ---
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKvgRboE7+PAeQccO2F3pl5v3+cLzvg0HnjlzCQ731JuoAoGCCqGSM49
=== does the enforcing test see any of them? ===
5 passed
```

Three live P-256 private keys in the image, test green. The static second line misses them too: it flags a `COPY` only if the line contains `keys/` or `secrets`, and `COPY decision_service/ ./` sweeping up `id_rsa` contains neither.

## The unexplained failure: reproduced, diagnosed, and demonstrated causally

It appeared on my first baseline run, one test this time:

```
FAILED tests/test_audit_ordering.py::test_a_real_page_passes_the_order_check
httpx.RemoteProtocolError: Server disconnected without sending a response.
1 failed, 36 passed in 115.96s
```

Matching the recorded shape: no server-side trace, ImmuDB healthy, `restarts=0 oomkilled=false exitcode=0`.

It is not a ledger fault. It is an HTTP keep-alive race. `tests/test_audit_ordering.py:78` holds one module-level `httpx.Client(timeout=60.0)`, so connections are pooled and reused across tests. The control plane runs uvicorn with no `--timeout-keep-alive`, so the default is 5 seconds. When a test's next request lands on a pooled connection at the moment the server is closing it as idle, the client sees the socket close instead of a response.

Sweeping the idle gap against `/health` on the same pooled client:

```
gap_s  result
4.99   0/6 RemoteProtocolError
5.0    2/6 RemoteProtocolError
5.01   0/6 RemoteProtocolError
6.0    0/6 RemoteProtocolError
```

Only at exactly 5.0s. Causation, by moving the server setting to `--timeout-keep-alive 2` and re-running the identical sweep:

```
1.99   2/6 RemoteProtocolError
2.0    0/6
4.99   0/6
5.0    0/6
```

The window moved with the setting. That accounts for every recorded property: intermittent, whichever test happens to issue a request about 5s after the previous one on that connection, nothing in the server log because closing an idle keep-alive connection is normal operation, and ImmuDB uninvolved. (My first attempt to move the setting silently did nothing, because `pkill` and `ps` are absent from that image; the container never restarted and the window stayed at 5.0s. The result above is from a Compose command override, verified with `docker inspect`.)

## Not on the list

**1. Two ordinary writes kill the entire audit page, permanently, from the write credential alone.** This is the most serious thing I found. Writing the same key twice through `/write-ordered` gives that key two index entries at two positions, and both resolve to the key's current transaction. The order check requires strictly increasing transaction with increasing position, so two positions on one transaction is a disagreement:

```
limit=1     HTTP=500
limit=5     HTTP=500
limit=200   HTTP=500
limit=2500  HTTP=500

{"error": "audit_ordering_fault", "message": "... position 1000000136.0 resolves to
 transaction 162 and position 1000000135.0 resolves to transaction 162 ...",
 "page_served": false}

top of the decision view index:
   score 1000000136 -> ledger_fault:a2479b9302be65 entry_tx 162
   score 1000000135 -> ledger_fault:a2479b9302be65 entry_tx 162
```

Both writes returned `verified: true`, `committed: true`. No corruption, no tamper, no privileged access, no direct ImmuDB reach: two well-formed calls to a documented route with the credential the decision service already holds. Unlike the previous pass's C5/C10 this needs no index injection, and it is repeatable at two writes per outage. The key does not have to be a fault key; any key re-written through the ordered route does it.

**2. A non-string `record_type` crashes the plain write route with a 500** rather than refusing with a 400. `record_type` in `_REFUSED_ON_PLAIN_WRITE` against an unhashable value:

```
verifier-1 | TypeError: unhashable type: 'list'
```

Effect is fail-closed (nothing is written), but it is an unhandled exception on a route whose whole job this phase is to refuse things deliberately.

**3. `total` and the page still describe different things**, confirmed again on a virgin ledger: rows 4, total 3. Carried from the previous pass; unchanged.

**4. Every service that mounts `./keys:/keys:ro` holds every writer's private key.** Already stated as a known D22 item in the completion pass; I note only that it is what makes finding 2 in A2 worse, since nothing on the read path checks a fault record's signature anyway.

## Environment cleanup: complete

Removed:

- Compose project `p3c3cred`: all containers, the three volumes (`test-immudb-data`, `test-verifier-state`, `test-control-plane-data`), and the network. Verified empty by `docker ps -a --filter label=...`, `docker volume ls`, `docker network ls`.
- The four images built from this run (`p3c3cred-verifier`, `-ail-control-plane`, `-decision-service`, `-anchor-service`), 8 layers.
- The cutproxy container and its image use.
- The scratch clone in full, including the generated `keys/*.key`, `keys/*.pub` and `decision_service/secrets/vault_api_token.txt`, and every probe script. Directory confirmed gone.

Could not remove: nothing. The Docker daemon stayed healthy throughout.

All source mutations were reverted in the scratch clone before teardown (`git status --short` empty at `5bfc097`). The primary working directory was never used and is untouched: `p3c3b-order` at `43bcc2e`, `git status` clean.
