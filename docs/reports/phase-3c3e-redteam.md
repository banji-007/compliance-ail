# Red-team report: Phase 3c-3e, run `p3c3e-red`

**Target:** PR #14 at `bfb87fd`, branch `p3c3b-order`. Not merged, nothing
fixed. The working head was `a878e7a`, which differs from `bfb87fd` by
`docs/reports/phase-3c3e-redteam-brief.md` alone
(`git diff --stat bfb87fd a878e7a` = 1 file, 53 insertions, the brief).

**Environment:** scratch clone `C:\Users\banji\ail-p3c3e-red`, never the
primary working directory. Compose project `p3c3ered`, stated with `-p` on
every invocation. All five images built `--no-cache` at the start of the run.
Keys generated in the clone with the openssl commands `make keygen` runs,
because `make` is not on PATH here.

**Baseline:** `tests/test_route_parity.py` and `tests/test_bounded_reads.py` =
**18 passed** in-process before anything was touched.
`tests/test_image_contents.py` = **18 passed in 209.89s** against the built
images. `tests/test_committed_is_a_fact.py::test_an_ordered_write_that_committed_is_reported_as_committed_when_its_response_is_dropped`
= **1 passed** against the stack. `tests/test_view_invariants.py` =
**7 passed, 1 skipped**.

**Six of ten claims refuted: B1, B4, B5, B6, B8, B10.** B2, B3, B7 and B9 were
attacked and not refuted. The brief's own "Also" item is refuted separately
and is the single most serious finding in this report.

**The most serious finding is the Also item, and it is not a variant of
anything on the list.** `cut_until_it_lands`'s docstring says in bold that it
retries the fixture and never the assertion. The call site in
`test_an_ordered_write_that_committed_is_reported_as_committed_when_its_response_is_dropped`
puts `r[0].json().get("committed") is True` into the `landed` predicate, which
is the assertion. A4.1 was injected back into `verifier/main.py` in
intermittent form, fired verbatim on the run, and the test went green:

```
call 1: route ANSWERED committed=false tx_id=null; ledger state=present tx=8
        key=tool_call:p3c3e-ZZORDZZ:f0701c6b312c475f8f8d4c32bc8e4b5f:query_database
...
1 passed, 8 deselected in 115.71s
```

**Second most serious: this phase's subject is enumeration, and both derived
enumerations miss a real production site.** The write-route walk filters
`app.routes` on `"POST" in route.methods`, so a `PUT` write route gated by
`_require_write_key` and holding none of the four properties leaves the parity
suite at `10 passed`. The bounded-read walk is scoped to two ImmuDB REST
routes, and the verifier reads the ledger over gRPC only, so
`verifier/main.py::_committed_position_for` - a bounded read this phase itself
added, in the same decision as D45 - is not a site at all, and it reports the
score it asked for rather than the one the index returned.

---

## Verdicts

| Claim | Verdict | In one line |
| :--- | :--- | :--- |
| B1 | **Refuted, twice** | The discriminator is `POST` and the gate; a `PUT` write route is invisible. And the gate is not "writes": `POST /verify` mutates the persisted trust anchor on the read key. |
| B2 | Not refuted | No cut found where a committed write is reported `committed: false`, on either route, other than by injection. |
| B3 | Not refuted | The `require_transaction=False` narrowing is safe on the routes that exist, and it rests on a different control, which is named below. |
| B4 | **Refuted, three times** | A production bounded read the walk cannot see and which asserts nothing; four spellings of a REST call it cannot attribute; and a site marked covered with one of its two bounds undriven. |
| B5 | **Refuted** | Three shapes of a live P-256 key shipped in the real `decision-service` image at `18 passed`, and the key came back byte-identical. |
| B6 | **Refuted** | A `call_id` that fits the budget and produces a key that cannot be encoded. No fault record is written, which is A1's outcome by another route. |
| B7 | Not refuted | The writer's derivation refused every wrong number I could make it derive, and no path reaches `_write_fault_record` with an unchecked transaction. |
| B8 | **Refuted, twice** | A long-form bind mount of `/var/lib/immudb` to a host path is invisible to the parse, and `external: True` is external to Compose and not to the regex. |
| B9 | Not refuted | The guard reads the bytes and holds. It does not read the key, which is unchanged and is bounded only by the retired caller count. |
| B10 | **Refuted, twice** | There are two views and the file walks one. And the one ledger-wide invariant that seeds nothing skips instead of failing. |
| Also | **Refuted** | The fixture retry masks a real, intermittent defect. Transcript above. |

---

## Checks I established could fail before trusting them

Every attack below has a recorded control from the same session.

| Check | How I established it can fail |
| :--- | :--- |
| `tests/test_route_parity.py` | the identical handler under `POST` instead of `PUT`: `2 failed, 8 passed`, naming all four missing cells and "no driver knows how to call '/write-express'" |
| `tests/test_bounded_reads.py` derivation | it produces all four production REST reads on unmodified head, and produces none of the four injected spellings |
| `tests/test_bounded_reads.py::_drive_scan_all` | the recorded prefix driver still refuses: "refused, as recorded" |
| `tests/test_image_contents.py` | the same key as a bare PEM in the same directory: `3 failed, 15 passed`, both surfaces plus the static Dockerfile check |
| the fault write path (B6) | a 32-character `call_id` wrote `ledger_fault:00000000000000000077:c8c3623f...:31870fc4...`; a 1200-character one took the digest fallback and still wrote |
| `_write_fault_record`'s cross-check (B7) | caller tx 99999 against a ledger holding the record at 1234: refused, 0 unverified writes; and the same for absent and unknown |
| `tests/test_view_invariants.py` | the identical fractional position in the decision view: `1 failed, 6 passed, 1 skipped` naming the key |
| the `/verify` anchor probe (B1) | the same call with no credential: `403 {"detail":"Invalid API key"}`; and the anchor unchanged across four writes made straight to ImmuDB |
| the no-proof guard (B9) | bytes that are not a fault record under the same key: `RuntimeError: refusing an unverified write for a 'decision' record` |
| the relay fixture (Also) | the same injection made deterministic instead of intermittent: `1 failed`, `AssertionError: the record is in the ledger at transaction 4 and the ordered route says the write never happened` |
| the compose parse (B8) | it produces the short-form `verifier-state:/data/verifier-state` mount from the same file it produces nothing for the long-form bind mount from |

---

## B1 - Refuted, twice

### B1.1 The walk selects `POST` and the gate, so a `PUT` write route is not a site

`write_routes()` is:

```python
def _post_routes(verifier) -> list[APIRoute]:
    return [route for route in verifier.app.routes
            if isinstance(route, APIRoute) and "POST" in route.methods]

def write_routes(verifier) -> dict[str, APIRoute]:
    return {route.path: route for route in _post_routes(verifier)
            if "_require_write_key" in _gate_names(route)}
```

The phase's own mutation M1 adds `POST /write-express`. The identical handler
under `PUT` is not a `POST` route, so it never reaches the gate filter.

**Control first.** The same handler body, decorated `@app.post`:

```
$ python b1_route.py --post --target verifier/main.py
$ python -m pytest tests/test_route_parity.py -q
FAILED tests/test_route_parity.py::test_every_write_route_has_a_recorded_state_for_every_property
FAILED tests/test_route_parity.py::test_no_write_route_reaches_the_unverified_path_with_anything_but_a_fault_record
2 failed, 8 passed
```

**The attack.** One character changed, `@app.post` to `@app.put`:

```
$ python b1_route.py --put --target verifier/main.py
$ python -m pytest tests/test_route_parity.py -q
10 passed
```

The route is registered, gated, and reachable:

```
all API routes on the app object:
  ['GET']                /health          gates=[]
  ['POST']               /write           gates=['_require_write_key']
  ['POST']               /write-ordered   gates=['_require_write_key']
  ['GET']                /state           gates=['_require_read_key']
  ['POST']               /verify          gates=['_require_read_key']
  ['PUT']                /write-express   gates=['_require_write_key']
write_routes() derives: ['/write', '/write-ordered']
```

`test_the_write_routes_are_selected_by_their_gate_and_not_by_their_path` is
the test that would catch an ungated route, and it also iterates
`_post_routes`, so a `PUT`, `PATCH` or `DELETE` route is outside both halves
of the check. The docstring says the discriminator is "the dependency and not
the path or the method". It is the dependency **and** the method.

`tests/test_verifier_auth.py` and `tests/test_ordered_route_refusals.py` were
run with the `PUT` route present and did not catch it either: `6 passed, 15
skipped` (they skip without a stack, and the skipped ones test the two known
routes by name).

### B1.2 The gate is not "writes": a read-gated route mutates durable state

`POST /verify` is gated by `_require_read_key`, so it is excluded from the
matrix by construction. On its unanchored path it hands `client._rs` to the
SDK's `verifiedGet.call()`, which calls `rs.set()` on success, and then calls
`client.currentState()`. The verifier's own `GET /state` docstring says why
that matters:

> Not client.currentState(). That SDK method calls rs.set() on the way out
> [...] so asking this service what the current state is would silently
> advance its persisted trust anchor - a read that mutates the thing every
> later proof is measured against.

`POST /verify` does exactly that, deliberately, on the read key. Driven live:

```
1. one write through the verifier, so there is something to verify
    200 {'tx_id': 11, 'verified': True, 'committed': True, ...}

2. the persisted trust anchor now
    4a313069642f6aaaa088e0676f78264dd38352ec3d08738078a0e2771c87fa68  /data/verifier-state/immudb.state
    {"immudb:3322/b'defaultdb'": 11}

3. moving the ledger head WITHOUT the verifier seeing it: four writes
   straight to ImmuDB's own REST route, which the verifier is not on
    ledger head is now tx 15

4. the anchor, unchanged, because nothing asked the verifier anything
    {"immudb:3322/b'defaultdb'": 11}
    unchanged since step 2: True

5. POST /verify with the READ key only - no write credential at all
    200 {'verified': True, 'tx_id': 11, 'state_id': 15}

6. the persisted trust anchor AFTER the read
    b6f25ff5f278a2526c3c63d1ba9edcf31a46bea944256680f1d09501ea7a6cee  /data/verifier-state/immudb.state
    {"immudb:3322/b'defaultdb'": 15}

   the read-gated route changed durable state: True

7. control - no credential
    403 {"detail":"Invalid API key"}
```

That file is on the `verifier-state` named volume and is the source state
every later unanchored proof runs from. It is not a ledger record, and none of
the four properties in the matrix is about it. What the matrix asserts is
therefore "every route gated by the write key", and what its module docstring
claims is "every property this service claims about a write [...] against
every write route". Those are not the same set, and nothing in the file says
which one it means.

Worth recording beside it: `control_plane/main.py::_has_tombstone` calls
`POST /verify` on every single `POST /content`, so an ordinary content write
advances the verifier's trust anchor as a side effect of a check.

**Answering the brief's question directly.** A write reachable from outside is
covered by the matrix if and only if it is a `POST` gated by
`_require_write_key`. Two writes reachable from outside are not: any route
under another verb, and the anchor advance on `POST /verify`.

---

## B2 - Not refuted

I could not find a cut where a write committed and the response said
`committed: false`, on either route.

What I read and what it costs to get past:

- `_ordered_commit` raises `OrderedCommitUncertain` from exactly two places,
  both after `stub.ExecAll` has been called, and every earlier failure
  genuinely precedes the wire. The `precondition failed` branch is the only
  one that returns to the loop, and a precondition failure means the ExecAll
  was refused whole.
- `write_ordered`'s `except Exception` branch answers `committed: false`, and
  the only way to reach it after a commit would be for `_ordered_commit` to
  raise something other than `OrderedCommitUncertain` after the ExecAll
  returned. The two statements after `stub.ExecAll` are `int(resp.id)`, which
  is wrapped, and `_seq_cache` assignment under a lock.
- `_record_key_present` answers `False` when its read cannot run, which
  retries. After `MAX_CAS_ATTEMPTS` the loop raises a bare `RuntimeError`
  saying "the ledger write did not happen", and `write_ordered` answers
  `committed: false` for it. That sentence is true on that path: every
  attempt was refused by a precondition. I could not construct a cut that
  produces `precondition failed` on the wire while making `client.get` fail
  for the whole retry budget, which is what it would take to reach it with
  the record actually present.
- The other direction, `committed: true` for a record not in the ledger:
  `_committed_tx_for_value` compares the stored bytes to the bytes this call
  wrote, so a previous record under the key answers `absent`. Driven in
  `tests/test_route_parity.py` and it holds.

The Also section is the finding adjacent to this claim, and it is about the
test rather than the route.

---

## B3 - Not refuted

`_tombstone_present_in_ledger(call_id, tx, require_transaction=False)` accepts
any `content_erasure` record for the call_id. The report argues both answers
are safe. I attacked the argument by looking for a state where a tombstone
exists for a call_id whose current content was written after it, because that
is the case where "the ledger already says this call_id is erased" is a claim
about different content.

That state is not reachable through the documented routes.
`control_plane/main.py::write_content` refuses at 409 when
`_has_tombstone(call_id)`, and `_has_tombstone` fails **closed**: anything but
a positively identified `error_class == "not_found"` is treated as a tombstone
being present, including the verifier being unreachable. So a row can coexist
with a tombstone only when the tombstone was written by a failed erasure of
that same row, which is exactly the case the narrowing is argued for.

**Stated because it matters for whoever changes either file:** the safety of
D45's narrowing on the GDPR path rests on P13-4's 409, in a different module,
with nothing tying the two together. If `_has_tombstone` ever fails open, or
if a route is added that writes content without consulting it, the narrowing
becomes a way to complete an erasure against a tombstone from an earlier
erasure of different content. That is one rule holding at two places with
nothing enumerating them, which is this phase's own subject.

A caller holding `VERIFIER_WRITE_KEY` can write `content_erasure:{call_id}`
directly through `POST /write`, which is the one record type that route
accepts, and could pre-seed a tombstone the narrowing would later accept. That
credential is strictly stronger than the control plane's own write key and is
not the boundary this claim is about, so it is recorded and not counted.

On the retry half: a caller told `committed: null` on the ordered route and
retrying the same key gets 409 whose detail names the key and says a record is
already committed under it, or, if nothing landed, a successful write. I found
no state from which a caller can neither retry nor learn what happened.

---

## B4 - Refuted, three times

### B4.1 The derivation is scoped to two REST routes, and the verifier is gRPC

`bounded_read_sites()` produces a site only for an `ast.Call` whose **first
positional argument** is a string literal containing `/api/v2/db/scan` or
`/api/v2/db/zscan`. What it produces on unmodified head:

```
  anchor_service/main.py::collect_positions      bounds=['minScore']         line=449
  control_plane/main.py::_faults_in_tx_window    bounds=['endKey','seekKey'] line=1553
  tools/ail_backfill_index.py::indexed_keys      bounds=['minScore']         line=267
  tools/ail_backfill_index.py::scan_all          bounds=['prefix','seekKey'] line=207
  tools/ail_ordering_cost_probe.py::key_walk     bounds=['prefix']           line=186
  tools/audit_read_cost_probe.py::scan           bounds=['prefix']           line=118
  tools/immudb_ordering_probe.py::<module>       bounds=['prefix']           line=213
  tools/immudb_ordering_probe.py::<module>       bounds=['prefix']           line=114
  tools/immudb_read_api_probe.py::<module>       bounds=['prefix']           line=121

  control - the four production REST reads are all found: True
  verifier/main.py::_committed_position_for in the enumeration? False
  any verifier/main.py site at all? []
```

**Zero sites in `verifier/main.py`.** The verifier talks to ImmuDB over the
gRPC SDK, so no read it makes is at either REST route. It makes one bounded
read, and this phase added it:

```python
def _committed_position_for(client, view_set, key, attempted_seq):
    entries = client.zScan(zset=view_set, minscore=float(attempted_seq),
                           maxscore=float(attempted_seq), limit=100)
    ...
    for entry in getattr(entries, "entries", []) or []:
        member = ...
        if member == key:
            return attempted_seq
    return None
```

`minscore` and `maxscore` are selective bounds by the module's own
definition. The function never looks at `entry.score`. It returns
`attempted_seq`, which is the number it asked for, so a read that came back
outside its bound is reported as a confirmed position:

```
  asked for      : minscore=1000000042.0 maxscore=1000000042.0
  ledger answered: this key at score 1000000007.0
  function returns: 1000000042
  -> the position it reports is the one it ASKED for, not the one the index holds

  control - the same client with the key ABSENT from the answer:
  returns: None
```

Its own docstring says "the position is reported only when the index agrees".
The index agreeing that the key is somewhere is not the index agreeing that
the key is at `attempted_seq`, and the two are the same statement only while
the bound holds.

**In fairness, and stated so the finding is not read as more than it is.** The
gRPC path is less exposed to D42's exact mechanism than the REST path: a
misspelled protobuf field is a `TypeError` in the SDK rather than a silently
dropped parameter, so "the bound was not applied at HTTP 200" is a REST
failure mode. What is refuted regardless is both halves of the claim as
stated: the enumeration does not find every bounded read in the repository,
and not every bounded read asserts its bound. The module names one blind spot
and it is not this one; nothing in it says the derivation is scoped to reads
that go over REST.

### B4.2 Four spellings of a REST call the walk cannot attribute

Four new bounded reads added to `control_plane/main.py`, each posting to
`/api/v2/db/scan` with a `prefix` bound:

```python
def redteam_read_kwarg_url(client, headers):     # url as a keyword argument
    return client.post(url=f"{IMMUDB_URL}/api/v2/db/scan", json={"prefix": ...})

def redteam_read_named_url(client, headers):     # url through a local name
    endpoint = f"{IMMUDB_URL}/api/v2/db/scan"
    return client.post(endpoint, json={"prefix": ...})

def redteam_read_concat_url(client, headers):    # url by concatenation
    return client.post(IMMUDB_URL + "/api/v2/db/scan", json={"prefix": ...})

def redteam_read_named_bound(client, headers):   # literal url, bound keyed by a name
    body = {"limit": 100}
    body[_BOUND] = ...
    return client.post(f"{IMMUDB_URL}/api/v2/db/scan", json=body)
```

```
$ python -m pytest tests/test_bounded_reads.py -q
8 passed

  any redteam_read_* attributed? []
```

The first three defeat `_string_of(node.args[0])`, which returns `""` for a
`Name`, a `BinOp` or an absent positional. The fourth is the sharper one: its
URL is spelled exactly as the walk expects, and it is dropped because
`_string_of(goal.slice)` returns `""` for `body[_BOUND]`, so the site is
recognised as a call to the route and then discarded for carrying no bounds.

This form works only for a **new** read.
`test_no_entry_in_the_table_names_a_read_that_no_longer_exists` catches the
same spelling applied to an existing one, which is that test doing its job.

### B4.3 A site is marked covered when one of its two bounds is driven

`COVERAGE` is keyed by `module::function`, and the derivation records which
bounds a site carries. Nothing compares the two.
`tools/ail_backfill_index.py::scan_all` is recorded with
`bounds=('prefix', 'seekKey')` and has one driver, which answers outside the
prefix.

Driven against a client that honours `prefix` and ignores `seekKey`, which is
what a dropped paging parameter looks like on that route:

```
the derivation attributes these bounds to scan_all: ['prefix', 'seekKey']
drivers for that key: 1

after 8 seconds against a client that ignores seekKey:
  scan_all has NOT returned and has NOT refused.
  pages requested so far: 225
  each one is the same 2500 rows, accumulated into the list it returns
  the loop's exit is `len(entries) < SCAN_PAGE`, and a full page never satisfies it

control - the driver the coverage table DOES have, the prefix bound:
   refused, as recorded

bounded reads with no recorded state: []
```

225 identical pages and about 562,500 rows accumulated in eight seconds, with
no refusal and no termination. The enumeration reports the site as covered.

---

## B5 - Refuted

Two limits are stated: only the first 16 KiB of a file is read, and binary
material must start at offset zero of the file or of a base64 body. There is a
third that is not stated, and it is the one that ships a key.

`key_material()` looks for PEM **armour** in the raw head only. A base64 body
is decoded and then offered to `_binary_key_material` alone, so base64 of a
PEM decodes to PEM text, fails the DER prefix test, and is not key material to
it. That is how a Kubernetes Secret, a Helm value, a JSON config and a `.env`
line all carry a key.

Measured against the detector, with the module's own enumerated shapes as
controls:

```
=== control: the shapes the module enumerates ===
  bare PEM                                             DETECTED as pem
  bare DER (sec1)                                      DETECTED as sec1-der
  base64 of DER, no armour                             DETECTED as base64-sec1-der

=== 1. a key inside an archive ===
  PEM inside an uncompressed .tar                      DETECTED as base64-sec1-der   recovered == original: True
  PEM inside a .gz                                     NOT DETECTED   recovered == original: True
  PEM inside a .zip (stored, deflated)                 DETECTED as base64-sec1-der   recovered == original: True

=== 2. base64 of a PEM, which is how a secret manifest carries one ===
  raw base64 of the PEM text                           NOT DETECTED   recovered == original: True
  a Kubernetes Secret manifest carrying it             NOT DETECTED   recovered == original: True
  a .env line carrying it                              NOT DETECTED   recovered == original: True

=== 3. past the two stated bounds ===
  PEM after 16 KiB of padding                          NOT DETECTED
  DER after one leading NUL byte                       NOT DETECTED

=== 4. the undocumented cap: only the first 20 base64 runs ===
  base64 DER behind 21 decoy base64 runs               NOT DETECTED
    control: the same behind 19 decoys                 DETECTED as base64-sec1-der
```

Recorded honestly: the tar and zip cases are **caught**, and not by the
archive being understood. The PEM's own base64 body survives inside the
archive and the `_B64RUN` rule decodes it to DER. The detector is stronger
there than I expected it to be. Gzip is not caught, because compression
destroys the body.

The 20-run cap is not in the module docstring beside the other two limits.
`_B64RUN.findall(head)[:20]` is where it lives.

### The key that ships

`keys/writer-decision.key`, the live signing key this stack is running with,
placed where `COPY decision_service/ ./` reaches, in three shapes:

```
=== 0. baseline: the image check on the unmodified image ===
     18 passed in 209.89s (0:03:29)

=== 1. ATTACK: three shapes of the same live key, shipped ===
   wrote decision_service/writer.b64  (312 bytes)
   wrote decision_service/backup.tar.gz  (215 bytes)
   wrote decision_service/notes.md  (16633 bytes)
   image rebuilt
     18 passed in 185.69s (0:03:05)

=== 2. and the key comes back out ===
   recovered 232 bytes from /app/writer.b64 inside the image
   byte-identical to keys/writer-decision.key: True
   first line: -----BEGIN EC PRIVATE KEY-----

=== 3. CONTROL: the same key as a bare PEM in the same directory ===
   wrote decision_service/leaked_credential.pem  (232 bytes)
   image rebuilt
     FAILED ...test_no_image_built_from_the_repository_root_carries_key_material[decision-service-every-layer-in-docker-save]
     FAILED ...test_no_image_built_from_the_repository_root_carries_key_material[decision-service-running-filesystem]
     FAILED ...test_no_dockerfile_copies_key_material
     3 failed, 15 passed in 182.64s (0:03:02)

=== 4. cleaning up ===
   image rebuilt
     18 passed in 223.40s (0:03:43)
```

`docker run --rm --entrypoint cat p3c3ered-decision-service /app/writer.b64`
piped through `base64 -d` is the whole recovery. The static Dockerfile check
does not see it either: it looks for `*.pem` and `*.key` by name, and
`writer.b64`, `backup.tar.gz` and `notes.md` are none of those.

**The surface half of B5 is not refuted.** I did not find a third surface. The
image config blob is skipped by `_every_layer` as metadata, so a key in `ENV`
or `LABEL` would be on neither surface, but no Dockerfile here puts one there
and I did not build the case; it is in Could not test below.

---

## B6 - Refuted

The budget arithmetic itself is exact:

```
FAULT_KEY_PREFIX       ledger_fault: 13
FAULT_KEY_TX_PAD       20
FAULT_KEY_FIXED_BYTES  51
MAX_LEDGER_KEY_BYTES   1023
MAX_FAULT_IDENTITY     972

  call_id  971 -> identity call_id  key 1022 bytes
  call_id  972 -> identity call_id  key 1023 bytes
  call_id  973 -> identity digest   key   87 bytes
```

The defect is not the length. Both length checks measure with
`errors="replace"`:

```python
if len(identity.encode("utf-8", "replace")) <= MAX_FAULT_IDENTITY_BYTES:
...
encoded = len(key.encode("utf-8", "replace"))
if encoded > MAX_LEDGER_KEY_BYTES:
```

and the write is `_set_without_verification(client, key.encode(), raw)`, plain
`encode`, strict. A lone surrogate is one character to both checks and
unencodable at the write. `{"call_id": "\ud800..."}` is well-formed JSON,
valid UTF-8 on the wire, and `json.loads` returns a `str` carrying the lone
surrogate, so it is caller-supplied input that reaches the key.

Driven through the real `POST /write` route function against a client whose
proof fails, which is the condition a fault record exists for:

```
=== control: an ordinary 32-character call_id ===
    committed        : True   tx_id: 77
    fault_record     : ledger_fault:00000000000000000077:c8c3623f1306457e92beb49720b7fd39:31870fc47d424464
    fault_record_err : None
    unverified writes the route actually made: 1

=== control: a 1200-character call_id, which P3c3e-6 closed ===
    committed        : True   tx_id: 77
    fault_record     : ledger_fault:00000000000000000077:key:954bb1f05c5cb0fd0808ba72b9a7ddb0:e488e9be937a4d34
    fault_record_err : None
    unverified writes the route actually made: 1

=== ATTACK: 300 lone surrogates - 300 bytes to both length checks ===
    committed        : True   tx_id: 77
    fault_record     : None
    fault_record_err : UnicodeEncodeError: 'utf-8' codec can't encode characters in position 34-333: surrogates not allowed
    unverified writes the route actually made: 0

    P3c3e-6 says a key that cannot be written raises at construction.
    _fault_key ACCEPTED the key (no raise at construction)
```

The record is committed, its proof failed, and nothing durable records why.
`/audit` shows it with `ledger_fault: null`, selected by the caller by
choosing its own `call_id`. That is A1's outcome, reached past the budget
rather than through it.

**What still holds, and it is the half worth keeping.** The failure is loud.
`fault_record_error` carries the exception and `detail` carries the sentence
`_fault_failure_detail` adds, so a caller that logs anything logs it. What is
refuted is the placement claim: "a key that cannot be written raises there
rather than at the ledger" is false for this class, and the digest fallback,
which exists precisely so an unusable `call_id` does not cost the fault
record, is never reached because the identity was never judged unusable.

---

## B7 - Not refuted

I could not make the writer derive a wrong transaction, and I found no path to
`_write_fault_record` with a transaction nothing checked. Both call sites pass
a real `tx_id`, and `if tx_id is not None and int(tx_id) != derived_tx` is
reached on both.

The cross-check fires in all three directions:

```
  caller tx agrees with the ledger (control)   -> key=ledger_fault:00000000000000001234:c1:62c56f6809f5440b
                                                  unverified writes made: 1
  caller tx 99999, ledger holds it at 1234     -> key=None
    err=this write reported transaction 99999 and the ledger holds these bytes at 1234...
                                                  unverified writes made: 0
  ledger holds different bytes under the key   -> key=None
    err=the record this fault would qualify is absent in the ledger...
                                                  unverified writes made: 0
  the read-back cannot run                     -> key=None
    err=the record this fault would qualify is unknown in the ledger...
                                                  unverified writes made: 0
```

The derivation reads the latest version under the key, so a concurrent write
of the same key between the commit and the read-back produces a disagreement
rather than a wrong key, and the disagreement refuses. That refusal costs the
fault record, and it is reported, so it lands in the same place B6 does rather
than being a separate finding.

---

## B8 - Refuted, twice

The asserted half of P3c3e-8 is `tests/test_ledger_state_does_not_survive_teardown.py`,
which parses both compose files with a small reader. Two shapes Docker Compose
accepts are invisible to it. Compose resolving both, so these are not
hypothetical spellings:

```yaml
services:
  immudb:
    image: busybox
    volumes:
      - type: bind
        source: ./ledger-on-the-host
        target: /var/lib/immudb
  verifier:
    image: busybox
    volumes:
      - verifier-state:/data/verifier-state
volumes:
  verifier-state:
    external: True
```

```
$ docker compose -p p3c3eredb8 config
  immudb:
    volumes:
      - type: bind
        source: C:\...\b8\ledger-on-the-host
        target: /var/lib/immudb
...
volumes:
  verifier-state:
    name: verifier-state
    external: true
```

The same file through the project's own parse:

```
mounts the parse produced: [('immudb', 'type', ' bind'), ('verifier', 'verifier-state', '/data/verifier-state')]
volumes the parse produced: {'verifier-state': 'external: True\n'}
stateful mounts it will examine: [('verifier', 'verifier-state', '/data/verifier-state')]
external volumes it will report: []
```

1. **The long-form mount.** `spec.split(":")` on `- type: bind` yields
   `("type", " bind")`, so ImmuDB's data directory bound to a host path
   becomes a mount named `type` at target `" bind"`, which is not in
   `STATEFUL_CONTAINER_PATHS` and is skipped. A host path survives `down -v`
   entirely, which is the exact thing the test exists to exclude.
   `assert covered` does not save it: it needs only one stateful short-form
   mount to remain, which is the realistic case where one service is changed
   and the others are not, and the transcript above is that case.

2. **`external: True`.** `re.search(r"external:\s*true", body)` is
   case-sensitive. Compose parses YAML, where `True` is the boolean, and
   resolves it to `external: true`. A ledger written into an external volume
   survives every teardown this project performs.

Two more things the check cannot see, recorded without a demonstration:
`COMPOSE_FILES` is itself hand-listed and does not include
`docker-compose.override.yml`, which `docker compose` loads by default when
present; and `STATEFUL_CONTAINER_PATHS` is an exact-match hand list, so a
service pointed at any other container path is skipped rather than reported.

**The second half of B8 I could not refute.** I found no route by which the
count on a page row exceeds the faults that exist. The legacy read is gone,
`_page_faults` takes no `legacy` argument, and the getall asks for
`content_erasure:{call_id}` and nothing else.

---

## B9 - Not refuted, and its blast radius composes with B1

The guard holds on the bytes and fires on a non-fault record. It does not read
the key, which is unchanged from the previous pass:

```
the guard reads the bytes. It does not read the key.

  ACCEPTED  key=b'ail_seq:commit'                    tx=4242
  ACCEPTED  key=b'ail_seq:reserve'                   tx=4242
  ACCEPTED  key=b'ail_view:decision:v1'              tx=4242
  ACCEPTED  key=b'tool_call:victim:1:query_database' tx=4242

control - the same key with bytes that are not a fault record:
  refused   RuntimeError: refusing an unverified write for a 'decision' record
```

The brief excludes the caller count from being reported, so this is recorded
rather than counted: a well-formed fault record under the sequence counter's
key is still writable, and it costs exactly one call to
`_set_without_verification`.

What is new is where the assertion that would catch it lives.
`test_no_write_route_reaches_the_unverified_path_with_anything_but_a_fault_record`
asserts `written_key.startswith(b"ledger_fault:")`, and it iterates
`sorted(write_routes(verifier))`. A route under a verb the walk does not read
(B1.1) reaches `_set_without_verification` with any key it likes and is
outside that assertion, so the one control that does look at the key is
scoped to the same incomplete site list.

---

## B10 - Refuted, twice

### B10.1 There are two views and the file walks one

`tests/test_view_invariants.py` hard-codes
`VIEW_DECISION = "ail_view:decision:v1"` and walks nothing else. The intent
view is written by `verifier/main.py::_VIEW_SETS`, read by `/audit` through
`control_plane/main.py::_zscan_view(client, token, _VIEW_INTENT, scan_limit)`,
walked by the reconciler and by the backfill, and **already enumerated by this
suite**: `tests/test_ledger_vocabulary.py::test_the_view_index_names_agree_everywhere`
compares the intent view's set name across five modules. So the site list was
derivable and is derived elsewhere in the same directory.

The same violation into each view in turn. A fractional position above the
reserve is
`test_every_allocated_position_is_an_integer_or_a_registered_violation`'s
whole subject, and neither key is named by any entry in
`tests/ledger_pollution.py`:

```
=== 0. baseline: the ledger-wide invariants on a clean stack ===
     7 passed, 1 skipped in 12.36s

=== 1. ATTACK: the violation in the INTENT view ===
   injected  tool_call_intent:p3c3e-red-intent:42465326ce314041ac3d2da6d828cc59:query_database
   at        1000000000.5 in ail_view:intent:v1
     7 passed, 1 skipped in 12.32s

=== 2. CONTROL: the identical violation in the DECISION view ===
   injected  tool_call:p3c3e-red-decision:0127680efa324012b9f4448f5078ad20:query_database
   at        1000000000.5 in ail_view:decision:v1
     E  AssertionError: position(s) above the reserve that are not integers and are not
        registered in tests/ledger_pollution.py: [('tool_call:p3c3e-red-decision:...
     FAILED tests/test_view_invariants.py::test_every_allocated_position_is_an_integer_or_a_registered_violation
     1 failed, 6 passed, 1 skipped in 13.22s
```

The attack ran before the control on purpose: ImmuDB's zset has no remove, so
the control poisons the decision view for the stack's lifetime. The stack was
torn down with `-v` and brought back up afterwards, and the report's later
runs are against that clean ledger.

All four ledger-wide invariants have this shape. Every one of them is
unenforced on `ail_view:intent:v1`, which is half the rows `/audit` pages.

### B10.2 The one invariant that seeds nothing skips instead of failing

Note the `1 skipped` in every run above:

```
$ python -m pytest tests/test_view_invariants.py -q -rs
SKIPPED [1] tests\test_view_invariants.py:253: this ledger has no records on one side of the seam yet
```

`test_the_seam_between_history_and_allocation_holds` is the only one of the
four that does not call `_seed_one_decision()`. It calls `pytest.skip` when
either side of the seam is empty. The phase's own report says the guard "a
check over zero rows asserts nothing" is what caught D44's defect in the file
enforcing D44, and that each test "seeds one ordered write now". This one does
not; it skips.

Whether it runs at all therefore depends on whether some other module has
written rows inside the reserve first, which is `tests/test_backfill_index.py`
and `tests/test_reconciliation.py`, both of which sort before
`test_view_invariants.py` alphabetically and after it in reverse. **The order
sweep's method cannot see this**, because it diffs failing sets and a skip is
never in one. The report's claim that the four scoped tests "appear in none of
the four failing sets" is true of this one for a reason the method does not
distinguish from passing.

### The registry, attacked directly and not refuted, with one thing recorded

`explains()` is a substring match on `key_fragment`, and
`test_the_registered_violations_are_the_only_exemptions_in_use` computes
`breaks_something` as `any(...)` over all rows matching a fragment, not per
row. So an ordinary row whose key contains `p3c3c-pad` is exempted from
`HISTORY_SCORE_IS_ITS_TRANSACTION` and the "only exemptions in use" test
passes, because the genuine pad rows satisfy the `any`. The fragments sit in
the agent-id segment, which is caller-controlled.

I did not drive this, because doing so requires writing a key of a chosen
shape into a view, and the brief excludes "`/write-ordered` still accepts a
key of any shape" from being reported. It is recorded as a composition rather
than as a finding: the standing residual limit plus substring matching plus
`any` means a row can mark itself exempt from a ledger-wide invariant.

---

## Also - Refuted. The fixture retry masks a real defect

`cut_until_it_lands`'s docstring:

> **This retries the FIXTURE, never the assertion.** Every test below draws a
> distinction its own message states: a write that reached the ledger and was
> misreported is the defect under test, and a write that never reached the
> ledger means the relay cut too early and the test exercised nothing.

The call site in
`test_an_ordered_write_that_committed_is_reported_as_committed_when_its_response_is_dropped`:

```python
key, (response, log), _tries = cut_until_it_lands(
    _build, _drive,
    lambda k, r: "dropping the" in r[1] and k in _getall(headers, [k])
    and r[0].json().get("committed") is True)
```

and then, twenty lines later:

```python
assert body["committed"] is True, (
    f"the record is in the ledger at transaction {ledger_tx} and the "
    f"ordered route says the write never happened: {body}")
```

The third conjunct of the retry predicate is the assertion. The comment above
it defends `committed: null` as a fixture condition, which it is, and `is True`
excludes `null` **and** `false`. `false` is the defect.

### Driven

A4.1 injected back into `verifier/main.py`, intermittently: the first time the
ordered route establishes that an uncertain write is PRESENT in the ledger it
answers the pre-D45 shape, and every time after that it tells the truth. The
counter lives on the `verifier-state` volume because the relay fixture
recreates the verifier container on every attempt.

**Control first: the same injection made deterministic.**

```
$ python -m pytest tests/test_committed_is_a_fact.py -q -k ordered_write_that_committed
E  AssertionError: the record is in the ledger at transaction 4 and the ordered
   route says the write never happened: {'tx_id': None, 'seq': None,
   'verified': False, 'committed': False, 'attempts': 1, ...}
1 failed, 8 deselected in 144.96s
```

So the test can fail, and it fails with exactly the message it was written to
produce.

**The attack: the same lie, once per run.**

```
$ python -m pytest tests/test_committed_is_a_fact.py -q -k ordered_write_that_committed
.                                                                        [100%]
1 passed, 8 deselected in 115.71s

=== durable transcript, written by the route itself ===
PRESENT-branch calls in this run:
2
what the route answered on the lying call:
call 1: route ANSWERED committed=false tx_id=null; ledger state=present tx=8
        key=tool_call:p3c3e-ZZORDZZ:f0701c6b312c475f8f8d4c32bc8e4b5f:query_database
```

Attempt one produced A4.1 verbatim: a record present in the ledger at
transaction 8, reported as `committed: false, tx_id: null`, which is the exact
shape `ledger/immudb_ledger.py` reads as "the write did not happen" and the
shape that produced the unerasable subject record on the GDPR path. The
predicate read `committed is True`, called it a miss, and drove the whole
write again. Attempt two behaved. The suite is green.

**Reverted and rebuilt: `1 passed` on the unmodified route.**

The fix the phase already found is the same one this needs. Section 19 of
`phase-3c3e.md` argues, correctly, that `is not False` is the claim and
`is True` was narrower than the property. That correction was applied to the
assertion in
`test_a_retry_after_a_dropped_response_is_told_the_record_already_exists` and
not to the retry predicate here, where the same over-narrow condition does not
fail loudly but swallows the defect.

---

## Not on the list

1. **`tests/test_view_invariants.py::_view_rows` is itself a bounded read that
   asserts nothing.** It pages the decision view with `minScore` and never
   checks that a returned row is at or above the score it asked for.
   `bounded_read_sites()` skips `tests/` by construction, and this read is
   what decides how many rows all four ledger-wide invariants see. A dropped
   bound there does not hang (the `seen` set breaks the loop) but it can
   under-read, and an invariant over fewer rows than it thinks is the
   condition D44 exists for.

2. **`GET /health` is gated by neither key.**
   `test_the_write_routes_are_selected_by_their_gate_and_not_by_their_path`
   asserts that every POST route declares which gate it takes; nothing asserts
   it for the GET routes, and `/health` takes neither. That is almost
   certainly intentional and it is not asserted anywhere, so a second ungated
   GET would be indistinguishable from it.

3. **The static Dockerfile check matches key material by filename.** With the
   three B5 shapes in `decision_service/`, `test_no_dockerfile_copies_key_material`
   passed; with `leaked_credential.pem` it failed. It is a name check standing
   behind a content check, which is fine as a second line and is worth saying
   because the module docstring's argument for the content check is that name
   matching was what the previous red team got past.

---

## Could not test

1. **A third inspection surface.** The image config blob is skipped by
   `_every_layer` as metadata, so a key placed in `ENV`, `ARG` or `LABEL`
   would be on neither surface and would be readable with
   `docker inspect` / `docker history`. No Dockerfile here does that and I did
   not build the case, so it is a reading of the code and not a result.

2. **B2's remaining cut.** Reaching `write_ordered`'s generic
   `committed: false` with the record actually present requires `ExecAll` to
   answer `precondition failed` while `client.get` fails for the whole retry
   budget. The relay fixture cuts on frames and not on RPC method, so I could
   not aim it at `Get` while leaving `ExecAll` answering.

3. **The two recorded flakes.** Neither
   `test_a_write_that_committed_is_reported_as_committed_when_the_state_call_fails`
   nor `test_the_sequence_is_gapless_under_concurrent_writes` was run enough
   times here to turn into a reproducible defect. Time went to the
   enumerations instead.

4. **A full-suite order sweep.** I ran no permutation of the whole suite. B10.2
   is a reading of the skip condition plus the observed `1 skipped` on a clean
   ledger, not a measured order flip. Finding a fifth order-dependent test was
   not attempted.

5. **Live end-to-end for B6.** The surrogate `call_id` was driven through the
   real `POST /write` route function against a stub client, which is the
   technique `tests/test_route_parity.py` uses and argues for. It was not
   driven through the container under a live corrupt anchor.

---

## What I could not remove from the machine

Everything this run created was removed. Enumerated with the commands.

Removed at the end of the session:

- Compose project `p3c3ered`: all seven containers, the three volumes and the
  network, with
  `docker compose -p p3c3ered -f docker-compose.test.yml down -v`.
- The five images built `--no-cache`: `p3c3ered-verifier`,
  `p3c3ered-ail-control-plane`, `p3c3ered-decision-service`,
  `p3c3ered-anchor-service`, `p3c3ered-dashboard`.
- The relay containers the fixture starts per test
  (`p3c3ered-p3c3d-cutproxy`, `p3c3ered-p3c3e-cutresponse`,
  `p3c3ered-p3c3e-blackhole`, `p3c3ered-p3c3e-droprequest`).
- The throwaway Compose project `p3c3eredb8`, which was only ever
  `docker compose config` and never brought up.
- Every probe, injection and patch script, written to the session scratchpad
  and never into the tree, so none could be committed by accident. The key
  material this run produced outside the tree went with them: the three B5
  shapes of `keys/writer-decision.key` and the in-process P-256 keys the
  detector probes generated.
- The scratch clone in full, including the generated `keys/*.key`,
  `keys/*.pub`, `decision_service/secrets/vault_api_token.txt` and the `.env`
  written for it from CI's own test values.

Verified empty afterwards, each filtered on the project name:

```
$ docker ps -a  --format '{{.Names}}'      | grep -i p3c3ered  ->  (nothing)
$ docker images --format '{{.Repository}}' | grep -i p3c3ered  ->  (nothing)
$ docker volume ls --format '{{.Name}}'    | grep -i p3c3ered  ->  (nothing)
$ docker network ls --format '{{.Name}}'   | grep -i p3c3ered  ->  (nothing)
```

**Could not remove: nothing of this run.** Left as found, and belonging to
earlier runs rather than this one: the `ail-scratch_*` and `compliance-ail_*`
volumes.

Every injection into the tree was reverted from a byte-for-byte copy taken
before it, and `git status --short` was empty apart from the untracked `.env`,
`keys/` and `decision_service/secrets/`, none of which is tracked. The stack
was rebuilt clean after each mutation and the affected test re-run: the relay
test at `1 passed`, the parity suite at `10 passed`, the bounded-read suite at
`8 passed`, the image suite at `18 passed`.

The primary working directory was never used for a stack. Nothing was written
there by this run.
