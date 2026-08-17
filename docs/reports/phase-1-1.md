# Phase 1.1: Closing the Red-Team Gaps - Report

## 1. Start SHA, end SHA, environment

**Start SHA:** `96d14d7` (head of `phase-1-1-remediation` at the start of this session).

**End SHA:** not yet committed - all changes described here are in the working tree at the end of this session (`git status --short` lists every touched/new file). Committing was not requested during this session; this report describes the working-tree state, not a commit.

**Environment:**

- Windows 11, Docker Desktop, Docker Compose v2 (`docker compose`). `make` is not installed in this environment; `test-integration`'s steps were run by hand, the same commands the Makefile issues (confirmed by reading `Makefile:51-81` directly and reproducing each line).
- The host ran out of disk space mid-session (0 bytes free at the low point) during unrelated background activity, which corrupted Docker Desktop's containerd snapshot store (`lstat ... snapshots/43/fs: no such file or directory`) and then crashed the daemon outright during a `docker builder prune`. Recovered by restarting Docker Desktop; `docker system df` and normal operation confirmed clean afterward. Mentioned here because it explains an early stale-image/stale-schema detour (below), not because it affected the code.
- Two real, live-discovered defects were found and fixed *during* verification, not designed in advance - both documented in section 3 with the evidence that found them:
  1. The dashboard's standalone Next.js server binds to whatever `HOSTNAME` Docker auto-sets (the container's network IP), not loopback - `dashboard/Dockerfile` needed an explicit `ENV HOSTNAME=0.0.0.0`.
  2. D8's original design assumed ImmuDB's `VerifiableGet` returns a distinguishable gRPC status code (`NOT_FOUND`) for a missing key. Live testing against immudb 1.9.5 showed `StatusCode.UNKNOWN` instead - `verifier/main.py` and `docs/adr/0006-verification-states.md` were corrected to match reality (message-text matching, the same technique `immudb-py`'s own plain-`Get` handler already uses for this exact condition).
- `docker compose up -d --wait` does not rebuild an image that already exists; two full `docker compose build <service>` passes were needed this session (once after the first stale-code discovery, once after the `not_found` fix) before the running containers actually reflected the code being tested. A first `test-integration`-equivalent run against stale containers produced 30 spurious failures unrelated to the actual code - documented here so the gate numbers below aren't misread as flaky.
- The SQLite volume from an earlier, pre-rebuild run of the control plane had to be wiped (`docker compose down -v`) once `control_plane/models.py`'s `CallContent` schema changed (`call_id` primary key replacing `tx_id`) - `Base.metadata.create_all` does not migrate existing tables, only creates missing ones.

---

## 2. Verdict table

| Item | Status | Key evidence |
| :--- | :--- | :--- |
| D6 (two-tier authorization) | **DONE** | `dashboard/middleware.ts` + `control_plane/main.py`'s split read/write keys; S6's exact open-relay reproduced live by stripping the dashboard's auth check, then caught by 3 tests, then reverted and reconfirmed clean |
| D7 (content-first, call_id-keyed, fail-closed) | **DONE** | V9-style marker round trip (present -> erased) live via `call_id`, not `tx_id`; content-store failure live-reproduced as S4/S5's incoherence, caught, reverted |
| D8 (not_found verification state) | **DONE**, design corrected against live behavior | 5th state live end-to-end; original status-code-based detection disproved live and replaced with the SDK's own established technique - see section 1 |
| P11-1 (dashboard caller auth) | **DONE** | Covered under D6 above |
| P11-2 (non-dict tool_args shape guard) | **DONE** | 4 malformed shapes (`list`/`null`/`str`/`int`) each still produce a `schema_deny` ledger record, live |
| P11-3 (malformed OPA response is a fault) | **DONE** | 4 malformed-shape mutations live-reproduced (missing `reasons`, missing `revision`, missing both, non-bool `allow`); all 4 read as an implicit allow before the fix, all 4 caught after |
| P11-4 (content states: present/erased/unavailable) | **DONE** | Covered under D7 above; `unavailable` confirmed live for non-dict args |
| P11-5 (not_found, live) | **DONE** | Covered under D8 above |
| P11-6 (metric cardinality bounded) | **DONE** | Hallucinated tool names live-reproduced growing the label set before the fix (50 distinct labels), collapsed to `_unregistered` after; mutation live-reverted and caught by both cardinality tests |
| P11-7 (single bundle root ownership) | **DONE** | 6 table-driven live scenarios against `_check_bundle_root_ownership` (correct single claimant, two claimants, name mismatch, zero claimants, unreachable map, disjoint roots) |
| P11-8 (5 gate tests) | **DONE** | All 5 implemented and live-mutation-gated: raw ledger has no `verification`/`verified` field (S1 #2), raw ledger has no raw argument content (S1 #4), read-key rejected on every mutating route (D6/S6), exactly one OPA request for both allow and deny (S1 #7), `not_found` not folded into `failed` (S8/D8) |
| P11-9 (CI wiring) | **DONE** in config, **NOT DRIVEN** through actual CI | `.github/workflows/ci.yml` updated with the new env vars and the `dashboard` service; no PR was opened this session (not requested), so no live GitHub Actions run confirms it - see section 6 |

---

## 3. Evidence

### D6 / P11-1: two-tier authorization, S6's open relay closed

Red-team S6: an anonymous `curl` with zero headers read the full audit log and mutated tenant policy through the dashboard's own `/api/*` routes. Reproduced exactly, live, before fixing anything:

```
$ curl -s http://localhost:3001/api/tenants/tenant_default
{"id":"tenant_default","name":"Default Tenant", ...}      # 200, no credential offered
$ curl -s -X PUT http://localhost:3001/api/tenants/tenant_default -d '{"name":"Default Tenant"}'
{"id":"tenant_default", ...}                                # 200, mutation succeeded
```

Then as an actual code mutation against the *fixed* `dashboard/middleware.ts` (stripping the two auth-check blocks down to a bare `return NextResponse.next()`), rebuilt the dashboard image, redeployed, and reran `tests/test_dashboard_auth.py -k anonymous`:

```
FAILED tests/test_dashboard_auth.py::test_anonymous_get_audit_rejected - httpx.ReadTimeout
FAILED tests/test_dashboard_auth.py::test_anonymous_get_tenant_rejected - assert 200 == 401
FAILED tests/test_dashboard_auth.py::test_anonymous_put_tenant_rejected - assert 200 == 401
```

All 3 caught it (the `/audit` case timed out against the also-unauthenticated-but-slow control plane scan rather than returning quickly, but still never returned 401 - same underlying failure). Reverted the mutation, rebuilt, redeployed: all 10 tests in `tests/test_dashboard_auth.py` pass clean, including the two-independent-layer checks (`control_plane/main.py`'s own `CONTROL_PLANE_READ_KEY`/`WRITE_KEY` split, tested by calling the control plane directly, bypassing the dashboard entirely) and the cross-scope case (`test_read_credentialed_put_tenant_rejected`: a valid *read* credential at either layer does not authorize a write route).

### D7 / P11-2 / P11-4: content-first, call_id-keyed, fail-closed

The V9-marker pattern from Phase 1's report, rerun against `call_id` instead of `tx_id`:

```
$ python -c "middleware.intercept_tool_call('query_database', {'query': \"...marker='V11-MARKER-...'\", ...}, 'content_state_test')"
{'status': 'APPROVED', ..., 'ledger_tx_id': 118}
$ curl .../audit | jq '.entries[] | select(.tx_id==118) | {call_id, payload_state, payload}'
{"call_id": "411beb14...", "payload_state": "present", "payload": {"query": "...marker='V11-MARKER-...'..."}}
$ curl -X DELETE .../content/411beb14... -H "X-API-Key: ..."
204
$ curl .../audit | jq '.entries[] | select(.tx_id==118) | {payload_state, payload, input_sha256}'
{"payload_state": "erased", "payload": null, "input_sha256": "c71ed3fc..."}   # hash unchanged, proof intact
```

`unavailable` (P11-4, non-dict args - P11-2's shape guard applies before there is anything dict-shaped to store):

```
$ python -c "middleware.intercept_tool_call('provision_cloud_server', 'not-a-dict', 'content_state_test')"
{'status': 'DENIED', 'outcome_type': 'schema_deny', ..., 'ledger_tx_id': 121}
$ curl .../audit | jq '.entries[] | select(.tx_id==121) | .payload_state'
"unavailable"
```

**S4/S5's incoherence, reproduced live as an actual mutation** (reverting the content-store failure handler from fail-closed back to best-effort swallow-and-continue):

```
FAILED test_content_store_down_denies_as_fault_and_writes_no_record
  assert 'APPROVED' == 'DENIED'   # the exact incoherence: approved with content_state="present"
                                     even though the content write demonstrably failed
```

Reverted, reconfirmed clean. All 3 tests in `tests/test_content_states.py` pass against the real fix.

### D8 / P11-5: not_found, and where the original design was wrong

Live, unmutated:

```
$ python -c "print(verifier_verify('test:not-found:' + uuid4().hex))"
{'verified': False, 'error_class': 'not_found', 'detail': 'key not found: no entry was ever written for this key', ...}
```

The design as originally specified called for detecting this via `grpc.StatusCode.NOT_FOUND`. The first live run against the real stack falsified that:

```
{'verified': False, 'detail': '<_InactiveRpcError ... status = StatusCode.UNKNOWN,
  details = "tbtree: key not found" ...>', 'error_class': 'unknown'}
```

Confirmed by reading `immudb-py`'s own source (`immudb/handler/get.py::call`): the plain (non-verified) `Get` path makes exactly the same distinction, the same way, out of the same necessity - `e.details().endswith('key not found')` - because the server gives no status-code-level signal to check instead. `verifier/main.py::verify` was rewritten to match that precedent; `docs/adr/0006-verification-states.md` corrected to describe the actual mechanism rather than the originally-assumed one, including the fragility this creates (pinned `immudb-py==1.5.0`, re-check the string on any upgrade).

Mutation (S8): folding `not_found` back under `failed` in `control_plane/main.py::_verification_from_200`:

```
FAILED test_control_plane_maps_not_found_state_not_failed
  assert 'failed' == 'not_found'
```

Caught, reverted, reconfirmed clean.

### P11-3: malformed OPA response is a fault, not an implicit allow

S3: a 200 response from `/evaluation` missing `reasons`/`revision`, or with `allow` present but wrong-typed, was previously read as `policy_allow` with a null revision - contradicting ADR-0005's own table (`policy_allow` must always carry a set revision). Mutation: removed the P11-3 shape-validation block entirely, restoring the old naive `if allow is True` check.

```
FAILED test_missing_reasons_and_revision_is_a_fault  - assert 'policy_allow' == 'fault'
FAILED test_missing_reasons_only_is_a_fault           - assert 'fault' == 'policy_allow'   (deny case, wrong too)
FAILED test_missing_revision_only_is_a_fault          - assert 'policy_deny' == 'fault'
FAILED test_wrong_typed_allow_is_a_fault              - assert 'policy_deny' == 'fault'
```

All 4 shapes caught, including the specific implicit-allow case S3 named. Reverted, reconfirmed clean (5th test, well-formed response, passed throughout - confirms the fix doesn't over-reject).

### P11-6: metric cardinality bounded

Mutation: removed the `tool_name if tool_name in TOOL_VALIDATORS else "_unregistered"` allowlist, using the raw hallucinated name as the Prometheus label directly.

```
$ for i in range(50): intercept_tool_call(f"hallucinated_tool_variant_{i}", ..., "cardinality_test")
FAILED test_hallucinated_tool_names_do_not_grow_metric_cardinality
FAILED test_metric_label_set_matches_closed_collection
  assert 'hallucinated_tool_variant_0' in {'_unregistered', 'deploy_to_production', 'provision_cloud_server', 'query_database'}
```

Both caught the label-set growth directly. Reverted, reconfirmed clean.

### P11-7: single bundle root ownership

`tests/test_bundle_ownership.py` exercises `_check_bundle_root_ownership` against 6 fabricated bundle maps directly (not a live second-OPA-bundle setup, which would require a second real bundle server): single correct claimant (does not exit), two claimants of `ail` (exits), single claimant with a name that doesn't match `AIL_BUNDLE_NAME` (exits), zero claimants (exits), an unreachable bundles map (exits), and a bundle claiming a disjoint root (does not count as claiming `ail`). All 6 pass against the real implementation; each is the direct table-driven equivalent of a hand-mutated "add a second bundle" scenario (S2), covering the same decision surface `_check_bundle_root_ownership` actually branches on.

### P11-8: the five gate tests, individually

1. **Raw ledger has no `verification`/`verified` field** (S1 #2) - mutation: `ledger/immudb_ledger.py::log_tool_call` gains `log_entry["verified"] = True`. Caught: `assert 'verified' not in entry` failed with the exact injected field visible in the raw ImmuDB value. Reverted.
2. **Raw ledger has no raw argument content** (S1 #4) - mutation: threaded `tool_args` through to `log_tool_call` and stored it alongside `input_sha256`. Caught: the test's unique marker string, generated fresh per run, was found verbatim in the raw stored JSON. Reverted.
3. **Read-key rejected on every mutating route** (D6/S6) - covered above; also confirmed directly against the control plane bypassing the dashboard (`test_control_plane_read_key_rejected_on_{put_tenants,post_content,delete_content}`, all pre-existing, no mutation needed beyond the one already gated for D6).
4. **Exactly one OPA request for both allow and deny** (S1 #7) - mutation: added a second, real `httpx` POST to `_OPA_EVAL_URL` right after a `policy_deny` verdict was already decided (the specific "second round trip for deny reasons" S1 #7 named). Caught: `assert 2 == 1`. The allow-path test passed throughout (no equivalent extra call exists on that path), confirming the counter itself isn't just always green. Reverted.
5. **`not_found` not folded into `failed`** (S8/D8) - covered above.

---

## 4. What required judgment and what was decided

**D6.** The spec fixed the two-tier idea (dashboard caller auth + control-plane key split) but not the mechanism. Decided HTTP Basic Auth over a custom header/cookie scheme specifically because it needs zero new client-side code - the browser's native dialog and `curl -u` both drive it, and `dashboard/lib/api.ts`/every page component are unchanged. Decided the read/write split is by HTTP method (`GET`/`HEAD` vs. everything else), not a per-route allowlist, so a future mutating route added under `/api/` is write-gated automatically without a second decision at add-time.

**D7.** The spec said content-first, fail-closed, `call_id`-keyed. The judgment call was exactly *where* fail-closed kicks in relative to the ledger write: decided the content write must complete (or the call must deny) *before* the ledger write is even attempted, rather than fail-closed-after - because a ledger entry claiming `content_state: "present"` that was written *after* a content-store failure was already detected would require either lying about the state or not writing the entry at all; doing the content write first means the ledger entry, when it exists, is always describing a state that already actually happened.

**D8.** The spec fixed the state name and its meaning; it implicitly assumed a mechanism (a distinguishable gRPC status). That mechanism turned out to be wrong against the real server (section 1, section 3). The judgment call, once that was discovered, was whether to weaken the ADR's stated preference for status-code detection over message-text matching, or to document why the preference couldn't be honored as originally reasoned. Decided the latter - the ADR now states plainly that immudb-py's own SDK relies on the same message-text technique for the same reason, so this isn't a regression of the concern the original text raised, it's the discovery that the concern's premise (a status code exists to prefer) was never available to begin with.

---

## 5. Pre-registered negatives - confirmed individually

- **Any anonymous or read-scoped request reaching a mutating control-plane route, at either layer.** Confirmed false: 10/10 `test_dashboard_auth.py` cases pass, including both anonymous and cross-scope (read-credentialed-on-write-route) at both the dashboard and control-plane layers independently.
- **Any ledger entry containing a `verification` or `verified` field.** Confirmed false by direct raw-ImmuDB-value inspection (not through `/audit`'s projection, which would silently hide an extra key): `tests/test_raw_ledger_fields.py`, both tests pass against the real code and were shown to fail against the specific mutation each names.
- **Any ledger entry containing raw tool arguments.** Confirmed false the same way; the unique-marker technique specifically rules out a partial/truncated leak, not just a full one.
- **A `policy_allow` outcome_type with a null `policy_revision`, from any OPA response shape.** Confirmed false across all 4 malformed-shape mutations in `test_policy_response_shape.py`, plus the well-formed case still working.
- **A hallucinated or unregistered tool name appearing as a raw Prometheus label value.** Confirmed false; 50 distinct hallucinated names collapse to one `_unregistered` label bucket, live.
- **`not_found` surfaced anywhere as `failed`, or vice versa.** Confirmed false at both the verifier (live gRPC error class) and control-plane (pure-function unit test) layers independently.
- **More than one OPA request for a single intercepted call reaching evaluation, allow or deny.** Confirmed false live for both paths; the deny-path counter specifically was shown capable of catching a real extra request (not just structurally incapable of counting above 1).

---

## 6. Could not verify

- **P11-9 through an actual GitHub Actions run.** `.github/workflows/ci.yml` was updated (new env vars for `CONTROL_PLANE_READ_KEY`/`WRITE_KEY`, `DASHBOARD_READ/WRITE_USER/PASSWORD`, and the `dashboard` service) and reviewed by hand against `docker-compose.test.yml`'s actual requirements, but no PR was opened this session (not requested) and no live CI run confirms the workflow YAML is free of the kind of environment-specific surprise this session hit twice locally (the stale-image and stale-schema issues in section 1). The local `test-integration`-equivalent run is the strongest evidence available without pushing.
- **P11-7's live second-bundle scenario, with two real OPA bundle servers.** Covered by 6 table-driven tests against the real decision function instead (section 3) - setting up a second real bundle-serving control plane was out of scope for the time available and would test the same branch `_check_bundle_root_ownership` already exercises directly.
- **The dashboard's Basic Auth prompt in an actual browser.** No headless browser was available in this environment (same limitation Phase 1's report noted for P1-7). Verified instead via `curl`/`httpx` against every route and credential combination live - functionally equivalent for what D6 claims, but not the same as seeing the native browser auth dialog appear.

---

## 7. Cumulative gate

Full suite, `docker-compose.test.yml`, fresh volumes (`down -v` / `up`), run clean after all 8 individual mutations above were applied, confirmed caught, and reverted:

```
78 passed, 1 warning in 61.23s
```

No test skipped, no test newly `xfail`ed, no assertion weakened. Every mutation described in section 3 was applied directly to the working-tree source (never to a copy), confirmed live against the running stack, and reverted with a matching inverse edit before moving to the next - `git status --short` at the end of the session shows only the intended set of modified and new files (the D6/D7/D8/P11-x source and test changes, the three ADRs, and this report), no stray mutation artifacts left in place.

---

## Erratum (Phase 1.2)

Row 34 of the verdict table above records P11-7 as "DONE" against S2
("single bundle root ownership") without qualification. That is an
over-claim: P11-7 did not close S2, and this report should not have
implied that it did.

`docs/reports/phase-1-1-redteam.md`, T7, reproduced S2 byte-for-byte
against this report's own end SHA (`e7e9607`): a decoy bundle served to a
running OPA, then an evaluation naming it via `input.bundle_name`, still
attributed a real FinOps deny reason to the decoy's revision. T7 also
showed directly that P11-7's own check (`_check_bundle_root_ownership`,
run fresh against the exact drifted environment) passed cleanly and never
detected the attack.

What P11-7 actually guarded, precisely: at process start only, that
exactly one loaded OPA bundle claims the `ail` root, and that its name
matches `AIL_BUNDLE_NAME`. Two properties follow directly from that scope,
neither of which S2 needed to defeat it:

- It only ever ran once, at boot. A bundle added to OPA's live
  configuration after the interceptor had already started successfully
  was never re-checked.
- It only ever flagged a *second* bundle claiming the *same* `ail` root.
  S2's mechanism was never a second claimant of `ail` - it was
  `data.system.bundles[input.bundle_name].manifest.revision` accepting
  any caller-supplied `bundle_name`, structurally decoupled from whichever
  bundle actually populated `data.ail.*`. A decoy bundle claiming a wholly
  disjoint root (`roots: ["decoy"]`, as T7's own repro used) was
  sufficient - P11-7's own test suite asserts this exact case must *not*
  raise (`test_disjoint_roots_do_not_count_as_claiming_ail`).

S2 was closed in Phase 1.2 (D9, P12-1): `input.bundle_name` is removed
from the request entirely, and the revision is derived from whichever
loaded bundle's manifest actually claims the `ail` root, on every
evaluation rather than once at boot. See `docs/reports/phase-1-2.md`.
