# AIL v1.1.0 Backlog

Items explicitly deferred from the hardening sprints. Nothing is blocking.

---

## Blocking

Nothing is blocking. The current build is stable and production-hardened; everything below is deferred.

**Closed in Phase 3c-3b (`docs/reports/phase-3c3b.md`, ADR-0014).** `GET /audit` used to return the lexicographically-largest agent ids and call them recent, because `desc: true` walks keys and a `tool_call:` key leads with `agent_id` - so a record written seconds ago was absent once the ledger exceeded `limit` (observed during `p3c2-defer` at 211 entries, reproduced at 501 during 3c-3b). No read parameter could fix it: `scan` has no ordering option, `TxScan` is not routed over REST, and no key this project writes is temporal or monotonic. The page is now selected through a view index whose score is a position allocated under a compare-and-set the ledger enforces, committed in the same transaction as the record it indexes. The count and tombstone halves of this entry closed earlier, in Phase 3c-3a (`docs/reports/phase-3c3a.md`).

What that phase added to the deferred list rather than closing is recorded in README's Residual Limits: the CAS globally serialises the ledger write path, so concurrency stops buying throughput, and the retry budget is an availability parameter that can deny traffic if it is set too low.

**Closed in Phase 3c-3c (`docs/reports/phase-3c3c.md`, ADR-0014 D35/D36/D37).** The red-team pass against 3c-3b refuted eight of ten claims; that set is closed. What it added to the deferred list rather than closing is the entry immediately below, plus three Residual Limits entries in the README.

**Closed in Phase 3c-3d (`docs/reports/phase-3c3d.md`, ADR-0014 D38-D42).** The red-team pass against 3c-3c refuted nine of ten claims, and a key-shape probe then established that the decision taken in response, D38 as originally written, was a rename that closed nothing. That set is closed. What it added to the deferred list rather than closing is the entry below on `/write-ordered` and a key of any shape, plus two Residual Limits entries in the README.

**Closed in Phase 3c-3e (`docs/reports/phase-3c3e.md`, ADR-0014 D43-D45).** The red-team pass against 3c-3d refuted six of ten claims, and what all six had in common was one thing: a rule that has to hold at N sites, with nothing enumerating the sites. That set is closed, and the control that produced the fixes - an enumeration derived from the code, which fails until every site is covered - is now the rule rather than one test. What it added to the deferred list rather than closing is the entry below on per-test isolation, plus three Residual Limits entries in the README.

**Closed in Phase 3c-3h (`docs/reports/phase-3c3h.md`), the last sub-phase of 3c.** The red-team pass against 3c-3g returned one recursive gap, seven applications and three carried findings. The pre-committed response to a recursive gap is not another generalisation: the claim is scoped to what the tests demonstrate, the limit goes to Residual Limits, and the project shares a smaller claim. So this phase added no enumeration machinery. It narrowed the route-parity and exemption-marker claims at every site that stated them, closed `state_read`'s vocabulary with a type, made a stale property cell fail instead of vanishing, corrected two bounds and a detector's stated limit, and closed the one production defect the pass diagnosed: an ordered write whose `ExecAll` reached the wire could be reported as never having happened. What it recorded as carried rather than closing is the four entries below.

---

## Deferred (v1.1.0)

### Per-test isolation was never measured

Raised in Phase 3c-3d's order sweep and carried through 3c-3e.

The sweep ran eleven modules alone against a destroyed and rebuilt ledger and found zero hidden dependence across 118 tests, which is what bounded D44's remediation to assertion scope rather than a suite-wide rewrite of preconditions. Two residuals stand:

- **Thirty-five modules were not isolated.** Nothing in the sweep data points at them and nothing excludes them.
- **Isolation was per module, not per test.** A dependence that one test in a module satisfies for a later test in the same module is invisible to it. Per-test isolation is 442 runs, and nothing measured indicates it.

The shape of the work, when it is taken: `pytest --forked` or one process per test id, against a ledger destroyed between each, with the failing set diffed against the alphabetical baseline the way the module sweep does it.

### `/write-ordered` accepts a key of any shape into a view

Raised in Phase 3c-3d and deliberately not taken there.

D39 made both write routes refuse a `ledger_fault` record, which is what the measured injection used: a caller holding only `VERIFIER_WRITE_KEY` wrote the ledger's own account of another record's standing, and because the ordered route allocates a position, that write became a page row with `outcome_type: null` so `entries` exceeded `total`. What is not closed is the general form. The ordered route does not require the key prefix to match the requested view, so a key of some other shape written into the decision view still becomes a page row.

Why it was not closed here: requiring the match would also refuse the writes `tests/test_reconciliation.py` uses to prove the reconciler finds a record indexed into the wrong view (D37, closing red-team C6a). Those writes are deliberately mismatched, and the enforcing test for a Phase 3c-3c fix would have to be rewritten to inject into the index directly. That is a design change, and this phase's rule is to escalate rather than substitute.

The shape of the fix, when it is taken: a view contract in `verifier/main.py` pairing each view with the key prefix and `record_type` it indexes, refused at the route the way D39's refusal is, with the reconciliation tests re-expressed as direct `zAdd` injections.

### `fault_class: verifier_unreachable` covers two materially different outcomes

Raised in review of Phase 3c-3c and deliberately **not** taken as a decision in that phase. Since D35 this one closed-set class covers both:

- the verifier could not be reached, or the write did not commit, so **no ledger entry exists** (the original meaning, and the structural limit ADR-0005's Documented Boundary describes: nothing can write a durable record of "the durable-record writer is down");
- the write **committed** and its proof did not check out, so the record is in the ledger at a real transaction and position, indexed, with the counter advanced, and a `ledger_fault:` record qualifies it.

Both return `outcome_type: fault, fault_class: verifier_unreachable` and the call denies either way. **This is the same collapse D1 exists to prevent, one level down**: D1's point was that a fault is distinguishable from a denial, and here two faults with opposite consequences for the audit record are not distinguishable from each other by the field a consumer switches on.

Why it is deferred rather than fixed in 3c-3c. The distinction is cheap to *compute* - the write response already carries `committed`, and `ledger/immudb_ledger.py` would need to raise a typed exception rather than a bare `RuntimeError` for `decision_service/main.py` to map it - but the change is not a rename. It alters ADR-0005's closed set, which is D1's own artifact; it changes the Prometheus label collection that `tests/test_outcome_types.py::test_metric_label_set_matches_closed_collection` asserts, so any alert or dashboard keyed on the class changes meaning; and the right shape is genuinely open, because a call whose record committed unproven may not belong under the same `outcome_type` at all rather than merely under a second `fault_class`. That is an ADR-0005 conversation, and running it inside a remediation phase already closing eight refutations would make the least-examined part of that phase the taxonomy.

What exists in the meantime: the distinction is available to a caller in the write response's `committed` field and on the `/audit` row's `ledger_fault`, and it is stated in ADR-0005's Documented Boundary amendment and README's Residual Limits. What is collapsed is the class name.

### `COMPOSE_FILES` does not read `docker-compose.override.yml` (R7)

Raised by the Phase 3c-3f red team with a control, re-demonstrated by the 3c-3g pass, carried through 3c-3h.

`COMPOSE_FILES = ("docker-compose.yml", "docker-compose.test.yml")` at `tests/test_ledger_state_does_not_survive_teardown.py:33`. `docker compose` loads `docker-compose.override.yml` by default, so a stateful mount or an external volume declared there is never read by the module whose whole subject is that a ledger must not outlive `down -v`. There is no override file in the tree today, which is why this is a hole rather than an instance: the check reads a file set that is narrower than the one Compose actually composes.

**Reproduction:** add `docker-compose.override.yml` binding ImmuDB's data directory to a host path, or declaring a volume `external: true`, and the module stays green.

**Scope.** One line: add the override file to `COMPOSE_FILES`, guarded on existence since the file is optional, and drive it with a fixture override the way `_BOTH_SPELLINGS` drives the parse. Phase 3c-3h's prefix-with-boundary fix (P3c3h-5) changed how a target is matched and did not change which files are read.

### The intermittent CI failure is a second `committed: false` branch, still open

Found in Phase 3c-3h while collecting the CI run for the report. **Not closed by P3c3h-4, and the natural reading that it was is wrong.**

CI run `34160811148`, on `4d402a8`, `tests/test_committed_is_a_fact.py::test_a_retry_after_a_dropped_response_is_told_the_record_already_exists`:

```
AssertionError: the caller is being told a write that committed did not happen,
which is the retry D39 refuses forever:
{'tx_id': None, 'seq': None, 'verified': False, 'committed': False,
 'attempts': 1, 'error_class': None, ...,
 'detail': '<_InactiveRpcError ... StatusCode.UNAVAILABLE ...
            details = "Stream removed (Socket closed)">'}
```

**`attempts: 1` is what identifies the branch.** `write_ordered`'s bottom handler - the one P3c3h-4's flag closes - passes no `attempts`, and `OrderedWriteResponse.attempts` defaults to 0, so that body cannot have come from it. It came from the `OrderedCommitUncertain` handler with `_committed_tx_for_value` answering ABSENT, which passes `attempts=exc.attempts`. Driven in process against a stub whose ExecAll response is cut and whose record-key read then runs and answers not-found, **with the P3c3h-4 flag in place**, reproducing the CI body exactly: `committed: False, attempts: 1, tx_id: None, seq: None` and the same detail shape.

**What is established and what is not.** Established: the read ran (it did not raise, or the answer would be `null`), it answered not-found, and the test then read the key directly out of ImmuDB and found it present. Not established: why. An ImmuDB index that has not caught up with a commit that just happened would produce exactly this, and so would other things; nothing here has measured it. The Phase 3c-3g red team said it could not establish that the branch it diagnosed was what CI hit, and this is evidence that it was not.

**Why it is not covered by D45's existing reasoning.** D45 separates "the read could not run" (`null`) from "the read ran and answered" (`false`). This is a third case: the read ran, answered not-found, and was wrong. Phase 3c-3h's pre-registered negatives explicitly preserve `_committed_tx_for_value` answering ABSENT **for a key holding different bytes**, which is honest; here the key holds the same bytes and `client.get(key)` returned `None`.

**It fired a second time, on a docs-only commit, and named the transaction.** Run `34167332033`, head `6949bb1`, a different test in the same file:

```
FAILED tests/test_committed_is_a_fact.py::
       test_an_ordered_write_that_committed_is_reported_as_committed_when_its_response_is_dropped
AssertionError: the record is in the ledger at transaction 255 and the ordered
route says the write never happened:
{'tx_id': None, 'seq': None, 'verified': False, 'committed': False,
 'attempts': 1, ..., 'detail': '<_InactiveRpcError ... StatusCode.UNAVAILABLE
 ... "Stream removed (Socket closed)">'}
```

Same `attempts: 1`, same detail shape, same branch, and this one states the record's transaction. Two tests in one module are exposed to it, so the defect is in the route rather than in either fixture.

**Frequency.** Four failures in the branch's last twenty five runs, of which two are this defect and both are from 2026-09-07: `4d402a8` and `6949bb1`. The other two (`6f5f51b`, `5ed4779`, 2026-09-05) are unrelated tests. Around this phase's work: `9eca2cb` green, `4d402a8` red, `d5793e4` green, `39decad` green, `a0c2e6e` green, `6949bb1` red. The Phase 3c-3g red team ran one of the two tests six times on one host and got six passes, so a local green says very little about it.

**It fired a third time**, run `34167778194` on `a7a6d93`, same test, same body, same transaction 255. Three firings in the branch's last seven runs, all on 2026-09-07, with the greens and reds differing only by report prose. **This is why PR #14 does not close green**, and neither the merge nor the design decision under it is one this phase can make for the owner. See `docs/reports/phase-3c3h.md`.

**Scope, and why it was not taken in 3c-3h.** The phase's instruction scoped P3c3h-4 to one change, the flag, and said to escalate rather than grow it. This is a different branch, so it is escalated here rather than folded in. Taking it means deciding what a read that answers not-found immediately after an ExecAll whose response was lost actually licenses, which is a D45-level decision and not a patch: a bounded re-read, a distinct fourth state, or `null` on that branch. Whichever it is, `test_a_retry_after_a_dropped_response_is_told_the_record_already_exists` is the enforcing test and it already exists.

### `state_read` is typed at the verifier and untyped at `/audit` (F5, the other half)

Raised by the Phase 3c-3g red team, half closed in 3c-3h by P3c3h-3.

`StateRead.source` and `.status` are `Literal` now, so the verifier cannot construct a value outside the vocabulary. Nothing types the field on the way out of the control plane: `control_plane/main.py::_verification_from_200` passes `vdata.get("state_read")` through verbatim in all four branches, and `GET /audit` carries no `response_model` at all.

**Reproduction (from the red team, against a verifier response constructed by hand):** `state_read = {"source": "moon", "status": "failed", ...}` renders on the row verbatim, as do `state_read = "failed"`, `17` and `["failed"]`. No instance is reachable from this verifier's own code, which is why this is a shape hole and not a live defect: the five construction sites are all inside `_state_read` and all now typed.

**Scope.** A `response_model` on `/audit`, or a typed sibling on the row the control plane builds. The first is the bigger change and the better one, and it is a decision about `/audit`'s whole response shape rather than about this field.

### The five-constructor shape test is itself a hand-list (F8)

Raised by the Phase 3c-3g red team, carried through 3c-3h.

`tests/test_post_proof_reporting.py::test_every_constructor_of_a_verification_object_agrees_on_its_shape` builds its `built` dict by naming five constructors of the `/audit` verification object. A sixth constructor added elsewhere in `control_plane/main.py` is outside it and the test stays green. `docs/reports/r6-headstate.md` states this limit for `POST_PROOF_SITES` and does not state it for this test.

**Scope.** Either derive the constructors (which needs a selector over them, and a selector is a claim - see the route-parity scoping in README's Residual Limits for where that argument goes), or state the limit in the test's own docstring the way `POST_PROOF_SITES` and `UNDETECTED_COMPOSITIONS` state theirs. The second is one paragraph and is the R6 convention.

### `tests/test_record_profile.py` fails in one recorded collection order

Raised in Phase 3c-3g, mechanism unestablished, carried through 3c-3h.

The module passes alone and passes in CI, and fails in a recorded multi-module collection order. Nothing has established why. It is not a flake in the sense of being timing-dependent: the order reproduces it.

**Reproduction pointer:** `docs/reports/phase-3c3g.md` records the order and the failure. `docs/reports/phase-3c3d-order-sweep.md` is the instrument for this class - eleven modules run alone against a destroyed and rebuilt ledger, with the failing set diffed against the alphabetical baseline - and is the shape the diagnosis should take.

### ImmuDB TLS
ImmuDB's REST API communicates over plain HTTP on the internal Docker network (`http://immudb:8080`). Internal Docker traffic is isolated from the host, but TLS should be enforced for defence-in-depth and to satisfy stricter SOC2 transport encryption requirements.

**Scope:** Configure ImmuDB with a TLS certificate, update `IMMUDB_URL` to `https://`, add the CA to the control plane and interceptor HTTP clients.

### SQLite → PostgreSQL
The control plane uses SQLite (`/data/control_plane.db`) backed by a Docker volume. This is sufficient for a single-instance deployment but provides no HA, no WAL replication, and no connection pooling under concurrent load.

**Scope:** Add a `postgres` service to `docker-compose.yml`, update `DATABASE_URL`, replace the volume with a managed DB in production Kubernetes deployments.

---

## Low Priority (unscheduled)

### Rate Limiting on OPA Queries
The interceptor middleware has no rate limit on the OPA policy evaluation path. A compromised or runaway agent could flood the policy engine.

**Scope:** Add a token-bucket or sliding-window rate limiter in `interceptor/middleware.py` before the `query_opa_policy` call.

### Remove Stale `/policies/` Directory
An old `/policies/` directory exists alongside the canonical `/policy/` directory. It is not referenced by any active code path but adds confusion.

**Scope:** Delete `/policies/`, confirm no scripts reference it, commit.

### Single-Instance ImmuDB
ImmuDB runs as a single container with a local volume. There is no backup, no replication, and no HA. A volume failure loses the entire audit ledger.

**Scope:** For production Kubernetes, deploy ImmuDB with a persistent volume claim backed by a replicated storage class, and implement scheduled backup to object storage (S3/GCS).

### Attacker-Reachable Signing-Key Mismatch Test
`tests/test_verification.py::test_tamper_pubkey` overwrites the `_vk` attribute on an `ImmudbClient` object the test itself constructs, then confirms `verifiedGet` raises `BadSignatureError`. This proves the SDK detects a verifying-key mismatch, but the vector it exercises (patching a private attribute on an in-process object) is not reachable by an external attacker or by anything the verifier's own deployment surface exposes. It does not simulate an attack; see README section 3.4 and ADR-001's References.

**Scope:** Add a test that exercises the vector an attacker (or a misconfigured deployment) with disk access to the verifier's mounted `IMMUDB_SIGNING_PUBKEY` file could actually cause: swap the file the *running* verifier process reads its public key from (e.g. mount a different key file, or point `IMMUDB_SIGNING_PUBKEY` at a second, unrelated keypair's public half before the verifier starts), then confirm the real `/verify` HTTP endpoint on the running verifier container returns `verified: false` for an otherwise-legitimate entry, exercising the same failure through the actual deployed service rather than a hand-modified client object.

### Workload Registrar Retry Logic
The `workload-registrar` script currently runs exactly once at startup. If it executes and completes before the agent is fully attested, the `langgraph-demo` container may start with stale or missing SPIFFE identity entries, causing a race condition in local environments.

**Scope:** Update the registrar startup script to include a retry/backoff loop or a liveness probe that verifies SVID fetch succeeds before the script exits.

- SPIRE `insecure_bootstrap` and `trust_domain` (`spire/agent/agent.conf`, `spire/server/server.conf`) are documented only in an inline comment, with no project-docs claim and no test (found in the Phase 2 completion pass B config sweep, `docs/reports/phase-2-completion-b.md`).
- Vault tool round trip is ~15s (a fresh Python interpreter per call, no persistent MCP session); Envoy's route timeout was raised to 45s to accommodate it (`docs/reports/phase-2.md`).
### Every service mounts every writer's private key (D22 item)

Raised in review of the Phase 3c-3c completion pass. `./keys:/keys:ro` is mounted by `ail-control-plane`, `verifier`, `decision-service`, `anchor-service` and `immudb` in `docker-compose.yml`, so each of them holds **every** writer's private key. The services are separated only by which path their own `AIL_WRITER_SIGNING_KEY` points at, which is a configuration convention rather than a boundary.

**What this costs.** D22's stated purpose was that "a bundle's `writer_key_fingerprint` names which service wrote the record". It does not: any of those services can read `/keys/writer-decision.key` and produce a signature indistinguishable from the decision service's own. The fingerprint names a key, and the key does not name a component. That matters exactly when it would be relied on, which is after one of them is compromised: a compromised control plane can forge a record attributed to the decision service, and no check in this project distinguishes that from the real thing.

**What is unaffected.** Per-key revocation, because `tools/ail_verify_bundle.py`'s deny-list operates on key fingerprints rather than on services. And the refusal of an unsigned record.

**Scope.** Give each service a mount of only the key it is configured to use (`./keys/writer-decision.key:/keys/writer-decision.key:ro` and so on).

**`immudb` gets its own directory holding only the signing key** (decided in review of the completion pass, and the awkward part of the split). It mounts `keys/` for `--signingKey=/keys/signing.key` and has no writer key of its own, so a naive per-service split still leaves the ledger server able to read every writer key it has no use for - which is the same defect this item exists to close, moved rather than removed. A separate directory is the answer rather than a per-file mount, because `--signingKey` names a path inside a directory the server also walks, and because it makes "what may ImmuDB see" a question with a directory listing for an answer instead of a mount list to audit. The claim in `docs/adr/0012-writer-signing-and-external-anchoring.md` and `readME.md` §5 is corrected to what the mechanism actually supports in the meantime, rather than left standing until this is done.

### Corpus coupling in the mapping check

- Writing a new mapping row can retire a historical baseline entry by making a stem generic; instanced by `docs/reports/phase-1-3.md` row 16 during `p3c1-complete` (`docs/adr/0013-mapping-table-self-check.md`). The same coupling runs the other way and is easier to trip: ordinary prose added to a *cited* document can make a word distinctive that was previously absent from it, which rewrites the reason string of a historical baseline entry and fails the build on a row nobody touched. Instanced during `p3c2-defer`: one word in a new README bullet changed `docs/reports/phase-3a.md` row 8's baselined reason from one selected term to two. Resolved by rewording the new prose, not by editing the quarantine record, since the row itself had not changed (`docs/reports/phase-3c2.md`). Both directions fired again in Phase 3c-3c, three times in one phase, always resolved the same way.
- A third shape, and the one no run of the checker reports: **a row can cite a document that is itself wrong.** Class (b) asks whether a cited section contains a distinctive term from the claim, so a claim that is false and a cited section that repeats the same false thing agree perfectly and the row passes. Instanced in the Phase 3c-3c completion pass: `readME.md` §5 said a `writer_key_fingerprint` names which service wrote a record, citing `docs/adr/0012-writer-signing-and-external-anchoring.md`, which is where the claim originates and where it was equally wrong - and `readME.md` §3.4 said a proof failure produces no ledger entry, citing `docs/adr/0005-outcome-taxonomy.md`, same shape. Correcting only the citing document leaves the citation pointing at the uncorrected source, and correcting only the source leaves the citing document wrong; the checker is satisfied either way, and in both instances above it was satisfied while both documents were wrong. Nothing mechanical catches this. What it means in practice: when a phase changes behaviour, sweep for the old claim's *wording* across the corpus rather than fixing the sites a review happened to name, and fix the cited source as well as the citing row.

---

## Structural Expansions (v1.1.0+)

### ~~Phase 3: `/audit` O(n) Verification Cost~~ (closed, Phase 3c-2)
Per-entry synchronous verifier round trip on `GET /audit` was `O(min(limit, ledger))`, not O(n) against ledger size - the bound is the page size whenever the ledger is larger than it, which is the case this item was actually reporting. Confirmed to time out tests at ~200 ledger entries (`docs/reports/phase-1-3-redteam.md`). Closed by D29 (`docs/adr/0006-verification-states.md`): the default page defers verification and one record is checked on expand. `GET /audit?verify=true` still costs the full per-record scan, so the cost is opt-in rather than removed (`docs/reports/phase-3c2.md`).

### Framework Expansion (PCI-DSS, ISO 27001)
The current gateway ships with 4 baseline policy frameworks (GDPR, SOC2, FinOps, HIPAA). To expand enterprise commercial viability, the Rego policy library needs to cover additional major compliance standards.

**Scope:** Author, test, and integrate new Rego packs for PCI-DSS (targeting CDE scoping) and ISO 27001. Update the FastAPI control plane to serve these as selectable toggles in the UI.
