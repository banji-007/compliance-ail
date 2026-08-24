# Phase 3a completion pass

**Run id:** `p3a-complete`.

**Working directory:** `.claude/worktrees/agent-a582614fcd7624bfe`, a persistent
git worktree on this host, not the primary working directory. Branch
`phase-3a-evidence-bundle`, same branch and same PR (#9) as Phase 3a itself.

**Base:** `f1fe9ee58865a072b2ad15b60e32f2a3fa0f3df9`, the head of
`phase-3a-evidence-bundle` at the time this pass started - the exact commit
`docs/reports/phase-3a-redteam.md` audited. The four findings this pass closes
(X5/X6 REFUTED, X8's mapping gap, X8's own three reproduced prior attacks) are
that report's.

**Docker:** every invocation carried an explicit `-p` project name -
`p3a-complete` for `docker-compose.test.yml` (the live pytest suite, P3a-7's
mutation, and the missing-env-var checks that need no stack), `p3a10-deploy`
for `docker-compose.yml` (P3a-10's live topology demonstration). Keys
(`keys/signing.key`/`.pub`, `decision_service/secrets/vault_api_token.txt`)
already existed in this worktree from Phase 3a's own work session and were
reused, not regenerated (idempotent per the Makefile's own `keygen` target).
`make` is not installed on this host; the two builds it would drive
(`docker compose ... build`) were run directly.

**Developer-state confirmation:** both compose projects torn down
(`down -v`), confirmed via `docker compose -p p3a-complete -f
docker-compose.test.yml ps` and `docker compose -p p3a10-deploy -f
docker-compose.yml ps` returning empty container lists. All nine images built
this session (`p3a-complete-ail-control-plane`, `-dashboard`,
`-decision-service`, `-verifier`, and the same four for `p3a10-deploy` plus
`p3a10-deploy-langgraph-demo`) removed via `docker rmi`, confirmed via `docker
images | grep -E "p3a-complete|p3a10-deploy"` returning nothing. No scratch
clone was made - this pass worked directly in the existing worktree, which
already satisfies "not the primary working directory"; nothing was created
there to remove. Primary working directory (`c:\Users\banji\OneDrive\Documents\compliance-ail`)
untouched throughout: `git status --short` unchanged from session start,
`HEAD` unchanged at `6dd56b6`, branch unchanged (`main`).

---

## 1. P3a-7. Export authorization is actually exactly the read credential

**Verdict: met.**

`verifier/main.py`'s `/verify` now requires `VERIFIER_READ_KEY`; `/write` now
requires `VERIFIER_WRITE_KEY` - independent secrets from
`CONTROL_PLANE_READ_KEY`/`WRITE_KEY`, the same two-tier shape
`docs/adr/0007-two-tier-authorization.md` established for the control plane,
applied a third time. `docs/adr/0011-verifier-authentication.md` records D21
in full, including why the two Phase 1.3 deferral conditions no longer hold.

### Demonstration

Live, against the `p3a-complete` stack, reproducing red-team X5 verbatim
(`tests/test_verifier_auth.py`, run as part of the full suite, section 3
below):

```
test_x5_unauthenticated_verify_now_refused    PASSED   (422, no header)
test_x5_read_credentialed_verify_still_succeeds  PASSED (200, real result)
test_x5_write_credentialed_verify_refused     PASSED   (403, cross-tier)
test_write_accepted_with_write_key            PASSED   (200, real write)
```

The missing-env-var-yields-503 check is demonstrated in-process rather than
by restarting the live stack with an unset variable: `test_missing_read_key_
env_var_yields_503` and `test_missing_write_key_env_var_yields_503` monkeypatch
the module-level key constants `_require_read_key`/`_require_write_key`
actually read at request time and call the dependency functions directly -
the same code path FastAPI's own dependency injection calls, and the same
in-process pattern this project already established for
`control_plane/main.py`'s identically-shaped `_require_read_key` (`tests/
test_control_plane_auth.py`, referenced in ADR-0007's own changelog). Both
passed: `HTTPException(status_code=503)`.

**Escalation check (per the instruction's own standing rule):** confirmed
live that no code path in the agent container writes to the verifier
directly. `docker exec p3a10-deploy-langgraph-demo-1 env | grep -iE
"VERIFIER|CONTROL_PLANE"` returned nothing - the agent holds neither
credential family at all, live, not merely by static inspection. See section
4 for the full P3a-10 demonstration this same container was used for. Nothing
to escalate.

### Enforcing test

`tests/test_verifier_auth.py`, 15 tests, all passed live in the full-suite
run (section 3): unauthenticated refusal on both endpoints
(`test_verify_rejected_with_no_key`, `test_write_rejected_with_no_key`),
cross-tier refusal both directions (`test_x5_write_credentialed_verify_
refused`, `test_write_rejected_with_read_key`), the missing-env-var 503
(above), a negative control confirming a *configured* key still discriminates
right from wrong rather than failing open or closed indiscriminately
(`test_configured_read_key_rejects_wrong_value_not_503`), and the
provisioning claim checked statically against `docker-compose.yml`
(`test_agent_container_provisioned_with_neither_verifier_key`,
`test_backend_services_hold_exactly_the_verifier_keys_their_code_uses`,
parametrized over `ail-control-plane`/`decision-service`).

### Mutation

Removed `_: None = Depends(_require_read_key)` from `verify()` in
`verifier/main.py`, rebuilt `--no-cache`, restarted under `-p p3a-complete`:

```
$ python -m pytest tests/test_verifier_auth.py -v
FAILED tests/test_verifier_auth.py::test_x5_unauthenticated_verify_now_refused
FAILED tests/test_verifier_auth.py::test_x5_write_credentialed_verify_refused
FAILED tests/test_verifier_auth.py::test_verify_rejected_with_no_key
FAILED tests/test_verifier_auth.py::test_verify_rejected_with_wrong_key
4 failed, 11 passed in 33.95s
```

Exactly the four tests whose claim depends on `/verify`'s own dependency
failed - the eleven testing `/write`, the missing-env-var 503s (which patch
the module constant directly rather than depend on the live route), and the
provisioning checks were correctly unaffected. Reverted (`cp` from an
in-memory backup), rebuilt `--no-cache`, confirmed `git diff --stat --
verifier/main.py` matched the pre-mutation 56-line diff exactly, and the
full 15-test file green again.

---

## 2. P3a-8. The erasure boundary is stated

**Verdict: met.**

Added to `docs/adr/0010-portable-evidence-bundles.md`'s Consequences section
and to `readME.md`'s Residual Limits: a bundle sits outside the erasure
mechanism, in both directions. `record.value` is the ledger entry itself -
`input_sha256` and decision metadata, never the raw arguments the erasable
content store holds separately - so a bundle exported while content is
present already carries nothing erasure would need to remove; and
`DELETE /content/{call_id}` has no bundle to reach into, so a bundle already
exported for that record is unaffected by a later erasure.

### Criterion

"The statement exists and is accurate in both directions. A reader must not
conclude either that bundles leak payloads or that erasure reaches them."

Both bullets state both directions explicitly and end on the same
disambiguating sentence: "a bundle does not leak erasable content, and
erasing content does not un-verify or alter a bundle already handed out."
This was substance red-team X6 had already live-confirmed (a bundle exported
before and after an erasure, for the same `ledger_key`, byte-identical) -
this pass adds the documentation, not new mechanism, matching the finding's
own framing ("substance holds... the documentation half REFUTED").

No new test was written for P3a-8, because none was needed: the underlying
claim (`record.value` carries no raw arguments; erasure does not touch a
bundle) is unchanged by this pass and was already enforced before it -
`tests/test_evidence_bundle.py::test_bundle_exported_for_a_content_erasure_
tombstone` and the byte-sweep table (`docs/reports/phase-3a.md` section 5)
already assert exactly this shape. P3a-8 is a documentation-accuracy item,
not a code item, and its own criterion asks only that the statement exist and
be accurate - both confirmed by reading the added text against the mechanism
it describes, not by a new mutation.

---

## 3. P3a-9. The mapping is derived, not asserted

**Verdict: met.**

### The flagged row

`docs/reports/phase-3a.md`'s mapping row for the `ail_verify_bundle.py`
command block previously cited only "Reproducible command, run in section 9
with the stack torn down" - a live transcript, no committed test. Closed by
adding `tests/test_offline_verify.py::test_readme_command_block_is_exactly_
reproducible`: it extracts the literal `python tools/ail_verify_bundle.py
...` command from `readME.md` §3.4.1's own fenced code block (not a
paraphrase - read from the file, joined across its line-continuation
backslash, checked to start as expected) and runs it as a real subprocess,
asserting exit code 0 and `"OK [verified]"` in stdout. Passed live:

```
tests/test_offline_verify.py::test_readme_command_block_is_exactly_reproducible PASSED
```

The mapping row now cites this test by name instead of the live transcript.

### Re-deriving every other row

Twenty-six rows total. Each was checked individually against the artifact it
cites rather than the row's own claim being re-asserted over the set:

**Test-function citations (18 rows)** - every named test function grepped for
by exact name in the file the row claims it lives in, confirming the
function exists where cited (not merely "a test with a similar name exists
somewhere"):

| Cited test | Found at |
| :--- | :--- |
| `test_bundle_exported_for_a_policy_allow` | `tests/test_evidence_bundle.py:446` |
| `test_bundle_export_requires_the_read_credential` | `tests/test_evidence_bundle.py:538` |
| `test_bundle_export_is_not_reachable_with_the_write_credential_alone` | `tests/test_evidence_bundle.py:562` |
| `test_fixture_bundle_verifies_offline_with_no_network` | `tests/test_offline_verify.py:162` |
| `test_the_network_block_is_actually_installed` | `tests/test_offline_verify.py:111` |
| `test_merely_importing_the_checker_blocks_the_network` | `tests/test_offline_verify.py:127` |
| `test_the_checker_implements_no_cryptography_of_its_own` | `tests/test_offline_verify.py:200` |
| `test_no_fixture_bundle_contains_key_material` | `tests/test_offline_verify.py:592` |
| `test_the_checker_loads_a_key_only_from_the_path_it_was_given` | `tests/test_offline_verify.py:629` |
| `test_wrong_key_fingerprint_fails_as_key_mismatch` | `tests/test_offline_verify.py:373` |
| `test_a_refingerprinted_bundle_fails_at_the_signature_not_the_fingerprint` | `tests/test_offline_verify.py:572` |
| `test_no_proof_material_is_exported_for_a_record_that_did_not_verify` | `tests/test_evidence_bundle.py:417` |
| `test_substituted_state_fails_as_signature_failure` | `tests/test_offline_verify.py:331` |
| `test_anchor_substituted_with_an_unsigned_genesis_state_is_refused` | `tests/test_offline_verify.py:352` |
| `test_flipped_record_byte_fails_as_record_mismatch` | `tests/test_offline_verify.py:284` |
| `test_relabelled_record_type_fails_as_record_mismatch` | `tests/test_offline_verify.py:390` |
| `test_relabelled_timestamp_fails_as_record_mismatch` | `tests/test_offline_verify.py:407` |
| `test_deleting_any_required_field_is_refused` | `tests/test_offline_verify.py:431` (parametrized) |
| `test_a_corrupted_transaction_header_is_reported_not_fatal` | `tests/test_offline_verify.py:462` |

All 19 (18 above plus the newly-added command-block test) ran and passed in
the full-suite run below - "cited" and "exists and passes" both confirmed,
not just the former.

**Code-symbol citations (7 rows)** - grepped for in the source file each row
names:

- `RESULT_CLASSES` - `tools/ail_verify_bundle.py:119`
- `error_class` vocabulary - `verifier/main.py:287` and its four literal
  values (`consistency_failure`, `signature_failure`, `not_found`, `unknown`)
  at lines 421/428/453/456, unchanged this phase
- `_SPIKE_REQUIRED_MATERIAL` - `tests/test_evidence_bundle.py:275`, its own
  docstring at line 9 stating it is transcribed from the spike
- `SDK_IDENTIFIER` - `verifier/main.py:105`, `"immudb-py==1.5.0"`
- `_BundleStub`/`_BundleRootService` - `tools/ail_verify_bundle.py:152,163`
- `tests/fixtures/evidence_bundles/PROVENANCE.json` and `README.md` - both
  present in the fixtures directory
- The five-record-type asymmetry row ("four enforcing tests, one per type")
  - re-checked against `docs/reports/phase-3a.md` section 3: five types
    (`policy_allow`, `policy_deny`, `fault`, `content_erasure`, `schema_deny`)
    demonstrated live, four dedicated tests (`schema_deny` shares the same
    code path with no per-type branch, by design - not an inconsistency, the
    row already states this asymmetry rather than hiding it)

**Documentation-location citations (6 rows)** - confirmed the cited section
or entry exists and says what the row claims:

- `docs/adr/0006-verification-states.md` exists
- The byte-sweep table (`docs/reports/phase-3a.md` section 5) has 33 table
  rows across its per-field breakdown
- Both Residual Limits bullets ("a bundle of a forged record", "export
  metadata not covered") present in `readME.md`, unchanged in substance by
  this pass (one was reworded for D21's own addition below them)
- `docs/adr/0010-portable-evidence-bundles.md`'s `## Consequences` section
  exists at line 182
- `readME.md` §3.4 confirmed unchanged by this phase's own diff (`git diff
  --stat -- readME.md` shows only the D21/P3a-8 additions to §3.4.1/§5/§6,
  none inside §3.4 itself)

**Result:** zero of the twenty-six rows cited enforcement that was absent,
skipped, or misdescribed. The one row with a real gap (the command block) is
now test-backed like the rest. No second instance of the Phase 2 W8 pattern
was found - re-derivation, not re-assertion, is what established this: each
row's own artifact was independently located, not presumed present because
the row said so.

### Enforcing test

The re-derivation above is itself the enforcement this item asks for - P3a-9
has no additional runtime behavior to test beyond the mapping's own accuracy,
confirmed above per row, and the one code change (`test_readme_command_
block_is_exactly_reproducible`) which is enforced by the full-suite run.

### Mutation

Not applicable in the usual sense - P3a-9 is a documentation-accuracy item
over an existing mapping, not new runtime behavior with a single point of
failure to mutate. The equivalent check is the re-derivation's own
methodology: had any cited test not existed at the stated location, the grep
in section 3 above would have reported it missing, the same way it would
report a mutation. None did.

---

## 4. P3a-10. The prior attacks, against the deployment topology, from the agent's position

**Verdict: met.**

### Demonstration

`docker-compose.yml` (the full deployment topology - SPIRE server and agent,
Envoy, the edge/backend network split) brought up under `-p p3a10-deploy`,
`--no-cache` build of all five custom images. All sixteen services reported
healthy, including `langgraph-demo` completing its own SPIFFE handshake:

```
$ docker logs p3a10-deploy-langgraph-demo-1
Waiting for SPIRE workload socket...
SPIRE ready. Starting demo...
SPIFFE SVID loaded in-memory: spiffe://ail.internal/workload/agent
HTTP Request: GET https://envoy:8443/health "HTTP/1.1 200 OK"
Startup check: decision service reachable at https://envoy:8443/decide
```

**Baseline - no DNS resolution at all**, before attempting any attack:

```
$ docker exec p3a10-deploy-langgraph-demo-1 python3 -c "socket.gethostbyname('opa')"
socket.gaierror: [Errno -2] Name or service not known
$ docker exec p3a10-deploy-langgraph-demo-1 python3 -c "socket.gethostbyname('verifier')"
socket.gaierror: [Errno -2] Name or service not known
```

**U1, U5, U8, X5, attempted live from inside the agent container**
(`docker exec p3a10-deploy-langgraph-demo-1 python3 -c "..."`, `httpx`, the
same tool the prior red-team reports used):

```
U1 (OPA manifest forgery, PUT /v1/data/system/bundles/ail-policies)      : FAILED -> ConnectError: [Errno -2] Name or service not known
U5 (forged tombstone, POST verifier/write, no credential)                : FAILED -> ConnectError: [Errno -2] Name or service not known
U8 step1 (DELETE bundle root-ownership)                                  : FAILED -> ConnectError: [Errno -2] Name or service not known
U8 step2 (PUT evil policy /v1/policies/evil-eval)                        : FAILED -> ConnectError: [Errno -2] Name or service not known
X5 (unauthenticated POST verifier/verify, bundle assembly)               : FAILED -> ConnectError: [Errno -2] Name or service not known
```

All five for the identical reason: DNS resolution failure, not a rejected
HTTP call. Each `httpx` call named above was constructed to match the
attack's real shape exactly (the same forged-manifest JSON U1's own report
uses, the same tombstone shape U5's report uses, the same two-step
delete-then-PUT U8's report uses, the same unauthenticated `/verify` body X5
found), so the failure is "cannot reach the endpoint to attempt this," not
"attempted something different that happened to fail."

**DNS is not the only thing standing in the way - confirmed by bypassing it
entirely.** Resolved `opa` and `verifier`'s real container IPs on the backend
network from the host (`docker inspect`, `172.22.0.12` and `172.22.0.8`) and
attempted a raw socket connection to each, by IP, from inside the agent
container:

```
$ docker exec p3a10-deploy-langgraph-demo-1 python3 -c "socket.create_connection(('172.22.0.12', 8181), timeout=3)"
opa (172.22.0.12:8181): FAILED -> TimeoutError: timed out
$ docker exec p3a10-deploy-langgraph-demo-1 python3 -c "socket.create_connection(('172.22.0.8', 8003), timeout=3)"
verifier (172.22.0.8:8003): FAILED -> TimeoutError: timed out
```

Both time out rather than refuse - there is no route between the `edge` and
`backend` Docker networks at all, not merely no DNS entry. This confirms
`test_decision_service_network_isolation.py`'s own docstring claim ("a client
on the agent's segment alone cannot resolve or route to anything on the
other segment") live, for the first time against this specific compose file
in a Phase 3a-or-later session - Phase 2's own live reproduction
(`docs/reports/phase-2.md`) predates D18/D21 and did not need to test the
verifier's newer surface specifically.

**Credential check, live, independent of the reach check above:**

```
$ docker exec p3a10-deploy-langgraph-demo-1 env | grep -iE "VERIFIER|CONTROL_PLANE"
(no output)
```

The agent holds neither `VERIFIER_READ_KEY`, `VERIFIER_WRITE_KEY`,
`CONTROL_PLANE_READ_KEY`, nor `CONTROL_PLANE_WRITE_KEY` - confirmed by
reading the actual running container's environment, not the compose file
that produced it.

### Enforcing test

`tests/test_decision_service_network_isolation.py::test_agent_has_no_reach_
to_the_verifiers_export_surface` (new this pass): asserts `langgraph-demo`
and `verifier` share no network in `docker-compose.yml`, naming the specific
consequence (X5-equivalent bundle assembly) rather than leaving it implicit
in the pre-existing, more general `test_backend_services_are_never_on_edge`
parametrization. The module docstring was extended to record that this file
now also closes X5, not only U1/U5/U8, and to point at this report.

### Mutation

Added `- backend` to `langgraph-demo`'s `networks:` list in
`docker-compose.yml` (the exact mutation the instruction names), no stack
required - this is a static config test:

```
$ python -m pytest tests/test_decision_service_network_isolation.py -v
FAILED tests/test_decision_service_network_isolation.py::test_agent_is_edge_only
FAILED tests/test_decision_service_network_isolation.py::test_agent_has_no_reach_to_the_verifiers_export_surface
FAILED tests/test_decision_service_network_isolation.py::test_envoy_is_the_only_dual_homed_service
3 failed, 5 passed in 4.78s
```

The new test fails alongside the two pre-existing tests the same mutation
already broke - confirming it checks a real, independent property rather
than being vacuously true. Reverted, confirmed `git diff --stat --
docker-compose.yml` matched the pre-mutation 37-line diff exactly, full file
green again (8 passed).

---

## 5. Full suite, live

`docker-compose.test.yml` under `-p p3a-complete`, `COMPOSE_PROJECT_NAME=p3a-
complete` set to match (closing the fallback gap red-team X7 found - the
suite's own compose-project-name derivation otherwise falls back to the
working directory's basename):

```
$ python -m pytest tests/ -v
215 passed, 9 skipped, 1 failed in 745.31s (0:12:25)
FAILED tests/test_docs_references_resolve.py::test_every_referenced_docs_path_exists_in_this_commit
```

The one failure is expected mid-pass, not a defect: `docs/adr/0011-verifier-
authentication.md`, `docs/reports/phase-3a-completion.md` (this file), and
`docs/reports/phase-3a-redteam.md` were all still untracked at the moment
this suite ran - the test correctly reports every doc reference to them as
dangling because none of the referencing files were committed yet. This
resolves itself in the same commit that adds these three files (below); it
is not re-run after that commit inside this report because doing so would
require yet another full 12-minute live run for a check that is purely a
function of `git ls-tree`, not of anything this pass changed at runtime. CI
runs it against the actual committed tree and is the authoritative
confirmation (CI run id below).

Every test file this pass touched passed in full: `test_verifier_auth.py`
(15/15), `test_evidence_bundle.py`, `test_offline_verify.py` (including the
new command-block test), `test_decision_service_network_isolation.py`
(including the new isolation test), `test_content_states.py`,
`test_intent_completion_visibility.py`, `test_record_profile.py`,
`test_verification.py`.

---

## 6. Pre-registered negatives

All confirmed individually, derived per item rather than asserted over the
set.

**Any verifier endpoint reachable without a credential: false.** Both
`/verify` and `/write` require a credential (section 1); confirmed live
(`test_verify_rejected_with_no_key`, `test_write_rejected_with_no_key`, both
422) and by the mutation (removing the dependency is the only way to make
this true, and doing so fails four named tests).

**Any caller able to obtain proof material without the read credential:
false.** `/verify` (the only source of `proof_material`) requires
`VERIFIER_READ_KEY`; `GET /audit/bundle` is unchanged and still requires the
control plane's own read key. Confirmed live
(`test_x5_read_credentialed_verify_still_succeeds` needs the read key;
`test_x5_write_credentialed_verify_refused` confirms the write key does not
substitute for it).

**Any bundle carrying erasable content: false.** Unchanged from Phase 3a -
`record.value` is decision metadata and `input_sha256`, never raw arguments
(red-team X6, live-confirmed, substance unchanged this pass); P3a-8 adds the
documentation, not new mechanism. `tests/test_evidence_bundle.py::test_
bundle_exported_for_a_content_erasure_tombstone` still enforces this.

**Any mapping row citing enforcement that is absent or skipped: false.**
Section 3 above re-derives all twenty-six rows individually; none cited
anything absent or skipped, and the one row that previously had a real gap
(live-transcript-only) is now test-backed.

**Any prior attack reproducing from the agent's position in the deployment
topology: false.** U1, U5, U8, and X5 all fail for lack of network reach,
confirmed live at both the DNS and raw-IP level (section 4). No prior attack
from Phase 1.2's own set was found to reproduce from this network position -
consistent with, and now additionally confirmed against, Phase 2's structural
fix and Phase 3a's own new surface.

**Any assertion weakened: false.** No existing test had an assertion
loosened this pass. Every test touched had a credential header *added* to an
existing call (making the test strictly more specific about what it
authenticates as), not a check removed or broadened. `git diff` for every
touched test file was read in full before this report was written to confirm
this.

**Any item met by live evidence alone with no test enforcing it: false.**
P3a-7: `tests/test_verifier_auth.py`. P3a-8: no new runtime behavior exists
to test beyond what Phase 3a's own tests already enforce (see section 2's own
reasoning for why this item is documentation-accuracy rather than
code-behavior). P3a-9: the mapping re-derivation in section 3, plus `test_
readme_command_block_is_exactly_reproducible` for the one row that needed a
new test. P3a-10: `test_agent_has_no_reach_to_the_verifiers_export_surface`,
mutation-tested in section 4.

---

## 7. Could not verify

- **Whether `decision-service`'s or `ail-control-plane`'s own compromise
  still carries verifier reach and valid credentials** - not attempted this
  pass, and not in scope: D21's own Consequences section
  (`docs/adr/0011-verifier-authentication.md`) and `readME.md`'s
  tamper-evidence-is-not-forgery-resistance bullet already state this
  explicitly as unchanged and out of scope (Phase 3b's provenance work, not
  this pass's).
- **Whether the missing-env-var 503 reproduces against the live stack with
  an actually-unset variable**, as opposed to the in-process monkeypatch used
  in section 1 - judged low-value given the monkeypatch calls the exact
  function FastAPI's dependency injection calls, and given the precedent this
  project already established for `control_plane/main.py`'s identically-
  shaped check; not independently re-verified against a live restart with the
  variable actually unset in this pass's session.
- **Whether the raw-IP timeout in section 4 is specifically iptables/bridge-
  isolation as opposed to some other Docker networking mechanism** - the
  practical property (no route exists) was confirmed; the exact kernel-level
  mechanism producing that property was not independently inspected.

---

## 8. CI run id

Three commits pushed to `phase-3a-evidence-bundle` (PR #9):
`7f19cf6` (feat, D21), `5e25ec5` (test), `3cba752` (docs, including this
report's own not-yet-final draft). CI run
[32764990412](https://github.com/banji-007/compliance-ail/actions/runs/32764990412):
215 passed, 9 skipped, 1 failed - `tests/test_docs_references_resolve.py::
test_every_referenced_docs_path_exists_in_this_commit`, reporting exactly
what section 5 above predicted: this report was self-referenced by three
already-committed files (`docs/adr/0011-verifier-authentication.md`,
`docs/reports/phase-3a.md`, `tests/test_decision_service_network_isolation.
py`) before it was committed itself. Not a defect in anything this pass
changed - the check is doing its job, and the same pattern already happened
inside Phase 3a's own history (`docs/reports/phase-3a.md`'s own final commit,
`f1fe9ee`, exists for the identical reason).

This commit (`3c835c8`) adds this report itself to the tree, closing that
gap. CI run
[32765365505](https://github.com/banji-007/compliance-ail/actions/runs/32765365505):
green, all steps passed, `integration-tests` in 2m50s. The report below this
line is otherwise unchanged from the version CI run 32764990412 evaluated.
