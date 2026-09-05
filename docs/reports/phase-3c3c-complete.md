# Phase 3c-3c completion pass: the drift the phase report did not catch

**Run id:** `p3c3c-fix`, second sitting.
**Working directory:** `C:\Users\banji\OneDrive\Documents\p3c3c-verify` (a scratch clone; not the primary working directory).
**Branch:** `p3c3b-order`, continuing PR #14. Not merged.
**Compose project:** `p3c3c-verify`, stated explicitly on every invocation. Deliberately equal to the directory basename, so the project-name fallback that broke CI run `33407673213` is exercised rather than bypassed.
**Base:** `006baca`.

---

## 1. What this pass is

A review of `readME.md` at `006baca` found three places where the phase's own Residual Limits entries contradict text upstream in the same file. All three are real. This pass fixes them, and it treats them as a class rather than three lines: **the phase changed behaviour and the prose describing that behaviour elsewhere was not swept.**

It also closes three review items that are not documentation: an assertion this phase weakened without noticing, a build context this phase widened, and a duplicated-rule defect this phase fixed once at the point it bit rather than as a class.

Nothing here changes a decision. D35, D36 and D37 are unchanged.

---

## 2. The prose drift, and its full extent

The review named three sites. A sweep for the two claims across every `.md`, `.py`, `.ts` and `.tsx` in the repository found **five**, one of which is a code comment.

### Claim A: "the one outcome that produces no ledger entry at all"

Contradicted by measurement: the record was at tx 7, holding position 1000000005, indexed, counter advanced, on a call that returned `fault_class: verifier_unreachable`.

| Site | Status |
| :--- | :--- |
| `readME.md:175` (§3.4) | named in review, fixed |
| `readME.md:563` (§6, ADR-0005 paragraph) | named in review, fixed |
| `docs/adr/0005-outcome-taxonomy.md`, Documented Boundary | **found by sweep**, amended |
| `docs/adr/0005-outcome-taxonomy.md:35` (the `fault_class` list) | **found by sweep**, corrected inline |

The ADR is the source the two README sites cite. Fixing only the README would have left the citation pointing at the un-corrected original, which is the shape of defect `tools/mapping_check.py` exists to catch and would not have caught here, because the row's terms still appear in the cited section.

The ADR is **amended, not rewritten**. The paragraph describing the structural limit is correct and stays: nothing can write a durable record of "the durable-record writer is down". What was wrong was applying it to a second case that is not a recording-path failure at all, and the amendment says so with a two-row table.

### Claim B: "and that the condition is not transient"

The exact `transient: false` wording P3c3c-7 removed from the response.

| Site | Status |
| :--- | :--- |
| `readME.md:551` (§6, ADR-0002 paragraph) | named in review, fixed |
| `control_plane/main.py:1589` | **found by sweep**, fixed. The handler's own comment, four lines above the call to the body builder whose field was removed |

Sites deliberately **not** changed: `docs/reports/phase-3c3b.md:132`, `:402` and `:497` carry the old body and the old mapping row. Errata are appends and history is not edited; the erratum this phase already appended to that report corrects the claim in place.

### The review's own diagnosis, confirmed

> The mutation for P3c3c-7 passed because it tests the response; nothing tests the prose describing the response.

That is exactly right, and it is not fixable by a test in the general case. What is stated instead, in section 6: the sweep is now part of the phase procedure rather than a thing that happened once.

---

## 3. `fault_class: verifier_unreachable` doing two jobs

**Answer: banked for 3d, and written down so it does not live in a conversation.**

The review is right that this is D1's collapse one level down. Two faults with opposite consequences for the audit record are not distinguishable by the field a consumer switches on.

Why not a D-number now:

- The distinction is cheap to **compute** - the write response already carries `committed`, and `ledger/immudb_ledger.py` would raise a typed exception instead of a bare `RuntimeError` for `decision_service/main.py` to map. Perhaps thirty lines.
- The change is not a rename. It alters ADR-0005's closed set, which is D1's own artifact; it changes the Prometheus label collection `tests/test_outcome_types.py::test_metric_label_set_matches_closed_collection` asserts, so every alert or dashboard keyed on the class changes meaning; and **the right shape is genuinely open** - a call whose record committed unproven may not belong under the same `outcome_type` at all, rather than merely under a second `fault_class`.
- Running that inside a remediation phase already closing eight refutations, immediately before a red-team pass, would make the taxonomy change the least-examined thing in it.

Where it is now written, so it survives this conversation (the P3c3c-9 lesson applied to itself):

- `TODO.md`, Deferred, with the two outcomes stated and the reason for deferring;
- `docs/adr/0005-outcome-taxonomy.md`, Documented Boundary amendment;
- `readME.md` §5, Residual Limits.

What exists meanwhile: the distinction is **available** to a caller in the write response's `committed` field and on the `/audit` row's `ledger_fault`. What is collapsed is the class name, not the information.

---

## 4. The P3b-5 assertion: the review was right, and it is demonstrated

The review's objection:

> it now depends on that enumeration being complete: add a fourth path to anchoring under a new name and the test passes while anchoring is possible. Ask for the mutation that proves otherwise.

There is no such mutation, and the demonstration is the other direction. `AIL_ANCHOR_SUBMISSION_TOKEN` added to the reconcile-only service:

```
MUTATION APPLIED: a credential the enumeration does not name
1 passed
```

**The test passed with an unlisted anchoring credential present.** A blacklist holds only if the enumeration is complete, and an enumeration of credentials cannot be.

So it is now a **whitelist**: the reconcile-only service may carry exactly the seven settings a reconciliation pass reads, and may mount exactly the one directory it writes its verdict to. Both halves are needed, because the second is how a blacklist over `environment` misses entirely - a `./keys` mount hands the service signing material with no environment variable naming a credential at all.

Both mutations now fail:

```
MUTATION: AIL_ANCHOR_SUBMISSION_TOKEN
  AssertionError: the reconcile-only anchor-service carries settings
  reconciliation does not read: ['AIL_ANCHOR_SUBMISSION_TOKEN'] ... 1 failed

MUTATION: - ./keys:/keys:ro
  AssertionError: the reconcile-only anchor-service mounts ['./keys']; a key
  mount would hand it signing material with no environment variable naming a
  credential at all ... 1 failed

reverted: 1 passed
```

This is stronger than the absence check it replaced, which the blacklist was not.

---

## 5. The verifier build context, and what it found next door

The review asked to confirm `.dockerignore` bounds the widened context and that the image carries no keys beyond the one it needs.

**The verifier image is clean.** Inspected directly:

```
/app: main.py  provenance  requirements.txt
/app/provenance: __init__.py  anchor.py  record_signature.py  rekor.py
find / for *.key and *vault* -> nothing
```

It is clean because `verifier/Dockerfile` names every path it copies. It is **not** clean because of `.dockerignore`, which had no `keys/` rule at all - so every private key was in the build context, one careless `COPY . .` from being baked, in a third image that had been structurally incapable of it before D35.

**The same check found a live defect next door, pre-existing and not this phase's.** `decision_service/Dockerfile`'s `COPY decision_service/ ./` bakes the vault API token into the image on any machine where `make keygen` has run. Demonstrated rather than reasoned about:

```
probe token written to decision_service/secrets/vault_api_token.txt, image rebuilt
  cat /app/secrets/vault_api_token.txt -> PROBE-TOKEN-DO-NOT-USE-0123456789
```

The token reaches the running service as a Compose secret at `/run/secrets/vault_api_token` and is never read from the image, so nothing depended on it being there. The initial clone did not reproduce it, because the token is gitignored and a fresh checkout has none - which is precisely why nobody had seen it.

Fixed: `.dockerignore` now excludes `keys/` and `decision_service/secrets/*.txt`.

**The enforcing test inspects the images, not `.dockerignore`.** A rule in that file is a described mechanism; `tests/test_image_contents.py` runs a search inside each of the four images built from the repository root. It failed on the pre-fix decision-service image and passes on the rebuilt one, which is the mutation and its revert in the order they actually happened.

One thing this pass did **not** change, stated because the check raises it: every service that mounts `./keys:/keys:ro` can read every private key in it, including writer keys belonging to other services. That is pre-existing, unchanged by this phase, and a D22 question rather than a D35 one.

---

## 6. The duplicated-rule sweep

The review's framing:

> it is the third instance of the same class: two copies of a rule with nothing comparing them, which is exactly what D36 just fixed for the reserve and what P3c3c-6 tests across four readers. Worth a sweep rather than one more point fix.

The sweep, over production modules only:

| Rule | Copies | Compared by anything, before this pass |
| :--- | :--- | :--- |
| `ail_seq:commit` | 3 | no |
| `ail_seq:reserve` | 4 | the *value* is, by D36; the key name was not |
| `ail_view:decision:v1` | 5 | no |
| `ail_view:intent:v1` | 4 | no |
| `ledger_fault:` prefix and record type | 2 | no |
| the 2500 scan ceiling | 3 | no |
| the default reserve | 4 | no |

`tools/ail_backfill_index.py` already carried the observation in a comment - "Three copies of these names is two too many, but they live in three images that do not import each other" - and left the copies uncompared. That is the defect stated and then not acted on.

`tests/test_ledger_vocabulary.py` compares them. It cannot remove the duplication: the modules live in images built separately, which is what ADR-0001's isolation buys, and `provenance/` is the one rule shared by being copied into three images. What it changes is that a disagreement fails a test rather than producing a record nothing can find.

Validated by mutation, since a comparison that compares nothing passes identically:

```
MUTATION: backfill points at ail_view:intent:v2
  AssertionError: the intent view's set name does not mean the same thing in
  every module that reads it: {'verifier': 'ail_view:intent:v1', ...,
  'backfill': 'ail_view:intent:v2'}
  1 failed, 5 passed
reverted: 6 passed
```

Scope stated rather than implied: this compares **named constants**. A module that renames its constant, or a sixth module that hardcodes a string and defines no constant, is invisible to it.

`control_plane/main.py` gained `_FAULT_KEY_PREFIX` and `_FAULT_RECORD_TYPE` for this, because the fault key was spelled inline at its two use sites and an inline string cannot be compared against another module's constant.

---

## 7. Files changed

| File | What changed |
| :--- | :--- |
| `readME.md` | §3.4 and §6's two paragraphs corrected; one Residual Limits entry added for the `fault_class` collapse |
| `docs/adr/0005-outcome-taxonomy.md` | Documented Boundary amended with the two-row table and the open taxonomy question; the `fault_class` list corrected inline |
| `control_plane/main.py` | the handler comment that still said "not transient"; `_FAULT_KEY_PREFIX` and `_FAULT_RECORD_TYPE` named |
| `.dockerignore` | `keys/` and `decision_service/secrets/*.txt` |
| `tests/test_anchored_export.py` | the P3b-5 assertion inverted from a blacklist to a whitelist, over settings and mounts |
| `tests/test_image_contents.py` | new: no image built from the repository root carries key material |
| `tests/test_ledger_vocabulary.py` | new: every copy of a ledger name, key or ceiling agrees |
| `TODO.md` | the `fault_class` question, deferred with its reasoning |

## 8. Mapping

| Claim | Backed by | Kind |
| :--- | :--- | :--- |
| No image built from the repository root carries a private key or the vault credential | `tests/test_image_contents.py::test_no_image_built_from_the_repository_root_carries_key_material` | test |
| No Dockerfile names key material in a COPY | `tests/test_image_contents.py::test_no_dockerfile_copies_key_material` | test |
| The reconcile-only anchor service carries no setting reconciliation does not read, and mounts nothing but its report directory | `tests/test_anchored_export.py::test_writes_continue_and_records_are_produced_with_anchoring_broken` | test |
| The sequence counter key is the same string in every module that reads it | `tests/test_ledger_vocabulary.py::test_the_sequence_counter_key_agrees_everywhere` | test |
| The bound-reserve key is the same string in every module that reads it | `tests/test_ledger_vocabulary.py::test_the_reserve_key_agrees_everywhere` | test |
| Both view index names are the same in every module that reads them | `tests/test_ledger_vocabulary.py::test_the_view_index_names_agree_everywhere` | test |
| The writer of the fault record and the reader that joins it use the same key prefix and record type | `tests/test_ledger_vocabulary.py::test_the_fault_record_vocabulary_agrees` | test |
| The scan ceiling is identical in every module that pages against it | `tests/test_ledger_vocabulary.py::test_the_scan_ceiling_agrees_everywhere` | test |
| The default reserve is identical in every module that reads one | `tests/test_ledger_vocabulary.py::test_the_reserve_default_agrees_everywhere` | test |
| The vault credential is baked into the decision-service image on a machine that has run keygen | `docker build` with a probe token, transcribed in section 5 | **command, marked: no test covers this** |
| A closed-set fault class covering two outcomes with opposite consequences for the audit record is deferred, not resolved | `readME.md` §5, Residual Limits | residual limit |

---

## 9. Suite and CI

**CI run `33418328641`, green: 406 passed, 9 skipped, 96.53s.** Commit `8027750` on `p3c3b-order`, PR #14. The phase itself was `33409450352` at 395 passed; the eleven new passes are this pass's three test modules.

Locally, 53 failed against 336 passed, down from the phase's 67 against 309. **No test file this phase touched or added is among the local failures** (confirmed by name). The 53 are the known host set recorded in the phase report's could-not-verify item 5: `sigstore` cannot be installed into the host Python, and the tests that drive `decision_service/main.py` in-process cannot resolve compose service names or hold the verifier's write key. CI is the authority.

Mapping check: **0 new, 12 known, 0 stale**, 31 heading pins, 0 unpinned. This pass's own 11 rows are clean.

**The mapping-table coupling fired a third time**, and was resolved the same way as the first two: two rows in this report's table used the word "number", which made the stem generic and retired `phase-1-3.md` row 16's baselined class (b) failure without that row changing. Both rows were reworded to "identical". Three instances in one phase is itself the finding - a new report's vocabulary silently weakens historical checks, and the only thing that catches it is running the checker and reading the stale line.

## 10. What a red-team pass should go at first

Offered because this pass exists to make that pass more useful, not to pre-empt it.

1. **The one write that needs no proof.** `_set_without_verification` is bounded by a `record_type` check, a single caller, and `POST /write`'s refusal of a `ledger_fault` from outside. Two of those three are asserted by parsing source rather than by driving the system, and the review is right that claims in this project have a poor record of surviving contact.
2. **`_fault_key`'s fallback.** A record with no `call_id` is keyed by a digest of the record key. Nothing on a page can ever join that, and the claim that such records never reach a page is an argument, not a test.
3. **The whitelist in section 4 is a list too.** It is complete against additions, which the blacklist was not, but it says nothing about a service that reads a setting it does not declare.
4. **The reserve binding on a pre-D36 ledger** was reasoned about and never run against a ledger written by the previous build.

---

## 11. The brief, and two corrections that landed with it

`docs/reports/phase-3c3c-redteam-brief.md`, commit `aaa0edd`. **CI `33421995261` green: 406 passed, 9 skipped.**

Ten claims, each stated as a behaviour that could be false. It names the two weakest points this session knows of rather than making the red team find them first (C3's parse-based bounds, C2's digest-keyed fallback), and it scopes out the two items already deferred in `TODO.md` so a restatement of a known limit is not mistaken for a finding.

**Correction A: writer-signature attribution was overstated, and at its source.** `docs/adr/0012-writer-signing-and-external-anchoring.md` said `decision-service` and `ail-control-plane` "hold separate pairs, so a bundle's `writer_key_fingerprint` names which service wrote the record". They do not hold separate pairs. `./keys:/keys:ro` is mounted by `ail-control-plane`, `verifier`, `decision-service`, `anchor-service` and `immudb`, so each holds every writer's private key and is separated from the others only by which path its own `AIL_WRITER_SIGNING_KEY` names, which is a configuration convention rather than a boundary. The fingerprint names a key; the key does not name a component. That matters exactly when it would be relied on, after one of those services is compromised: a compromised control plane can forge a record attributed to the decision service and nothing here distinguishes it. Per-key revocation is unaffected, because the deny-list operates on keys.

Corrected in the ADR and in both `readME.md` §5 bullets that rest on it. Segregating the mounts is a D22 item in `TODO.md`, not done here: it changes deployment topology and needs a decision about what `immudb` requires from that directory.

**Correction B: a third corpus-coupling direction, in `TODO.md`.** Correction A is the shape section 2 of this report describes, met again: a citing document and the cited source were both wrong, and class (b) is satisfied when a false claim and a section repeating the same false thing agree. Both instances found this phase passed the checker while both documents were wrong. Nothing mechanical catches it, so it is written down as a direction rather than as a check.

**One thing the phase's own test caught in the brief, twice.** The first push of the brief spelled out the path of the report it was asking the red team to write, and `tests/test_docs_references_resolve.py` refused it: a `docs/` reference that does not resolve in the commit. CI run `33421709886` failed on it. Correct behaviour, and the 3c-3b brief avoided it by saying "inline"; the naming convention is now stated without a path.

Then this section did it again. Writing *about* the dangling reference, in prose, reintroduced the same literal path and `4b38425` failed CI (`33422877139`) for the identical reason. **That commit was pushed without its run being checked**, so the failure sat unnoticed until the next commit's run surfaced it; the green run reported for this pass, `33421995261`, was the commit before it. Two lessons rather than one: a path in prose is a reference as far as the checker is concerned, whatever the sentence around it is doing, and a docs-only commit is not a reason to skip watching its run.

