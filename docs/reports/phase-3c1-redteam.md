# Phase 3c-1 red team: attacking the mapping-table self-check

**Run id:** `rt-p3c1-a`
**Working directory:** `C:\Users\banji\AppData\Local\Temp\claude\c--Users-banji-OneDrive-Documents-compliance-ail\f3591756-3217-4f27-b2a8-8e830785f6d5\scratchpad\rt-p3c1-a`
(a scratch clone under an unused name, not the primary working directory; removed at the end of the session, see "What was removed")
**Branch:** `p3c1-mapping` (PR #11), not merged, not pushed
**Audited commit:** `85e90906de302794f551977d3c17c101beed4758`
**Live tip at report time:** `gh/p3c1-mapping` = `85e90906de302794f551977d3c17c101beed4758` (identical), `gh/main` = `c034ce0d8b0e643faabf2ceefe80a544db336bea`

Nothing was fixed. Every mutation below was applied alone and reverted in the
same step that recorded it; `git status --porcelain` on the clone was empty
before teardown.

**One edit was made to this report after the fact, by the Phase 3c-1 completion
pass (`p3c1-complete`), and it is disclosed here rather than made quietly.**
Three of the attacks above constructed a file path that deliberately never
existed: a renamed `phase-3a` report, an `archive/` directory under `docs/`, and
an `appendix/` subdirectory under `docs/reports/`. Written as literal
paths under the docs directory, all three were read as references by
`tests/test_docs_references_resolve.py::test_every_referenced_docs_path_exists_in_this_commit`,
which failed on them the moment this report was committed. That test has caught
five real dangling-reference incidents, one of them in this session's own
protocol change, so it was not weakened. Instead those three sentences now name
the same constructions without spelling them as paths. No verdict, transcript,
count or line reference was altered.

---

## Verdict per claim

| Claim | Verdict |
| :--- | :--- |
| Z1. The two checks catch every instance of the defect class in the tree | **REFUTED.** `phase-1-3-complete.md` rows 14 and 15 cite the report's own section 2 for a live verification that section 2 does not contain and that appears nowhere in the report. Row 15 is one of the thirteen baselined failures and its erratum's triage reasoning does not reach this. |
| Z2. Every one of the 13 baselined failures is a citation defect, not a false claim | **Holds, with one qualification.** All thirteen claims were re-derived individually against the artefact each names and none is false. The triage reasoning recorded for `phase-1-3-complete.md` row 15 is wrong: it inspects only the Location cell and concludes "everything the row claims is true of the section it cites", while the row's backing cell claims a live verification nothing in the tree evidences. |
| Z3. Term derivation cannot be gamed | **REFUTED**, three independent ways. The serious one: retitling the cited README subsection neutralises the phase's own named class (b) mutation, so the disclosure can be deleted outright and both checks still pass. |
| Z4. The baseline cannot hide a new failure | **REFUTED.** A baseline key is `report#row#class` and nothing else, and current failures are collapsed into a dict on that key. Two brand-new class (a) defects added to an already-baselined row report as "0 new, 13 known, 0 stale" and the suite stays green. |
| Z5. Discovery by header shape finds every mapping table | **REFUTED**, three ways: a leading-pipe-less GFM table, a row containing the standard `\|` escape, and any file below `docs/reports/` in a subdirectory. Each hides a citation to a file that does not exist, with the suite green. |
| Z6. The erratum convention held | **HOLDS.** Zero removed lines across all seven historical reports, one hunk each, every hunk a pure append at end of file, each file's pre-existing content byte-identical to `c034ce0`. |
| Z7. The suite's failure mode is sound | **REFUTED.** Demonstrated live: with only the verifier stopped, all 8 tests in `tests/test_record_profile.py` fail rather than skip, with messages indistinguishable from a real regression, and nothing in the output names the environment. The guards are import-time only and 38 stack-gated tests are gated on a predicate that never probes the verifier. |

---

## Z1. The checks do not catch every instance

**REFUTED.**

The known miss (`phase-2-completion-b.md` row 1) was confirmed and is not
restated here. Reading the claim and the cited backing for all 52 rows class
(b) could not decide, plus all 22 rows that name nothing checkable (65 distinct
rows; the two sets overlap on 9), produced one further instance of the same
species, spread over two rows.

`docs/reports/phase-1-3-complete.md:346-347`:

```
| README §4.5, bundle-load confirmation step | **Corrected this pass (R1)** -
  `curl localhost:8181` broke when OPA's port was unpublished; replaced with a
  compose-network command | Verified live in section 2 above |
| README §4.6, service endpoint table | **Corrected this pass (R1)** - Control
  Plane API and OPA rows removed (no longer published); replacement commands
  given and verified live | Same as §4.5 |
```

Both rows point at the report's own section 2 for a live verification of the
replacement command. Section 2 (`docs/reports/phase-1-3-complete.md:32-99`) is
R1's port-binding evidence. It demonstrates the break and never runs the
replacement:

```
$ grep -n 'compose exec\|docker exec\|urllib' docs/reports/phase-1-3-complete.md
447:replacement commands (`docker compose exec ail-control-plane python -c ...`
```

Line 447 is inside the erratum this phase itself appended on 2026-08-25. The
report contains no other occurrence, so the `docker compose exec
ail-control-plane python -c "...urlopen('http://opa:8181/v1/data/ail/config')..."`
command that `readME.md:410` now gives has no transcript anywhere in the report
that cites one.

The chain is worse than a single missing transcript. Section 2's own escalation
note (`docs/reports/phase-1-3-complete.md:97`) says the broken affordance "is
fixed in documentation (section 5 below)". Section 5 of that report is
`## 5. R4 - GET /bundles/{tenant_id} requires a credential` (line 156), and
section 6 is R5, whose subsections 5a to 5d cover four other statements.
Neither covers the section 4.5 or 4.6 edit. So the row cites section 2, section
2 defers to a section that is about a different item, and the live verification
the row asserts is in neither.

This is the `phase-2-completion-b.md` row 1 species exactly: a citation into a
report section for evidence that section does not carry. Neither check reports
it. Row 14 is invisible to both checks: its backing cell names nothing
mechanically checkable, and its Claim yields no load-bearing term against
`readME.md` §4.5. Row 15 is caught by class (b), but for the wrong reason and
against the wrong cell: it is failed on `readME.md` §4.6 not containing `given`
and `replacement`, then baselined and triaged as sound.

**Attacks on Z1 that failed.** Every other row in the 65 was traced to its cited
artefact and found supported. The ones worth naming because they looked wrong
and were not:

- `phase-3a.md` row 4, "Five types exported live, section 3; four enforcing
  tests, one per type", reads as an arithmetic contradiction. It is not.
  `docs/reports/phase-3a.md:130-146` exports five record types live and
  `:164-172` names four tests, one per record type, with `schema_deny`
  deliberately untested and said to be so.
- `phase-2-completion.md` row 8 cites "the same scope boundary `phase-2.md` §3
  drew for its own dashboard sweep". `docs/reports/phase-2.md:210` draws exactly
  that boundary.
- `phase-1-3-complete.md` row 37, "there really are four `OutcomeType` values",
  is true: `dashboard/lib/types.ts:27` defines exactly four, and
  `dashboard/components/audit-table.tsx:57-58` carries the "all four
  outcome_types" comment the row is about.
- `phase-2.md` rows 2 and 3 cite "live transcript §2 above" for the Envoy
  retarget, which is where `phase-2.md` row 15's missing 504/200 transcript
  would have been. They survive: `docs/reports/phase-2.md:51` shows
  `DECISION_SERVICE_URL=https://envoy:8443/decide` in a live environment dump
  and `:145` shows a legitimate call through the same real mTLS channel.
- `phase-3a.md` row 21 quotes ADR-0010 D19 as "raw ImmuDB key rather than a
  `call_id`". `docs/adr/0010-portable-evidence-bundles.md:96` carries that
  string verbatim.
- `phase-1-3.md` row 21 cites "§3's live U1/U8/U5 transcripts".
  `docs/reports/phase-1-3.md:64`, `:74` and `:88` carry all three.

---

## Z2. The triage of the thirteen holds; one triage argument does not

**Holds, with one qualification.**

Each of the thirteen was re-derived against the artefact it names rather than
against the build report's conclusion.

The three class (a) rows, all in `docs/reports/phase-3b.md`:

- Row 2, "The signature is inside the record, so the inclusion proof covers it".
  True. `docs/reports/phase-3b.md:456-463` states and evidences it: every
  writer-field tamper returns `consistency_failure` from `store.VerifyInclusion`
  because the signature is a field inside `record.value`.
- Row 38, "The arbitrary-pair capability rests on a library seam". True,
  verbatim at `readME.md:525`.
- Row 39, "`external_anchor.state` can be downgraded to `not_anchored`
  undetectably". True, `docs/reports/phase-3b.md:449-455` and `readME.md:524`.

The ten class (b) rows: each cited section was opened and carries the substance.
`readME.md:404-412` carries the exact FinOps deny string for `phase-1-3.md` row
15; `readME.md:446-452` carries the endpoint table for row 16; the README §6 ADR
summaries carry rows 23 and `phase-2.md` row 7; `readME.md:185-208` carries the
three §3.4.1 sentences `phase-3a.md` rows 3, 8 and 9 quote;
`docs/reports/phase-0-1.md` and `docs/reports/phase-1.md` both exist for
`phase-1-3.md` row 18. No false claim among the thirteen.

**The qualification.** The erratum for the thirteenth,
`docs/reports/phase-1-3-complete.md:444-451`, concludes "Everything the row
claims is true of the section it cites." That reasoning inspects only the row's
Location cell (`readME.md` §4.6). The row's Claim also says "verified live", and
its backing cell points at the report's own section 2, which is where the
verification is not (Z1). The verdict "citation defect, not a false claim"
survives, because whether the author ran the command cannot be falsified from
the tree. The argument offered for it does not survive.

**Attacks on Z2 that failed.** Two rows were pushed hardest as candidate false
claims and both survived. `phase-1-3-complete.md` row 12 claims
`tests/test_dashboard_auth.py` has "17 tests, up from 13":
`grep -c '^def test_' tests/test_dashboard_auth.py` returns 17.
`phase-1-3-complete.md` row 9 claims "Five integration tests, one a real tamper
vector" for the §3.4 coverage paragraph: `readME.md:183` names five and singles
out the persisted-anchor corruption test as the one reachable tamper vector.

---

## Z3. The term rule can be gamed

**REFUTED**, by three independent attacks. Each was applied alone and reverted.

### Z3-a. Retitling the cited subsection defeats the phase's own named mutation

This is the serious one. `docs/reports/phase-3c1.md:280-291` records scope
narrowing as load-bearing for class (b), and `:305-330` records the named
mutation (delete the `external_anchor.state` disclosure from `readME.md`'s
Residual Limits) being caught. `resolve_scope` narrows only when a child
heading's title text appears in the row's own text
(`tools/mapping_check.py:497-507`), so retitling that heading widens the search
back to the whole of section 5, which still contains `not_anchored` in the
fail-closed table.

Applied together: delete the disclosure bullet (the phase's own named
mutation), and change `### Residual Limits (Mixed Profile, Since Phase 2)` to
`### Residual limits and still-open gaps (mixed profile, since Phase 2)`.

```
$ python tools/mapping_check.py --repo <clone>
  docs/reports/phase-3b.md row 39 [class a]: Kind declares command but the backing column names no command :: external_anchor.state can be downgraded to not_anchored undetectably
against the baseline: 0 new, 13 known, 0 stale

$ python -m pytest tests/test_mapping_tables.py -q
...........                                                              [100%]
11 passed in 8.57s
```

The class (b) failure the phase demonstrates catching is gone. `readME.md` no
longer carries the disclosure at all, phase-3b's row 39 still claims it, and the
build is green. One ordinary editorial retitle of a README heading, of the kind
any later phase might make for unrelated reasons, silently retires the check on
the row it was built for.

For comparison, the same deletion without the retitle is caught, as the phase
reports:

```
$ python tools/mapping_check.py --repo <clone>
against the baseline: 1 new, 13 known, 0 stale
  NEW   docs/reports/phase-3b.md row 39 [class b]: readME.md section 5 / Residual Limits (Mixed Profile, Since Phase 2) contains none of the claim's distinctive terms (external_anchor, not_anchor) :: external_anchor.state can be downgraded to not_anchored undetectably
```

### Z3-b. A Claim cell worded to yield no load-bearing term

Applied to `docs/reports/phase-3c1.md`'s own table, the one table this phase
holds to zero failures and nothing baselined. One row appended:

```
| Unchanged this pass | readME.md §7, Stack Reference | document |
```

```
$ python tools/mapping_check.py --repo <clone> | grep phase-3c1
phase-3c1.md                                15     1     0     0       0       1
$ python -m pytest tests/test_mapping_tables.py -q
11 passed in 8.72s
```

`readME.md` §7 is a version-pin table. The row cites it for nothing it says, and
`test_the_current_phase_table_is_clean_rather_than_baselined` passes.

### Z3-c. Colliding stems

`occurs()` anchors at a word start but still prefix-matches
(`tools/mapping_check.py:548-556`), so a claim's stem is satisfied by any
unrelated word beginning with it. One row appended to the same table:

```
| Every tool call is governed by an active policy before it executes | readME.md §9, Known Limitations | document |
```

```
selected: ['active', 'govern'] hits: ['govern']
evidence: ['*ail - agentic integrity ledger. built for the governance gap.*']
$ python tools/mapping_check.py --repo <clone> | grep phase-3c1
phase-3c1.md                                15     1     0     0       0       0
$ python -m pytest tests/test_mapping_tables.py -q
11 passed in 7.97s
```

The `unchk-b` column reads 0, so class (b) counts this row as checked and
supported rather than as unchecked. Its only support is the stem `govern`
matching `governance` in the document's closing tagline. `readME.md` §9 is a
backlog entry about signing-key rotation.

**Attack on Z3 that failed.** Making a claim's terms pervasive by adding them to
a further top-level README section retires them from selection
(`_DISTINCTIVE_FRACTION = 0.25` over 9 top-level sections, so a document
frequency above 2 is discarded). Against row 39 this half works and is caught:
`not_anchor` is hardcoded as a must-be-selected term in
`tests/test_mapping_tables.py:205-231`, so pushing it over the ceiling fails
`test_the_term_rule_selects_terms_rather_than_reading_a_list`:

```
$ python -m pytest tests/test_mapping_tables.py -q
FAILED tests/test_mapping_tables.py::test_the_term_rule_selects_terms_rather_than_reading_a_list
FAILED tests/test_mapping_tables.py::test_no_mapping_failure_outside_the_committed_baseline
3 failed, 8 passed in 10.13s
```

That guard protects exactly one term of one claim. The retitle in Z3-a walks
around it without touching term selection at all.

---

## Z4. The baseline absorbs new failures silently

**REFUTED.**

`Failure.key()` is `"%s#%d#%s" % (report, row, cls)`
(`tools/mapping_check.py:764-765`) and `classify_against_baseline` builds
`current = {f.key(): f for f in all_failures(results)}`
(`tools/mapping_check.py:1010`). Two consequences: the reason is not part of the
identity, and several failures on one row and class collapse to one dict entry.

Attack: `docs/reports/phase-3b.md` row 2 already holds a baselined class (a)
entry ("Kind declares command but the backing column names no command"). Append
a citation to a test file that does not exist to that same row's backing cell.

```
$ python tools/mapping_check.py --repo <clone>
TOTAL                                      177    81     5    10      21      52
...
  docs/reports/phase-3b.md row 2 [class a]: cited test test_writer_field_tamper_is_caught is not collected under tests/ in tests/test_z4_absorbed.py :: The signature is inside the record, so the inclusion proof covers it
  docs/reports/phase-3b.md row 2 [class a]: cited path tests/test_z4_absorbed.py does not resolve to a file in this tree :: The signature is inside the record, so the inclusion proof covers it
  docs/reports/phase-3b.md row 2 [class a]: Kind declares command but the backing column names no command :: The signature is inside the record, so the inclusion proof covers it

against the baseline: 0 new, 13 known, 0 stale

$ python -m pytest tests/test_mapping_tables.py -q
...........                                                              [100%]
11 passed in 9.59s
```

The class (a) total moves from 3 to 5, the run prints both new failures in the
failing-rows list, and the baseline classification still says "0 new". The build
gate (`test_no_mapping_failure_outside_the_committed_baseline`) passes. Any row
that already holds a baselined entry of a given class is a permanently open slot
for further defects of that class, including a cited test that does not exist,
which is the exact defect class (a) was built for.

**Attacks on Z4 that failed.**

- Renaming a report carrying baselined rows
  (`git mv` of `docs/reports/phase-3a.md` to `phase-3a-archived.md` in the same
  directory) is loud:
  `3 new, 10 known, 3 stale`, and 4 of 11 tests fail, including
  `test_every_baseline_entry_names_a_real_row`.
- Moving a table out of `docs/reports/` entirely
  (`git mv` of `docs/reports/phase-3b.md` into a new `archive/` directory under
  `docs/`) is loud the same
  way: `STALE docs/reports/phase-3b.md#2#a`, `#38#a`, `#39#a`.
- Inserting a row above a baselined row shifts its number, which produces a new
  failure and a stale entry at once, both named. Not silent.

---

## Z5. Discovery misses three shapes of table

**REFUTED.** No eighth table exists in the tree: searching every `.md` file for
a header carrying a Claim column together with a `Maps to` or `Backed by` column
returns the same eight the checker finds. All three attacks below therefore
construct one, each hiding a citation to a file that does not exist. Each was
applied alone and reverted. The independent regex scan in
`test_every_mapping_table_in_docs_reports_is_discovered` misses all three too,
because it reproduces the parser's `startswith("|")` line filter and its
per-table (not per-row) counting.

### Z5-a. A GFM table with no leading pipes

`_tables_in` only inspects lines matching `line.strip().startswith("|")`
(`tools/mapping_check.py:145`). Leading and trailing pipes are optional in
GitHub-flavoured Markdown and this table renders identically. Appended to
`docs/reports/phase-2-completion.md`:

```
Claim | Maps to
:--- | :---
Retry budget is bounded | `tests/test_nonexistent_z5a.py::test_missing`
```

```
$ python tools/mapping_check.py --repo <clone>
mapping tables found: 8
...
against the baseline: 0 new, 13 known, 0 stale
$ python -m pytest tests/test_mapping_tables.py -q
...........                                                              [100%]
11 passed in 9.97s
```

### Z5-b. A row containing the standard escaped pipe

`_split_row` splits on `"|"` and only afterwards calls `.replace(r"\|", "|")`
(`tools/mapping_check.py:80-86`), so the escape can never take effect: a row
using it yields one cell too many and is dropped by the
`len(cells) == len(header)` guard (`tools/mapping_check.py:176`), with no
diagnostic. Inserted into `docs/reports/phase-2.md`'s discovered table:

```
| `decision_service/main.py` | Retry budget is bounded \| and audited | `tests/test_z5b_missing.py::test_missing` |
```

```
$ python tools/mapping_check.py --repo <clone>
phase-2.md                                  17     8     0     1       1       5
TOTAL                                      177    81     3    10      22      52
$ python -m pytest tests/test_mapping_tables.py -q
...........                                                              [100%]
11 passed in 10.80s
```

The row count for `phase-2.md` is unchanged at 17 and the total is unchanged at
177. The row sits inside a table both checks are running over and neither check
sees it. This is the sharpest of the three, because it hides a row rather than a
whole table, and the table-count agreement test cannot detect it by
construction.

### Z5-c. A subdirectory under `docs/reports/`

`find_mapping_tables` globs `"*.md"`, which is not recursive
(`tools/mapping_check.py:137`). A new `appendix/phase-3c1-appendix.md` under
`docs/reports/`,
with a full `Claim | Backed by | Kind` table citing
`tests/test_z5c_missing.py::test_retry_budget`:

```
$ python tools/mapping_check.py --repo <clone>
mapping tables found: 8
$ python -m pytest tests/test_mapping_tables.py -q
...........                                                              [100%]
11 passed in 7.53s
```

**Attack on Z5 that failed.** The red-team reports carry
`| Claim | Verdict | Key evidence |` tables (`docs/reports/phase-0-1-redteam.md:25`
and five others) which are shaped like claim-to-evidence maps and are not
discovered. On reading them they are verdicts on someone else's claims rather
than a report mapping its own claims to its own backing, so this is a genre
boundary and is not counted as a refutation.

---

## Z6. The erratum convention held

**HOLDS.**

```
$ git diff --numstat c034ce0 85e9090 -- docs/reports/
108	0	docs/reports/mapping-check-baseline.json
37	0	docs/reports/phase-1-3-complete.md
55	0	docs/reports/phase-1-3.md
48	0	docs/reports/phase-2-completion-b.md
21	0	docs/reports/phase-2-completion.md
58	0	docs/reports/phase-2.md
46	0	docs/reports/phase-3a.md
64	0	docs/reports/phase-3b.md
696	0	docs/reports/phase-3c1.md

$ git diff --unified=0 c034ce0 85e9090 -- docs/reports/ | grep -c '^-[^-]'
0
```

One hunk per historical file, each an append starting at the old last line:

```
phase-1-3.md            @@ -314,0 +315,55 @@
phase-1-3-complete.md   @@ -428,0 +429,37 @@
phase-2.md              @@ -285,0 +286,58 @@
phase-2-completion.md   @@ -89,0 +90,21 @@
phase-2-completion-b.md @@ -134,0 +135,48 @@
phase-3a.md             @@ -818,0 +819,46 @@
phase-3b.md             @@ -645,0 +646,64 @@
```

Byte-level confirmation that nothing before the append moved. For each file,
comparing the whole `c034ce0` blob against the first N lines of the current file
(N = the old line count) reports no difference:

```
phase-1-3.md: PREFIX IDENTICAL
phase-1-3-complete.md: PREFIX IDENTICAL
phase-2.md: PREFIX IDENTICAL
phase-2-completion.md: PREFIX IDENTICAL
phase-2-completion-b.md: PREFIX IDENTICAL
phase-3a.md: PREFIX IDENTICAL
phase-3b.md: PREFIX IDENTICAL
```

No row was edited in place and no line was removed. See finding 1 below for a
numbering collision introduced by one of the appends, which is an addition and
does not disturb this verdict.

---

## Z7. One test can mask unrelated results, and it is not evident

**REFUTED.** Demonstrated live against a stack built `--no-cache` under compose
project `rt-p3c1-a`, all six services healthy before the run.

Exactly one test stops a container: `tests/test_content_states.py:407-409` stops
the verifier and `:420-434` restarts it and waits for health. That much the
build report discloses. What was tested here is whether the masking is evident,
and how far it reaches.

### The guards do not see it

Baseline, stack fully healthy:

```
$ python -m pytest tests/test_outcome_types.py tests/test_record_profile.py -q
........................                                                 [100%]
24 passed in 272.83s (0:04:32)
```

Then `docker compose -p rt-p3c1-a -f docker-compose.test.yml stop verifier`,
which is the exact state the flake leaves behind, and nothing else changed:

```
$ python -m pytest tests/test_record_profile.py -q
FAILED tests/test_record_profile.py::test_raw_decision_record_carries_observed_profile
FAILED tests/test_record_profile.py::test_raw_tombstone_record_carries_observed_profile
FAILED tests/test_record_profile.py::test_audit_forged_profile_less_record_renders_as_unknown_not_observed
FAILED tests/test_record_profile.py::test_audit_response_carries_profile_from_closed_set
FAILED tests/test_record_profile.py::test_raw_decision_record_for_mediated_tool_carries_mediated_profile_and_demonstrated_exclusivity
FAILED tests/test_record_profile.py::test_raw_decision_record_for_observed_tool_carries_no_exclusivity_key_at_all
FAILED tests/test_record_profile.py::test_one_session_produces_both_observed_and_mediated_records
FAILED tests/test_record_profile.py::test_audit_response_surfaces_exclusivity_for_mediated_records
8 failed in 58.88s
```

Restart the verifier, change nothing else, same eight tests:

```
$ python -m pytest tests/test_record_profile.py -q
........                                                                 [100%]
8 passed in 97.77s (0:01:37)
```

The eight failures were entirely environmental. Nothing in the output says so.
Grepping the failing run for the word `verifier` returns three lines, all echoed
source, none a diagnosis:

```
$ python -m pytest tests/test_record_profile.py -q | grep -i -n verifier
95:        to the verifier with no "profile" key at all must render distinctly as
123:            f"{os.getenv('VERIFIER_URL', 'http://localhost:8003')}/write",
125:            headers={"X-API-Key": VERIFIER_WRITE_KEY},
```

The assertion text a reader actually sees is

```
E  AssertionError: Expected a recorded, approved call, got: {'status': 'DENIED',
   'message': 'DENIED: Compliance engine fault (content_store_unreachable).
   Fail-closed policy enforced.', 'outcome_type': 'fault',
   'fault_class': 'content_store_unreachable', 'policy_revision': None}
```

which is precisely what a genuine regression in the profile or exclusivity code
path would print.

### Why the guards let it through

There are 12 `requires_stack` definitions. Nine of them, covering **38 tests**,
are `not (_opa_reachable() and _immudb_reachable())` and never probe the
verifier:

```
tests/test_base_agent.py                    2
tests/test_content_states.py                8
tests/test_intent_completion_visibility.py  3
tests/test_opa_request_count.py             2
tests/test_outcome_types.py                10
tests/test_policy_digest.py                 2
tests/test_raw_ledger_fields.py             2
tests/test_record_profile.py                8
tests/test_response_contract.py             1
```

Confirmed directly, with stand-in listeners on 8181 and 8080 and nothing on
8003, evaluating `tests/test_content_states.py:155-175`'s own predicate
verbatim:

```
opa 8181 reachable : True
immudb 8080 reachable : True
verifier 8003 reachable: False
requires_stack would SKIP test_content_states.py? -> False
```

The test that stops the verifier is itself gated by a predicate that does not
look at the verifier.

All 12 are module-level `pytest.mark.skipif`, so each predicate runs once at
import. Even the three that do probe the verifier
(`tests/test_anchored_export.py:81`, `tests/test_evidence_bundle.py:154`,
`tests/test_verifier_auth.py:50`) cannot help after collection: they produce a
clean skip only when the service is already down at import time, which is what
the contrast run shows:

```
$ python -m pytest tests/test_verifier_auth.py -q     # verifier down at import
sssssssss......                                                          [100%]
6 passed, 9 skipped in 9.04s
```

There is no `conftest.py` anywhere in the repository, so there is no
session-scoped health check, no re-probe between files, and no marker separating
"environment broken" from "assertion regressed". `tests/test_content_states.py`
sorts fifth of 34 test files, so a verifier left down there precedes roughly 29
files out of a 306-test collection.

### The test also masks its own primary failure

`assert start.returncode == 0` and `assert healthy` sit inside the `finally`
block (`tests/test_content_states.py:423-434`). An assertion raised in a
`finally` replaces the exception in flight, so if the erasure assertion this
test exists for genuinely regressed and the restart wait also timed out, the
real regression is discarded. Reproduced on the same control flow:

```
reported failure: Verifier did not come back healthy after restart
```

The only message that survives is the environmental one.

**Attack on Z7 that failed.** Looking for a second test that can leave the stack
broken: the only other `docker compose exec` in the suite,
`tests/test_content_states.py:367-372`, deletes a single SQLite row it created
itself, and `tests/test_vault_tool_bypass.py:111` execs read-only probes.
Container-level breakage is genuinely confined to one test. The masking, though,
is a property of the guards rather than of that test, so any future service
disruption reaches the same 38 tests the same way.

---

## Could not test, and what blocked it

- **The full 306-test suite was not run green end to end on this host.** The
  targeted Z7 runs alone cost about 8 minutes of wall clock for 32 tests, and
  the build report records the full local suite as far slower on this machine.
  Everything Z1 through Z6 needed is static and was run in full: the clean tree
  gives `mapping tables found: 8`, `0 new, 13 known, 0 stale`, and
  `python -m pytest tests/test_mapping_tables.py -q` gives `11 passed`, before
  and after every mutation.
- **Whether the `docker compose exec` replacement command in Z1 was actually run
  live during the Phase 1.3 completion pass.** Unfalsifiable from the tree. What
  is established is that no transcript of it exists in the report that cites
  one, which is the citation defect. Whether the author performed it cannot be
  decided here, which is why Z2 is not called refuted.
- **The class (a) case "cited test exists and is collected but tests something
  else".** Reading test bodies against claims for all 177 rows was out of scope
  for this pass; the build report already names this as a human judgement the
  checker does not make.
- **The CI runs named in the phase report** (`32887830855`, `32886943698`) were
  not re-fetched. No network calls to GitHub Actions were made beyond
  `git fetch`.

---

## Findings outside Z1 to Z7

1. **The erratum appended to `docs/reports/phase-2-completion.md` duplicates an
   existing section number.** The file already had `## 6. CI run id` at line 87;
   this phase appended `## 6. Erratum, 2026-08-25` at line 93.
   `Document.find_number("6")` returns the first match, so any future row citing
   `phase-2-completion.md` §6 resolves to the CI section rather than the
   erratum:

   ```
   section 6 -> 'CI run id' lines 87 92
   section 6 -> 'Erratum, 2026-08-25 (added by Phase 3c-1, p3c1-mapping, item P3c1-3)' lines 93 110
   ```

   No row cites it today, so the defect is latent.
   `docs/reports/phase-3c1.md:358` records the erratum as "§6 appended",
   repeating the collision rather than catching it. This is an addition, not an
   edit to history, so Z6 stands.

2. **`readME.md`'s ADR-005 summary is stale and contradicts §3.2 and §3.4.** The
   §6 paragraph says every record carries a profile "- this codebase produces
   `observed` only, see Residual Limits above". §3.2's registry table gives
   `read_vault_secret` the `mediated` profile, §3.4 describes `mediated` records
   additionally carrying `exclusivity`, and §5 is titled "Residual Limits (Mixed
   Profile, Since Phase 2)". Phase 2 changed the fact and did not change this
   sentence. No mapping row covers it: `phase-2.md`'s table maps README §6 only
   for the ADR-0007 and ADR-0008 summaries.

3. **Two `phase-3b.md` rows cite a byte-sweep pass that report does not have.**
   Rows 2 and 39 (`docs/reports/phase-3b.md:343` and `:381`) both cite "Byte
   sweep pass 3". `docs/reports/phase-3b.md:384-475` documents pass 1 and pass 2
   only; "Pass 3, targeted field-level tamper" is a Phase 3a heading
   (`docs/reports/phase-3a.md:370`). The substance both rows want is in
   phase-3b's byte-sweep section, in the unnumbered paragraphs at `:449` and
   `:456`, so this is a wrong pointer rather than a missing fact. Both rows are
   already baselined for class (a), for a different reason.

4. **The independent scan is weaker than its stated purpose.**
   `test_every_mapping_table_in_docs_reports_is_discovered` is documented as the
   guard against a parser that goes blind. It reimplements the same
   `startswith("|")` line filter and the same non-recursive glob as the parser
   it checks, and it counts tables rather than rows, so it agrees with the
   parser on all three Z5 attacks and on the Z5-b hidden row. A second scan that
   inherits the first one's assumptions cannot detect the first one going blind
   along those axes.

---

## What was removed

- The scratch clone
  `...\f3591756-3217-4f27-b2a8-8e830785f6d5\scratchpad\rt-p3c1-a` and everything
  in it, including the generated `keys/` pairs and
  `decision_service/secrets/vault_api_token.txt` (both gitignored, both
  generated inside the clone, never present in the primary tree).
- The Docker stack under compose project `rt-p3c1-a`, torn down with
  `docker compose -p rt-p3c1-a -f docker-compose.test.yml down -v`: six
  containers, the `rt-p3c1-a_default` network, and the three named volumes
  `test-control-plane-data`, `test-verifier-state`, `test-immudb-data`.
- The four images built `--no-cache` for that project
  (`rt-p3c1-a-ail-control-plane`, `rt-p3c1-a-verifier`,
  `rt-p3c1-a-decision-service`, `rt-p3c1-a-dashboard`). The pulled `opa` and
  `immudb` base images were left in place, since they are shared and were not
  built by this run.
- Four temporary helper files written outside the repository: `/tmp/rt_env.sh`,
  `/tmp/z7_probe.py`, `/tmp/rt_build.log`, `/tmp/rt_up.log`.

Nothing in the primary working directory was modified except the addition of
this report. Nothing was committed, pushed, or merged. `p3c1-mapping` is
untouched at `85e9090`.
