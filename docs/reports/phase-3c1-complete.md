# Phase 3c-1 completion pass: each check enforces or says it did not decide

**Run id:** `p3c1-complete`
**Working directory:** a scratch clone under an unused name, not the primary
working directory, removed before this report was delivered
**Branch:** `p3c1-mapping` (PR #11), based on `85e9090` with `origin/main`
merged in for protocol section 5

---

## Objective, restated

The mapping checks must not report success while not running. Two of them did,
within one session of shipping. This pass makes each check either enforce or
say plainly that it did not decide, and it closes the suite's ability to hide
unrelated failures. It is the last mapping work: report-internal and
sibling-report citations become a stated coverage limitation, not a future
phase.

Everything below is measured against that. Items 7 and 8 do not serve it. They
are housekeeping, they are in their own commits, and they are not offered as
evidence the objective was met.

## What was challenged before building, and what changed

Nine points were raised before any code was written and all nine were
answered. Two changed the shape of the work and are recorded here because the
report would otherwise read as though the instruction had been followed as
written.

- **Item 8 was not buildable on this branch.** Protocol section 5 landed on
  `main` after `p3c1-mapping` was cut, so `origin/main` was merged in first.
- **Item 7 broke the build as written.** Committing the red-team report
  unmodified failed
  `test_every_referenced_docs_path_exists_in_this_commit` on three paths that
  three attacks had constructed and which deliberately never existed. Three
  sentences were reworded rather than weakening a test that has caught five
  real incidents, and the edit is disclosed inside the red-team report.
- **Item 3's phrasing would have produced the goal-shaped Claim item 6 bans.**
  "Every mapping table is found by shape" quantifies over tables that do not
  exist. It was restated as four behaviours, the fourth of which neither side
  had listed and is the one that matters: a row whose cell count does not
  match its header is a failure rather than a silent drop.
- **Item 4 invalidated a number in six immutable errata.** Deleting the pass
  bucket makes class (b) decisive only where it fails. The recount is stated
  once here and in ADR-0013 rather than by appending six errata that restate
  arithmetic.
- **Item 5 as written would have traded 38 failures for 38 silent skips.** The
  per-file re-probe is paired with a session-scoped end-of-run check.

---

## Verdict per item

| Item | Verdict |
| :--- | :--- |
| 1. Baseline keys on the full failure tuple | **Met.** Key is report, row, class and reason; comparison is a multiset. Mutation caught. |
| 2. Heading pins | **Met.** `docs/reports/heading-pins.json`, 19 pins. Mutation caught, named by row and by both titles. |
| 3. Discovery gaps closed | **Met**, as the four behaviours the item was restated to. Fenced examples are excluded, which the item did not anticipate and which the red-team report itself forced. |
| 4. Class (b) is a falsifier only | **Met.** No pass bucket, no supported count. The recount is 10 failed and 71 not decided, of 81 citing rows. |
| 5. Per-file health re-probe plus session check | **Met.** Seventeen test files on a shared marker, no import-time service guard left. Mutation caught: skips naming the service, and the run fails. |
| 6. Claim cells describe behaviour | **Met.** Three of `phase-3c1.md`'s fourteen rewritten, including the worked example. This report's own sixteen audited on the same rule. |
| 7. Red-team report committed | **Met**, reworded and disclosed. Housekeeping, separate commit. |
| 8. Protocol sections 3 and 5 cross-referenced | **Met.** Housekeeping, separate commit. |
| 9. ADR and README state coverage honestly | **Met.** ADR-0013 D28; `readME.md` section 5 Residual Limits and section 6. |
| Q5. Eighth erratum | **Met.** `docs/reports/phase-1-3-complete.md`, rows 14 and 15. |

---

## 1. Item 1. A failure's identity includes its reason

### The defect

`Failure.key()` was report, row and class, and `classify_against_baseline`
built `{f.key(): f for f in all_failures(results)}`. Two separate leaks: the
reason was not part of the identity, and duplicates collapsed before the
comparison ran. A row already baselined for one class was an open slot for
every later failure of that class.

### The behaviour now

The key is report, row, class and the whitespace-normalised reason. The
comparison walks a sorted list and counts, so a genuine repeat is not lost.
This makes the reason string a contract: rewording it re-baselines every entry
carrying it, loudly, as stale-plus-new.

### Enforcing test

`tests/test_mapping_tables.py::test_a_second_failure_of_a_baselined_class_on_a_baselined_row_reports_as_new`,
which builds the two failures directly and asserts the classifier separates
them, and
`tests/test_mapping_tables.py::test_no_mapping_failure_outside_the_committed_baseline`,
the build gate.

### Mutation

**Named mutation:** add a second class (a) failure to an already-baselined
row. `docs/reports/phase-3b.md` row 2, baselined for "Kind declares command
but the backing column names no command", had a citation to a test file that
does not exist appended to its backing cell. This is red team `rt-p3c1-a`'s Z4
verbatim, which previously reported "0 new, 13 known, 0 stale" and passed.

```
$ python -m pytest "tests/test_mapping_tables.py::test_no_mapping_failure_outside_the_committed_baseline" -q
E       AssertionError: 2 new mapping failure(s), on top of 13 known and baselined:
E           docs/reports/phase-3b.md row 2 [class a]: cited path tests/test_z4_absorbed.py does not resolve to a file in this tree :: The signature is inside the record, so the inclusion proof covers it
E           docs/reports/phase-3b.md row 2 [class a]: cited test test_writer_field_tamper_is_caught is not collected under tests/ in tests/test_z4_absorbed.py :: The signature is inside the record, so the inclusion proof covers it
FAILED tests/test_mapping_tables.py::test_no_mapping_failure_outside_the_committed_baseline
1 failed in 6.32s
```

---

## 2. Item 2. Scope narrowing is pinned to the heading it matched

### The defect

Class (b) narrows a citation to a named subsection by matching the cited
document's own heading titles against the row's text. Retitling the heading
stops the narrowing and widens the search to the whole numbered section, and
nothing notices. Red team `rt-p3c1-a` deleted the `external_anchor.state`
disclosure from `readME.md` (this phase's own named class (b) mutation, which
the first pass demonstrates being caught) and retitled Residual Limits in the
same edit. Both checks passed and all eleven tests passed.

Explicit anchors were rejected, per the instruction and for the reason it
gives: history cannot be edited, and widening to the whole section would pass
row 38 pre-fix, trading the flagship catch for the fix.

### The behaviour now

`docs/reports/heading-pins.json` records, for every citation that narrows, the
heading title that was matched. A run reports unpinned narrowings, retitled
headings and stale pins, in the same shape as the stale-baseline check. Pins
exist only where narrowing occurs: a row that does not narrow has no heading
to pin, and inventing one would be a pin that cannot fail.

### Demonstration

```
$ python -c "import json; d = json.load(open('docs/reports/heading-pins.json')); print(json.dumps(d['pins'][0], indent=2))"
{
  "key": "docs/reports/phase-1-3-complete.md#1#readME.md#5",
  "report": "docs/reports/phase-1-3-complete.md",
  "row": 1,
  "doc": "readME.md",
  "section": "5",
  "title": "Residual Limits (Mixed Profile, Since Phase 2)"
}

$ python tools/mapping_check.py
heading pins: 19 recorded, 0 unpinned, 0 retitled, 0 stale
```

### Enforcing test

`tests/test_mapping_tables.py::test_every_narrowed_citation_is_pinned_to_the_heading_it_matched`.

### Mutation

**Named mutation:** retitle a pinned heading.

```
$ python -m pytest "tests/test_mapping_tables.py::test_every_narrowed_citation_is_pinned_to_the_heading_it_matched" -q
E       AssertionError: 16 pin(s) match no narrowing any more, so those rows are being checked against a whole section:
E           docs/reports/phase-1-3-complete.md#1#readME.md#5
E           docs/reports/phase-1-3-complete.md#18#readME.md#5
E           docs/reports/phase-1-3-complete.md#4#readME.md#5
E           docs/reports/phase-1-3.md#11#readME.md#5
E           docs/reports/phase-1-3.md#2#readME.md#5
            [... 11 more ...]
FAILED tests/test_mapping_tables.py::test_every_narrowed_citation_is_pinned_to_the_heading_it_matched

Then the whole rt-p3c1-a Z3-a attack, retitle plus the disclosure deleted,
which passed everything before this pass:

$ python -m pytest tests/test_mapping_tables.py -q
FAILED tests/test_mapping_tables.py::test_every_narrowed_citation_is_pinned_to_the_heading_it_matched
1 failed, 17 passed in 8.63s

Reverted, and clean again:

$ python -m pytest tests/test_mapping_tables.py -q
18 passed in 8.70s
```

---

## 3. Item 3. Discovery, as four behaviours

The item said "close the discovery gaps so every mapping table is found by
shape". That is not falsifiable: it quantifies over tables that do not exist.
It was restated, and accepted, as four behaviours.

| Behaviour | Was |
| :--- | :--- |
| A table written without outer pipes is discovered | The gate was `line.strip().startswith("|")`; outer pipes are optional in GitHub-flavoured markdown and such a table renders identically |
| A table below `docs/reports/` in a subdirectory is discovered | The walk was `glob("*.md")`, not recursive |
| An escaped pipe stays inside its cell | `_split_row` split on every pipe and unescaped afterwards, so the escape could never take effect |
| A row whose cell count does not match its header is a class (a) failure | Such a row was skipped, with no diagnostic and no effect on any count |

The fourth is the general fix. The defect red team `rt-p3c1-a` found was not
the escape, it was that a row could leave a table the checker was running over
with no number moving; the escape was one way to produce that. Any mismatch,
however produced, now fails.

**One consequence the item did not anticipate.** With outer pipes optional,
the parser discovered the pipe-less table inside `docs/reports/phase-3c1-redteam.md`,
which is that report's own demonstration that discovery missed one. A table
inside a fenced code block renders as literal text rather than as a table, so
it is an example and not a claim the report makes. Fenced blocks are now
excluded from discovery. This is a deliberate scope boundary, recorded in
ADR-0013: a real mapping table hidden in a fence would also stop looking like
a table to a reader.

### Item C2. The second-opinion scan is now a second opinion

`test_every_mapping_table_in_docs_reports_is_discovered` was documented as the
guard against a parser that goes blind. It reimplemented the parser's own
`startswith("|")` filter and its non-recursive glob, and it counted tables
rather than rows, so it agreed with the parser on all three constructed tables
and on the hidden row. The same opinion twice.

It is now
`test_every_mapping_table_and_row_in_docs_reports_is_discovered`: an `os.walk`
sweep with its own hand-written splitter, agreeing with the parser on table
count **and** row count.

### Enforcing tests

`test_a_table_written_without_outer_pipes_is_discovered`,
`test_a_table_in_a_subdirectory_of_docs_reports_is_discovered`,
`test_an_escaped_pipe_stays_inside_its_cell`,
`test_a_row_whose_cell_count_does_not_match_the_header_is_a_failure`,
`test_every_mapping_table_and_row_in_docs_reports_is_discovered`. The first
four build a synthetic tree under `tmp_path` rather than mutating
`docs/reports/`, so they assert the behaviour rather than the current corpus.

---

## 4. Item 4. Class (b) is a falsifier

### Why the pass bucket had to go

Red team `rt-p3c1-a` (Z3-c) added a row claiming "Every tool call is governed
by an active policy before it executes", cited at `readME.md` section 9, a
backlog entry about signing-key rotation. It was reported as checked and
supported. Its only support was the stem `govern` prefix-matching
`governance` in the file's closing tagline.

A check that can be satisfied by accident cannot report a pass without
overstating itself.

### The behaviour now

Every citing row is failed or not decided. The `unchk-b` column and the
`unchecked_support` field are gone; the run reports `b-fail` and `b-undec`,
and `b-undec` is exactly `cites` minus `b-fail`.

### The recount, stated once

**Class (b) fails 10 of the 81 rows that cite a section and decides nothing
about the other 71.** The previous figure, "decisive on 29 of 81", counted a
term match as a decision. Six errata carry per-report figures computed the old
way (`phase-1-3.md`, `phase-1-3-complete.md`, `phase-2.md`, `phase-3a.md`,
`phase-3b.md` state a non-zero count; `phase-2-completion.md` and
`phase-2-completion-b.md` state zero and stay correct). Those errata are not
edited: they are point-in-time records, and appending six more to restate
arithmetic is noise. This paragraph and ADR-0013 D28 supersede them.

### Demonstration

```
$ python tools/mapping_check.py
mapping tables found: 9

report                                    rows cites a-fail b-fail a-undec b-undec unparsed
-------------------------------------------------------------------------------------------
phase-1-3-complete.md                       38    25      0      1      12      24        0
phase-1-3.md                                28    23      0      5       4      18        0
phase-2-completion-b.md                      2     1      0      0       0       1        0
phase-2-completion.md                        9     2      0      0       2       2        0
phase-2.md                                  17     8      0      1       1       7        0
phase-3a.md                                 30    17      0      3       2      14        0
phase-3b.md                                 39     5      3      0       1       5        0
phase-3c1-complete.md                       16     0      0      0       0       0        0
phase-3c1.md                                14     0      0      0       0       0        0
-------------------------------------------------------------------------------------------
TOTAL                                      193    81      3     10      22      71        0

heading pins: 19 recorded, 0 unpinned, 0 retitled, 0 stale

against the baseline: 0 new, 13 known, 0 stale

There is no pass column. 81 rows cite a section; 10 are failed and 71 are not
decided. The 13 baselined failures are the same 13 the first pass recorded,
re-derived under the new key format.
```

### Enforcing test

`tests/test_mapping_tables.py::test_class_b_reports_no_pass_bucket`, which
asserts the arithmetic identity per report and that the removed field has not
come back.

---

## 5. Item 5. The suite cannot hide a broken stack

### The defect

One test stops the verifier on purpose. When its restart wait timed out once
in CI, the verifier stayed down and 66 later tests failed against a dead
service, each reporting an ordinary assertion failure on a response body.
Nothing in the output said the environment was broken.

Two mechanisms let it through. Every guard was a module-level
`pytest.mark.skipif`, evaluated once at import, so a stack that breaks
mid-session is never re-examined. And nine of the twelve `requires_stack`
predicates, covering 38 tests, asked only about OPA and ImmuDB: the test that
stops the verifier was gated by a predicate that does not look at the verifier.

### The behaviour now

`tests/conftest.py` defines `@pytest.mark.needs_stack(*services)`. The probe
runs per file, at `pytest_runtest_setup`, not at import, so a service that
dies mid-session is caught at the next file boundary and its dependants skip
with a reason naming the service.

Seventeen test files now declare what they need. A file that drives
`middleware.intercept_tool_call` reaches decision-service, which queries OPA,
writes content to the control plane and writes the ledger entry through the
verifier, so all of those are declared. No import-time service guard is left:
the six other guards under different names were converted too, gating on
exactly the services they already named, because two guard styles in one suite
leaves a reader unsure which is authoritative. The two remaining `skipif`
guards are not service probes (`requires_docker_cli` checks the CLI binary,
`requires_full_stack` checks a container in a different compose project).

**The skip alone would have been a worse bug.** A genuine crash would then
produce a run of quiet skips instead of a run of failures: the same hiding in
a different coat. `pytest_sessionstart` records which services were up,
`pytest_sessionfinish` fails the run if one that was up is down at the end. A
crash is one loud failure naming the service; the tests that could not run are
skips naming the same service.

### The flaky test's own masking

`assert start.returncode == 0` and `assert healthy` sat inside the `finally`
block. An assertion raised in a `finally` replaces the exception in flight, so
if the erasure assertion this test exists for had genuinely regressed and the
restart wait had also timed out, the real regression was discarded. The
restore result is now carried out of the block and raised only when there is
no primary failure to lose.

### Mutation

**Named mutation:** stop the verifier. The run must skip and name why.

```
Against a live stack built --no-cache under compose project `p3c1-complete`,
all six services healthy. Control first:

$ python -m pytest tests/test_record_profile.py -q
........                                                                 [100%]
8 passed in 47.33s

Then `docker compose -p p3c1-complete -f docker-compose.test.yml stop verifier`,
which is what the flake leaves behind, and nothing else changed. Before this
pass these 8 tests failed with content_store_unreachable assertion errors:

$ python -m pytest tests/test_record_profile.py -q -rs
ssssssss                                                                 [100%]
SKIPPED [8] tests\conftest.py:131: stack service(s) not answering: verifier. This is an environment condition, not an assertion failure.
8 skipped in 12.60s

That is the skip half. The session half needs the service to die mid-run, so a
throwaway test reproducing the flake's end state was placed first in the run
and deleted afterwards:

$ python -m pytest tests/test_aa_stack_killer.py tests/test_record_profile.py -q -rs
.ssssssss                                                                [100%]
========================= STACK DIED DURING THIS RUN ==========================
service(s) healthy at session start and down at session end: verifier. Tests after the failure point were skipped, not passed; something in this run left the stack broken.

SKIPPED [8] tests\conftest.py:131: stack service(s) not answering: verifier. This is an environment condition, not an assertion failure.
1 passed, 8 skipped in 19.08s
$ echo $?
1

Both halves. The tests that could not run say which service and say it is the
environment; the run fails anyway, so a wall of skips cannot be read as a
pass. Verifier restarted, throwaway deleted, and the rewritten flaky test runs
its own stop and restart cycle green:

$ python -m pytest tests/test_content_states.py tests/test_record_profile.py -q
................                                                         [100%]
16 passed in 123.45s (0:02:03)
```

---

## 6. Item 6. Claim cells describe behaviour

The worked example, `docs/reports/phase-3c1.md` row 5, stated the goal in the
artifact built to stop that substitution:

| | Before | After |
| :--- | :--- | :--- |
| Row 5 | A row citing a document section that does not discuss its claim is a failure | A row citing a document section that contains none of its claim's selected terms is a failure |
| Row 2 | The discovery agrees with an independent scan, so a parser that goes blind fails the build | The parser's table count and row count both equal a scan that shares no code with it |
| Row 10 | A baselined entry that stops failing fails the build, so the baseline cannot accumulate | A baseline entry that no longer matches a current failure fails the build |

Row 2 is the sharpest of the three, because the outcome it asserted was not
delivered: the scan it named did not catch a parser going blind, and red team
`rt-p3c1-a` walked past both. Rows 1 and 2 were also repointed at the renamed
test.

The other eleven were audited against the same rule and left. `A Kind naming a
test requires a function pytest actually collects, not merely a def` and `The
baseline may not carry an entry for a row that is not in any table` are
behaviours; `Mapping tables are discovered by structure, never from a list of
filenames` asserts an absence, which is a behaviour a reader can check by
reading the module.

`docs/reports/phase-3c1.md` was rewritten in place rather than corrected by
erratum, which is authorized and disclosed: that report is unmerged, on this
branch, and is this phase's own artifact rather than shipped history.

---

## 7. Mapping

Derived per row. Clean under both checks: this pass fixes its own table rather
than baselining it. Every Claim cell states what the mechanism does.

| Claim | Backed by | Kind |
| :--- | :--- | :--- |
| A failure's identity includes its reason, so two failures of one class on one row do not collapse | `tests/test_mapping_tables.py::test_a_second_failure_of_a_baselined_class_on_a_baselined_row_reports_as_new` | test |
| A failure whose key is absent from the committed baseline fails the build and is listed as new | `tests/test_mapping_tables.py::test_no_mapping_failure_outside_the_committed_baseline` | test |
| A baseline entry that no longer matches a current failure fails the build | `tests/test_mapping_tables.py::test_the_baseline_holds_no_entry_that_no_longer_fails` | test |
| A citation that narrows to a subsection has that subsection's title recorded, and a changed title fails the build | `tests/test_mapping_tables.py::test_every_narrowed_citation_is_pinned_to_the_heading_it_matched` | test |
| A table whose rows omit the outer pipes is parsed and its rows are counted | `tests/test_mapping_tables.py::test_a_table_written_without_outer_pipes_is_discovered` | test |
| A table in a subdirectory of `docs/reports/` is parsed | `tests/test_mapping_tables.py::test_a_table_in_a_subdirectory_of_docs_reports_is_discovered` | test |
| A cell containing an escaped pipe keeps the pipe and does not add a cell | `tests/test_mapping_tables.py::test_an_escaped_pipe_stays_inside_its_cell` | test |
| A row whose cell count differs from its header produces a class (a) failure naming both widths | `tests/test_mapping_tables.py::test_a_row_whose_cell_count_does_not_match_the_header_is_a_failure` | test |
| The parser's table count and row count both equal a scan that shares no code with it | `tests/test_mapping_tables.py::test_every_mapping_table_and_row_in_docs_reports_is_discovered` | test |
| Every citing row is reported as failed or as not decided, and the two totals sum to the citing count | `tests/test_mapping_tables.py::test_class_b_reports_no_pass_bucket` | test |
| Both reports written by this phase contribute zero failures and zero baseline entries | `tests/test_mapping_tables.py::test_the_current_phase_table_is_clean_rather_than_baselined` | test |
| Both reports written by this phase carry a table the parser discovers | `tests/test_mapping_tables.py::test_the_current_phase_reports_carry_a_mapping_table` | test |
| A test declaring a service that is not answering is skipped with the service named, rather than run | `tests/conftest.py::pytest_runtest_setup` reached by `python -m pytest tests/test_record_profile.py -q` with the verifier stopped, section 5 | command |
| A service healthy at session start and down at session end fails the run | `tests/conftest.py::pytest_sessionfinish`, exercised by `python -m pytest tests/test_record_profile.py -q` with the verifier stopped, transcript in section 5 | command |
| The whole run is reproducible outside pytest against an arbitrary tree | `python tools/mapping_check.py --repo <tree>`, the transcripts in sections 1 through 4 | command |
| The completion pass's four mechanism changes and the coverage limitation are recorded as a decision | `docs/adr/0013-mapping-table-self-check.md`, D28 | document |

---

## 8. Could not verify

- **Whether `docs/reports/phase-1-3-complete.md`'s replacement command was
  actually run live during the Phase 1.3 completion pass.** Rows 14 and 15
  claim it and cite that report's own section 2, which carries no such
  transcript, and no transcript of it exists anywhere in the report. Whether
  the author ran it cannot be established from this tree either way, so it is
  filed as a citation defect in that report's second erratum rather than
  escalated. It is the worked instance of the report-internal limitation.

- **Class (b) still cannot decide 71 of 81 citing rows,** and this pass does
  not improve that number. It stops the number being reported as though it
  meant something else. Raising it would mean a different mechanism, and
  ADR-0013 D28 argues against building one.

- **Report-internal and sibling-report citations remain unreachable by
  construction.** Stated in ADR-0013 D28 and `readME.md` section 5, instanced
  in three errata. Not scheduled.

- **A cited test that exists, is collected, and tests something else still
  passes class (a).** Nothing here reads a test body. That is triage-Blocking
  territory and stays a human judgement.

- **Fenced tables are out of scope by choice.** A mapping table written inside
  a code fence is not discovered. The argument is that it does not render as a
  table, so it is not the population this check is about, but it is an
  exclusion rather than a proof.

- **The pin mechanism is defeatable by a decoy.** `resolve_scope` returns the
  first child heading whose title appears in the row's text. A second
  subsection added earlier in the same section with the identical title would
  satisfy the pin while moving the scope. Adding one is a visible edit to a
  rendered document and it was not attempted.

- **The full suite was not run green end to end locally.** The Z7 mutation and
  its control were run against a live stack under an explicit compose project;
  the mapping work is static. CI runs the whole suite with the stack up.

---

## 9. CI run id

CI_RUN
