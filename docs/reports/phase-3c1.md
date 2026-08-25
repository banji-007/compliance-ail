# Phase 3c-1: the mapping table checks itself

**Run id:** `p3c1-mapping`
**Working directory:** `/c/Users/banji/OneDrive/Documents/ail-p3c1-mapping`
(a scratch clone, not the primary working directory)
**Branch:** `p3c1-mapping`, based on `main` at `c034ce0`

---

## Verdict per item

| Item | Verdict |
| :--- | :--- |
| P3c1-1. Class (a): Kind matches the shape of its backing | **Met.** Demonstrated across all seven historical tables, enforced by `tests/test_mapping_tables.py`, mutation caught. |
| P3c1-2. Class (b): the cited section supports the claim | **Met.** Demonstrated on the committed tree and on the pre-fix tree at `ab2a678`, where row 38 fails by name. Mutation caught. |
| P3c1-3. History is quarantined, not fixed | **Met.** Eight tables run, seven dated errata appended, thirteen failures baselined, mutation caught and distinguished from the baselined ones. |
| P3c1-4. Documentation | **Met.** `docs/adr/0013-mapping-table-self-check.md`. The circularity is stated rather than worked around. |

**One discrepancy with the instruction, resolved by deriving rather than
counting.** The instruction says "Five prior reports carry mapping tables. Run
both checks across all six." Discovery by header shape finds **seven** prior
tables, in seven reports, plus this one, for eight. The two the count appears
to have missed are `docs/reports/phase-1-3-complete.md` section 9 and
`docs/reports/phase-2-completion.md` section 3, both of which carry a
`Location | Claim | Maps to` table of exactly the same shape as the others.
This is not a correction offered lightly: an asserted count of mapping tables
is the same defect as an asserted mapping row, one level up, which is why the
checker discovers tables by structure and never from a list. All eight are
run and reported below.

---

## 1. P3c1-1. Class (a): Kind matches the shape of its backing

### The check

For every row, the Kind column declares what backs the claim, and the check
asserts that what it declares exists in the shape it declares. A Kind naming a
test requires a test function of that name that pytest actually collects
(defined in a `tests/test_*.py` file with a `test_` prefix, matching
`pytest.ini`'s `testpaths = tests` and pytest's default naming convention), not
merely a `def` with that name somewhere. A Kind naming a command requires the
backing to name one and its script to be present and to parse. A Kind naming
Residual Limits requires the cited document and section to exist.

Six of the eight tables have no Kind column; they use
`Location | Claim | Maps to`. There the Kind is implicit and the same existence
checks run over every artefact the backing column names.

The Kind cell is split into atoms on `+`, `,` and `;`, and only an atom that is
exactly a kind word counts. This is what preserves the project's existing
honesty convention: `command, marked: no test covers this` declares *command*
and nothing else. A looser word search would read "test" out of that
disclaimer and invert its meaning, failing the one row that was already
scrupulous.

### Demonstration

```
$ python tools/mapping_check.py
mapping tables found: 8

report                                    rows cites     a     b unchk-a unchk-b
--------------------------------------------------------------------------------
phase-1-3-complete.md                       38    25     0     1      12      17
phase-1-3.md                                28    23     0     5       4      15
phase-2-completion-b.md                      2     1     0     0       0       1
phase-2-completion.md                        9     2     0     0       2       2
phase-2.md                                  17     8     0     1       1       5
phase-3a.md                                 30    17     0     3       2      10
phase-3b.md                                 39     5     3     0       1       2
phase-3c1.md                                14     0     0     0       0       0
--------------------------------------------------------------------------------
TOTAL                                      177    81     3    10      22      52
```

**Three rows fail class (a), all in `docs/reports/phase-3b.md`:**

```
docs/reports/phase-3b.md row 2  [class a]: Kind declares command but the backing column names no command
docs/reports/phase-3b.md row 38 [class a]: Kind declares test but the backing column names no test
docs/reports/phase-3b.md row 39 [class a]: Kind declares command but the backing column names no command
```

Each was derived individually against the artefact it names, and each is a
**citation defect rather than a false claim**: the backing exists and is named
elsewhere in that report, just not in a form anything can follow. Row 2's
command is `python tools/bundle_byte_sweep.py`, transcribed in Phase 3b's own
byte-sweep section. Row 38's test is row 33's,
`test_the_proof_source_still_comes_from_the_injected_root_service`, cited only
as "(and the test above)". Row 39's command is the same byte sweep as row 2's.
Full reasoning is in that report's own dated erratum. None is Blocking under
the triage rule.

**Run against the pre-fix tree at `ab2a678`**, the commit before Phase 3b's
verification pass, the same check reports row 2 failing twice, once for each
kind its then-current `test + command` Kind declared:

```
docs/reports/phase-3b.md row 2 [class a]: Kind declares command but the backing column names no command
docs/reports/phase-3b.md row 2 [class a]: Kind declares test but the backing column names no test
```

That is the finding `docs/reports/phase-3b-verify.md` section B3 reached by
hand, reproduced mechanically.

### Enforcing test

`tests/test_mapping_tables.py::test_every_mapping_row_kind_matches_the_shape_of_its_backing`,
supported by
`tests/test_mapping_tables.py::test_a_kind_naming_a_test_requires_a_test_pytest_actually_collects`,
which asserts the collection rule itself rather than only its output.

### Mutation

**Named mutation:** change one row's Kind to name a test that does not exist.
Applied to this report's own mapping table, row 1.

PLACEHOLDER_MUTATION_1

---

## 2. P3c1-2. Class (b): the cited section supports the claim

### Why class (a) is not enough

Phase 3b's row 38 (the downgrade row, before the `/anchors` row was inserted
above it) read:

```
| `external_anchor.state` can be downgraded to `not_anchored` undetectably
| Byte sweep pass 3; readME.md §5
| Residual Limits + command |
```

`readME.md` existed, section 5 existed, and Residual Limits is a real
subsection of it. The row is perfectly shape-consistent and class (a) passes
it. What was not true is the only thing that mattered: the disclosure was not
in that subsection. Ship class (a) alone and the next red team finds this
again.

### How terms are selected, and what makes one load-bearing

Terms come from the row's own Claim cell, never from a list. The full rule is
in `docs/adr/0013-mapping-table-self-check.md` (D26); in summary, a term is
load-bearing when all of:

1. it survives stemming to at least 5 characters (a fixed suffix-stripping
   rule, so `downgraded` reaches `downgrad`; identifiers such as
   `external_anchor` yield both the whole identifier and its parts);
2. the cited document uses it **at least once**;
3. the cited document does **not** use it in more than a quarter of its
   top-level sections;
4. **no other Claim cell in any mapping table uses it.**

Rules 2 and 4 are what make the check bite rather than drown.

Rule 2, the lower bound, is the less obvious one. A term the cited document
never uses anywhere carries no information about *which section* is right: it
is usually report vocabulary rather than document vocabulary. Row 38 is still
caught, because its claim's real subject, `not_anchored`, did appear in the
README twice, just never in the subsection the row pointed at. **The defect
class this check exists for is a claim pointed at the wrong section of a
document that discusses it**, and a document frequency of at least one is
exactly the shape that selects for.

Rule 4 is the contrast axis, and its corpus is the Claim cells themselves. A
term two claims share is doing labelling work, not naming work: the
`Location | Claim | Maps to` tables put the claim's real wording in the
Location column and a label in the Claim column, so terms like `unchang`,
`reproducible`, `compliance` and `number` recur across rows and prove nothing
about any section.

**The corpus choice was forced, not preferred.** The first implementation
measured the contrast axis against whole report bodies. That made the verdict
depend on the prose of the errata recording the verdict: writing an erratum
about a failing row put that row's vocabulary into the corpus and retired the
failure, and deleting the erratum brought it back. This was observed live
during the phase, on `docs/reports/phase-2-completion-b.md` row 1. A check that
argues with its own write-up is not a check. Claim cells move only when a
mapping row is added or changed, which is the thing being measured.

Matching is anchored at a word start rather than anywhere in the string. A
stem has to prefix-match, but a bare substring match let `timeout` match
inside `ConnectTimeout` and pass a row whose cited section had nothing to do
with route timeouts.

**Scope narrowing.** A citation resolves to a numbered section and then
narrows to a named subsection when the row itself names one, matched against
the document's own heading titles. This is load-bearing for row 38: before the
fix, section 5 *as a whole* did contain the string `not_anchored`, in the
fail-closed table under the "Infrastructure Failure" subsection, while
"Residual Limits", the subsection the row's Kind actually pointed at, did not.
Checking section 5 whole would have passed the row.

### Demonstration, committed tree

Ten rows fail class (b), none of them in this phase's own table:

```
phase-1-3-complete.md row 15 b  readME.md 4.6      terms (given, replacement)
phase-1-3.md          row 9  b  readME.md 3.4      terms (semantic)
phase-1-3.md          row 14 b  readME.md 4.1      terms (sequence)
phase-1-3.md          row 15 b  readME.md 4.5      terms (message)
phase-1-3.md          row 16 b  readME.md 4.6      terms (number)
phase-1-3.md          row 18 b  readME.md 5 / Prompt Injection   terms (instruction)
phase-2.md            row 7  b  readME.md 6        terms (during)
phase-3a.md           row 3  b  readME.md 3.4.1    terms (authorization)
phase-3a.md           row 8  b  readME.md 3.4.1    terms (structural)
phase-3a.md           row 9  b  readME.md 3.4.1    terms (compliance)
```

Each of the ten was derived individually against the section it cites, and
**all ten are citation defects, not false claims.** Every cited section was
read directly and carries what its row claims: README section 4.5 carries the
exact `DENIED: Production environments must include a valid 'cost_center'
tag. Approved values: executive, finance.` string, section 4.6 carries the
endpoint table with its port numbers, section 6 carries the ADR-0007 summary,
section 3.4.1 carries "behind the same read credential `GET /audit` already
requires", "replaces `socket.socket.connect`" and "No cryptography is
implemented in the checker" verbatim. What fails in every case is the Claim
column: it labels the row rather than stating the claim, so the term rule is
left with `semantic`, `number`, `compliance` and their kin. Per-row reasoning
is in each report's dated erratum. None is Blocking.

### Demonstration, row 38 as it stood before its fix

```
$ git archive ab2a678 | tar -x -C <tree>
$ cp tools/mapping_check.py <tree>/tools/
$ python tools/mapping_check.py --repo <tree>
...
docs/reports/phase-3b.md row 38 [class b]: readME.md section 5 / Residual
  Limits (Mixed Profile, Since Phase 2) contains none of the claim's
  distinctive terms (external_anchor, not_anchor) :: external_anchor.state
  can be downgraded to not_anchored undetectably
```

Row 38 rather than 39 in that tree, because the verification pass later
inserted the `/anchors` credential-split row above it. Against the committed
tree the same row passes, because the fix put the disclosure into the Residual
Limits subsection. **This is the Y5/Y8 defect, caught mechanically, on the
tree where it was live.**

### Enforcing test

`tests/test_mapping_tables.py::test_every_cited_section_contains_a_distinctive_term_from_the_claim`,
supported by
`tests/test_mapping_tables.py::test_the_term_rule_selects_terms_rather_than_reading_a_list`,
which asserts the selection rule directly: that `not_anchored` survives
stemming, that it is selected as load-bearing (so the row-38 defect is
catchable), and that a term the README uses pervasively is never selected.

### Mutation

**Named mutation:** revert row 38's fix, meaning remove the disclosure from
`readME.md` while leaving the row.

PLACEHOLDER_MUTATION_2

---

## 3. P3c1-3. History is quarantined, not fixed

### The full run across every table

| Report | Rows | Cite a section | Class (a) fail | Class (b) fail | Shape-unchecked | Support-unchecked |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| `phase-1-3.md` §8 | 28 | 23 | 0 | 5 | 4 | 15 |
| `phase-1-3-complete.md` §9 | 38 | 25 | 0 | 1 | 12 | 17 |
| `phase-2.md` §3 | 17 | 8 | 0 | 1 | 1 | 5 |
| `phase-2-completion.md` §3 | 9 | 2 | 0 | 0 | 2 | 2 |
| `phase-2-completion-b.md` §3 | 2 | 1 | 0 | 0 | 0 | 1 |
| `phase-3a.md` §7 | 30 | 17 | 0 | 3 | 2 | 10 |
| `phase-3b.md` | 39 | 5 | 3 | 0 | 1 | 2 |
| `phase-3c1.md` (this report) | 14 | 0 | 0 | 0 | 0 | 0 |
| **Total** | **177** | **81** | **3** | **10** | **22** | **52** |

**Per class:** 3 class (a), all in `phase-3b.md`; 10 class (b), spread across
`phase-1-3.md` (5), `phase-3a.md` (3), `phase-1-3-complete.md` (1) and
`phase-2.md` (1). Thirteen failures total, in four of the eight tables.

**What the clean columns do not mean.** 22 of 177 rows name nothing
mechanically checkable at all, backing a claim with prose ("Live transcript
section 2 above", "Manual review", "Reproducible commands, unchanged"). They
are reported as unchecked, not passed. Of the 81 rows that cite a document
section, 52 yield no load-bearing term, so **class (b) is decisive on 29 rows,
not 81.** `docs/reports/phase-2-completion.md` is the sharpest case: its clean
result is entirely a class (a) result, because class (b) is decisive on none
of its rows. These numbers are in the report rather than folded into a pass.

### Errata, not edits

No historical row was edited. A dated erratum was appended to each of the
seven historical reports, including the three whose tables are clean, because
"checked and clean" and "never checked" are the two states this phase exists
to keep apart. Each erratum names its failing rows and the class of each, the
per-report coverage numbers, and the derivation showing why each failure is a
citation defect rather than a false claim.

| Report | Erratum | Rows named |
| :--- | :--- | :--- |
| `phase-1-3.md` | appended | rows 9, 14, 15, 16, 18, class (b); plus row 5, examined and passing, recorded because its citation has drifted |
| `phase-1-3-complete.md` | appended | row 15, class (b) |
| `phase-2.md` | §8 appended | row 7, class (b); plus row 15, a hand finding the check does not report |
| `phase-2-completion.md` | §6 appended | none failing; coverage recorded |
| `phase-2-completion-b.md` | §7 appended | none failing; row 1 recorded as a false negative found by hand |
| `phase-3a.md` | appended | rows 3, 8, 9, class (b) |
| `phase-3b.md` | appended | rows 2, 38, 39, class (a); plus the pre-fix class (b) result on row 39 |

### Triage: no false claim was found

The instruction requires escalation rather than an erratum if a historical row
is a **false claim** rather than a citation defect. **Each of the thirteen was
checked individually against the artefact it names, and none is a false
claim.** For every class (b) failure the cited section was read directly and
carries the substance of the claim in different words; for every class (a)
failure the declared backing exists and is named elsewhere in the same report.
Nothing is escalated as Blocking.

The row that came closest is **not** one of the thirteen, and is recorded here
because it is the sharpest finding of the phase.
`docs/reports/phase-2-completion-b.md` row 1 claims "Retargeted cluster; 45s
route timeout" and cites `docs/reports/phase-2.md` section 2 for a live
transcript. **That transcript does not exist.** Section 2 was read directly;
`45s`, `cluster` and `504` appear in that report only inside its own mapping
row and inside the errata quoting it, and the phrase the row gives elsewhere
for the transcript, "504 before the fix, 200 after", appears nowhere in its
evidence. This is the row-38 defect on a substantive claim rather than a
label. It is still a citation defect rather than a false claim, because the
claim is independently derivable without the cited transcript
(`envoy/envoy.yaml:43` carries `timeout: 45s`, and
`tests/test_envoy_config_boundary.py::test_every_network_cluster_targets_only_the_decision_service`
is collected and asserts the retargeting), so it is filed as an erratum. **The
committed check does not catch it**, for two reasons stated in the ADR and in
section 6 below.

### The baseline

`docs/reports/mapping-check-baseline.json`, committed, thirteen entries. Every
entry is named in this report: the three class (a) rows in section 1 and the
ten class (b) rows in section 2, and each appears again in its own report's
erratum.

`tests/test_mapping_tables.py` asserts four properties of it:

- **no failure outside the baseline**
  (`test_no_mapping_failure_outside_the_committed_baseline`). A new failure
  fails the build and is named as new, distinct from the baselined ones.
- **no entry that no longer fails**
  (`test_the_baseline_holds_no_entry_that_no_longer_fails`), so the baseline
  cannot silently accumulate.
- **no entry naming a row that does not exist**
  (`test_every_baseline_entry_names_a_real_row`).
- **nothing of this phase's own table in it**
  (`test_the_current_phase_table_is_clean_rather_than_baselined`).

**How a row leaves the baseline.** Not by editing the historical row, which is
forbidden. A row leaves when the artefact it cites changes so the row starts
resolving: a cited test is added under the name the row already used, or a
cited section gains the disclosure the row already claimed. The stale check
then fails the build and names the entry, and the entry is deleted in the same
commit, with the phase report saying which entry left and why.

### Mutation

**Named mutation:** add a new failing row to a historical table.

PLACEHOLDER_MUTATION_3

---

## 4. P3c1-4. Documentation

`docs/adr/0013-mapping-table-self-check.md` records D24 (class (a)), D25
(class (b), with row 38 as the worked example and the argument for why (a)
alone is insufficient), D26 (the term-selection rule with its measured
threshold sweep), and D27 (the baseline mechanism, including how a row leaves
it). It also records what the checks do not catch, the alternatives rejected,
and the circularity below.

### The circularity, stated rather than worked around

This report's own mapping table is checked by the same two checks, and the
tests that table cites are the same tests that implement them. If the checker
were broken in a way that made it find nothing, this table would pass
vacuously and so would every other, and the report would say "0 failures".

Two things narrow that, and neither closes it.
`test_every_mapping_table_in_docs_reports_is_discovered` re-counts the tables
with a second, deliberately dumb regex scan written independently of the
parser and requires the two to agree, so a parser that stopped seeing tables
fails the build rather than reporting health.
`test_a_kind_naming_a_test_requires_a_test_pytest_actually_collects` asserts
the collection rule itself rather than only its output.

What neither fixes: a checker and a table written in the same session by the
same author share that author's blind spots, and no amount of self-checking
reaches those. **What is genuinely removed is the specific failure this
project suffered three times**, which is a row nobody re-derived, because now
something re-derives every row on every CI run. The next red team should
attack `tools/mapping_check.py`, not the table it produces.

---

## 5. Mapping

Derived per row. Subject to both checks, and clean under both: this phase
fixes its own table rather than baselining it.

| Claim | Backed by | Kind |
| :--- | :--- | :--- |
| Mapping tables are discovered by structure, never from a list of filenames | `tests/test_mapping_tables.py::test_every_mapping_table_in_docs_reports_is_discovered` | test |
| The discovery agrees with an independent scan, so a parser that goes blind fails the build | `test_every_mapping_table_in_docs_reports_is_discovered` re-counts with a separate regex sweep | test |
| A Kind naming a test requires a function pytest actually collects, not merely a def | `tests/test_mapping_tables.py::test_a_kind_naming_a_test_requires_a_test_pytest_actually_collects` | test |
| A row declaring a backing kind its backing column does not name is a failure | `tests/test_mapping_tables.py::test_every_mapping_row_kind_matches_the_shape_of_its_backing` | test |
| A row citing a document section that does not discuss its claim is a failure | `tests/test_mapping_tables.py::test_every_cited_section_contains_a_distinctive_term_from_the_claim` | test |
| Load-bearing terms are derived from the claim and the corpus, with no curated list anywhere | `tests/test_mapping_tables.py::test_the_term_rule_selects_terms_rather_than_reading_a_list` | test |
| The term that catches phase 3b's downgrade row survives selection | `test_the_term_rule_selects_terms_rather_than_reading_a_list` asserts `not_anchor` is selected | test |
| A word the README uses pervasively is never treated as load-bearing | `test_the_term_rule_selects_terms_rather_than_reading_a_list` asserts the ceiling excludes it | test |
| A failure outside the committed baseline fails the build and is reported as new | `tests/test_mapping_tables.py::test_no_mapping_failure_outside_the_committed_baseline` | test |
| A baselined entry that stops failing fails the build, so the baseline cannot accumulate | `tests/test_mapping_tables.py::test_the_baseline_holds_no_entry_that_no_longer_fails` | test |
| The baseline may not carry an entry for a row that is not in any table | `tests/test_mapping_tables.py::test_every_baseline_entry_names_a_real_row` | test |
| This phase's own table is fixed rather than quarantined | `tests/test_mapping_tables.py::test_the_current_phase_table_is_clean_rather_than_baselined` | test |
| The whole run is reproducible outside pytest, including against an arbitrary tree | `python tools/mapping_check.py --repo <tree>`, the transcripts in sections 1 and 2 | command |
| Both check classes and the baseline mechanism are recorded as decisions | `docs/adr/0013-mapping-table-self-check.md`, D24 through D27 | document |

---

## 6. Pre-registered negatives, individually confirmed

- [ ] **Any mapping row in the current phase failing either check.**
- [ ] **Any historical failing row edited in place rather than recorded as a dated erratum.**
- [ ] **Any historical false claim filed as an erratum rather than escalated.**
- [ ] **Any hand-maintained term list that nothing derives.**
- [ ] **Any baseline entry added without the report naming it.**
- [ ] **Any assertion weakened.**
- [ ] **Any item met by live evidence alone with no test enforcing it.**

PLACEHOLDER_NEGATIVES

---

## 7. Could not verify / known gaps

PLACEHOLDER_GAPS

---

## 8. CI run id

PLACEHOLDER_CI
