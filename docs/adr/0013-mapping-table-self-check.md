# ADR-0013: The claim-mapping table checks itself

**Status:** Accepted
**Date:** 2026-08-25
**Phase:** 3c-1 (`p3c1-mapping`)
**Supersedes:** nothing. **Amends:** nothing. This ADR records a
documentation-integrity mechanism; it changes no product behaviour, no
service, no schema and no policy.

---

## Context

Since Phase 1.3 every phase report has carried a **claim-mapping table**: one
row per new or changed claim, naming what backs it. The table is the report's
own integrity mechanism, and it has failed three times running.

| Phase | Finding | What slipped |
| :--- | :--- | :--- |
| 1.3 | V1 | The mapping's completeness claim was itself unbacked |
| 2 | W8 | A row cited enforcement (`envoy/envoy.yaml`) that no test covered |
| 3b | Y5, Y8 | Row 38 cited `readME.md` section 5 for a disclosure not in it |
| 3b verify | B3 | Row 2's Kind said `test + command` over a backing that named no test |

Each of those instructions required the table to be derived per row. Each time
it was derived by hand, by a reader with 30-odd rows to check and no tool. The
common cause is not carelessness; it is that **nothing mechanical derived any
of it**, so the table drifts and only a full manual re-derivation finds the
drift. `docs/reports/phase-3b-verify.md` section B3 says so explicitly and
proposes the fix this ADR implements.

## Decision

Two checks run over every mapping table in `docs/reports/`, implemented in
`tools/mapping_check.py` and enforced by `tests/test_mapping_tables.py`.

### D24. Class (a): a row's Kind must match the shape of its backing

The Kind column declares what backs a claim. The check asserts that what it
declares exists in the shape it declares:

- a Kind naming a **test** requires a test function of that name that pytest
  actually collects: defined in a `tests/test_*.py` file with a `test_`
  prefix, per `pytest.ini`'s `testpaths = tests` and pytest's default naming
  convention. A `def` with the right name in a helper module nothing collects
  does not count.
- a Kind naming a **command** requires the backing to name a command, and the
  script it names to be present and to parse. "Runnable in form" stops at
  parsing: running it is not a documentation test's job, and would make this
  check depend on a live stack.
- a Kind naming **Residual Limits** requires the cited document and section to
  exist.

Where a table has no explicit Kind column (every table before Phase 3b used
`Location | Claim | Maps to`), the Kind is implicit and the same existence
checks run over every artefact the backing column names.

The Kind cell is parsed into atoms split on `+`, `,` and `;`, and only an atom
that is exactly a kind word counts. This preserves the project's existing
honesty convention: `command, marked: no test covers this` declares *command*
and nothing else, because "marked: no test covers this" is a disclosure, not a
kind. A looser word search would read the word "test" out of that disclaimer
and invert its meaning.

### D25. Class (b): a cited section must support the claim

Class (a) alone is not enough, and **row 38 is the worked example**.

Phase 3b's row 38 read:

```
| `external_anchor.state` can be downgraded to `not_anchored` undetectably
| Byte sweep pass 3; readME.md §5
| Residual Limits + command |
```

`readME.md` existed. Section 5 existed. Its Kind said Residual Limits and
Residual Limits is a real subsection of section 5. **The row is perfectly
shape-consistent and class (a) passes it.** What was not true is the only
thing that mattered: the downgrade disclosure was not in that subsection. A
reader who followed the citation found nothing, which is worse than no
citation at all, because the citation asserted that someone had checked.

So a second check: for each row citing a document section, at least one
**distinctive term** from the row's Claim column must appear in that section.

This is an approximation and that is the point. It cannot tell whether a
section *supports* a claim; it can only tell whether the section is about the
same thing. It turns "nobody checked" into "a keyword must appear", and that
is enough to have caught row 38.

**Scope resolution.** A citation resolves to a numbered section, then narrows
to a named subsection when the row itself names one. Row 38's Kind said
Residual Limits, and `readME.md` has a heading whose title begins "Residual
Limits", inside section 5, so the scope narrows to that subsection. This
matters concretely: before its fix, section 5 as a whole *did* contain the
string `not_anchored`, in the fail-closed table under a different subsection,
while Residual Limits, the subsection the row actually pointed at, did not.
Checking section 5 whole would have passed the row. The subsection is found by
matching the document's own heading titles against the row's text; nothing is
listed in the checker.

### D26. The term-selection rule

The instruction that produced this ADR required terms to be chosen from the
claim text rather than from a hand-maintained list, because a list nobody
derives is the same defect one level up. A term is **load-bearing** when all
of the following hold. Every threshold is a property of the corpus, not of a
curated list.

1. **It comes from the Claim cell.** The cell is stripped of markdown, split
   on non-identifier characters, and each word is stemmed by removing one of a
   fixed set of English suffixes (`ing`, `ed`, `es`, `s`, `ly` and relatives)
   down to a stem of at least 5 characters. `downgraded` and `downgrading`
   both reach `downgrad`. An identifier such as `external_anchor` yields both
   the whole identifier and its parts.
2. **It is at least 5 characters after stemming.** Below that a substring
   match is noise: `not` matches "nothing", `can` matches "cannot".
3. **The cited document uses it at least once** (`df >= 1`, measured over the
   document's own top-level sections).
4. **The cited document does not use it everywhere** (`df <= 0.25 * sections`).
   A word the document uses in most of its sections proves nothing about the
   one that was cited; a word it uses in at most a quarter of them is a word
   that section has to earn.
5. **No other Claim cell in any mapping table uses it.** Measured across all
   163 rows of all mapping tables in `docs/reports/`.

Rules 3 and 5 are the two that make the check usable, and rule 5 is the one
worth defending.

A Claim cell is not always a claim about the system. In the
`Location | Claim | Maps to` tables this project used from Phase 1.3 to 3a,
the Claim column is frequently a label for the row rather than a statement
about the system: "Unchanged this pass", "Reproducible command", "D20
compliance", "Port numbers", "Corrected this pass (R2, R5b)". Those cells
yield terms like `unchang`, `reproducible`, `compliance`, `number`, which are
mapping-table vocabulary. A README section that does not contain the word
"unchanged" has told you nothing, and a check that fails on that is a check
people learn to ignore. A term shared with another claim is a term doing
labelling work rather than naming work.

**The contrast corpus is the Claim cells, not the reports' prose, and that
choice was forced.** The first implementation measured against whole report
bodies. It made the verdict depend on the prose of the errata recording the
verdict: writing an erratum about a failing row put that row's own vocabulary
into the corpus and retired the failure, and deleting the erratum brought it
back. A check that argues with its own write-up is not a check. Claim cells
move only when a mapping row is added or changed, which is the thing being
measured.

**Matching is at a word start, not anywhere in the string.** A stem has to
prefix-match, so `downgrad` finds "downgraded"; a bare substring match also
let `timeout` match inside `ConnectTimeout` and passed a row whose cited
section had nothing to do with route timeouts.

**The threshold was measured, not guessed.** Sweeping the maximum number of
Claim cells allowed to share a term, against the committed tree and against
the pre-fix tree at `ab2a678` (the commit where row 38's defect was still
live):

| max claims sharing a term | class (b) failures | rows class (b) is decisive on, of 81 citing | row 38 pre-fix |
| ---: | ---: | ---: | :--- |
| 0 | 0 | 0 | **missed** |
| **1** | **10** | **29** | **caught** |
| 2 | 17 | 43 | caught |
| 3 | 17 | 46 | caught |
| 4 | 19 | 48 | caught |
| no limit | 31 | 62 | caught |

Row 38's pre-fix defect is caught at every setting above zero, so this
parameter does not trade away the defect the check exists for. It trades
coverage against noise. The failures added above 1 are the label-shaped Claim
cells described above rather than defects, each of which would enter the
baseline and have to be justified there. 1 was chosen, and the cost is stated
in Consequences rather than hidden: class (b) is decisive on 29 of the 81 rows
that cite a section.

### D27. History is quarantined in a baseline, not fixed in place

The checks run over every mapping table in `docs/reports/`, not only the
newest. Historical tables are **not edited**: this project corrects a shipped
report with a dated erratum, and a report quietly corrected is worth less than
one carrying its own corrections.

Known historical failures live in `docs/reports/mapping-check-baseline.json`,
which is committed. `tests/test_mapping_tables.py` asserts:

- **no failure outside the baseline.** A new failure fails the build and is
  named as new, distinct from the baselined ones.
- **no baseline entry that no longer fails.** A stale entry fails the build,
  so the baseline cannot silently accumulate entries nobody removes.
- **no baseline entry naming a row that does not exist.**
- **nothing of the current phase's own table in the baseline.** The current
  phase fixes its table; only history is quarantined.

**How a row leaves the baseline.** Not by editing the historical row, which is
forbidden. A row leaves when the artefact it cites changes so the row starts
resolving: a cited test is added under the name the row already used, or a
cited section gains the disclosure the row already claimed. The stale check
then fails the build and names the entry, and the entry is deleted from the
baseline in the same commit, with the phase report saying which entry left and
why. The baseline is a record of known-bad rows, never a permanent excuse
attached to one.

**A coupling worth stating.** Rule 5 measures across every Claim cell in
every mapping table, so adding a mapping row anywhere can move a term across
the threshold and add or retire a baseline entry with no historical row having
changed. This is far narrower than the first implementation's coupling to
report prose, and it is not silent either: the stale check fails the build and
names the entry. It does mean the baseline is re-derived and re-justified when
a new phase report lands, rather than being append-only.

## Consequences

**What this catches.** A row citing a test that does not exist or is not
collected; a row citing a path or a command script that does not exist; a row
whose Kind claims a backing kind its backing column does not name; a row
citing a document section that does not exist; a row citing a section that
does not discuss the claim. Rows 2, 38 and 39 of Phase 3b's table are all
caught, two of them by class (a) and one by class (b).

**What this does not catch, stated plainly.**

- **A claim that is simply false, backed by a real test that tests something
  else.** Class (a) checks that the test exists; nothing here reads it. That
  is triage-Blocking territory and stays a human judgement.
- **Rows naming nothing checkable.** 22 of 163 historical rows back a claim
  with prose ("Live transcript section 2 above", "Manual review", "Unchanged
  this pass"). The checker reports these as unchecked rather than passing
  them, and the phase report carries the count. They are not failures, and
  they are not coverage either.
- **Rows whose claim yields no load-bearing term.** 52 of the 81 rows that
  cite a section fall here, almost all of them label-shaped Claim cells in the
  older tables. Class (b) is decisive on 29 rows of 81. The report carries
  this number rather than reporting "0 failures" as though it meant "81 rows
  verified".

- **A claim cited into a report that contains the mapping row itself.** The
  term rule measures rarity inside the cited document, so when the cited
  document is a phase report, the row's own claim text counts toward making
  its own terms look common. `docs/reports/phase-2-completion-b.md` row 1 is
  a live instance: it cites `docs/reports/phase-2.md` section 2 for an Envoy
  route-timeout transcript that is not there, which is exactly the row 38
  defect on a substantive claim, and the check does not report it, because
  `cluster` occurs in three of that report's sections, all of them discussing
  this row. Found by hand during this phase, recorded in that report's
  erratum and in `docs/reports/phase-3c1.md`, and not baselined, because a
  baseline records what the check reports.

- **An unqualified section marker.** "section 2 above" names no document and
  is deliberately not treated as a citation: it usually points inside the
  report making it, which no external artefact can confirm. This is why
  `docs/reports/phase-2.md` row 15 escapes the check while the identical claim
  in `phase-2-completion-b.md` row 1, which does name a document, is at least
  parsed.
- **A row citing one supporting section alongside one irrelevant one.** A row
  passes when *any* one of its cited sections carries the claim's vocabulary.
  Requiring every cited section to carry it would fail rows that deliberately
  split a claim across a normative section and a limits section, which this
  project does routinely.
- **Wording drift in the other direction.** A section rewritten to use
  different words for the same thing turns a good row into a class (b)
  failure. `docs/reports/phase-1-3.md` row 5 was exactly this case during
  development: its claim said "static-secret theft" and the subsection it
  cited had been rewritten in Phase 2. It resolves through the row's other
  citation, but a row with only one citation would not.

**The circularity, since this ADR is cited by a table the checks run over.**
The Phase 3c-1 report's own mapping table is checked by the same two checks,
and the tests that enforce them are the same tests that table cites. If the
checker were broken in a way that made it find nothing, the report's table
would pass vacuously and so would every other. This is why
`test_every_mapping_table_in_docs_reports_is_discovered` re-counts the tables
with a second, deliberately dumb regex scan written independently of the
parser, and requires the two to agree, and why
`test_a_kind_naming_a_test_requires_a_test_pytest_actually_collects` asserts
the collection rule itself rather than only its output. It does not fully
dissolve the circularity: a checker and a table written in the same session
share an author's blind spots, and no amount of self-checking fixes that.
What it does remove is the specific failure this project actually suffered
three times, which is a row nobody re-derived. The next red team should attack
the checker, not the table.

## Alternatives considered

**Derive the Kind column and delete it.** The verify pass suggested this: Kind
is a function of the backing column, so it could be computed rather than
written. Rejected because deleting the column removes the disagreement the
check reads. Row 2 was caught precisely because a human wrote `test + command`
and the backing said otherwise; with Kind derived, there would have been
nothing to disagree with, and the row would have silently become "command".

**Fix the historical tables.** Rejected: `docs/reports/cleanup-p13-b.md`
established that historical reports are point-in-time records corrected by
dated erratum, not edited. Editing them would also destroy the evidence that
the drift happened.

**Fail the build on unchecked rows.** Rejected for this phase: 22 shape-
unchecked and 52 support-unchecked rows are all historical, and turning them
into failures would put 74 entries into the baseline, which is a baseline
nobody reads. The counts are reported instead, and a future phase can tighten
the bar for new tables specifically.

## References

- `tools/mapping_check.py`, `tests/test_mapping_tables.py`
- `docs/reports/mapping-check-baseline.json`
- `docs/reports/phase-3c1.md`
- `docs/reports/phase-3b-verify.md` section B3, which proposed this
- `docs/reports/phase-3b-redteam.md` (Y5, Y8), `docs/reports/phase-2-completion-b.md` (W8),
  `docs/reports/phase-1-3-redteam.md` (V1)
