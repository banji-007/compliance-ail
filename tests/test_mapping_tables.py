"""
tests/test_mapping_tables.py

Phase 3c-1. The claim-mapping tables in docs/reports/ are checked, not
asserted.

Three consecutive phases required per-row derivation of a mapping table and
three consecutive red-team or verification passes found a row that had
slipped anyway: Phase 1.3's V1, Phase 2's W8, Phase 3b's Y5 and Y8. The
common cause is that nothing mechanical derived any of it, so every pass had
to re-derive 30-odd rows by hand and every pass missed one.

Two checks run here, over every mapping table in docs/reports/, not only the
newest. They are not the same check and shipping only the first leaves the
defect that actually misled a reader:

  class (a), shape   - what a row's Kind declares must exist in the shape it
                       declares. Caught phase-3b row 2, whose Kind said
                       "test + command" over a backing column that named no
                       test.

  class (b), support - a cited document section must actually contain the
                       claim. Caught phase-3b row 38, which cited readME.md
                       section 5 for a disclosure that was not in it. That
                       row is perfectly shape consistent, so class (a) passes
                       it, which is the whole reason class (b) exists.

Historical failures are quarantined in a committed baseline
(docs/reports/mapping-check-baseline.json) rather than fixed in place: this
project corrects a shipped report with a dated erratum, never by editing the
original claim away. A new failure fails the build; a known one does not, and
a baselined row that stops failing also fails the build, so the baseline
cannot silently accumulate entries nobody ever removes.

See docs/adr/0013-mapping-table-self-check.md.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECKER_SRC = REPO_ROOT / "tools" / "mapping_check.py"
BASELINE_FILE = REPO_ROOT / "docs" / "reports" / "mapping-check-baseline.json"

# The reports this phase writes. Their tables are held to a stricter rule than
# the historical ones: zero failures, nothing baselined. Both passes of Phase
# 3c-1 are here, because the completion pass rewrote the first pass's table
# rather than appending an erratum to it: that report is unmerged, on the same
# branch, and is this phase's own artifact rather than shipped history.
CURRENT_PHASE_REPORTS = (
    "docs/reports/phase-3c1.md",
    "docs/reports/phase-3c1-complete.md",
)


def _load_checker():
    """Load tools/mapping_check.py by path.

    Same reason tests/test_offline_verify.py loads the offline checker this
    way: an unqualified import would depend on sys.path ordering that differs
    between a bare pytest run and the containerised suite.
    """
    spec = importlib.util.spec_from_file_location("mapping_check", CHECKER_SRC)
    module = importlib.util.module_from_spec(spec)
    # Registered before exec: the checker's dataclasses are declared under
    # "from __future__ import annotations", and dataclasses resolves a field's
    # module through sys.modules while the class body runs.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def checker():
    module = _load_checker()
    module._DOC_CACHE.clear()
    module._VOCAB_CACHE.clear()
    return module


@pytest.fixture(scope="module")
def results(checker):
    return checker.run(REPO_ROOT)


@pytest.fixture(scope="module")
def baseline(checker):
    return checker.load_baseline(REPO_ROOT)


def _describe(failures):
    return "\n".join("  " + str(f) for f in failures)


# ---------------------------------------------------------------------------
# The checker must see every table there is
# ---------------------------------------------------------------------------

def _independent_scan():
    """A second opinion on what is in docs/reports/, sharing nothing with the parser.

    The version this replaces was not a second opinion. It reimplemented the
    parser's own two blind spots, a `startswith("|")` line filter and a
    non-recursive glob, and it counted tables rather than rows. Red team
    rt-p3c1-a got three constructed tables and one hidden row past both at
    once, and the two agreed every time: the same opinion twice.

    This one walks with os.walk instead of pathlib, accepts a row with or
    without outer pipes, splits on unescaped pipes with a different mechanism
    (a hand loop, not the parser's regex), and returns row counts as well as
    table count, so a row leaving a table is visible and not only a table
    leaving the tree.
    """
    def split(line):
        cells, buf, k = [], [], 0
        while k < len(line):
            ch = line[k]
            if ch == "\\" and k + 1 < len(line) and line[k + 1] == "|":
                buf.append("|")
                k += 2
                continue
            if ch == "|":
                cells.append("".join(buf))
                buf = []
                k += 1
                continue
            buf.append(ch)
            k += 1
        cells.append("".join(buf))
        if cells and not cells[0].strip():
            cells = cells[1:]
        if cells and not cells[-1].strip():
            cells = cells[:-1]
        return [c.strip() for c in cells]

    tables, rows = 0, 0
    for dirpath, dirnames, filenames in os.walk(os.path.join(REPO_ROOT, "docs", "reports")):
        for filename in sorted(filenames):
            if not filename.endswith(".md"):
                continue
            text = Path(dirpath, filename).read_text(encoding="utf-8")
            lines = text.splitlines()
            fenced, open_fence = set(), False
            for idx, line in enumerate(lines):
                if line.lstrip().startswith(("```", "~~~")):
                    open_fence = not open_fence
                    fenced.add(idx)
                elif open_fence:
                    fenced.add(idx)
            idx = 0
            while idx < len(lines) - 1:
                if idx in fenced or idx + 1 in fenced:
                    idx += 1
                    continue
                cells = [
                    re.sub(r"\s+", " ", re.sub(r"\([^)]*\)", "", c).strip(" `*_").lower()).strip()
                    for c in split(lines[idx])
                ]
                below = split(lines[idx + 1])
                if len(below) != len(cells) or not below:
                    idx += 1
                    continue
                if not all(re.fullmatch(r":?-{2,}:?", c.strip()) for c in below):
                    idx += 1
                    continue
                if "claim" not in cells or not ({"maps to", "backed by"} & set(cells)):
                    idx += 1
                    continue
                tables += 1
                j = idx + 2
                while (
                    j < len(lines)
                    and j not in fenced
                    and lines[j].strip()
                    and not lines[j].lstrip().startswith("#")
                    and "|" in lines[j]
                ):
                    rows += 1
                    j += 1
                idx = j
    return tables, rows


def test_every_mapping_table_and_row_in_docs_reports_is_discovered(checker):
    """The independent scan must agree with the parser on tables and on rows.

    Named mutation: hide a row from the parser. This test must fail.
    """
    naive_tables, naive_rows = _independent_scan()
    found = checker.find_mapping_tables(REPO_ROOT)
    parsed_rows = sum(len(t.rows) for t in found)

    assert found, "no mapping tables found at all under docs/reports/"
    assert naive_tables == len(found), (
        "the independent scan found %d mapping tables and the checker found %d; "
        "the checker is skipping a table" % (naive_tables, len(found))
    )
    assert naive_rows == parsed_rows, (
        "the independent scan counted %d mapping rows and the checker counted "
        "%d; a row is leaving a table the checker is running over"
        % (naive_rows, parsed_rows)
    )


def test_the_current_phase_reports_carry_a_mapping_table(checker):
    """This phase's own reports are subject to both checks, not exempt from them."""
    reports = {t.report for t in checker.find_mapping_tables(REPO_ROOT)}
    for expected in CURRENT_PHASE_REPORTS:
        assert expected in reports, (
            "%s carries no mapping table with a Claim column and a backing column"
            % expected
        )


# ---------------------------------------------------------------------------
# P3c1-1, class (a): Kind matches the shape of its backing
# ---------------------------------------------------------------------------

def test_every_mapping_row_kind_matches_the_shape_of_its_backing(
    checker, results, baseline
):
    """Class (a). Nothing a row declares may be absent in the shape declared.

    Named mutation: change one row's Kind so it names a test that does not
    exist. This test must fail.
    """
    failures = [f for f in checker.all_failures(results) if f.cls == "a"]
    unexpected = [f for f in failures if f.key() not in baseline]
    assert not unexpected, (
        "%d mapping row(s) declare a backing that does not exist in the shape "
        "declared, and are not in the committed baseline:\n%s"
        % (len(unexpected), _describe(unexpected))
    )


def test_a_kind_naming_a_test_requires_a_test_pytest_actually_collects(checker):
    """The shape check means collected, not merely defined somewhere.

    A def with the right name in a helper module pytest never collects would
    otherwise satisfy a row claiming a test backs it.
    """
    collected = checker.Collected(REPO_ROOT)
    assert collected.functions, "no test functions were collected at all"
    for name, where in collected.functions.items():
        assert name.startswith("test_")
        for path in where:
            assert path.startswith("tests/"), (
                "%s was collected from %s, outside tests/" % (name, path)
            )
            assert Path(path).name.startswith("test_"), (
                "%s was collected from %s, which pytest's default naming "
                "convention does not pick up" % (name, path)
            )


# ---------------------------------------------------------------------------
# P3c1-2, class (b): the cited section supports the claim
# ---------------------------------------------------------------------------

def test_every_cited_section_contains_a_distinctive_term_from_the_claim(
    checker, results, baseline
):
    """Class (b). A row citing a document section must be supported by it.

    Named mutation: remove the external_anchor.state downgrade disclosure from
    readME.md's Residual Limits while leaving phase-3b's row in place, which
    is exactly the state row 38 was in before its fix. This test must fail.
    """
    failures = [f for f in checker.all_failures(results) if f.cls == "b"]
    unexpected = [f for f in failures if f.key() not in baseline]
    assert not unexpected, (
        "%d mapping row(s) cite a document section that carries none of the "
        "claim's distinctive terms, and are not in the committed baseline:\n%s"
        % (len(unexpected), _describe(unexpected))
    )


def test_the_term_rule_selects_terms_rather_than_reading_a_list(checker):
    """The load-bearing terms are derived from the claim and the corpus.

    A hand-maintained term list nobody derives is the defect this phase
    exists to fix, one level up, so the rule itself is asserted: a term must
    be present in the cited document, rare within it, and not ordinary report
    vocabulary. not_anchored is the worked example, because it is the term
    that catches phase-3b's row 38.
    """
    readme = checker.load_document(REPO_ROOT, "readME.md")
    assert readme is not None
    index = checker.TermIndex(readme, checker.report_vocabulary(REPO_ROOT))

    terms = checker.claim_terms(
        "`external_anchor.state` can be downgraded to `not_anchored` undetectably"
    )
    assert "not_anchor" in terms, (
        "stemming lost the claim's own subject: %r" % (terms,)
    )

    selected = [t for _df, t in index.distinctive(terms)]
    assert "not_anchor" in selected, (
        "not_anchored is not selected as load-bearing, so the row-38 defect "
        "would not be caught; selected=%r" % (selected,)
    )

    # A word the README uses in most of its sections must never be selected:
    # a section containing it has not earned anything.
    everywhere = [
        t for t in checker.claim_terms("the record and the policy and the ledger")
        if index.document_frequency(t) > index.total * checker._DISTINCTIVE_FRACTION
    ]
    assert everywhere, "the corpus has no pervasive term to test the ceiling with"
    assert not set(everywhere) & set(selected)


# ---------------------------------------------------------------------------
# P3c1-3: history is quarantined in a baseline, not fixed
# ---------------------------------------------------------------------------

def test_no_mapping_failure_outside_the_committed_baseline(
    checker, results, baseline
):
    """The build gate. A new failure fails; a baselined one does not.

    Named mutation: add a new failing row to a historical table. This test
    must fail, and must name it as new rather than folding it in with the
    baselined ones.
    """
    assert baseline, (
        "%s is missing or empty; the baseline is committed, not generated at "
        "test time" % BASELINE_FILE.relative_to(REPO_ROOT).as_posix()
    )
    new, known, _stale = checker.classify_against_baseline(results, baseline)
    assert not new, (
        "%d new mapping failure(s), on top of %d known and baselined:\n%s"
        % (len(new), len(known), _describe(new))
    )


def test_the_baseline_holds_no_entry_that_no_longer_fails(
    checker, results, baseline
):
    """A row leaves the baseline by being fixed and having its entry deleted.

    Without this, a baseline drifts into a list of things that used to be
    wrong, and a genuinely fixed row keeps a permanent excuse attached to it.
    """
    _new, _known, stale = checker.classify_against_baseline(results, baseline)
    assert not stale, (
        "%d baseline entr(ies) no longer fail and must be deleted from %s:\n%s"
        % (
            len(stale),
            BASELINE_FILE.relative_to(REPO_ROOT).as_posix(),
            "\n".join("  " + key for key in stale),
        )
    )


def test_every_baseline_entry_names_a_real_row(checker, baseline):
    """The baseline may not carry an entry for a row that does not exist."""
    rows = set()
    for table in checker.find_mapping_tables(REPO_ROOT):
        for row in table.rows:
            rows.add((table.report, row.number))
    for key, entry in sorted(baseline.items()):
        assert (entry["report"], entry["row"]) in rows, (
            "baseline entry %s names a row that is not in any mapping table" % key
        )


def test_the_current_phase_table_is_clean_rather_than_baselined(
    checker, results, baseline
):
    """This phase fixes its own table. Nothing of its own goes in the baseline."""
    own = [
        f
        for f in checker.all_failures(results)
        if f.report in CURRENT_PHASE_REPORTS
    ]
    assert not own, (
        "this phase's own mapping table has %d failing row(s); the instruction "
        "is to fix the current table, not baseline it:\n%s"
        % (len(own), _describe(own))
    )
    baselined_own = [
        k for k, e in baseline.items() if e["report"] in CURRENT_PHASE_REPORTS
    ]
    assert not baselined_own, (
        "this phase's own table has baseline entries: %r" % (baselined_own,)
    )


def test_the_baseline_file_is_readable_and_shaped_as_expected():
    data = json.loads(BASELINE_FILE.read_text(encoding="utf-8"))
    assert isinstance(data.get("entries"), list)
    for entry in data["entries"]:
        assert set(entry) >= {"key", "report", "row", "class", "reason"}
        assert entry["class"] in {"a", "b"}
        assert entry["key"] == "%s#%d#%s#%s" % (
            entry["report"], entry["row"], entry["class"],
            re.sub(r"\s+", " ", entry["reason"]).strip(),
        )


def test_a_second_failure_of_a_baselined_class_on_a_baselined_row_reports_as_new(checker):
    """The reason is part of a failure's identity, so a slot does not stay open.

    Named mutation: add a second class (a) failure to an already-baselined row.
    That is red team rt-p3c1-a's Z4, which reported "0 new" against a key of
    report, row and class alone.
    """
    real = checker.load_baseline(REPO_ROOT)
    assert real, "the baseline is committed, not generated at test time"
    sample = sorted(real.values(), key=lambda e: (e["report"], e["row"], e["class"]))[0]

    known = checker.Failure(
        sample["report"], sample["row"], sample["class"], sample["reason"], "x"
    )
    second = checker.Failure(
        sample["report"], sample["row"], sample["class"],
        "cited path tests/test_that_does_not_exist.py does not resolve to a file "
        "in this tree",
        "x",
    )
    assert known.key() in real
    assert second.key() not in real, (
        "a second failure of the same class on the same row shares an identity "
        "with the baselined one, so the baseline absorbs it"
    )

    stub = checker.ReportResult(sample["report"], 1, 0)
    stub.failures = [known, second]
    new, known_out, stale = checker.classify_against_baseline([stub], real)
    assert [f.reason for f in new] == [second.reason], (
        "the second failure was not reported as new: %r" % ([f.reason for f in new],)
    )
    assert len(known_out) == 1, (
        "two failures on one row and class collapsed before the comparison ran"
    )


def _table_from(tmp_path, body, name="synthetic.md"):
    target = tmp_path / "docs" / "reports" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")
    return target


def test_a_table_written_without_outer_pipes_is_discovered(checker, tmp_path):
    """Leading and trailing pipes are optional in GitHub-flavoured markdown."""
    _table_from(tmp_path, (
        "# Synthetic\n\n"
        "Claim | Backed by | Kind\n"
        ":--- | :--- | :---\n"
        "The budget is bounded | `tests/test_absent.py::test_absent` | test\n"
    ))
    tables = checker.find_mapping_tables(tmp_path)
    assert len(tables) == 1, "a table without outer pipes was not discovered"
    assert len(tables[0].rows) == 1
    assert tables[0].rows[0].claim == "The budget is bounded"


def test_a_table_in_a_subdirectory_of_docs_reports_is_discovered(checker, tmp_path):
    """The walk is recursive; a subdirectory is not a hiding place."""
    _table_from(tmp_path, (
        "# Appendix\n\n"
        "| Claim | Backed by | Kind |\n"
        "| :--- | :--- | :--- |\n"
        "| The budget is bounded | `tests/test_absent.py::test_absent` | test |\n"
    ), name="appendix/deep.md")
    tables = checker.find_mapping_tables(tmp_path)
    # Built from parts rather than written as a literal: a literal would read
    # as a reference to a docs/ path that does not exist, which
    # test_every_referenced_docs_path_exists_in_this_commit correctly rejects.
    expected = "/".join(["docs", "reports", "appendix", "deep.md"])
    assert [t.report for t in tables] == [expected]


def test_an_escaped_pipe_stays_inside_its_cell(checker, tmp_path):
    """The markdown escape is honoured, so the row is not one cell too wide."""
    _table_from(tmp_path, (
        "# Synthetic\n\n"
        "| Claim | Backed by | Kind |\n"
        "| :--- | :--- | :--- |\n"
        "| Bounded \\| and audited | `tests/test_absent.py::test_absent` | test |\n"
    ))
    rows = checker.find_mapping_tables(tmp_path)[0].rows
    assert len(rows) == 1
    assert not rows[0].malformed
    assert rows[0].claim == "Bounded | and audited"


def test_a_row_whose_cell_count_does_not_match_the_header_is_a_failure(checker, tmp_path):
    """A row may not leave a table silently.

    The escaped pipe is one way to produce a cell-count mismatch and it is now
    handled, but the defect red team rt-p3c1-a found is the silent drop, not
    that one cause. Any mismatch, however produced, is a class (a) failure.
    """
    _table_from(tmp_path, (
        "# Synthetic\n\n"
        "| Claim | Backed by | Kind |\n"
        "| :--- | :--- | :--- |\n"
        "| Bounded | `tests/test_absent.py::test_absent` | test |\n"
        "| Bounded | too | many | cells |\n"
    ))
    tables = checker.find_mapping_tables(tmp_path)
    rows = tables[0].rows
    assert len(rows) == 2, "the malformed row was dropped instead of counted"
    assert rows[1].malformed and rows[1].cell_count == 4

    results = checker.run(tmp_path)
    reasons = [f.reason for f in checker.all_failures(results) if f.row == 2]
    assert any("does not parse" in r for r in reasons), (
        "a row that does not parse produced no failure: %r" % (reasons,)
    )


def test_every_narrowed_citation_is_pinned_to_the_heading_it_matched(checker, results):
    """Class (b)'s scope narrowing may not stop happening silently.

    Narrowing is found by matching a document's heading titles against the
    row's text, so retitling the heading widens the search back to the whole
    section and the row starts passing on terms from somewhere else. Red team
    rt-p3c1-a (Z3-a) used one retitle to neutralise this phase's own named
    class (b) mutation.

    Named mutation: retitle a pinned heading. This test must fail by name.
    """
    pins = checker.load_pins(REPO_ROOT)
    assert pins, "docs/reports/heading-pins.json is missing or empty"

    unpinned, changed, stale = checker.classify_against_pins(results, pins)
    assert not unpinned, (
        "%d narrowed citation(s) have no pin, so a retitle of the heading they "
        "match would widen the search silently:\n%s"
        % (len(unpinned), "\n".join(
            "  %s row %d -> %s section %s %r" % (n.report, n.row, n.doc, n.section, n.title)
            for n in unpinned))
    )
    assert not changed, (
        "%d cited heading(s) were retitled, so class (b) is now searching a "
        "wider scope than when the row was derived:\n%s"
        % (len(changed), "\n".join(
            "  %s row %d -> %s section %s is now %r, pinned as %r"
            % (n.report, n.row, n.doc, n.section, n.title, was)
            for n, was in changed))
    )
    assert not stale, (
        "%d pin(s) match no narrowing any more, so those rows are being checked "
        "against a whole section:\n%s" % (len(stale), "\n".join("  " + k for k in stale))
    )


def test_class_b_reports_no_pass_bucket(checker, results):
    """Class (b) is a falsifier. Every citing row is failed or not decided.

    A reported pass would overstate itself: a distinctive term can match by
    accident, which red team rt-p3c1-a demonstrated with a claim satisfied by
    the stem `govern` matching `governance` in a closing tagline.
    """
    for result in results:
        assert result.undecided_support == result.citing - result.count("b"), (
            "%s reports a third bucket between failed and not decided"
            % result.report
        )
        assert result.undecided_support >= 0
    assert not hasattr(checker.ReportResult, "unchecked_support"), (
        "the supported count is back"
    )
