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
import sys
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECKER_SRC = REPO_ROOT / "tools" / "mapping_check.py"
BASELINE_FILE = REPO_ROOT / "docs" / "reports" / "mapping-check-baseline.json"

# The report this phase writes. Its own table is held to a stricter rule than
# the historical ones: zero failures, nothing baselined.
CURRENT_PHASE_REPORT = "docs/reports/phase-3c1.md"


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

def test_every_mapping_table_in_docs_reports_is_discovered(checker):
    """A second, deliberately dumb scan must agree with the checker's parser.

    A checker that silently stopped finding tables would report zero failures
    and look healthy. This counts qualifying header rows with a plain regex
    sweep, independent of MappingTable's parsing, and requires the two to
    agree.
    """
    header = re.compile(r"^\|.*\|.*\|")
    naive = 0
    for path in sorted((REPO_ROOT / "docs" / "reports").glob("*.md")):
        lines = path.read_text(encoding="utf-8").splitlines()
        for idx, line in enumerate(lines[:-1]):
            if not header.match(line.strip()):
                continue
            cells = [
                re.sub(r"\([^)]*\)", "", c).strip(" `*_").lower()
                for c in line.strip().strip("|").split("|")
            ]
            cells = [re.sub(r"\s+", " ", c).strip() for c in cells]
            following = lines[idx + 1].strip().strip("|").split("|")
            if not all(re.fullmatch(r":?-{2,}:?", c.strip()) for c in following):
                continue
            if "claim" in cells and ({"maps to", "backed by"} & set(cells)):
                naive += 1

    found = checker.find_mapping_tables(REPO_ROOT)
    assert naive == len(found), (
        "the independent scan found %d mapping tables and the checker found %d; "
        "the checker is skipping a table" % (naive, len(found))
    )
    assert found, "no mapping tables found at all under docs/reports/"


def test_the_current_phase_report_carries_a_mapping_table(checker):
    """This phase's own report is subject to both checks, not exempt from them."""
    reports = {t.report for t in checker.find_mapping_tables(REPO_ROOT)}
    assert CURRENT_PHASE_REPORT in reports, (
        "%s carries no mapping table with a Claim column and a backing column"
        % CURRENT_PHASE_REPORT
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
        if f.report == CURRENT_PHASE_REPORT
    ]
    assert not own, (
        "this phase's own mapping table has %d failing row(s); the instruction "
        "is to fix the current table, not baseline it:\n%s"
        % (len(own), _describe(own))
    )
    baselined_own = [k for k, e in baseline.items() if e["report"] == CURRENT_PHASE_REPORT]
    assert not baselined_own, (
        "this phase's own table has baseline entries: %r" % (baselined_own,)
    )


def test_the_baseline_file_is_readable_and_shaped_as_expected():
    data = json.loads(BASELINE_FILE.read_text(encoding="utf-8"))
    assert isinstance(data.get("entries"), list)
    for entry in data["entries"]:
        assert set(entry) >= {"key", "report", "row", "class", "reason"}
        assert entry["class"] in {"a", "b"}
        assert entry["key"] == "%s#%d#%s" % (
            entry["report"], entry["row"], entry["class"]
        )
