"""
tools/mapping_check.py

Phase 3c-1. The claim-mapping tables in docs/reports/ check themselves.

Three consecutive phases produced the same finding: a mapping row asserted
rather than derived (Phase 1.3's V1, Phase 2's W8, Phase 3b's Y5 and Y8).
Each instruction required per-row derivation and each time a row slipped,
because nothing mechanical derived the table. This module derives it.

There are two checks, and they fail differently. Shipping only the first one
leaves the defect that actually misled a reader.

Class (a), SHAPE. The Kind a row declares must match the shape of what its
backing column names. A Kind naming a test means a test function of that name
is defined under tests/ and is collected by pytest. A Kind naming a command
means the command's script is present and parses. A Kind naming Residual
Limits means the cited document and section exist. Phase 3b's row 2 failed
here: its Kind said "test + command" and its backing column named only a
byte-sweep pass, no test.

Class (b), SUPPORT. A row citing a document section must have that section
actually contain the claim. Phase 3b's row 38 was perfectly shape consistent
(it cited readME.md section 5, which existed) and the disclosure it claimed
was not in it. A shape check passes that row. This check approximates support
by requiring a distinctive term from the row's own Claim column to appear in
the cited section. It is an approximation and that is the point: it turns
"nobody checked" into "a keyword must appear".

Neither check reads a hand-maintained list of tables, rows, or terms. A
hand-maintained list nobody derives is the defect this module exists to fix,
one level up.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

BASELINE_PATH = Path("docs") / "reports" / "mapping-check-baseline.json"


# ---------------------------------------------------------------------------
# Discovering mapping tables
# ---------------------------------------------------------------------------

# A mapping table is recognised structurally, by its header row, not by being
# named in a list. It must carry a Claim column and a backing column. The two
# backing-column spellings this project has used are "Maps to" (phase 1.3
# through 3a) and "Backed by" (phase 3b onward). Recognising a shape rather
# than a filename is what makes the set of checked tables derived: a new
# report with the same header is picked up with no edit here.
_CLAIM_HEADERS = {"claim"}
_BACKING_HEADERS = {"maps to", "backed by"}
_KIND_HEADERS = {"kind"}
_LOCATION_HEADERS = {"location", "readme/adr location"}


def _normalise_header(cell):
    """Lowercase, drop markdown emphasis and any trailing parenthetical.

    "Maps to (corrected)" and "**Maps to**" both normalise to "maps to", so
    phase-2-completion-b's delta table is recognised as the same shape.
    """
    text = cell.strip()
    text = re.sub(r"[`*_]", "", text)
    text = re.sub(r"\([^)]*\)", "", text)
    return re.sub(r"\s+", " ", text).strip().lower()


def _split_row(line):
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|"):
        stripped = stripped[:-1]
    return [c.replace(r"\|", "|").strip() for c in stripped.split("|")]


def _is_separator(cells):
    return bool(cells) and all(re.fullmatch(r":?-{2,}:?", c) for c in cells)


@dataclass
class MappingRow:
    number: int      # 1-based index among the table's data rows
    claim: str
    backing: str
    kind: str        # "" when the table has no Kind column
    line: int        # 1-based line number in the report
    location: str = ""       # "" when the table has no Location column
    location_doc: str = ""   # document the Location column's own header names

    def citing_text(self):
        """Every (cell, default document) this row can cite a section from.

        The Location column names where a claim lives and the backing column
        names what supports it. Both are citations into a document, and both
        are subject to class (b): a row saying "README section 3.4.1 claims X"
        is making the same kind of assertion row 38 made, and can be wrong the
        same way.

        The default document matters for phase-1.3's table, whose Location
        column is headed "README/ADR location" and whose cells therefore write
        a bare section marker: the header already said which document. The
        header is the table's own text, so reading it is derivation, not a
        hardcoded guess.
        """
        out = []
        if self.location:
            out.append((self.location, self.location_doc))
        if self.backing:
            out.append((self.backing, ""))
        return out


@dataclass
class MappingTable:
    report: str      # repo-relative, forward slashes
    heading: str
    header_line: int
    columns: list
    rows: list = field(default_factory=list)

    @property
    def has_kind_column(self):
        return any(_normalise_header(c) in _KIND_HEADERS for c in self.columns)


def find_mapping_tables(repo_root=REPO_ROOT):
    """Every mapping table under docs/reports/, discovered by header shape."""
    tables = []
    for path in sorted((repo_root / "docs" / "reports").glob("*.md")):
        tables.extend(_tables_in(path, repo_root))
    return tables


def _tables_in(path, repo_root):
    lines = path.read_text(encoding="utf-8").splitlines()
    found = []
    heading = ""
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("#"):
            heading = line.lstrip("#").strip()
        if line.strip().startswith("|") and i + 1 < len(lines):
            header = _split_row(line)
            sep = _split_row(lines[i + 1])
            normalised = [_normalise_header(c) for c in header]
            if (
                _is_separator(sep)
                and len(sep) == len(header)
                and any(n in _CLAIM_HEADERS for n in normalised)
                and any(n in _BACKING_HEADERS for n in normalised)
            ):
                table = MappingTable(
                    report=path.relative_to(repo_root).as_posix(),
                    heading=heading,
                    header_line=i + 1,
                    columns=header,
                )
                claim_at = next(
                    k for k, n in enumerate(normalised) if n in _CLAIM_HEADERS
                )
                backing_at = next(
                    k for k, n in enumerate(normalised) if n in _BACKING_HEADERS
                )
                kind_at = next(
                    (k for k, n in enumerate(normalised) if n in _KIND_HEADERS), None
                )
                location_at = next(
                    (k for k, n in enumerate(normalised) if n in _LOCATION_HEADERS),
                    None,
                )
                location_doc = ""
                if location_at is not None and "readme" in normalised[location_at]:
                    location_doc = "readME.md"
                j = i + 2
                count = 0
                while j < len(lines) and lines[j].strip().startswith("|"):
                    cells = _split_row(lines[j])
                    if len(cells) == len(header):
                        count += 1
                        table.rows.append(
                            MappingRow(
                                number=count,
                                claim=cells[claim_at],
                                backing=cells[backing_at],
                                kind=cells[kind_at] if kind_at is not None else "",
                                line=j + 1,
                                location=(
                                    cells[location_at] if location_at is not None else ""
                                ),
                                location_doc=location_doc,
                            )
                        )
                    j += 1
                if table.rows:
                    found.append(table)
                i = j
                continue
        i += 1
    return found


# ---------------------------------------------------------------------------
# Extracting what a backing cell names
# ---------------------------------------------------------------------------

_PATH_RE = re.compile(
    r"(?<![\w/])((?:[A-Za-z0-9_.*-]+/)+[A-Za-z0-9_.*-]+"
    r"\.(?:py|json|md|ya?ml|tsx?|rego|conf|txt))"
    r"((?:::[A-Za-z_][A-Za-z0-9_]*)*)"
)
_BARE_FILE_RE = re.compile(
    r"(?<![\w/.])([A-Za-z0-9_-]+\.(?:py|json|ya?ml|rego|conf))"
    r"((?:::[A-Za-z_][A-Za-z0-9_]*)*)"
)
_TEST_NAME_RE = re.compile(r"\btest_[A-Za-z0-9_]{3,}")
_CLASS_NAME_RE = re.compile(r"\bTest[A-Za-z0-9_]{3,}")

# A document-section citation: a .md file (or the literal README) adjacent to
# a section number. "This report section 2" and "section 3 above" name no
# document and are deliberately not citations; they point inside the report
# being checked, which no external artefact can confirm. The gap between the
# document name and the marker may not cross a semicolon or the words above /
# below, because those separate two independent references: phase-2.md row 1
# reads "docs/adr/0008-....md; section 2 below", where the section belongs to
# the report, not to the ADR.
_DOC_SECTION_RE = re.compile(
    r"(?P<doc>[A-Za-z0-9_./-]+\.md|README)"
    r"(?P<gap>(?:(?!\babove\b|\bbelow\b)[^|;§]){0,30}?)§\s*(?P<num>\d+(?:\.\d+)*)"
)
_EXTRA_SECTION_RE = re.compile(r"§\s*(\d+(?:\.\d+)*)")

_COMMAND_LEAD_RE = re.compile(
    r"`\s*(?:\$\s*)?"
    r"((?:python|python3|pytest|docker|make|curl|bash|sh)\b[^`]*)`"
)

_SCRIPT_ARG_RE = re.compile(r"(?<![\w/])((?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+\.py)")


@dataclass
class Tokens:
    tests: list = field(default_factory=list)          # (name, path or None)
    classes: list = field(default_factory=list)        # (name, path or None)
    paths: list = field(default_factory=list)
    doc_sections: list = field(default_factory=list)   # (doc path, section number)
    commands: list = field(default_factory=list)

    def is_empty(self):
        return not (
            self.tests
            or self.classes
            or self.paths
            or self.doc_sections
            or self.commands
        )


def _dedup(seq):
    out, seen = [], set()
    for item in seq:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def extract_tokens(cell, repo_root=None, default_doc=""):
    """Everything in a backing cell that names a mechanically checkable artefact."""
    tok = Tokens()

    for match in _COMMAND_LEAD_RE.finditer(cell):
        tok.commands.append(match.group(1).strip())

    for match in _DOC_SECTION_RE.finditer(cell):
        doc = match.group("doc")
        if doc == "README":
            doc = "readME.md"
        tok.doc_sections.append((doc, match.group("num")))
    # "readME.md 3.4.2 and 5" cites two sections off one filename.
    if tok.doc_sections:
        doc = tok.doc_sections[0][0]
        seen = set(num for _, num in tok.doc_sections)
        for match in _EXTRA_SECTION_RE.finditer(cell):
            if match.group(1) not in seen:
                seen.add(match.group(1))
                tok.doc_sections.append((doc, match.group(1)))
    elif repo_root is not None:
        # An unqualified marker names no document, so on its own it is not a
        # citation. It becomes one in two derived ways: the column's own header
        # already named the document (default_doc), or the cell names one of
        # readME.md's own subsection titles inside that section, as in
        # "Residual Limits section 5 bullet 1". In the second case readME.md's
        # heading text is what supplies the evidence. Nothing is listed here.
        readme = load_document(repo_root, "readME.md")
        if readme is not None:
            for match in _EXTRA_SECTION_RE.finditer(cell):
                number = match.group(1)
                section, child = resolve_scope(readme, number, cell)
                if section is None:
                    continue
                if child is not None or default_doc == "readME.md":
                    tok.doc_sections.append(("readME.md", number))

    # Paths first, then blank them out, so "tests/test_offline_verify.py" does
    # not also read as a test function named test_offline_verify.
    working = cell
    for regex in (_PATH_RE, _BARE_FILE_RE):
        for match in regex.finditer(working):
            path, suffix = match.group(1), match.group(2)
            tok.paths.append(path)
            for name in [s for s in suffix.split("::") if s]:
                if name.startswith("test_"):
                    tok.tests.append((name, path))
                elif name.startswith("Test"):
                    tok.classes.append((name, path))
        working = regex.sub(lambda m: " " * len(m.group(0)), working)

    for match in _TEST_NAME_RE.finditer(working):
        tok.tests.append((match.group(0), None))
    for match in _CLASS_NAME_RE.finditer(working):
        tok.classes.append((match.group(0), None))

    tok.tests = _dedup(tok.tests)
    tok.classes = _dedup(tok.classes)
    tok.paths = _dedup(tok.paths)
    tok.doc_sections = _dedup(tok.doc_sections)
    tok.commands = _dedup(tok.commands)
    return tok


# ---------------------------------------------------------------------------
# The repository's collected test names
# ---------------------------------------------------------------------------

class Collected:
    """Every test function and test class pytest collects, and where it lives.

    "Collected" is not "a def with that name exists somewhere". pytest.ini
    sets testpaths = tests, and pytest's own default naming convention is
    test_*.py / test_* / Test*. This walks only files that satisfy that
    convention, so a function defined in a helper module that pytest never
    collects does not count as backing a row.
    """

    def __init__(self, repo_root=REPO_ROOT):
        self.repo_root = repo_root
        self.functions = {}   # name -> set of repo-relative paths
        self.classes = {}
        tests_dir = repo_root / "tests"
        for path in sorted(tests_dir.rglob("test_*.py")):
            rel = path.relative_to(repo_root).as_posix()
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.name.startswith("test_"):
                        self.functions.setdefault(node.name, set()).add(rel)
                elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
                    self.classes.setdefault(node.name, set()).add(rel)

    def has_function(self, name, path=None):
        where = self.functions.get(name)
        if not where:
            return False
        if path is None:
            return True
        return any(w.endswith(path.lstrip("./")) for w in where)

    def has_class(self, name, path=None):
        where = self.classes.get(name)
        if not where:
            return False
        if path is None:
            return True
        return any(w.endswith(path.lstrip("./")) for w in where)


# ---------------------------------------------------------------------------
# Markdown documents and their sections
# ---------------------------------------------------------------------------

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
_SECTION_NUM_RE = re.compile(r"^(\d+(?:\.\d+)*)[.)]?\s+(.*)$")


@dataclass
class Section:
    level: int
    number: str      # "" when the heading carries no number
    title: str
    start: int       # index of the heading line
    end: int         # exclusive


class Document:
    def __init__(self, path):
        self.path = path
        self.lines = path.read_text(encoding="utf-8").splitlines()
        self.sections = self._parse()

    def _parse(self):
        raw = []
        for idx, line in enumerate(self.lines):
            match = _HEADING_RE.match(line)
            if match:
                level = len(match.group(1))
                text = match.group(2).strip()
                num_match = _SECTION_NUM_RE.match(re.sub(r"[`*]", "", text))
                number = num_match.group(1) if num_match else ""
                title = num_match.group(2) if num_match else text
                raw.append(Section(level, number, title, idx, len(self.lines)))
        for k, sec in enumerate(raw):
            for later in raw[k + 1:]:
                if later.level <= sec.level:
                    sec.end = later.start
                    break
        return raw

    def body(self, section):
        return "\n".join(self.lines[section.start + 1: section.end])

    def find_number(self, number):
        for sec in self.sections:
            if sec.number == number:
                return sec
        return None

    def children(self, section):
        return [
            s
            for s in self.sections
            if s.start > section.start and s.end <= section.end and s.level > section.level
        ]

    def top_level_sections(self):
        levels = [s.level for s in self.sections if s.level > 1]
        if not levels:
            return list(self.sections)
        top = min(levels)
        return [s for s in self.sections if s.level == top]


_DOC_CACHE = {}


def load_document(repo_root, rel_path):
    key = (str(repo_root), rel_path)
    if key not in _DOC_CACHE:
        path = repo_root / rel_path
        if not path.is_file() and "/" not in rel_path:
            # A bare document name, as one report cites another by filename.
            matches = sorted(repo_root.glob("docs/**/" + rel_path))
            path = matches[0] if matches else path
        _DOC_CACHE[key] = Document(path) if path.is_file() else None
    return _DOC_CACHE[key]


def resolve_scope(doc, number, row_text):
    """Resolve a section citation, narrowing to a named subsection when the row names one.

    Row 38 cited "readME.md section 5" with Kind "Residual Limits". Section 5
    is the whole threat model, three subsections; Residual Limits is one of
    them. Narrowing to the subsection the row itself names is what makes the
    support check bite: pre-fix, section 5 as a whole did contain the string
    not_anchored (in the fail-closed table under a different subsection) while
    Residual Limits, the subsection the row actually pointed at, did not.

    The subsection is found by matching the document's own heading titles
    against the row's text. Nothing is hand-listed.
    """
    section = doc.find_number(number)
    if section is None:
        return None, None
    haystack = row_text.lower()
    for child in doc.children(section):
        if child.number:
            continue
        key = re.split(r"[(–—-]", child.title)[0].strip().lower()
        if len(key) >= 5 and key in haystack:
            return section, child
    return section, None


# ---------------------------------------------------------------------------
# Distinctive terms
# ---------------------------------------------------------------------------

_WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{2,}")
_SUFFIXES = ("ingly", "ously", "ising", "izing", "ing", "edly", "ably", "ibly",
             "ies", "ied", "ed", "es", "ly", "s")

# A term must survive stemming at this length to be considered. Below it, a
# substring match is noise: "not" matches "nothing", "can" matches "cannot".
_MIN_STEM = 5

# A term is distinctive when it appears in at least one and at most this
# fraction of the cited document's own top-level sections.
#
# The upper bound is what makes a term load-bearing. A word the document uses
# everywhere ("record", "policy", "the") proves nothing about the section that
# was cited, while a word it uses in at most a quarter of its sections is a
# word that section has to earn.
#
# The lower bound of one is the less obvious half, and it is what keeps the
# check from drowning in false positives. A term the cited document never uses
# anywhere carries no information about whether the cited section is the right
# section: it is usually report vocabulary rather than document vocabulary
# ("Unchanged this pass", "Reproducible command", "D20 compliance" are Claim
# cells whose words the README has no reason to contain). Row 38 is still
# caught, because its claim's real subject, not_anchored, did appear in the
# README twice, just never in the subsection the row pointed at. The defect
# class this check exists for is a claim pointed at the wrong section of a
# document that discusses it, and that is exactly the shape a df of at least
# one selects for.
_DISTINCTIVE_FRACTION = 0.25
_MIN_DOCUMENT_FREQUENCY = 1

# The second half of the term rule, and the one that makes the check usable.
#
# A Claim cell is not always a claim about the system. In the Location / Claim
# / Maps to tables this project used from phase 1.3 to 3a, the Claim column is
# often a note about the row itself: "Unchanged this pass", "Reproducible
# command", "Corrected this pass (R2, R5b)". Those cells yield terms that are
# ordinary mapping-table vocabulary, and a section that does not contain the
# word "unchanged" has told you nothing.
#
# So a term must be rare on both axes: rare inside the document it cites, and
# not shared with any other claim anywhere in the corpus of mapping tables. A
# term used by more than this many Claim cells is generic and is discarded.
# One means the only claim using it is the row's own.
_MAX_CLAIMS_SHARING_A_TERM = 1


def occurs(term, text):
    """Does `term` appear at the start of a word in `text`?

    A stem has to prefix-match ("downgrad" must find "downgraded"), so this
    cannot be a whole-word match. It must not be a bare substring match
    either: that let "timeout" match inside "ConnectTimeout" and passed a row
    whose cited section had nothing to do with route timeouts. Anchoring at a
    word start keeps the prefix behaviour and drops the accidents.
    """
    return re.search(r"(?<![A-Za-z0-9_])" + re.escape(term), text) is not None


def stem(word):
    """Crude suffix stripping, so "downgraded" and "downgrading" both reach "downgrad"."""
    lowered = word.lower()
    for suffix in _SUFFIXES:
        if lowered.endswith(suffix) and len(lowered) - len(suffix) >= _MIN_STEM:
            return lowered[: -len(suffix)]
    return lowered


def claim_terms(claim):
    """Candidate terms from a Claim cell, derived from the cell, never from a list."""
    text = re.sub(r"[`*]", " ", claim)
    out = []
    for word in _WORD_RE.findall(text):
        s = stem(word)
        if len(s) >= _MIN_STEM:
            out.append(s)
        # An identifier like external_anchor also yields its parts.
        if "_" in word:
            for part in word.split("_"):
                ps = stem(part)
                if len(ps) >= _MIN_STEM:
                    out.append(ps)
    return _dedup(out)


class ReportVocabulary:
    """How generic a term is across every Claim cell in every mapping table.

    The contrast corpus is the Claim cells themselves, not the reports' prose.
    Two reasons, and the second was learned the hard way.

    It is the right corpus: the question this axis answers is "do mapping
    claims use this word generically", and the mapping claims are what to ask.

    It is also the only stable one. Measuring against whole report bodies made
    the verdict depend on the prose of the errata that record the verdict.
    Writing an erratum about a failing row put that row's own vocabulary into
    the corpus and retired the failure, and deleting the erratum brought it
    back. A check that argues with its own write-up is not a check. Claim
    cells move only when a mapping row is added or changed, which is the thing
    being measured.
    """

    def __init__(self, repo_root):
        self._claims = [
            re.sub(r"[`*]", " ", row.claim).lower()
            for table in find_mapping_tables(repo_root)
            for row in table.rows
        ]
        self.total = max(1, len(self._claims))
        self._cache = {}

    def claim_frequency(self, term):
        if term not in self._cache:
            self._cache[term] = sum(1 for c in self._claims if occurs(term, c))
        return self._cache[term]

    def is_generic(self, term):
        return self.claim_frequency(term) > _MAX_CLAIMS_SHARING_A_TERM


_VOCAB_CACHE = {}


def report_vocabulary(repo_root):
    key = str(repo_root)
    if key not in _VOCAB_CACHE:
        _VOCAB_CACHE[key] = ReportVocabulary(repo_root)
    return _VOCAB_CACHE[key]


class TermIndex:
    """Per-document term rarity, measured over the document's own top-level sections."""

    def __init__(self, doc, vocabulary):
        self.doc = doc
        self.vocabulary = vocabulary
        self._bodies = [doc.body(s).lower() for s in doc.top_level_sections()]
        self.total = max(1, len(self._bodies))
        self._cache = {}

    def document_frequency(self, term):
        if term not in self._cache:
            self._cache[term] = sum(1 for b in self._bodies if occurs(term, b))
        return self._cache[term]

    def distinctive(self, terms):
        limit = self.total * _DISTINCTIVE_FRACTION
        out = []
        for term in terms:
            df = self.document_frequency(term)
            if not (_MIN_DOCUMENT_FREQUENCY <= df <= limit):
                continue
            if self.vocabulary.is_generic(term):
                continue
            out.append((df, term))
        return sorted(out)


# ---------------------------------------------------------------------------
# The two checks
# ---------------------------------------------------------------------------

@dataclass
class Failure:
    report: str
    row: int
    cls: str          # "a" or "b"
    reason: str
    claim: str

    def key(self):
        return "%s#%d#%s" % (self.report, self.row, self.cls)

    def __str__(self):
        return "%s row %d [class %s]: %s :: %s" % (
            self.report,
            self.row,
            self.cls,
            self.reason,
            _clip(self.claim),
        )


def _clip(text, width=72):
    flat = re.sub(r"\s+", " ", re.sub(r"[`*]", "", text)).strip()
    return flat if len(flat) <= width else flat[: width - 3] + "..."


_KIND_ATOM = {
    "test": "test",
    "tests": "test",
    "command": "command",
    "commands": "command",
    "residual limits": "document",
    "residual limit": "document",
    "document": "document",
    "documentation": "document",
}


def _declared_kinds(kind_cell):
    """What the Kind column declares, normalised to the derived vocabulary.

    The cell is split into atoms on + and , and only an atom that is exactly a
    kind word counts. This is what keeps the project's existing honesty
    convention working: "command, marked: no test covers this" declares
    command and nothing else, because "marked: no test covers this" is not a
    kind, it is a disclosure. A looser word search would read the word test
    out of that disclaimer and invert its meaning.
    """
    lowered = re.sub(r"[`*]", "", kind_cell).lower()
    declared = set()
    unknown = []
    for part in re.split(r"[+,;]", lowered):
        atom = part.strip().strip(".")
        if not atom:
            continue
        if atom in _KIND_ATOM:
            declared.add(_KIND_ATOM[atom])
        elif ":" not in atom:
            # An atom carrying a colon is a disclosure, not a kind: the
            # project writes "command, marked: no test covers this" and that
            # second clause is a warning to the reader. Anything else is a
            # kind word the checker does not know, and a Kind vocabulary
            # nothing constrains is how a row comes to declare a backing no
            # check can look for.
            unknown.append(atom)
    return declared, unknown


class RepoIndex:
    """Basenames of every committed file, so a bare filename can be resolved.

    Rows cite PROVENANCE.json and policy_deny.json without a directory,
    because the surrounding row already says which fixture directory they live
    in. A bare name resolves when exactly the named file exists somewhere in
    the tree; that is what "exists in the shape it declares" means for a
    filename with no path.
    """

    _SKIP = {".git", "node_modules", "__pycache__", ".next", ".pytest_cache"}

    def __init__(self, repo_root):
        self.repo_root = repo_root
        self.by_name = {}
        for path in repo_root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in self._SKIP for part in path.parts):
                continue
            self.by_name.setdefault(path.name, []).append(path)

    def resolve(self, cited):
        """True when a cited path or bare filename resolves to a real file."""
        if "*" in cited:
            return bool(list(self.repo_root.glob(cited)))
        direct = self.repo_root / cited
        if direct.exists():
            return True
        if "/" not in cited:
            return bool(self.by_name.get(cited))
        # A path fragment such as tests/fixtures/x.json cited from elsewhere.
        return any(
            p.as_posix().endswith("/" + cited)
            for p in self.by_name.get(cited.rsplit("/", 1)[-1], [])
        )

    def resolve_script(self, cited):
        """The real file behind a script named in a command, or None."""
        direct = self.repo_root / cited
        if direct.is_file():
            return direct
        candidates = self.by_name.get(cited.rsplit("/", 1)[-1], [])
        for path in candidates:
            if path.as_posix().endswith("/" + cited):
                return path
        return candidates[0] if candidates and "/" not in cited else None


def check_shape(table, row, repo_root, collected, index):
    """Class (a). What the row declares must exist in the shape it declares."""
    failures = []
    tok = extract_tokens(row.backing, repo_root)

    for name, path in tok.tests:
        if not collected.has_function(name, path):
            where = " in %s" % path if path else ""
            failures.append(
                Failure(table.report, row.number, "a",
                        "cited test %s is not collected under tests/%s" % (name, where),
                        row.claim))
    for name, path in tok.classes:
        if not collected.has_class(name, path):
            where = " in %s" % path if path else ""
            failures.append(
                Failure(table.report, row.number, "a",
                        "cited test class %s is not collected under tests/%s" % (name, where),
                        row.claim))

    for path in tok.paths:
        if not index.resolve(path):
            failures.append(
                Failure(table.report, row.number, "a",
                        "cited path %s does not resolve to a file in this tree" % path,
                        row.claim))

    for command in tok.commands:
        for script in _SCRIPT_ARG_RE.findall(command):
            target = index.resolve_script(script)
            if target is None:
                failures.append(
                    Failure(table.report, row.number, "a",
                            "cited command names %s, which does not exist" % script,
                            row.claim))
                continue
            # "Runnable in form" without running it: the interpreter can parse
            # the script it names. Running it is not this check's job and would
            # make a documentation test depend on a live stack.
            try:
                compile(target.read_text(encoding="utf-8"), script, "exec")
            except SyntaxError as exc:
                failures.append(
                    Failure(table.report, row.number, "a",
                            "cited command's script %s does not parse: %s" % (script, exc),
                            row.claim))

    for rel, number in tok.doc_sections:
        doc = load_document(repo_root, rel)
        if doc is None:
            failures.append(
                Failure(table.report, row.number, "a",
                        "cited document %s does not exist" % rel, row.claim))
            continue
        if doc.find_number(number) is None:
            failures.append(
                Failure(table.report, row.number, "a",
                        "cited document %s has no section %s" % (rel, number),
                        row.claim))

    if table.has_kind_column:
        declared, unknown = _declared_kinds(row.kind)
        for atom in unknown:
            failures.append(
                Failure(table.report, row.number, "a",
                        "Kind declares %r, which is not a kind this check "
                        "knows how to look for" % atom,
                        row.claim))
        derived = derive_kinds(tok)
        for missing in sorted(declared - derived):
            failures.append(
                Failure(table.report, row.number, "a",
                        "Kind declares %s but the backing column names no %s"
                        % (missing, missing),
                        row.claim))

    return failures


def derive_kinds(tok):
    """The Kind a row's backing column actually supports."""
    kinds = set()
    if tok.tests or tok.classes:
        kinds.add("test")
    if tok.commands:
        kinds.add("command")
    if tok.doc_sections or any(p.endswith(".md") for p in tok.paths):
        kinds.add("document")
    return kinds


def _cited_sections(row, repo_root):
    """Every (cell, document, section number) this row cites."""
    out = []
    for cell, default_doc in row.citing_text():
        for rel, number in extract_tokens(cell, repo_root, default_doc).doc_sections:
            out.append((cell, rel, number))
    return _dedup(out)


def check_support(table, row, repo_root):
    """Class (b). A cited section must contain a distinctive term from the Claim.

    The row passes when any one of its cited sections carries the claim's
    vocabulary. Requiring every cited section to carry it would fail rows that
    deliberately split a claim across a normative section and a limits
    section, which this project does routinely. The consequence is stated
    plainly in the ADR: a row that cites one supporting section alongside one
    irrelevant one still passes.
    """
    citations = _cited_sections(row, repo_root)
    if not citations:
        return []

    terms = claim_terms(row.claim)
    checked_any = False
    misses = []

    for cell, rel, number in citations:
        doc = load_document(repo_root, rel)
        if doc is None:
            continue  # class (a) already reported this
        section, child = resolve_scope(doc, number, cell + " " + row.kind)
        if section is None:
            continue  # class (a) already reported this
        scope = child or section
        label = "%s section %s" % (rel, number)
        if child is not None:
            label += " / " + child.title

        distinctive = TermIndex(doc, report_vocabulary(repo_root)).distinctive(terms)
        if not distinctive:
            continue  # counted as unchecked, not as a failure
        checked_any = True
        body = doc.body(scope).lower()
        if any(occurs(term, body) for _, term in distinctive):
            return []
        misses.append((label, [t for _, t in distinctive]))

    if not checked_any or not misses:
        return []

    label, terms_missed = misses[0]
    return [
        Failure(table.report, row.number, "b",
                "%s contains none of the claim's distinctive terms (%s)"
                % (label, ", ".join(sorted(terms_missed)[:6])),
                row.claim)
    ]


def support_is_checkable(row, repo_root):
    """True when class (b) had distinctive terms to work with on this row."""
    citations = _cited_sections(row, repo_root)
    if not citations:
        return False
    terms = claim_terms(row.claim)
    for _cell, rel, _number in citations:
        doc = load_document(repo_root, rel)
        if doc is None:
            continue
        if TermIndex(doc, report_vocabulary(repo_root)).distinctive(terms):
            return True
    return False


# ---------------------------------------------------------------------------
# Running everything
# ---------------------------------------------------------------------------

@dataclass
class ReportResult:
    report: str
    rows: int
    unchecked_shape: int     # rows whose backing names nothing checkable
    unchecked_support: int   # rows citing a section but yielding no distinctive term
    citing: int = 0          # rows that cite at least one document section
    failures: list = field(default_factory=list)

    def count(self, cls):
        return sum(1 for f in self.failures if f.cls == cls)


def run(repo_root=REPO_ROOT):
    collected = Collected(repo_root)
    index = RepoIndex(repo_root)
    results = []
    for table in find_mapping_tables(repo_root):
        result = ReportResult(table.report, len(table.rows), 0, 0)
        for row in table.rows:
            tok = extract_tokens(row.backing, repo_root)
            if tok.is_empty():
                result.unchecked_shape += 1
            result.failures.extend(
                check_shape(table, row, repo_root, collected, index)
            )
            if _cited_sections(row, repo_root):
                result.citing += 1
                if not support_is_checkable(row, repo_root):
                    result.unchecked_support += 1
            result.failures.extend(check_support(table, row, repo_root))
        results.append(result)
    return results


def all_failures(results):
    out = []
    for result in results:
        out.extend(result.failures)
    return out


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------

def load_baseline(repo_root=REPO_ROOT):
    path = repo_root / BASELINE_PATH
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {entry["key"]: entry for entry in data.get("entries", [])}


def classify_against_baseline(results, baseline):
    """Split current failures into new ones and known ones, and find stale entries."""
    current = {f.key(): f for f in all_failures(results)}
    new = [f for key, f in sorted(current.items()) if key not in baseline]
    known = [f for key, f in sorted(current.items()) if key in baseline]
    stale = sorted(key for key in baseline if key not in current)
    return new, known, stale


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[2])
    parser.add_argument("--repo", default=str(REPO_ROOT))
    parser.add_argument("--json", action="store_true", help="emit failures as JSON")
    parser.add_argument("--write-baseline", action="store_true",
                        help="rewrite the baseline file from the current failures")
    args = parser.parse_args(argv)

    repo_root = Path(args.repo).resolve()
    _DOC_CACHE.clear()
    results = run(repo_root)
    failures = all_failures(results)

    if args.write_baseline:
        entries = [
            {
                "key": f.key(),
                "report": f.report,
                "row": f.row,
                "class": f.cls,
                "reason": f.reason,
                "claim": _clip(f.claim, 120),
            }
            for f in sorted(failures, key=lambda f: (f.report, f.row, f.cls))
        ]
        path = repo_root / BASELINE_PATH
        path.write_text(
            json.dumps({"entries": entries}, indent=2) + "\n", encoding="utf-8"
        )
        print("wrote %d entries to %s" % (len(entries), BASELINE_PATH.as_posix()))
        return 0

    if args.json:
        print(json.dumps(
            [
                {"key": f.key(), "report": f.report, "row": f.row,
                 "class": f.cls, "reason": f.reason, "claim": _clip(f.claim, 120)}
                for f in failures
            ],
            indent=2,
        ))
        return 1 if failures else 0

    print("mapping tables found: %d" % len(results))
    print()
    header = "%-40s %5s %5s %5s %5s %7s %7s" % (
        "report", "rows", "cites", "a", "b", "unchk-a", "unchk-b")
    print(header)
    print("-" * len(header))
    for result in results:
        print("%-40s %5d %5d %5d %5d %7d %7d" % (
            result.report.replace("docs/reports/", ""),
            result.rows,
            result.citing,
            result.count("a"),
            result.count("b"),
            result.unchecked_shape,
            result.unchecked_support,
        ))
    print("-" * len(header))
    print("%-40s %5d %5d %5d %5d %7d %7d" % (
        "TOTAL",
        sum(r.rows for r in results),
        sum(r.citing for r in results),
        sum(r.count("a") for r in results),
        sum(r.count("b") for r in results),
        sum(r.unchecked_shape for r in results),
        sum(r.unchecked_support for r in results),
    ))

    if failures:
        print()
        print("failing rows:")
        for f in sorted(failures, key=lambda f: (f.report, f.row, f.cls)):
            print("  " + str(f))

    baseline = load_baseline(repo_root)
    if baseline:
        new, known, stale = classify_against_baseline(results, baseline)
        print()
        print("against the baseline: %d new, %d known, %d stale"
              % (len(new), len(known), len(stale)))
        for f in new:
            print("  NEW   " + str(f))
        for key in stale:
            print("  STALE " + key)
        return 1 if (new or stale) else 0

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
