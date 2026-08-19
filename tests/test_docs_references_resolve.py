"""
tests/test_docs_references_resolve.py

cleanup-p13-b, item 4. Every docs/ path referenced anywhere in the tree must
exist in the commit that references it, not merely on the filesystem of the
session that wrote the reference. Three prior incidents shipped a reference
to a docs path that was not committed: a missing plan document, a missing
spike report on MCP mediation, and a missing spike report on WASM parity. In
each case the file was present locally and uncommitted when the reference
was written, and the reference survived into a pushed commit anyway.

roadmap-commit, item 4. A fifth incident (README section 1's "see this
repository's roadmap for the isolation work (Phase 2) that closes it") was
not a dangling path at all: it named no path, so test_every_referenced_docs_
path_exists_in_this_commit above could not see it, because that test only
ever looks for something shaped like a docs/ path and checks whether it
resolves. There was nothing here for it to check.

A fully general rule for "this prose sentence promises a path it doesn't
give" is not expressible as a regex: the same nouns are used constantly in
ways that are not references to a specific unnamed document at all -
"an ADR" (indefinite - a category, not a document), "the original plan
called for X" (ordinary English, not a pointer), "note in the report" (an
instruction about a report not yet written), "this ADR's own subject" (a
document talking about itself). Distinguishing those from "this
repository's roadmap" or "Phase 2 of the roadmap" - both real instances of
the bug - requires modeling intent, not just matching a noun.

What is expressible, and is what test_no_dangling_definite_document_
reference below checks: a **definite** reference ("the roadmap", "this
ADR", "this repository's plan") to one of five document nouns (roadmap,
plan, protocol, ADR, report), with no resolvable docs/ path and no ADR-NNNN
number anywhere nearby. That pattern is specific enough to have caught the
actual README sentence without also flagging "an ADR" or "the original plan
called for". It deliberately does not scan docs/reports/, docs/audit/, or
spikes/: those are point-in-time evidentiary records, and their prose
routinely discusses "the roadmap" or "the plan" as they stood, informally,
at the time the report was written - often before any file by that name was
committed. Rewriting that frozen narrative to inject a link to a file that
did not exist yet would misrepresent the record, not fix a bug. It also
exempts a document from being flagged for referring to itself in its own
terms (an ADR file saying "this ADR", a docs/plan/ file saying "the plan"),
since a reader already inside the document is not left to guess what it
means.

Scans the committed tree only (git ls-tree -r HEAD), so a locally
uncommitted scratch file cannot mask a real dangling reference, and cannot
be mistaken for a fix either.
"""

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_DOC_PATH_RE = re.compile(
    r"docs/[A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]+)*\.(?:md|json|ya?ml)"
)

_EXCLUDE_DIR_PARTS = {
    ".git",
    "node_modules",
    "build",
    "build2",
    "build3",
    "build_embed",
    "build_eval",
    "build_probe",
}

# Point-in-time evidentiary records: spike reports, red-team reports, audit
# reports. Their prose narrates what "the roadmap" or "the plan" meant at
# the time, which often predates any file carrying that name. Not scanned
# by the definite-reference check below; see the module docstring.
_PROSE_EXCLUDE_PATH_PREFIXES = (
    "docs/reports/",
    "docs/audit/",
    "spikes/",
)

# Nouns unambiguous enough in this codebase's vocabulary that a bare
# definite reference ("the roadmap", "this ADR") with nothing resolvable
# nearby is safe to flag without a pointer phrase.
_STRICT_NOUN_RE = re.compile(
    r"\b(?:the|this|that|its|our|this repository's|this repo's|the project's)"
    r"\s+(roadmap|ADR)\b",
    re.IGNORECASE,
)

# Nouns too common as ordinary English words ("the original plan called
# for...", "note in the report") to flag on a bare determiner; only flagged
# when preceded by phrasing that specifically promises a pointer.
_GATED_NOUN_RE = re.compile(
    r"\b(?:this repository's|this repo's|the project's|see the|see this|per the)"
    r"\s+(plan|protocol|report)\b",
    re.IGNORECASE,
)

_ADR_NUMBER_RE = re.compile(r"\bADR-\d{3,4}\b", re.IGNORECASE)

_WINDOW_CHARS = 200


def _self_reference_exempt(noun: str, rel_path: str) -> bool:
    noun = noun.lower()
    posix_path = rel_path.replace("\\", "/")
    if noun == "roadmap":
        return posix_path == "docs/plan/ail-roadmap.md"
    if noun == "adr":
        return posix_path.startswith("docs/adr/")
    if noun == "protocol":
        return posix_path == "docs/process/review-protocol.md"
    if noun == "plan":
        return posix_path.startswith("docs/plan/")
    return False


def _has_nearby_resolver(text: str, start: int, end: int) -> bool:
    window = text[max(0, start - _WINDOW_CHARS): end + _WINDOW_CHARS]
    return bool(_DOC_PATH_RE.search(window) or _ADR_NUMBER_RE.search(window))


def _committed_files() -> set[str]:
    result = subprocess.run(
        ["git", "ls-tree", "-r", "HEAD", "--name-only"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return set(result.stdout.splitlines())


def _find_doc_references(committed: set[str]) -> dict[str, list[str]]:
    """Map each referenced docs/ path to the committed files citing it."""
    refs: dict[str, list[str]] = {}
    for rel_path in sorted(committed):
        if any(part in _EXCLUDE_DIR_PARTS for part in Path(rel_path).parts):
            continue
        full_path = REPO_ROOT / rel_path
        try:
            text = full_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for match in _DOC_PATH_RE.finditer(text):
            refs.setdefault(match.group(0), []).append(rel_path)
    return refs


def test_every_referenced_docs_path_exists_in_this_commit():
    committed = _committed_files()
    refs = _find_doc_references(committed)

    dangling = {
        path: citing_files
        for path, citing_files in refs.items()
        if path not in committed
    }

    assert not dangling, "docs/ references that do not resolve in this commit:\n" + "\n".join(
        f"  {path} referenced by {citing_files}" for path, citing_files in sorted(dangling.items())
    )


def _find_dangling_prose_references(committed: set[str]) -> list[str]:
    """Definite references to roadmap/plan/protocol/ADR/report with nothing
    resolvable nearby. See the module docstring for why this is scoped to
    definite phrasing rather than a bare noun match."""
    findings: list[str] = []
    for rel_path in sorted(committed):
        if not rel_path.endswith(".md"):
            continue
        posix_path = rel_path.replace("\\", "/")
        if any(posix_path.startswith(prefix) for prefix in _PROSE_EXCLUDE_PATH_PREFIXES):
            continue
        if any(part in _EXCLUDE_DIR_PARTS for part in Path(rel_path).parts):
            continue
        full_path = REPO_ROOT / rel_path
        try:
            text = full_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for pattern in (_STRICT_NOUN_RE, _GATED_NOUN_RE):
            for match in pattern.finditer(text):
                noun = match.group(1)
                if _self_reference_exempt(noun, rel_path):
                    continue
                if _has_nearby_resolver(text, match.start(), match.end()):
                    continue
                line_no = text.count("\n", 0, match.start()) + 1
                findings.append(
                    f"  {rel_path}:{line_no}: {match.group(0)!r} names no resolvable "
                    f"docs/ path or ADR-NNNN number within {_WINDOW_CHARS} chars"
                )
    return findings


def test_no_dangling_definite_document_references():
    committed = _committed_files()
    findings = _find_dangling_prose_references(committed)

    assert not findings, (
        "prose references to a roadmap/plan/protocol/ADR/report that name no "
        "resolvable path or ADR number:\n" + "\n".join(findings)
    )
