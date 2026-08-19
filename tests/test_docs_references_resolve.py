"""
tests/test_docs_references_resolve.py

cleanup-p13-b, item 4. Every docs/ path referenced anywhere in the tree must
exist in the commit that references it, not merely on the filesystem of the
session that wrote the reference. Three prior incidents shipped a reference
to a docs path that was not committed: a missing plan document, a missing
spike report on MCP mediation, and a missing spike report on WASM parity. In
each case the file was present locally and uncommitted when the reference
was written, and the reference survived into a pushed commit anyway.

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
