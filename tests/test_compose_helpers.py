"""tests/test_compose_helpers.py - Phase 3c-3c.

The two copies of the Compose project-name rule must agree.

Why this exists. tests/compose_helpers.py was written this phase by copying
the rule out of tests/test_content_states.py, and the copy dropped a
character class: `"".join(c for c in name if c.isalnum())` instead of
`re.sub(r"[^a-z0-9_-]", "", name)`. This repository's directory is
`compliance-ail`, so the copy resolved to `complianceail` and every
`docker compose` call against it addressed a project that does not exist -
creating a second empty one, and then failing on a port the real stack
already held.

It was invisible locally, where COMPOSE_PROJECT_NAME is set explicitly and
the fallback never runs, and it cost a CI run. Two copies of a rule that
must agree, with nothing checking that they do, is the defect; this is the
check.
"""

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tests"))

import compose_helpers  # noqa: E402


def _load_content_states():
    """test_content_states.py under its own module name, without importing
    it as a test module (which would run its stack probes at collection)."""
    spec = importlib.util.spec_from_file_location(
        "content_states_for_compose_rule", REPO_ROOT / "tests" / "test_content_states.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["content_states_for_compose_rule"] = module
    spec.loader.exec_module(module)
    return module


def test_the_two_copies_of_the_compose_project_rule_agree():
    other = _load_content_states()
    assert (compose_helpers.default_compose_project_name()
            == other._default_compose_project_name()), (
        "the two copies of Compose's default-project-name rule disagree: "
        f"compose_helpers says {compose_helpers.default_compose_project_name()!r} "
        f"and test_content_states says {other._default_compose_project_name()!r}. "
        "One of them is addressing a Compose project that does not exist."
    )
    assert (compose_helpers.compose_project_name()
            == other._compose_project_name()), (
        "the two copies disagree about which project this session is talking to"
    )


def test_the_rule_keeps_a_hyphen():
    """The specific character the broken copy dropped, named.

    Compose's own normalisation keeps `-`. A rule that strips it turns
    `compliance-ail` into `complianceail`, which is a different project.
    """
    import re

    assert re.sub(r"[^a-z0-9_-]", "", "Compliance-AIL".lower()) == "compliance-ail"
    # And the live answer for this checkout carries whatever separators its
    # directory name has, rather than a squashed version of them.
    resolved = compose_helpers.default_compose_project_name()
    expected = re.sub(r"[^a-z0-9_-]", "", REPO_ROOT.name.lower()).lstrip("_-") or "default"
    assert resolved == expected, (resolved, expected)
