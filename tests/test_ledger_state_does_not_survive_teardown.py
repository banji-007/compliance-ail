"""tests/test_ledger_state_does_not_survive_teardown.py - Phase 3c-3e (P3c3e-8).

No ledger this project brings up survives `docker compose down -v`.

**Why this is a test and not a sentence in a report.** P3c3e-8 deletes the
legacy `ledger_fault:{call_id}` read path from `/audit`. That path exists only
to render faults committed under the pre-D38 key shape, and deleting it is
correct exactly to the extent that no ledger anywhere still holds one. Half of
that is a fact about deployments, which this suite cannot check and does not
try to: it is recorded in the phase instruction and in the report, not derived
here. The other half is a property of this repository's own compose files, and
it is checkable: every volume that could carry ledger state is a named volume
declared in the compose file that uses it, so `down -v` removes it, and none
is `external`, which `down -v` would leave alone.

What that establishes, stated narrowly. A stack brought up from either compose
file and torn down with `-v` leaves no ImmuDB data behind. It does not
establish that nobody ran `down` without `-v`, and it does not establish
anything about a deployment that is not one of these two files.

Static, over the compose files. No stack required.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

COMPOSE_FILES = ("docker-compose.yml", "docker-compose.test.yml")

# Where each service in these files keeps state that would carry a ledger
# record forward. Matched against the container-side path of a mount, so a
# service that starts writing somewhere new has to be added here rather than
# passing by not matching.
STATEFUL_CONTAINER_PATHS = (
    "/var/lib/immudb",     # ImmuDB's own data directory
    "/data",              # the control plane's SQLite store
    "/data/verifier-state",  # the verifier's persisted trust anchor
)


def _parse(compose_text: str):
    """Service mounts and the file's own top-level `volumes:` names.

    A small reader rather than a YAML dependency, for the same reason
    tests/test_image_contents.py gives: this repository has none.

    **Two shapes of mount, not one (P3c3f-9, Phase 3c-3f).** Compose accepts a
    short form, `- name:/path`, and a long form:

        - type: bind
          source: ./ledger-on-the-host
          target: /var/lib/immudb

    The reader used to `spec.split(":")` every list item, so the long form's
    first line became a mount named `type` at target `" bind"`, which is in no
    stateful path list and was skipped. `docker compose config` resolves that
    file to a host bind mount of ImmuDB's data directory, and a host path
    survives `down -v` entirely - the exact thing this module exists to
    exclude. `assert covered` does not save it: one short-form stateful mount
    left anywhere in the file satisfies that, which is the realistic case
    where one service is changed and the others are not.
    """
    mounts: list[tuple[str, str, str]] = []       # (service, source, target)
    declared: dict[str, str] = {}                 # name -> the lines under it
    service = None
    section = None
    top_level_volumes = False
    pending_volume = None
    long_form: dict[str, str] | None = None

    def _flush_long_form():
        """One long-form entry, once it is complete, as (source, target).

        An entry with no `source` is an anonymous volume, which Compose
        creates and `down -v` removes - but it is not declared in the file,
        so it is reported under a name the caller's "this file declares no
        such volume" branch refuses rather than being dropped silently.
        """
        nonlocal long_form
        if long_form is None:
            return
        entry, long_form = long_form, None
        target = entry.get("target", "")
        if target:
            mounts.append((service or "", entry.get("source") or "<anonymous>",
                           target))

    for raw in compose_text.splitlines():
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        line = raw.strip()

        if indent == 0:
            _flush_long_form()
            top_level_volumes = line.startswith("volumes:")
            section = None
            if line.startswith("services:"):
                section = "services"
            pending_volume = None
            continue

        if top_level_volumes:
            if indent == 2 and line.endswith(":"):
                pending_volume = line[:-1].strip()
                declared[pending_volume] = ""
            elif pending_volume is not None and indent > 2:
                declared[pending_volume] += line + "\n"
            continue

        if indent == 2 and line.endswith(":"):
            _flush_long_form()
            service = line[:-1].strip()
            section = None
            continue
        if indent == 4 and line.startswith("volumes:"):
            _flush_long_form()
            section = "volumes"
            continue
        if indent == 4 and line.endswith(":"):
            _flush_long_form()
            section = None
            continue
        if section != "volumes":
            _flush_long_form()
            continue

        if line.startswith("- "):
            _flush_long_form()
            spec = line[2:].strip()
            key, _colon, value = spec.partition(":")
            if key.strip() in ("type", "source", "target") and _colon:
                long_form = {key.strip(): value.strip()}
                continue
            parts = spec.split(":")
            if len(parts) >= 2:
                mounts.append((service or "", parts[0], parts[1]))
        elif long_form is not None and ":" in line:
            key, _colon, value = line.partition(":")
            long_form[key.strip()] = value.strip()
    _flush_long_form()
    return mounts, declared


@pytest.mark.parametrize("compose_name", COMPOSE_FILES)
def test_every_stateful_mount_is_a_named_volume_that_down_v_removes(compose_name):
    """A ledger that outlives `down -v` is a ledger this suite cannot reason
    about. Both files, because a stack can be brought up from either."""
    path = REPO_ROOT / compose_name
    assert path.exists(), f"{compose_name} is missing"
    mounts, declared = _parse(path.read_text(encoding="utf-8"))
    assert mounts, f"no service mounts were parsed out of {compose_name}"

    offenders = []
    covered = []
    for service, source, target in mounts:
        if target not in STATEFUL_CONTAINER_PATHS:
            continue
        if source.startswith(".") or source.startswith("/") or ":" in source:
            offenders.append(
                f"{compose_name}: {service} mounts {source!r} at {target!r}, "
                "which is a host path and survives `down -v` entirely"
            )
            continue
        if source not in declared:
            offenders.append(
                f"{compose_name}: {service} mounts the volume {source!r} at "
                f"{target!r} and this file declares no such volume"
            )
            continue
        covered.append(f"{service}:{source}")
    assert not offenders, offenders
    assert covered, (
        f"{compose_name} declares no stateful mount at any of "
        f"{STATEFUL_CONTAINER_PATHS}. Either the paths moved and this list is "
        "stale, or the parse stopped seeing them - and a check that matches "
        "nothing passes for the wrong reason."
    )


def external_volumes(declared: dict[str, str]) -> list[str]:
    """The volume names this file declares `external`.

    **P3c3f-9: case-insensitive, and a function rather than a line inside the
    test below.** The test that drives the three spellings has to drive THIS
    rule. Spelled inline in both places, the phase's own mutation left the
    suite at `6 passed` against a check the test was written to catch, which is
    this phase's subject one level up: a rule holding at two sites with nothing
    tying them together.

    YAML's boolean is `true`, `True` or `TRUE`; Compose parses all three and
    `docker compose config` resolves every one of them to `external: true`.
    The Phase 3c-3e red team wrote `external: True` and this check reported
    nothing, which is a ledger written into a volume `down -v` leaves alone.
    """
    return sorted(name for name, body in declared.items()
                  if re.search(r"external:\s*true", body, re.IGNORECASE))


@pytest.mark.parametrize("compose_name", COMPOSE_FILES)
def test_no_volume_is_external(compose_name):
    """`down -v` removes the volumes the project created and leaves an
    external one alone, so an external volume is a ledger that persists
    across every run by design."""
    path = REPO_ROOT / compose_name
    _mounts, declared = _parse(path.read_text(encoding="utf-8"))
    external = external_volumes(declared)
    assert not external, (
        f"{compose_name} declares external volume(s) {external}. `docker "
        "compose down -v` does not remove those, so a ledger written into one "
        "survives every teardown this project performs."
    )


# ---------------------------------------------------------------------------
# P3c3f-9: the two spellings Compose accepts and this parse could not see.
# ---------------------------------------------------------------------------

# Verified against `docker compose -p p3c3ffixb9 config`, which resolves this
# to a bind mount of ImmuDB's data directory to a host path and to
# `external: true` on the named volume. Neither is hypothetical YAML.
_BOTH_SPELLINGS = """services:
  immudb:
    image: busybox
    volumes:
      - type: bind
        source: ./ledger-on-the-host
        target: /var/lib/immudb
  verifier:
    image: busybox
    volumes:
      - verifier-state:/data/verifier-state
volumes:
  verifier-state:
    external: True
"""


def test_a_long_form_bind_mount_of_the_ledger_is_seen():
    """The mount spelling the parse could not read.

    `spec.split(":")` on `- type: bind` produced a mount named `type` at
    target `" bind"`, which matches no stateful container path and was
    skipped. The stack it describes keeps its ledger on the host, where
    `down -v` cannot touch it.

    Driven through the same check the compose files go through, so this
    asserts what the test does rather than what the parse returns.
    """
    mounts, _declared = _parse(_BOTH_SPELLINGS)
    stateful = [(service, source, target) for service, source, target in mounts
                if target in STATEFUL_CONTAINER_PATHS]
    assert ("immudb", "./ledger-on-the-host", "/var/lib/immudb") in stateful, (
        "the long-form bind mount of ImmuDB's data directory is not a mount "
        f"this parse produced. It produced: {mounts}"
    )

    offenders = [f"{source} at {target}" for service, source, target in stateful
                 if source.startswith(".") or source.startswith("/")]
    assert offenders, (
        "the host path this file binds the ledger to is not refused, so a "
        "ledger that survives every `down -v` this project performs passes "
        "this module"
    )

    # And the control: the short-form mount in the same file is still read.
    assert ("verifier", "verifier-state", "/data/verifier-state") in mounts, (
        "the short-form mount stopped being parsed, so a parse that returns "
        f"nothing at all would satisfy the assertion above: {mounts}"
    )


def test_an_external_volume_is_seen_whatever_case_yaml_spells_true_in():
    """`external: True` is external to Compose and was not to the regex.

    YAML's boolean is case-insensitive and Compose resolves `True`, `TRUE`
    and `true` alike. `down -v` does not remove an external volume, so a
    ledger written into one survives every teardown.
    """
    for spelling in ("true", "True", "TRUE"):
        _mounts, declared = _parse(_BOTH_SPELLINGS.replace("external: True",
                                                           f"external: {spelling}"))
        external = external_volumes(declared)
        assert external == ["verifier-state"], (
            f"`external: {spelling}` is not reported as an external volume: "
            f"{declared}"
        )

    _mounts, declared = _parse(_BOTH_SPELLINGS.replace("    external: True\n", ""))
    assert not external_volumes(declared), (
        "a volume with no `external:` key is reported as external, so the "
        "check above would pass against a file with no external volume in it"
    )
