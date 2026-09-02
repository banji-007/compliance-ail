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
    tests/test_image_contents.py gives: this repository has none, and what is
    needed here is two shapes - `- name:/path` under a service's `volumes:`,
    and the bare names under the top-level `volumes:` block.
    """
    mounts: list[tuple[str, str, str]] = []       # (service, source, target)
    declared: dict[str, str] = {}                 # name -> the lines under it
    service = None
    section = None
    top_level_volumes = False
    pending_volume = None

    for raw in compose_text.splitlines():
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        line = raw.strip()

        if indent == 0:
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
            service = line[:-1].strip()
            section = None
            continue
        if indent == 4 and line.startswith("volumes:"):
            section = "volumes"
            continue
        if indent == 4 and line.endswith(":"):
            section = None
            continue
        if section == "volumes" and line.startswith("- "):
            spec = line[2:].strip()
            parts = spec.split(":")
            if len(parts) >= 2:
                mounts.append((service or "", parts[0], parts[1]))
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


@pytest.mark.parametrize("compose_name", COMPOSE_FILES)
def test_no_volume_is_external(compose_name):
    """`down -v` removes the volumes the project created and leaves an
    external one alone, so an external volume is a ledger that persists
    across every run by design."""
    path = REPO_ROOT / compose_name
    _mounts, declared = _parse(path.read_text(encoding="utf-8"))
    external = sorted(name for name, body in declared.items()
                      if re.search(r"external:\s*true", body))
    assert not external, (
        f"{compose_name} declares external volume(s) {external}. `docker "
        "compose down -v` does not remove those, so a ledger written into one "
        "survives every teardown this project performs."
    )
