"""tests/test_image_contents.py - Phase 3c-3c completion pass.

No image carries key material.

Why this exists. D35 moved the verifier's build context from `./verifier`
(three files) to the repository root, so the image could carry
`provenance/` - the canonicalization rule it needs to sign the fault record
it now writes. That is correct and it widened what the context can reach
from three files to the whole tree, including `keys/`.

The verifier image turned out clean, because its Dockerfile names every
path it copies. What the check found instead was a sibling that does not:
`decision_service/Dockerfile`'s `COPY decision_service/ ./` bakes
`decision_service/secrets/vault_api_token.txt` into the image on any
machine where `make keygen` has run. Confirmed by writing a probe token and
rebuilding - it was readable at `/app/secrets/vault_api_token.txt`. The
token reaches the running service as a Compose secret at
`/run/secrets/vault_api_token` and is never read from the image, so nothing
depended on it being there.

`.dockerignore` now excludes both. **This test does not check
`.dockerignore`**, deliberately: a rule in that file is a described
mechanism, and what matters is what is in the artifact. It inspects the
built images.

Requires the docker CLI and the images the compose stack was built from.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tests"))

from compose_helpers import COMPOSE_PROJECT, requires_docker_cli  # noqa: E402

# The services whose images are built from the repository root, which is the
# whole of what this test is about. `dashboard` builds from ./dashboard and
# `opa`/`immudb` are upstream images.
ROOT_CONTEXT_SERVICES = ("verifier", "ail-control-plane", "decision-service",
                         "anchor-service")

# What must not be in an image, by name. Private keys and the vault token;
# the public halves are not secret and `signing.pub` is legitimately mounted.
_FORBIDDEN = r"""
import os, sys
hits = []
for root, dirs, files in os.walk("/"):
    if root.startswith(("/proc", "/sys", "/dev", "/run")):
        dirs[:] = []
        continue
    if "site-packages" in root or "/usr/share" in root or "/usr/lib" in root:
        dirs[:] = []
        continue
    for name in files:
        if name.endswith(".key") or "vault_api_token" in name:
            hits.append(os.path.join(root, name))
print("\n".join(hits))
"""


def _image_name(service: str) -> str:
    """Compose names a built image {project}-{service}."""
    return f"{COMPOSE_PROJECT}-{service}"


def _image_exists(image: str) -> bool:
    result = subprocess.run(["docker", "image", "inspect", image],
                            capture_output=True, text=True)
    return result.returncode == 0


@requires_docker_cli
@pytest.mark.parametrize("service", ROOT_CONTEXT_SERVICES)
def test_no_image_built_from_the_repository_root_carries_key_material(service):
    """
    Asserted against the image, not against `.dockerignore`.

    A rule in `.dockerignore` is a claim about what the daemon was sent. This
    is a claim about what a reader of the image can find, which is the one
    that matters if the rule is ever wrong or removed.
    """
    image = _image_name(service)
    if not _image_exists(image):
        pytest.skip(
            f"image {image!r} is not built; this test inspects the images the "
            "running stack was built from"
        )

    result = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "python", image, "-c", _FORBIDDEN],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, (
        f"could not inspect {image}: {result.stderr[-300:]}"
    )
    found = [line for line in result.stdout.splitlines() if line.strip()]
    assert not found, (
        f"{image} carries key material or a credential: {found}. No Dockerfile "
        "should copy keys/ or decision_service/secrets/, and .dockerignore "
        "keeps them out of the build context so a future COPY cannot reach "
        "them by accident."
    )


def test_no_dockerfile_copies_key_material():
    """The second line, static, over every Dockerfile rather than the four
    images the test above happens to find built.

    Not the criterion - the image inspection above is - but it catches a new
    Dockerfile before anything is built from it.
    """
    offenders = []
    for path in sorted(REPO_ROOT.rglob("Dockerfile")):
        if ".git" in path.parts:
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if not stripped.startswith(("COPY", "ADD")):
                continue
            if "keys/" in stripped or "secrets" in stripped:
                offenders.append(f"{path.relative_to(REPO_ROOT).as_posix()}:{number}: {stripped}")
    assert not offenders, (
        f"a Dockerfile names key material or secrets in a COPY: {offenders}"
    )
