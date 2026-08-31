"""tests/test_image_contents.py - Phase 3c-3c, rewritten in Phase 3c-3d.

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

`.dockerignore` now excludes both. **The first check below does not consult
`.dockerignore`**, deliberately: a rule in that file is a described
mechanism, and what matters is what is in the artifact. It inspects the
built images.

**P3c3d-9 (Phase 3c-3d): both lines were rewritten, because both were name
matching.**

The image check matched `*.key` and `vault_api_token` by filename and pruned
site-packages, `/usr/share` and `/usr/lib`. The red team put three live P-256
private keys into an image - `/app/deploy_credential.pem`, `/app/id_rsa` and
`/usr/local/lib/python3.11/site-packages/leaked.key` - and it passed, 5
passed. Reproduced here before the rewrite, against an image built
`FROM p3c3dfix-decision-service` carrying exactly those three files:
`returncode=0 hits=[]`. It detects key material by content now, and it does
not prune the directories a key can be dropped into.

The static check flagged a `COPY` only if the line contained `keys/` or
`secrets`, which `COPY decision_service/ ./` does not - the line that
actually baked a credential was the one the string match missed. It resolves
each COPY source against the repository now, applies `.dockerignore`, and
asks what the daemon would actually receive.

Requires the docker CLI and the images the compose stack was built from.
"""

import fnmatch
import re
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

# What key material looks like, structurally, and why this is not a list of
# strings to grep for.
#
# A private key file carries a PEM armour BEGIN line at column zero, followed
# by a matching END line at column zero. Source code that MENTIONS the same
# header carries it inside a quoted string, so it is never at column zero -
# which is exactly the difference between `keys/writer-verifier.key` and
# `ecdsa/test_keys.py`, `cryptography/.../ssh.py` and their bytecode, all of
# which a bare substring match flags. Those four are in every image this
# project builds, so a substring match is not a check that can pass.
#
# The bound, stated: only the first 16 KiB of a file is read. A PEM P-256 key
# is about 230 bytes and an RSA 4096 key about 3.2 KiB, so a key file is
# covered whole; a key buried past 16 KiB of some other content is not.
_KEY_MATERIAL = (
    r"(?:\A|\n)-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----\r?\n"
    r"[\s\S]{0,20000}?"
    r"(?:\A|\n)-----END [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----"
    r"|(?:\A|\n)PuTTY-User-Key-File-\d+: "
)

# The vault token has no content signature - it is 64 hex characters - so it
# is still matched by name, and that limit is stated rather than papered over.
_CREDENTIAL_NAMES = ("vault_api_token",)

_HEAD_BYTES = 16384

# What must not be in an image. Private key material is found by CONTENT, not
# by filename: a name blacklist is defeated by renaming the file, which is
# exactly how three live P-256 keys rode into an image past the old version of
# this check.
#
# Only /proc, /sys, /dev and /run are skipped, because they are kernel
# interfaces rather than image contents. site-packages, /usr/share and
# /usr/lib are walked: they were pruned before, and the red team's third key
# was in site-packages.
_FORBIDDEN = """
import os, re

PATTERN = re.compile({pattern!r}.encode())
NAMES = {names!r}
HEAD = {head}

hits = []
for root, dirs, files in os.walk("/", onerror=lambda exc: None):
    if root.startswith(("/proc", "/sys", "/dev", "/run")):
        dirs[:] = []
        continue
    for name in files:
        path = os.path.join(root, name)
        if any(fragment in name for fragment in NAMES):
            hits.append("name:" + path)
            continue
        try:
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            with open(path, "rb") as handle:
                head = handle.read(HEAD)
        except Exception:
            continue
        if PATTERN.search(head):
            hits.append("content:" + path)
print("|".join(hits))
""".format(pattern=_KEY_MATERIAL, names=list(_CREDENTIAL_NAMES), head=_HEAD_BYTES)


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
        capture_output=True, text=True, timeout=900,
    )
    assert result.returncode == 0, (
        f"could not inspect {image}: {result.stderr[-300:]}"
    )
    found = [hit for hit in result.stdout.strip().split("|") if hit.strip()]
    assert not found, (
        f"{image} carries key material or a credential: {found}. No Dockerfile "
        "should copy keys/ or decision_service/secrets/, and .dockerignore "
        "keeps them out of the build context so a future COPY cannot reach "
        "them by accident. `content:` means the file's bytes carry a private "
        "key header, whatever the file is called."
    )


# ---------------------------------------------------------------------------
# The second line: static, over every Dockerfile, and about what a COPY
# reaches rather than about what its line says.
# ---------------------------------------------------------------------------

def _build_contexts() -> dict[Path, Path]:
    """Dockerfile -> the directory its build context actually is.

    Taken from the compose files, which are what declares it, rather than
    assumed to be the Dockerfile's own directory or the repository root.
    Both are wrong for some service here: `verifier/Dockerfile` builds from
    the repository root since D35, and `dashboard/Dockerfile` builds from
    `./dashboard`, so its `COPY . .` copies the dashboard and not the tree.
    Resolving every source against the root would report that line as
    reaching `decision_service/secrets/`, which it cannot.

    Parsed with a small reader rather than a YAML dependency, because this
    file has none and adding one to a test that runs in CI is a cost with no
    return: the two keys it needs are `context:` and `dockerfile:` inside a
    `build:` block, both plain scalars in both compose files.
    """
    contexts: dict[Path, Path] = {}
    for compose_name in ("docker-compose.yml", "docker-compose.test.yml"):
        compose = REPO_ROOT / compose_name
        if not compose.exists():
            continue
        context = None
        for line in compose.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("context:"):
                context = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("dockerfile:") and context is not None:
                dockerfile = stripped.split(":", 1)[1].strip()
                contexts[(REPO_ROOT / context / dockerfile).resolve()] = (
                    (REPO_ROOT / context).resolve())
                context = None
    return contexts


def _dockerignore_patterns(context: Path) -> list[str]:
    """The rules the `.dockerignore` for this build context states.

    Per context, because that is where the daemon looks for it: a Dockerfile
    built from `./dashboard` is filtered by `dashboard/.dockerignore` and not
    by the root one.

    Negations (`!pattern`) are deliberately NOT honoured: a negation makes
    this check weaker, and a check that can be switched off by a line in the
    file it is checking is not a check. If one is ever added it fails here
    with a message saying so, rather than silently letting a path through.
    """
    path = context / ".dockerignore"
    if not path.exists():
        return []
    patterns = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        assert not line.startswith("!"), (
            f"{path} carries a negation ({line!r}). This check does not honour "
            "one, because a rule that re-includes a path is a rule that can "
            "switch this check off."
        )
        patterns.append(line.rstrip("/"))
    return patterns


def _is_ignored(relative: Path, patterns: list[str]) -> bool:
    """Would the daemon have been sent this path.

    Matched per path and per ancestor directory, which is what a
    `.dockerignore` directory rule means: `keys/` excludes everything under
    `keys`.
    """
    candidates = [relative.as_posix()]
    candidates += [parent.as_posix() for parent in relative.parents
                   if parent.as_posix() != "."]
    for pattern in patterns:
        for candidate in candidates:
            if fnmatch.fnmatch(candidate, pattern):
                return True
            if fnmatch.fnmatch(Path(candidate).name, pattern):
                return True
    return False


def _looks_like_key_material(path: Path) -> bool:
    """Private key material by content, plus the vault token by name.

    Same rule as the image check above, applied to the source tree: the
    question asked is what the file is, not what it is called. A name
    blacklist is what let `COPY decision_service/ ./` through.
    """
    if any(fragment in path.name for fragment in _CREDENTIAL_NAMES):
        return True
    try:
        with path.open("rb") as handle:
            head = handle.read(_HEAD_BYTES)
    except Exception:
        return False
    return re.search(_KEY_MATERIAL.encode(), head) is not None


def _copy_sources(line: str) -> list[str]:
    """The source operands of a COPY or ADD instruction.

    A `--from=` stage copies out of another image and not out of the build
    context, so it reaches nothing in this repository. The last operand is
    the destination.
    """
    operands = line.split()[1:]
    if any(operand.startswith("--from=") for operand in operands):
        return []
    operands = [operand for operand in operands if not operand.startswith("--")]
    return operands[:-1]


def test_no_dockerfile_copies_key_material():
    """The second line, static, over every Dockerfile rather than the four
    images the test above happens to find built.

    Not the criterion - the image inspection above is - but it catches a new
    Dockerfile, or a removed `.dockerignore` rule, before anything is built.

    **What it asks.** For every COPY source, resolved against that
    Dockerfile's own build context, what the daemon would actually send: the
    paths under it that the context's `.dockerignore` does not exclude,
    filtered by what is key material by content. `COPY decision_service/ ./`
    names no forbidden string and reaches `decision_service/secrets/` all the
    same, which is the line that baked a live credential into an image while
    the old string match read it and found nothing.

    Demonstrated rather than asserted about itself: commenting the
    `decision_service/secrets/*.txt` rule out of `.dockerignore` fails this
    test with `decision_service/Dockerfile:28: 'COPY decision_service/ ./'
    reaches decision_service/secrets/vault_api_token.txt`, on a machine where
    `make keygen` has run. The old version read that same line and found
    nothing, because the line does not contain the string `secrets`.
    """
    contexts = _build_contexts()
    patterns_by_context: dict[Path, list[str]] = {}
    offenders = []
    for dockerfile in sorted(REPO_ROOT.rglob("Dockerfile")):
        if ".git" in dockerfile.parts:
            continue
        context = contexts.get(dockerfile.resolve(), dockerfile.parent.resolve())
        if context not in patterns_by_context:
            patterns_by_context[context] = _dockerignore_patterns(context)
        patterns = patterns_by_context[context]
        for number, line in enumerate(
                dockerfile.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if not stripped.startswith(("COPY", "ADD")):
                continue
            for source in _copy_sources(stripped):
                base = (context / source).resolve()
                try:
                    base.relative_to(context)
                except ValueError:
                    continue
                if not base.exists():
                    continue
                reachable = [base] if base.is_file() else list(base.rglob("*"))
                for candidate in reachable:
                    if not candidate.is_file():
                        continue
                    relative = candidate.relative_to(context)
                    if _is_ignored(relative, patterns):
                        continue
                    if _looks_like_key_material(candidate):
                        offenders.append(
                            f"{dockerfile.relative_to(REPO_ROOT).as_posix()}:{number}: "
                            f"{stripped!r} reaches {relative.as_posix()}"
                        )
    assert not offenders, (
        "a COPY or ADD reaches key material that .dockerignore does not "
        "exclude, so the daemon would receive it and the instruction would bake "
        f"it in: {offenders}"
    )
