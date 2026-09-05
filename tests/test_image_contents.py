"""tests/test_image_contents.py - Phase 3c-3c, rewritten in 3c-3d and 3c-3e.

No image carries key material, in any encoding, on any inspection surface.

Why this exists. D35 moved the verifier's build context from `./verifier`
(three files) to the repository root, so the image could carry `provenance/` -
the canonicalization rule it needs to sign the fault record it now writes.
That is correct and it widened what the context can reach from three files to
the whole tree, including `keys/`.

The verifier image turned out clean, because its Dockerfile names every path
it copies. What the check found instead was a sibling that does not:
`decision_service/Dockerfile`'s `COPY decision_service/ ./` bakes
`decision_service/secrets/vault_api_token.txt` into the image on any machine
where `make keygen` has run. `.dockerignore` now excludes both. **The image
check does not consult `.dockerignore`**, deliberately: a rule in that file is
a described mechanism, and what matters is what is in the artifact.

**Phase 3c-3d rewrote both checks, because both were name matching.** The
image check matched `*.key` by filename and pruned site-packages; the red team
put three live P-256 keys into an image under other names and it passed. The
static check flagged a `COPY` only if the line contained `keys/` or `secrets`,
which `COPY decision_service/ ./` does not.

**Phase 3c-3e (P3c3e-5): the rewrite was still one encoding on one surface,
and the red team got past both.**

  A10.1  The same key as DER - `openssl ec -outform DER` is one flag - rode
         into the real image and the module reported `5 passed`. Read back out
         with `docker cp` and re-armoured, it was byte-identical to the key on
         the host.

  A10.2  A PEM at column zero, deleted by a later layer, was invisible to a
         check that walks the running filesystem, and came back
         byte-identical out of `docker save` with two commands.

So there are two enumerations here, and **both are hand-listed and both are
weaker for it.** That is stated rather than implied, because this phase's rule
is that an enumeration is derived from the code wherever it can be, and
neither of these can be:

  * The **encodings** are a fact about cryptography and about what tools
    people have, not about this repository. Nothing in the tree names them, so
    there is nothing to derive them from. What can be checked is that the
    detector actually finds each one, which is what
    `test_the_detector_finds_every_encoding_this_file_enumerates` does with
    real key material generated in-process - so an encoding listed here and
    not detected fails, and dropping one from the detector fails.

  * The **inspection surfaces** are a fact about Docker's image format. Same
    reasoning: nothing in the tree enumerates them.

What is NOT enumerated, and is therefore the honest ceiling of both lists: an
encoding nobody here thought of, and a surface nobody here thought of. The
first list is a table anyone can extend; the second has the two that exist for
a local image - what a running container sees, and what the image holds.

**Phase 3c-3f (P3c3f-7): three shapes closed, one bound kept with its cost.**
The Phase 3c-3e red team shipped three shapes of the live
`keys/writer-decision.key` in the real decision-service image at `18 passed`
and recovered one byte-identical with `docker run` and `base64 -d`. Two
detector gaps produced that, and both are closed: a decoded base64 body was
offered to the binary rule but never to the PEM armour rule, so base64 of a
PEM was not key material - which is how a Kubernetes Secret, a Helm value, a
JSON config and a `.env` line each carry a key. And `_B64RUN.findall(head)[:20]`
decoded the first twenty base64 runs only, so a DER key behind 21 decoy runs
was invisible while the same key behind 19 was found. Gzip is caught now too.

**The bound on reading, stated, and kept for a measured reason:** only the
first 16 KiB of a file is examined. A PEM P-256 key is about 230 bytes and an
RSA 4096 key about 3.2 KiB, so a key file is covered whole; a key buried past
16 KiB of other content is not.

That bound is a decision rather than an oversight, and here is what it buys,
measured inside `decision-service` (6800 files, 43 MB read at 16 KiB against
170 MB whole):

    16 KiB head, first 20 base64 runs (the old detector)   17.7s, 16.5s
    16 KiB head, every base64 run (this phase)             18.5s, 18.3s
    whole files, every base64 run                          57.5s, 57.4s

Dropping the twenty-run cap costs about a second and a half per image.
Dropping the head bound is 3.1 times the work on the running-filesystem
surface, four images and two surfaces, against a check pass that already
measures about three and a half minutes.

**And there is a second reason, which the measurement turned up.** The
whole-file walk returns one hit:

    base64-pkcs8-der /usr/local/lib/python3.11/site-packages/ecdsa/
                     __pycache__/test_keys.cpython-311.pyc  (62047 bytes)

That is a published test vector inside a dependency's bytecode, past 16 KiB,
and it is real private key material by every rule here. Abandoning the bound
therefore means an exemption list keyed by path - name matching, standing in
front of a content check, which is exactly what the Phase 3c-3d red team got
past and what the rewrite above exists to replace. Buying the bound is a scope
call and it is not this phase's to make.

**Gzip, closed rather than bounded.** A `.gz` of a PEM was the one archive
shape missed while the same key inside an uncompressed `.tar` and inside a
`.zip` was caught, because compression destroys the base64 body the `_B64RUN`
rule decodes. A failed `gzip.decompress` on a 16 KiB head measures 0.010 ms
and the four-image pass did not move, so it is caught. What is still not
caught: a gzip member whose compressed form runs past the head, which raises
`EOFError` and answers nothing, and any compression this list does not name.

Binary key material is additionally required to start at offset zero of the
file, of a base64 body inside it, or of a decompressed gzip member, which is
what a key file is - a DER blob embedded in the middle of some other binary is
not found, and `ecdsa/__pycache__/ssh.cpython-311.pyc`, which carries the
OpenSSH magic string as a constant because it is the module that parses the
format, is correctly not a hit.

Requires the docker CLI and the images the compose stack was built from.
"""

import fnmatch
import io
import subprocess
import sys
import tarfile
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

# The vault token has no content signature - it is 64 hex characters - so it
# is still matched by name, and that limit is stated rather than papered over.
_CREDENTIAL_NAMES = ("vault_api_token",)

_HEAD_BYTES = 16384


# ---------------------------------------------------------------------------
# The detector. One source, two surfaces.
# ---------------------------------------------------------------------------
#
# Written as a string because one of the two surfaces runs it inside the image
# under test, where nothing from this repository is importable. The host-side
# surface execs the same string, so the two surfaces cannot drift into
# checking different things - which is the defect class this whole phase is
# about, one level down.
#
# Stdlib only, for the same reason.
_DETECTOR_SOURCE = r'''
import base64 as _b64, gzip as _gzip, io as _io, re as _re

# How much of a compressed body is decompressed before the detector gives up.
# The same 16 KiB the caller reads, so a crafted member cannot cost more than
# an ordinary file does.
_DECOMPRESS_LIMIT = 16384

# PEM, in every armour that says PRIVATE KEY, plus PuTTY's own header. The
# BEGIN line has to be at column zero with a matching END: source code that
# MENTIONS the same header carries it inside a quoted string, which is the
# difference between keys/writer-verifier.key and ecdsa/test_keys.py,
# cryptography/.../ssh.py and their bytecode - all of which a bare substring
# match flags, and all of which are in every image this project builds.
_ARMOUR = _re.compile(
    br"(?:\A|\n)-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----\r?\n"
    br"[\s\S]{0,20000}?"
    br"(?:\A|\n)-----END [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----"
    br"|(?:\A|\n)PuTTY-User-Key-File-\d+: ")

# DER, by ASN.1 structure rather than by extension. Each of these is the
# distinctive prefix of a private key and of nothing else:
#   PKCS8   version INTEGER (0 or 1), then an AlgorithmIdentifier SEQUENCE
#           carrying one of three algorithm OIDs.
#   SEC1    version INTEGER 1, then an OCTET STRING of exactly 32, 48 or 66
#           bytes - the private scalar for P-256, P-384 or P-521.
#   PKCS1   version INTEGER 0, then a long-form INTEGER, which is the modulus.
_ALG_OIDS = (br"\x06\x07\x2a\x86\x48\xce\x3d\x02\x01",              # ecPublicKey
             br"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01",      # rsaEncryption
             br"\x06\x03\x2b\x65\x70")                              # Ed25519
_PKCS8 = _re.compile(br"\x02\x01[\x00\x01]\x30.{0,3}(?:" + br"|".join(_ALG_OIDS)
                     + br")", _re.S)
_SEC1 = _re.compile(br"\x02\x01\x01\x04[\x20\x30\x42]")
_PKCS1 = _re.compile(br"\x02\x01\x00\x02[\x81\x82]")

_OPENSSH_MAGIC = b"openssh-key-v1" + bytes([0])
_DER_SEQUENCE = bytes([0x30])

# A base64 body with the armour stripped. Long enough not to fire on ordinary
# words; the shortest thing here is a P-256 SEC1 key at about 160 characters.
_B64RUN = _re.compile(br"[A-Za-z0-9+/=\r\n]{120,}")


def _binary_key_material(blob):
    """Which binary encoding this blob STARTS with, or None.

    Anchored at offset zero, which is what a key file is. Not anchored, the
    OpenSSH magic matches `ecdsa/__pycache__/ssh.cpython-311.pyc`, which
    carries it as a constant because it is the module that parses the format -
    a mention, not material, and the same distinction the armour rule draws
    with column zero.
    """
    if blob[:len(_OPENSSH_MAGIC)] == _OPENSSH_MAGIC:
        return "openssh"
    if blob[:1] != _DER_SEQUENCE:
        return None
    head = blob[:64]
    if _PKCS8.search(head):
        return "pkcs8-der"
    if _SEC1.search(head):
        return "sec1-der"
    if _PKCS1.search(head):
        return "pkcs1-der"
    return None


def _b64_candidates(run):
    """The bodies a matched base64 run could actually be.

    `=` is base64 PADDING and is only valid at the end of a body, so a run
    holding `=` with more base64 characters after it is not one body: it is a
    name, an assignment, and then the body. `AIL_WRITER_SIGNING_KEY_B64=<key>`
    is that shape, and decoding the run whole shifts the alignment by four
    characters and produces nothing. So the run is offered whole and then in
    the pieces the padding runs cut it into.

    P3c3f-7. Without this the `.env` line is not detected while the identical
    key in a Kubernetes Secret is, because YAML happens to put a space between
    the key and the value and `AIL_..._B64=` has no separator the run rule
    breaks on.
    """
    flat = _re.sub(br"[\r\n]", b"", run)
    seen = [flat]
    for piece in _re.split(br"=+", flat):
        # Re-padded: the split removed this piece's own trailing `=`, and
        # b64decode refuses a body whose length is not a multiple of four
        # however lenient it is about everything else.
        piece = piece + b"=" * (-len(piece) % 4)
        if len(piece) >= 120 and piece not in seen:
            seen.append(piece)
    return seen


def _gzip_body(head):
    """A gzip member's contents, bounded, or empty.

    Anchored at offset zero by the magic, which is the same rule the binary
    check draws: a `.gz` file is a gzip member at offset zero, and a byte
    sequence that happens to contain the magic somewhere is a mention.

    A member whose compressed form runs past the head raises `EOFError` and
    answers nothing, so this catches a small compressed key and states that it
    does not catch a large one.
    """
    if head[:2] != b"\x1f\x8b":
        return b""
    try:
        return _gzip.GzipFile(fileobj=_io.BytesIO(head)).read(_DECOMPRESS_LIMIT)
    except Exception:
        return b""


def key_material(head):
    """Which encoding of private key material these bytes carry, or None."""
    if _ARMOUR.search(head):
        return "pem"
    found = _binary_key_material(head)
    if found:
        return found

    # P3c3f-7: gzip. Compression destroys the base64 body the archive rules
    # below rely on, so a `.gz` of a PEM was not key material to this detector
    # while the same PEM inside an uncompressed `.tar` or a `.zip` was. Cheap
    # to close and measured: a failed `gzip.decompress` on a 16 KiB head is
    # 0.010 ms, and the whole four-image pass did not move.
    body = _gzip_body(head)
    if body:
        if _ARMOUR.search(body):
            return "gzip-pem"
        found = _binary_key_material(body)
        if found:
            return "gzip-" + found

    # And the same, inside a base64 body with no armour around it.
    #
    # P3c3f-7 (Phase 3c-3f), two corrections here, both driven by the Phase
    # 3c-3e red team against the real decision-service image:
    #
    #   1. A decoded body is offered to the ARMOUR rule as well as to the
    #      binary one. It used to be offered to the binary rule alone, so
    #      base64 of a PEM decoded to PEM text, failed the DER prefix test,
    #      and was not key material - which is how a Kubernetes Secret, a Helm
    #      value, a JSON config and a `.env` line all carry a key. Three
    #      shapes of the live `keys/writer-decision.key` shipped in the real
    #      image at `18 passed` and came back byte-identical with one
    #      `docker run` and one `base64 -d`.
    #
    #   2. Every base64 run in the head is decoded, not the first twenty. A
    #      DER key behind 21 decoy runs was not detected and behind 19 it was,
    #      and that cap was stated in neither the module docstring nor
    #      anywhere else. A 16 KiB head holds at most 136 runs at this rule's
    #      120-character minimum, so the bound was buying very little; the
    #      measurement is in the module docstring.
    for run in _B64RUN.findall(head):
        for candidate in _b64_candidates(run):
            try:
                decoded = _b64.b64decode(candidate, validate=False)
            except Exception:
                continue
            if _ARMOUR.search(decoded):
                return "base64-pem"
            found = _binary_key_material(decoded)
            if found:
                return "base64-" + found
    return None
'''

_DETECTOR = {}
exec(compile(_DETECTOR_SOURCE, "<detector>", "exec"), _DETECTOR)  # noqa: S102
key_material = _DETECTOR["key_material"]


# The walk that runs INSIDE an image. Only /proc, /sys, /dev and /run are
# skipped, because they are kernel interfaces rather than image contents.
# site-packages, /usr/share and /usr/lib are walked: they were pruned before,
# and the red team's third key was in site-packages.
_IN_IMAGE_WALK = _DETECTOR_SOURCE + '''
import os

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
        found = key_material(head)
        if found:
            hits.append(found + ":" + path)
print("|".join(hits))
'''.format(names=list(_CREDENTIAL_NAMES), head=_HEAD_BYTES)


# ---------------------------------------------------------------------------
# Enumeration one: the encodings. Hand-listed, and weaker for it.
# ---------------------------------------------------------------------------

def _signing_key():
    import ecdsa
    return ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)


def _armoured_openssh(key) -> bytes:
    """An OpenSSH-format private key file, structurally.

    The real thing is this armour around a base64 body whose first bytes are
    the `openssh-key-v1` magic. Built rather than generated because
    `ssh-keygen` is not a dependency of this suite; what the detector has to
    find is the armour and the magic, and both are here.
    """
    import base64
    body = (_DETECTOR["_OPENSSH_MAGIC"] + b"\x00\x00\x00\x04none" * 8
            + key.to_string())
    return (b"-----BEGIN OPENSSH PRIVATE KEY-----\n"
            + base64.encodebytes(body)
            + b"-----END OPENSSH PRIVATE KEY-----\n")


def _pkcs8_version_zero(key) -> bytes:
    """PKCS8 as OpenSSL writes it.

    `ecdsa` emits the PrivateKeyInfo version INTEGER as 1 and OpenSSL emits
    it as 0; the two DER blobs are otherwise byte-identical for the same key,
    measured against `openssl pkcs8 -topk8 -nocrypt -outform DER`. Both are
    enumerated because the SEC1 signature also begins `02 01 01`, so a
    detector that had lost its PKCS8 rule would still classify the version-1
    form and would miss the one OpenSSL actually produces.
    """
    blob = bytearray(key.to_der(format="pkcs8"))
    version = blob.index(b"")
    blob[version + 2] = 0
    return bytes(blob)


def _base64_no_header(key) -> bytes:
    import base64
    return base64.encodebytes(key.to_der())


def _base64_of_a_pem(key) -> bytes:
    """A PEM, base64'd. How a secret manifest carries a key.

    P3c3f-7. This is what the Phase 3c-3e red team shipped in the real
    decision-service image at `18 passed`: `key_material` looked for PEM
    armour in the RAW head only, so a decoded base64 body was offered to the
    binary rule alone, failed the DER prefix test, and was not key material.
    A Kubernetes Secret, a Helm value, a JSON config and a `.env` line all
    carry a key exactly this way.
    """
    import base64
    return base64.encodebytes(key.to_pem())


def _kubernetes_secret(key) -> bytes:
    """The same, in the manifest it usually arrives in."""
    import base64
    return (b"apiVersion: v1\nkind: Secret\nmetadata:\n  name: ail-writer\n"
            b"type: Opaque\ndata:\n  writer.key: "
            + base64.b64encode(key.to_pem()) + b"\n")


def _dotenv_line(key) -> bytes:
    import base64
    return b"AIL_WRITER_SIGNING_KEY_B64=" + base64.b64encode(key.to_pem()) + b"\n"


def _gzipped_pem(key) -> bytes:
    """A PEM inside a gzip member.

    Compression destroys the base64 body, so this was the one archive shape
    the detector missed while catching the same key inside an uncompressed
    `.tar` and inside a `.zip`.
    """
    import gzip
    import io
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb") as handle:
        handle.write(key.to_pem())
    return buffer.getvalue()


def _base64_behind_decoys(key) -> bytes:
    """A base64 DER key behind 21 base64 runs that are not keys.

    `_B64RUN.findall(head)[:20]` decoded the first twenty runs and no more, so
    this was not detected and the same key behind 19 decoys was. That cap was
    stated in neither the module docstring nor anywhere else.
    """
    import base64
    return b" ".join([b"Q" * 130] * 21) + b" " + base64.b64encode(key.to_der())


# name -> (builder, what the detector should call it). Extend this table to
# extend the check; a name here that the detector does not find fails.
KEY_ENCODINGS = {
    "pem":              (lambda key: key.to_pem(), "pem"),
    "pem-pkcs8":        (lambda key: key.to_pem(format="pkcs8"), "pem"),
    "der-sec1":         (lambda key: key.to_der(), "sec1-der"),
    "der-pkcs8":        (lambda key: key.to_der(format="pkcs8"), "pkcs8-der"),
    "der-pkcs8-openssl": (_pkcs8_version_zero, "pkcs8-der"),
    "openssh":          (_armoured_openssh, "pem"),
    "base64-no-header": (_base64_no_header, "base64-sec1-der"),
    # P3c3f-7, the shapes the Phase 3c-3e red team got past.
    "base64-of-a-pem":  (_base64_of_a_pem, "base64-pem"),
    "kubernetes-secret": (_kubernetes_secret, "base64-pem"),
    "dotenv-line":      (_dotenv_line, "base64-pem"),
    "gzipped-pem":      (_gzipped_pem, "gzip-pem"),
    "base64-behind-21-decoy-runs": (_base64_behind_decoys, "base64-sec1-der"),
}


@pytest.mark.parametrize("encoding", sorted(KEY_ENCODINGS))
def test_the_detector_finds_every_encoding_this_file_enumerates(encoding):
    """Real key material, generated here, in each enumerated encoding.

    This is the half of the encoding list that can be checked: the list itself
    is a judgement, and whether the detector honours it is not. Dropping one
    encoding from the detector fails exactly one of these.
    """
    build, expected = KEY_ENCODINGS[encoding]
    blob = build(_signing_key())
    found = key_material(blob)
    assert found is not None, (
        f"the detector does not find a private key encoded as {encoding}. "
        f"First bytes: {blob[:40]!r}"
    )
    assert found == expected, (
        f"a {encoding} key was detected as {found!r} rather than {expected!r}"
    )


def test_the_detector_does_not_fire_on_public_key_material_or_prose():
    """The control. A detector that flags everything passes for the wrong
    reason, and this one walks every file in four images."""
    key = _signing_key()
    for name, blob in (
        ("public pem", key.get_verifying_key().to_pem()),
        ("public der", key.get_verifying_key().to_der()),
        ("prose", b"the private key lives in keys/ and is never copied\n" * 40),
        ("empty", b""),
    ):
        assert key_material(blob) is None, (
            f"the detector reports key material in {name}: {key_material(blob)}"
        )


def test_the_two_enumerations_are_hand_listed_and_say_so():
    """This file's own weakest point, asserted so it cannot be quietly
    forgotten.

    Neither list can be derived: nothing in this repository enumerates the
    encodings a private key can be written in, or the surfaces a Docker image
    can be read on. What is here is two tables anyone can extend, and the
    ceiling is an entry nobody thought of.
    """
    module_doc = sys.modules[__name__].__doc__
    assert "hand-listed" in module_doc, (
        "the module docstring no longer states that these enumerations are "
        "hand-listed, which is the one thing a reader has to know about them"
    )
    assert len(KEY_ENCODINGS) >= 5, KEY_ENCODINGS
    assert len(INSPECTION_SURFACES) >= 2, INSPECTION_SURFACES


# ---------------------------------------------------------------------------
# Enumeration two: the inspection surfaces. Hand-listed, and weaker for it.
# ---------------------------------------------------------------------------

def _image_name(service: str) -> str:
    """Compose names a built image {project}-{service}."""
    return f"{COMPOSE_PROJECT}-{service}"


def _image_exists(image: str) -> bool:
    result = subprocess.run(["docker", "image", "inspect", image],
                            capture_output=True, text=True)
    return result.returncode == 0


def _running_filesystem(image: str) -> list[str]:
    """What a reader of the RUNNING container can find.

    This is the surface the check had before P3c3e-5, and on its own it is a
    claim about the last layer rather than about the image.
    """
    result = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "python", image, "-c",
         _IN_IMAGE_WALK],
        capture_output=True, text=True, timeout=1800,
    )
    assert result.returncode == 0, (
        f"could not inspect {image}: {result.stderr[-300:]}"
    )
    return [hit for hit in result.stdout.strip().split("|") if hit.strip()]


def _every_layer(image: str) -> list[str]:
    """What the IMAGE contains, layer by layer, including deleted files.

    `docker save` streamed through this process rather than written to disk:
    the four images here are about 1.2 GB together and none of it needs to
    land anywhere. Each blob in the archive is either a layer (a tar, possibly
    gzipped) or JSON metadata; the metadata does not open as a tar and is
    skipped.

    This is the surface A10.2 used. `FROM <image>` / `COPY id_ecdsa` /
    `RUN rm -f` leaves the key in the layer that added it, invisible to the
    running filesystem and recoverable from the archive with two commands.
    """
    hits: list[str] = []
    process = subprocess.Popen(["docker", "save", image], stdout=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            for member in archive:
                if not member.isfile():
                    continue
                stream = archive.extractfile(member)
                if stream is None:
                    continue
                blob = stream.read()
                if not (blob[:2] == b"\x1f\x8b" or blob[257:262] == b"ustar"):
                    continue          # image metadata, not a layer
                try:
                    inner = tarfile.open(fileobj=io.BytesIO(blob), mode="r:*")
                except Exception:
                    continue
                with inner:
                    for entry in inner:
                        if not entry.isfile():
                            continue
                        name = Path(entry.name).name
                        if any(fragment in name for fragment in _CREDENTIAL_NAMES):
                            hits.append(f"name:{member.name}!{entry.name}")
                            continue
                        handle = inner.extractfile(entry)
                        if handle is None:
                            continue
                        found = key_material(handle.read(_HEAD_BYTES))
                        if found:
                            hits.append(f"{found}:{member.name}!{entry.name}")
    finally:
        process.stdout.close()
        process.wait()
    return hits


# name -> the function that reads it. Two, because a local image has two:
# what a process inside it sees, and what the artifact holds.
INSPECTION_SURFACES = {
    "running-filesystem": _running_filesystem,
    "every-layer-in-docker-save": _every_layer,
}


@requires_docker_cli
@pytest.mark.parametrize("surface", sorted(INSPECTION_SURFACES))
@pytest.mark.parametrize("service", ROOT_CONTEXT_SERVICES)
def test_no_image_built_from_the_repository_root_carries_key_material(service, surface):
    """Asserted against the image, not against `.dockerignore`.

    A rule in `.dockerignore` is a claim about what the daemon was sent. This
    is a claim about what a reader of the image can find, which is the one
    that matters if the rule is ever wrong or removed - and it is asked on
    both surfaces now, because a file deleted by a later layer answers
    differently on each.
    """
    image = _image_name(service)
    if not _image_exists(image):
        pytest.skip(
            f"image {image!r} is not built; this test inspects the images the "
            "running stack was built from"
        )
    found = INSPECTION_SURFACES[surface](image)
    assert not found, (
        f"{image} carries key material or a credential on the {surface} "
        f"surface: {found}. No Dockerfile should copy keys/ or "
        "decision_service/secrets/, and .dockerignore keeps them out of the "
        "build context so a future COPY cannot reach them by accident. A hit "
        "prefixed with an encoding name means the file's bytes ARE a private "
        "key in that encoding, whatever the file is called; on the layer "
        "surface it may be a file a later layer deleted, which is still in "
        "the image."
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

    The same detector the image checks run, applied to the source tree: the
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
    return key_material(head) is not None


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
    images the tests above happen to find built.

    Not the criterion - the image inspection is - but it catches a new
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
