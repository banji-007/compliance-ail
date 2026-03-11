"""
OPA Bundle Generator
====================
Produces a spec-compliant OPA bundle (tar.gz) for a given tenant.

Bundle structure:
  .manifest          — OPA manifest with revision (ETag) and roots
  data.json          — tenant-specific config variables (injected into data.ail.config)
  core/main.rego     — always included (the fail-closed aggregator)
  packs/<fw>/<fw>.rego — included for each enabled compliance framework

The ETag is a SHA-256 digest of all file contents, computed before the
archive is built. OPA sends If-None-Match on subsequent polls; returning
304 avoids unnecessary bundle re-downloads.
"""

import hashlib
import io
import json
import tarfile
from pathlib import Path

from models import Tenant

# Mounted read-only from ./policy in docker-compose.yml
POLICY_ROOT = Path("/policy")


def _add_bytes(tar: tarfile.TarFile, archive_path: str, content: bytes) -> None:
    info = tarfile.TarInfo(name=archive_path)
    info.size = len(content)
    tar.addfile(info, io.BytesIO(content))


def generate_bundle(tenant: Tenant) -> tuple[bytes, str]:
    """
    Build an OPA bundle tar.gz for the given tenant.
    Returns (bundle_bytes, etag).
    """
    pack_flags: dict[str, bool] = {
        "gdpr": tenant.enable_gdpr,
        "soc2": tenant.enable_soc2,
        "finops": tenant.enable_finops,
        "hipaa": tenant.enable_hipaa,
    }

    # --- Collect policy files ---
    files: dict[str, bytes] = {}

    # Core is always active
    for rego in sorted((POLICY_ROOT / "core").glob("*.rego")):
        files[f"core/{rego.name}"] = rego.read_bytes()

    # Enabled packs only
    for pack_name, enabled in pack_flags.items():
        if enabled:
            pack_dir = POLICY_ROOT / "packs" / pack_name
            for rego in sorted(pack_dir.glob("*.rego")):
                files[f"packs/{pack_name}/{rego.name}"] = rego.read_bytes()

    # --- Build data.json with tenant-specific config ---
    def _split(value: str) -> list[str]:
        return [v.strip() for v in value.split(",") if v.strip()]

    data_doc = {
        "ail": {
            "config": {
                "tenant_id": tenant.id,
                "allowed_cost_centers": _split(tenant.allowed_cost_centers),
                "approved_regions": _split(tenant.approved_regions),
                "approved_purposes": _split(tenant.approved_purposes),
            }
        }
    }
    data_json = json.dumps(data_doc, sort_keys=True, indent=2).encode()

    # --- Compute ETag (SHA-256 over all content, deterministic order) ---
    h = hashlib.sha256()
    for archive_path, content in sorted(files.items()):
        h.update(archive_path.encode())
        h.update(content)
    h.update(data_json)
    etag = h.hexdigest()

    # --- Build manifest ---
    manifest = json.dumps(
        {"revision": etag, "roots": ["ail"]},
        sort_keys=True,
    ).encode()

    # --- Assemble tar.gz in memory ---
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        _add_bytes(tar, ".manifest", manifest)
        _add_bytes(tar, "data.json", data_json)
        for archive_path, content in sorted(files.items()):
            _add_bytes(tar, archive_path, content)

    return buf.getvalue(), etag
