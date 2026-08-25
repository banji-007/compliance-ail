#!/usr/bin/env python3
"""
export_evidence_fixtures.py - regenerate tests/fixtures/evidence_bundles/.

Run ONLINE against a live docker-compose.test.yml stack. Produces one real
ledger record of each shape the audit trail can hold, exports each one's
evidence bundle through the real GET /audit/bundle route (not by assembling
JSON here), and writes the results plus the public key they were exported
against into the fixture directory.

    docker compose -p p3b-bundle -f docker-compose.test.yml up -d --build --wait
    python tools/export_evidence_fixtures.py
    docker compose -p p3b-bundle -f docker-compose.test.yml down -v

D23 (Phase 3b) makes one step of this reach the public internet. Between
writing the first two records and the last two, this script runs one real
anchoring cycle - a genuine submission to a Rekor v2 instance discovered
from Sigstore's own TUF-distributed configuration - so the committed
fixtures contain both states a bundle can be in:

    policy_allow, policy_deny   written before the anchor  -> anchored
    fault, content_erasure      written after it           -> not_anchored

Both are real. Neither is hand-edited into that state, and the difference
between them is a fact about transaction ordering rather than a flag this
script sets. The anchoring step runs in a one-shot container built from
anchor_service/Dockerfile and attached to the compose project's own
network, because sigstore-python's TUF client needs symlink privileges this
project's own spike found Windows refuses (WinError 1314,
docs/reports/spike-signing-anchor.md, "What blocked it").

The bundles are committed so tests/test_offline_verify.py can check them
with no stack at all. The key is committed alongside them, as its own file,
because a bundle never carries the key it is checked against (D18, P3a-5).

The fixture key is deliberately NOT keys/signing.pub from a later run: these
bundles were signed by whatever ImmuDB signing key was mounted when they
were exported, so the matching public key has to travel with them. That is
the same constraint any real auditor faces, made concrete.
"""

import base64
import json
import os
import shutil
import subprocess
import sys
import uuid
from datetime import datetime
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT = REPO_ROOT / "tests" / "fixtures" / "evidence_bundles"

CONTROL_PLANE = os.getenv("CONTROL_PLANE_URL", "http://localhost:8002")
VERIFIER = os.getenv("VERIFIER_URL", "http://localhost:8003")
READ_KEY = os.getenv("CONTROL_PLANE_READ_KEY", "test-read-key")
WRITE_KEY = os.getenv("CONTROL_PLANE_WRITE_KEY", "test-write-key")
# D21 (Phase 3a completion): ledger/immudb_ledger.py, loaded in-process below
# via decision_service/main.py, now needs this to write through the verifier.
VERIFIER_WRITE_KEY = os.getenv("VERIFIER_WRITE_KEY", "test-verifier-write-key")
VERIFIER_READ_KEY = os.getenv("VERIFIER_READ_KEY", "test-verifier-read-key")

# The compose project the anchoring container attaches to. Every compose
# invocation in this repository passes an explicit -p, and this is the same
# name; a mismatch here surfaces as an unresolvable network rather than as a
# silently wrong fixture.
COMPOSE_PROJECT = os.getenv("AIL_COMPOSE_PROJECT", "p3b-bundle")
ANCHOR_ONESHOT_IMAGE = "ail-anchor-oneshot"

# This script loads the decision service in-process on the host, while the
# stack it drives runs in compose. decision_service/main.py,
# ledger/immudb_ledger.py and ledger/content_store.py all default to the
# compose service names (http://opa:8181, http://verifier:8003,
# http://ail-control-plane:8002), which do not resolve from here, so each is
# pointed at the published loopback port. Without this the script still runs
# and still writes fixtures, but every decision comes back as a fault record
# instead of the record type asked for; the assertions in main() catch that,
# and setting these means they do not have to.
os.environ.setdefault("SPIRE_DISABLED", "true")
os.environ.setdefault("OPA_URL", "http://localhost:8181/v1/data/ail/main/evaluation")
os.environ.setdefault("VERIFIER_URL", VERIFIER)
os.environ.setdefault("CONTROL_PLANE_URL", CONTROL_PLANE)
os.environ.setdefault("CONTROL_PLANE_WRITE_KEY", WRITE_KEY)
os.environ.setdefault("VERIFIER_WRITE_KEY", VERIFIER_WRITE_KEY)
# D22 (Phase 3b): ledger/immudb_ledger.py signs every record before writing
# it, and refuses to write one it cannot sign. Loaded in-process here, so
# the key path has to be a host path rather than the container's /keys.
os.environ.setdefault(
    "AIL_WRITER_SIGNING_KEY", str(REPO_ROOT / "keys" / "writer-decision.key")
)

sys.path.insert(0, str(REPO_ROOT / "decision_service"))
sys.path.insert(0, str(REPO_ROOT / "ledger"))

_APPROVED_ARGS = {
    "instance_type": "t3.micro",
    "region": "us-east-1",
    "cost_per_hour": 5.0,
    "tags": {
        "environment": "dev",
        "data_classification": "internal",
        "cost_center": "engineering",
        "project": "webapp",
    },
}

# Denied by the FinOps pack: an instance class far outside the approved set.
_DENIED_ARGS = {**_APPROVED_ARGS, "instance_type": "p4d.24xlarge", "cost_per_hour": 50.0}


def _load_decision_service_main():
    """Same explicit-module-name load tests/ use, for the same reason:
    decision_service/main.py and control_plane/main.py are both main.py."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "decision_service_main", REPO_ROOT / "decision_service" / "main.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["decision_service_main"] = module
    spec.loader.exec_module(module)
    return module


def _decide(decision_main, tool_name, tool_args, agent_id):
    import asyncio

    req = decision_main.DecideRequest(
        tool_name=tool_name, tool_args=tool_args, agent_id=agent_id
    )
    return asyncio.run(decision_main.decide(req))


def _audit_entries():
    resp = httpx.get(
        f"{CONTROL_PLANE}/audit",
        params={"limit": 200},
        headers={"X-API-Key": READ_KEY},
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()["entries"]


def _export_bundle(ledger_key: str) -> dict:
    """Through the real route, with the real read credential."""
    resp = httpx.get(
        f"{CONTROL_PLANE}/audit/bundle",
        params={"key": ledger_key},
        headers={"X-API-Key": READ_KEY},
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()


def _erasure_tombstone_key(agent_id: str) -> str:
    """Produce a real content_erasure tombstone by driving the control
    plane's own erasure route, never by writing one directly."""
    call_id = f"p3a-fixture-{uuid.uuid4().hex}"
    httpx.post(
        f"{CONTROL_PLANE}/content",
        json={"call_id": call_id, "payload": {"fixture": agent_id, "note": "erased below"}},
        headers={"X-API-Key": WRITE_KEY},
        timeout=30,
    ).raise_for_status()
    httpx.delete(
        f"{CONTROL_PLANE}/content/{call_id}",
        headers={"X-API-Key": WRITE_KEY},
        timeout=30,
    ).raise_for_status()
    return base64.b64encode(f"content_erasure:{call_id}".encode()).decode()


def _write_trusted_root() -> None:
    """Copy the TUF-fetched Sigstore TrustedRoot out of the one-shot image.

    Fetched inside the container for the reason this script's own docstring
    gives: sigstore-python's TUF client calls os.symlink, which Windows
    refuses without elevated privileges. Written to the fixture directory so
    tests/test_external_anchor.py can verify the committed inclusion proof
    with no network at all.
    """
    out = OUT / "trusted_root.json"
    result = subprocess.run(
        [
            "docker", "run", "--rm", ANCHOR_ONESHOT_IMAGE,
            "python", "-c",
            "import sys;"
            "from sigstore._internal.tuf import TrustUpdater, DEFAULT_TUF_URL;"
            "u = TrustUpdater(DEFAULT_TUF_URL, offline=False);"
            "sys.stdout.write(open(u.get_trusted_root_path()).read())",
        ],
        check=True, capture_output=True, text=True,
    )
    out.write_text(result.stdout, encoding="utf-8", newline="\n")
    print(f"wrote {out.relative_to(REPO_ROOT)} ({out.stat().st_size} bytes)")


def _anchor_now() -> None:
    """Run one real anchoring cycle against the live public log.

    This is the one step in this script that leaves the machine. It builds
    anchor_service's image and runs it with --once on the compose project's
    own network, so it reaches the verifier and control plane by their
    service names exactly as the long-running service does in
    docker-compose.yml. Non-zero exit is fatal here, unlike in the
    unattended loop: fixtures that quietly came out unanchored would make
    every anchored-bundle test vacuous.
    """
    print("anchoring: building the one-shot image")
    subprocess.run(
        ["docker", "build", "-q", "-t", ANCHOR_ONESHOT_IMAGE,
         "-f", "anchor_service/Dockerfile", "."],
        cwd=str(REPO_ROOT), check=True,
    )
    print(f"anchoring: submitting to a Rekor v2 instance "
          f"(network {COMPOSE_PROJECT}_default)")
    subprocess.run(
        [
            "docker", "run", "--rm",
            "--network", f"{COMPOSE_PROJECT}_default",
            "-v", f"{REPO_ROOT / 'keys'}:/keys:ro",
            "-e", "VERIFIER_URL=http://verifier:8003",
            "-e", "CONTROL_PLANE_URL=http://ail-control-plane:8002",
            "-e", f"VERIFIER_READ_KEY={VERIFIER_READ_KEY}",
            "-e", f"CONTROL_PLANE_WRITE_KEY={WRITE_KEY}",
            "-e", "AIL_ANCHOR_SIGNING_KEY=/keys/anchor-signing.key",
            ANCHOR_ONESHOT_IMAGE, "python", "main.py", "--once",
        ],
        check=True,
    )


def main():
    agent_id = f"p3a_fixture_{uuid.uuid4().hex[:8]}"
    decision_main = _load_decision_service_main()

    print(f"agent_id for this run: {agent_id}")

    wanted = {}

    allow = _decide(decision_main, "provision_cloud_server", _APPROVED_ARGS, agent_id)
    print(f"  policy_allow: outcome={allow['outcome_type']} tx={allow.get('ledger_tx_id')}")
    wanted["policy_allow"] = allow["ledger_tx_id"]

    deny = _decide(decision_main, "provision_cloud_server", _DENIED_ARGS, agent_id)
    print(f"  policy_deny:  outcome={deny['outcome_type']} tx={deny.get('ledger_tx_id')}")
    wanted["policy_deny"] = deny["ledger_tx_id"]

    # D23: everything above this line is covered by the anchored
    # checkpoint; everything below it was written after and is not. The two
    # committed states differ by transaction ordering and nothing else.
    _anchor_now()

    # A fault, produced where the decision service would actually observe
    # one: OPA unreachable. Same mechanism tests/test_outcome_types.py uses.
    original_opa = decision_main._OPA_URL
    decision_main._OPA_URL = "http://localhost:1/v1/data/ail/main/evaluation"
    try:
        fault = _decide(decision_main, "provision_cloud_server", _APPROVED_ARGS, agent_id)
    finally:
        decision_main._OPA_URL = original_opa
    print(f"  fault:        outcome={fault['outcome_type']} "
          f"fault_class={fault.get('fault_class')} tx={fault.get('ledger_tx_id')}")
    wanted["fault"] = fault["ledger_tx_id"]

    tombstone_key = _erasure_tombstone_key(agent_id)
    print(f"  content_erasure tombstone key: {tombstone_key}")

    # Map tx ids back to ledger keys through /audit, the same path any
    # operator would take.
    entries = {e["tx_id"]: e for e in _audit_entries()}
    OUT.mkdir(parents=True, exist_ok=True)

    exported = {}
    for record_type, tx_id in wanted.items():
        entry = entries.get(tx_id)
        if entry is None:
            raise SystemExit(f"tx {tx_id} ({record_type}) not present in /audit")
        if entry["outcome_type"] != record_type:
            raise SystemExit(
                f"tx {tx_id} is {entry['outcome_type']}, expected {record_type}"
            )
        bundle = _export_bundle(entry["ledger_key"])
        assert bundle["record"]["record_type"] == record_type, bundle["record"]
        exported[record_type] = bundle

    exported["content_erasure"] = _export_bundle(tombstone_key)
    assert exported["content_erasure"]["record"]["record_type"] == "content_erasure"

    for record_type, bundle in exported.items():
        path = OUT / f"{record_type}.json"
        path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8", newline="\n")
        print(f"wrote {path.relative_to(REPO_ROOT)} "
              f"(tx={bundle['record']['tx_id']}, {path.stat().st_size} bytes)")

    # Every public key these bundles are checked against, each copied as its
    # own file. None of them is inside a bundle, and that separation is the
    # subject of P3a-5 and P3b-3 rather than an accident of layout.
    #   signing.pub               ImmuDB's state-signing key (D18)
    #   writer-decision.pub       the decision service's writer key (D22)
    #   writer-control-plane.pub  the control plane's writer key (D22)
    #   anchor-signing.pub        the key the Rekor submission was made under (D23)
    for name in (
        "signing.pub",
        "writer-decision.pub",
        "writer-control-plane.pub",
        "anchor-signing.pub",
    ):
        shutil.copyfile(REPO_ROOT / "keys" / name, OUT / name)
        print(f"wrote {(OUT / name).relative_to(REPO_ROOT)}")

    # Sigstore's TrustedRoot, fetched via TUF by the same one-shot container
    # that made the submission, so the committed trust root and the
    # committed entry come from one run rather than two. It plays exactly
    # the role signing.pub plays: an independently obtained trust anchor the
    # checker holds, never something the entry supplies about itself.
    _write_trusted_root()

    fingerprints = {b["signing_key"]["fingerprint"] for b in exported.values()}
    print(f"all bundles name signing key: {fingerprints}")
    assert len(fingerprints) == 1, "bundles disagree about which key signed them"

    anchored = {rt for rt, b in exported.items()
                if b["external_anchor"]["state"] == "anchored"}
    unanchored = set(exported) - anchored
    print(f"anchored: {sorted(anchored)}  not anchored: {sorted(unanchored)}")
    assert anchored, (
        "no fixture came out anchored; the anchoring cycle did not cover any "
        "of these records and every anchored-bundle test would be vacuous"
    )
    assert unanchored, (
        "every fixture came out anchored; P3b-5 needs a real unanchored bundle "
        "to compare against, not a hand-edited one"
    )

    (OUT / "PROVENANCE.json").write_text(
        json.dumps(
            {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "generated_by": "tools/export_evidence_fixtures.py",
                "agent_id": agent_id,
                "signing_key_fingerprint": sorted(fingerprints)[0],
                "record_types": sorted(exported),
                "writer_key_fingerprints": sorted({
                    json.loads(base64.b64decode(b["record"]["value"]))["writer_key_fingerprint"]
                    for b in exported.values()
                }),
                "anchored": sorted(anchored),
                "not_anchored": sorted(unanchored),
                "anchor": {
                    rt: {
                        "log_url": exported[rt]["external_anchor"]["log_url"],
                        "log_index": exported[rt]["external_anchor"]["log_index"],
                        "anchored_tx_id": exported[rt]["proof"]["source_state"]["tx_id"],
                    }
                    for rt in sorted(anchored)
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print("done")


if __name__ == "__main__":
    sys.exit(main())
