"""
tests/test_external_anchor.py - P3b-4 and P3b-5 (Phase 3b, D23).

Every test in this file runs with no live stack, no Docker, and no network.
The transparency log entry under test is a real one: a genuine submission to
https://log2025-1.rekor.sigstore.dev, made by tools/export_evidence_fixtures.py
while it was regenerating the committed bundles, and verified here against
Sigstore's own TrustedRoot fetched via TUF in the same run.

The live submission itself is a command-backed claim, not a test - see
docs/reports/phase-3b.md, which marks that row explicitly rather than
claiming test coverage for it. Nothing in this file talks to Rekor. What is
enforced here is that the entry it returned verifies offline, that tampering
with it is refused by name, and that a bundle with no corroboration says so
in a field rather than by leaving one out.

Why sigstore-python does the work
---------------------------------
verify_merkle_inclusion is an RFC 6962 audit-path recomputation and
verify_checkpoint parses a C2SP signed note and checks the log operator's
signature against a keyring built from the TrustedRoot. Both are reached
through TransparencyLogEntry._verify, the same path sigstore-python's own
client takes, for the same reason immudb-py's verifiedGet.call() does the
ledger half: ADR-0001 records what happened the one time this project wrote
its own proof code.
"""

import ast
import base64
import copy
import importlib.util as _importlib_util
import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "evidence_bundles"
CHECKER_SRC = REPO_ROOT / "tools" / "ail_verify_bundle.py"

FIXTURE_KEY = FIXTURES / "signing.pub"
WRITER_KEYS = [FIXTURES / "writer-decision.pub", FIXTURES / "writer-control-plane.pub"]
ANCHOR_KEYS = [FIXTURES / "anchor-signing.pub"]
OTHER_KEY = FIXTURES / "other-signing.pub"
TRUSTED_ROOT = FIXTURES / "trusted_root.json"
PROVENANCE = json.loads((FIXTURES / "PROVENANCE.json").read_text(encoding="utf-8"))

BUNDLE_FILES = {
    "policy_allow": FIXTURES / "policy_allow.json",
    "policy_deny": FIXTURES / "policy_deny.json",
    "fault": FIXTURES / "fault.json",
    "content_erasure": FIXTURES / "content_erasure.json",
}

# Which fixtures are in which state is read from PROVENANCE.json rather than
# written down here. The difference between the two states is a fact about
# transaction ordering during the export run - records written before the
# anchoring cycle are covered by it, records written after are not - so
# hardcoding it would make these tests wrong the first time a regeneration
# ordered things differently, in the direction of passing anyway.
ANCHORED = sorted(PROVENANCE["anchored"])
NOT_ANCHORED = sorted(PROVENANCE["not_anchored"])


def _load_checker():
    spec = _importlib_util.spec_from_file_location("ail_verify_bundle", CHECKER_SRC)
    module = _importlib_util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_REAL_SOCKET_CONNECT = socket.socket.connect

checker = _load_checker()

socket.socket.connect = _REAL_SOCKET_CONNECT


@pytest.fixture(autouse=True)
def _offline_only():
    saved = socket.socket.connect
    checker.block_network()
    try:
        yield
    finally:
        socket.socket.connect = saved


def _bundle(name) -> dict:
    return json.loads(BUNDLE_FILES[name].read_text(encoding="utf-8"))


def _keys(paths):
    return checker.load_writer_keys([str(p) for p in paths])


def _check(bundle: dict, trusted_root=TRUSTED_ROOT, anchor_keys=None, **kwargs):
    checker.block_network()
    return checker.verify_bundle(
        bundle,
        checker.load_key(FIXTURE_KEY),
        _keys(WRITER_KEYS),
        trusted_root_path=trusted_root,
        anchor_keys=_keys(anchor_keys if anchor_keys is not None else ANCHOR_KEYS),
        **kwargs,
    )


def _entry(bundle: dict) -> dict:
    return bundle["external_anchor"]["transparency_log_entry"]


def _flip_first_byte(b64_value: str) -> str:
    raw = bytearray(base64.b64decode(b64_value))
    raw[0] ^= 0xFF
    return base64.b64encode(bytes(raw)).decode()


# ---------------------------------------------------------------------------
# The fixtures have to contain both states for anything below to mean
# anything. Asserted first rather than assumed.
# ---------------------------------------------------------------------------

def test_the_committed_fixtures_cover_both_anchor_states():
    """
    P3b-5's precondition. A fixture set that was entirely anchored, or
    entirely not, would let every test below pass while exercising one half
    of the rule. tools/export_evidence_fixtures.py asserts the same thing at
    generation time; this asserts it about what actually landed in the repo.
    """
    assert ANCHORED, "no committed fixture is anchored"
    assert NOT_ANCHORED, "no committed fixture is unanchored"
    assert set(ANCHORED) | set(NOT_ANCHORED) == set(BUNDLE_FILES)
    for name in ANCHORED:
        assert _bundle(name)["external_anchor"]["state"] == "anchored"
    for name in NOT_ANCHORED:
        assert _bundle(name)["external_anchor"]["state"] == "not_anchored"


def test_an_anchored_bundles_proof_runs_to_the_anchored_checkpoint():
    """
    P3b-1, asserted on the committed artifacts rather than on a live stack,
    so it runs in CI unconditionally.

    Two things have to hold for an anchored bundle to mean anything to an
    outside party, and they are different claims:

      1. The dual proof runs to the checkpoint that was published, so
         proof.prove_since_tx is the checkpoint's transaction.
      2. That checkpoint is not simply whatever the exporting verifier
         happened to hold, which nobody outside can check.

    The second is what the P3b-1 mutation attacks, and the fixture set
    distinguishes them by construction: the anchored bundles were exported
    against a checkpoint at an earlier transaction than the unanchored ones,
    which fell back to the verifier's own state. Under the mutation all four
    would name the same transaction, and this comparison fails.
    """
    anchored_since = {name: _bundle(name)["proof"]["prove_since_tx"] for name in ANCHORED}
    held_since = {name: _bundle(name)["proof"]["prove_since_tx"] for name in NOT_ANCHORED}

    for name, since in anchored_since.items():
        bundle = _bundle(name)
        assert bundle["proof"]["source_state"]["tx_id"] == since
        assert bundle["record"]["tx_id"] <= since, (
            f"{name}: the record is newer than the checkpoint its proof runs to"
        )

    assert len(set(anchored_since.values())) == 1, (
        f"the anchored fixtures name different checkpoints: {anchored_since}"
    )
    assert set(anchored_since.values()).isdisjoint(set(held_since.values())), (
        "the anchored bundles are anchored at the same transaction the "
        f"unanchored ones fell back to ({anchored_since} vs {held_since}); "
        "the export is anchoring at the verifier's held state"
    )


# ---------------------------------------------------------------------------
# P3b-4: a committed fixture proof verifies offline.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("record_type", ANCHORED)
def test_an_anchored_bundle_verifies_its_log_entry_offline(record_type):
    """
    P3b-4, the enforcing test. A real inclusion proof and a real witnessed
    checkpoint from the public log, checked against a TUF-fetched TrustedRoot
    held as its own file, in a process whose sockets are dead.
    """
    try:
        result = _check(_bundle(record_type))
    except checker.NetworkAccessAttempted as exc:
        pytest.fail(f"the checker attempted a network connection: {exc}")

    assert result["result_class"] == checker.VERIFIED
    external = result["external_anchor"]
    assert external["state"] == "anchored"
    assert external["checked"] is True
    assert external["log_url"].startswith("https://")
    assert int(external["log_index"]) > 0


def test_the_checker_attempts_no_network_while_checking_an_anchored_bundle():
    """
    P3b-4: "a test asserting the checker attempts no network access".

    The block is asserted to be live in this process first, so a pass below
    cannot be explained by a machine that happened to have no route out.
    sigstore-python is imported inside verify_external_anchor, after the
    block is already installed, deliberately: the anchor check has to prove
    it needs no network rather than be trusted not to use one.
    """
    checker.block_network()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(checker.NetworkAccessAttempted):
            sock.connect(("127.0.0.1", 443))
    finally:
        sock.close()

    result = _check(_bundle(ANCHORED[0]))
    assert result["external_anchor"]["checked"] is True


def test_nothing_but_a_hash_a_signature_and_a_key_reached_the_public_log():
    """
    Pre-registered negative 6, checked against the entry the log actually
    returned rather than against the code that built the request.

    docs/reports/spike-signing-anchor.md B5 established this shape by
    decoding a live canonicalizedBody; this re-establishes it for the entry
    this project's own anchoring path produced, and additionally checks that
    no field of the anchored record - the agent id, the tool name, the call
    id, the input hash - appears anywhere in the entry.
    """
    for record_type in ANCHORED:
        bundle = _bundle(record_type)
        entry = _entry(bundle)
        body = json.loads(base64.b64decode(entry["canonicalizedBody"]))
        spec = body["spec"]["hashedRekordV002"]
        assert set(spec) == {"data", "signature"}, spec
        assert set(spec["data"]) == {"algorithm", "digest"}
        assert set(spec["signature"]) == {"content", "verifier"}
        assert set(spec["signature"]["verifier"]) == {"keyDetails", "publicKey"}

        record = json.loads(base64.b64decode(bundle["record"]["value"]).decode())
        entry_text = json.dumps(entry)
        for field in ("agent_id", "tool_name", "call_id", "input_sha256", "policy_revision"):
            value = record.get(field)
            if isinstance(value, str) and value:
                assert value not in entry_text, (
                    f"{record_type}: the record's {field} appears inside the "
                    "transparency log entry; the log must hold a hash of a "
                    "checkpoint, never record content"
                )


# ---------------------------------------------------------------------------
# P3b-4's mutation: tamper the persisted root hash.
# ---------------------------------------------------------------------------

def test_a_tampered_root_hash_is_refused_with_the_invalid_root_hash_error():
    """
    P3b-4's named mutation. The claimed rootHash is not trusted: sigstore
    recomputes the root from the leaf and the audit path and compares, and
    separately cross-checks it against the root the signed checkpoint
    commits to. CLIENTS.md warns about exactly this ("do not use the
    unverified root hash and tree size"), and the warning is only worth
    anything if something enforces it.
    """
    bundle = _bundle(ANCHORED[0])
    proof = _entry(bundle)["inclusionProof"]
    proof["rootHash"] = _flip_first_byte(proof["rootHash"])

    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check(bundle)
    assert excinfo.value.result_class == checker.ANCHOR_FAILURE
    assert "invalid root hash" in excinfo.value.detail, excinfo.value.detail


def test_a_tampered_audit_path_is_refused():
    """A hash in the audit path changed. The recomputed root then differs
    from the signed checkpoint's, which is the same refusal by a different
    route - the proof is bound to the path, not only to its endpoints."""
    bundle = _bundle(ANCHORED[0])
    proof = _entry(bundle)["inclusionProof"]
    proof["hashes"][0] = _flip_first_byte(proof["hashes"][0])

    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check(bundle)
    assert excinfo.value.result_class == checker.ANCHOR_FAILURE


def test_a_tampered_checkpoint_envelope_is_refused():
    """The checkpoint is a signed note. Editing a byte of it breaks the log
    operator's signature over it, which is what makes the root hash it
    commits to worth cross-checking against in the first place."""
    bundle = _bundle(ANCHORED[0])
    proof = _entry(bundle)["inclusionProof"]
    envelope = proof["checkpoint"]["envelope"]
    proof["checkpoint"]["envelope"] = envelope.replace("log2025", "log2026", 1)

    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check(bundle)
    assert excinfo.value.result_class == checker.ANCHOR_FAILURE


def test_a_tampered_log_index_is_refused():
    bundle = _bundle(ANCHORED[0])
    entry = _entry(bundle)
    entry["inclusionProof"]["logIndex"] = str(int(entry["inclusionProof"]["logIndex"]) + 1)

    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check(bundle)
    assert excinfo.value.result_class == checker.ANCHOR_FAILURE


# ---------------------------------------------------------------------------
# The binding: an entry has to be about THIS bundle's anchor.
# ---------------------------------------------------------------------------

def test_a_real_log_entry_about_a_different_state_does_not_corroborate_this_one():
    """
    The forgery this check exists for, and the one a naive implementation
    misses: paste a genuine, fully verifiable transparency log entry into a
    bundle it has nothing to do with.

    Every signature in that entry is valid, its inclusion proof checks out,
    and its checkpoint is witnessed - it simply concerns another ledger
    state. The bundle is refused because the checker recomputes the anchored
    payload from proof.source_state, the checkpoint its own dual proof runs
    to, and requires the log's digest to be that payload's.
    """
    victim = _bundle(NOT_ANCHORED[0])
    donor = _bundle(ANCHORED[0])
    assert victim["proof"]["source_state"]["tx_id"] != donor["proof"]["source_state"]["tx_id"]

    victim["external_anchor"] = copy.deepcopy(donor["external_anchor"])
    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check(victim)
    assert excinfo.value.result_class == checker.ANCHOR_FAILURE
    assert "not about this bundle's trust anchor" in excinfo.value.detail


def test_the_anchor_binding_is_recomputed_from_the_proofs_own_source_state():
    """
    The same binding, exercised on the function directly so the failing
    comparison is unambiguous rather than inherited from an earlier check.

    A source_state one transaction away from the anchored one is refused,
    which is what makes the tx_id inside proof.source_state load-bearing
    rather than decorative.
    """
    bundle = _bundle(ANCHORED[0])
    shifted = dict(bundle["proof"]["source_state"])
    shifted["tx_id"] = int(shifted["tx_id"]) + 1

    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        checker.verify_external_anchor(bundle, shifted, TRUSTED_ROOT, _keys(ANCHOR_KEYS))
    assert excinfo.value.result_class == checker.ANCHOR_FAILURE


def test_a_rewritten_log_index_is_refused():
    """
    Found by tools/bundle_byte_sweep.py, not anticipated - the same way
    Phase 3a found `record_type`. Before this check, all 17 bytes of
    log_index were inert: the field is not an input to any proof, so a
    bundle could point a reader at a different entry in the same log and
    still verify. log_index is exactly the thing a person acts on when they
    go and look the entry up for themselves, so it is compared against the
    entry rather than believed.
    """
    bundle = _bundle(ANCHORED[0])
    section = bundle["external_anchor"]
    section["log_index"] = str(int(section["log_index"]) + 1)

    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check(bundle)
    assert excinfo.value.result_class == checker.ANCHOR_FAILURE
    assert "log_index" in excinfo.value.detail


def test_a_rewritten_log_url_is_refused():
    """
    The other half of the same byte-sweep finding: 43 inert bytes of
    log_url, which is the other thing a reader acts on.

    It cannot be checked against the bundle - the bundle is what is under
    suspicion - so it is checked against the TrustedRoot the checker holds:
    the entry names the log that signed it by key id, the trust root says
    what that log's base URL is, and the bundle's claim has to agree with
    both. The checkpoint signature is then verified under that same key, so
    the key id is not taken on the entry's word either.
    """
    bundle = _bundle(ANCHORED[0])
    bundle["external_anchor"]["log_url"] = "https://rekor.example.invalid"

    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check(bundle)
    assert excinfo.value.result_class == checker.ANCHOR_FAILURE
    assert "log_url" in excinfo.value.detail


def test_an_entry_naming_a_log_the_trust_root_does_not_know_is_refused():
    """A log key id absent from your TrustedRoot is a log you have no
    reason to trust, and no key to check a checkpoint against."""
    bundle = _bundle(ANCHORED[0])
    entry = _entry(bundle)
    entry["logId"]["keyId"] = _flip_first_byte(entry["logId"]["keyId"])

    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check(bundle)
    assert excinfo.value.result_class == checker.ANCHOR_FAILURE


def test_an_anchor_naming_a_key_the_checker_does_not_hold_is_refused():
    """
    Distinct from a tamper, for the reason P3b-3 draws the same distinction
    for writer keys: not holding a key is answerable by obtaining one, and a
    checker that reported it as a failed proof would send an auditor after
    the wrong problem.
    """
    bundle = _bundle(ANCHORED[0])
    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check(bundle, anchor_keys=[OTHER_KEY])
    assert excinfo.value.result_class == checker.ANCHOR_KEY_UNKNOWN


def test_an_anchored_bundle_is_not_quietly_passed_when_nothing_can_check_it():
    """
    A bundle that claims corroboration and is checked by someone holding no
    trust root has not been fully checked. Reporting "verified" there would
    print the same word for two different amounts of evidence, so it is
    refused by name instead, and the opt-out is explicit.
    """
    bundle = _bundle(ANCHORED[0])
    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check(bundle, trusted_root=None)
    assert excinfo.value.result_class == checker.ANCHOR_UNCHECKED

    skipped = _check(bundle, trusted_root=None, skip_anchor_check=True)
    assert skipped["result_class"] == checker.VERIFIED
    assert skipped["external_anchor"]["checked"] is False, (
        "an explicitly skipped anchor check must report itself as unchecked, "
        "not as checked"
    )


# ---------------------------------------------------------------------------
# P3b-5: fail-closed on the claim.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("record_type", NOT_ANCHORED)
def test_an_unanchored_bundle_states_its_lack_of_corroboration_in_a_field(record_type):
    """
    P3b-5, the enforcing test and the mutation target.

    The mutation is: make an unanchored bundle omit external_anchor rather
    than state it. Nothing about the local proof chain would change and the
    bundle would still verify against Phase 3a's checks, so only an
    assertion on the field itself catches it.

    Absence of a field and absence of corroboration are different facts. A
    bundle exported by an older build, a bundle whose section was stripped
    in transit, and a bundle for a record no checkpoint covers would all
    look identical if this were an omission - and only the third of those is
    honest evidence.
    """
    bundle = _bundle(record_type)
    section = bundle["external_anchor"]
    assert section["state"] == "not_anchored"
    assert section["detail"], "the unanchored state must say so in words, not only by a flag"
    assert "transparency_log_entry" not in section, (
        "an unanchored bundle carries no log entry; carrying an empty one "
        "would be a corroboration-shaped field with nothing in it"
    )

    result = _check(bundle)
    assert result["result_class"] == checker.VERIFIED
    assert result["external_anchor"]["state"] == "not_anchored"
    assert result["external_anchor"]["checked"] is False


def test_a_bundle_that_omits_the_anchor_section_entirely_is_refused():
    """
    The mutation, applied. A bundle with no external_anchor section is not a
    bundle making no claim - it is a bundle this checker cannot tell apart
    from one whose claim was removed, so it is refused rather than read as
    "presumably not anchored".
    """
    bundle = _bundle(NOT_ANCHORED[0])
    del bundle["external_anchor"]
    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check(bundle)
    assert excinfo.value.result_class == checker.MALFORMED_BUNDLE
    assert "external_anchor" in excinfo.value.detail


def test_an_anchor_section_with_no_state_is_refused():
    bundle = _bundle(NOT_ANCHORED[0])
    del bundle["external_anchor"]["state"]
    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check(bundle)
    assert excinfo.value.result_class == checker.MALFORMED_BUNDLE


def test_an_unrecognised_anchor_state_is_refused_rather_than_guessed_at():
    bundle = _bundle(NOT_ANCHORED[0])
    bundle["external_anchor"]["state"] = "probably_fine"
    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check(bundle)
    assert excinfo.value.result_class == checker.MALFORMED_BUNDLE


def test_the_two_states_are_distinguishable_without_reading_an_absence():
    """
    P3b-5: "the two are distinguishable without reading the absence of a
    field". Both bundles have the same key set at the top level and the same
    key present inside it; what differs is a value.
    """
    anchored = _bundle(ANCHORED[0])
    unanchored = _bundle(NOT_ANCHORED[0])
    assert set(anchored) == set(unanchored)
    assert "state" in anchored["external_anchor"] and "state" in unanchored["external_anchor"]
    assert anchored["external_anchor"]["state"] != unanchored["external_anchor"]["state"]


def test_an_unanchored_bundle_cannot_claim_corroboration_by_relabelling():
    """
    Fail-closed on the claim, in its most direct form: flipping the state
    string to "anchored" does not produce corroboration, it produces a
    refusal, because the section then has to carry an entry that binds to
    this bundle's own anchor and it has none.
    """
    bundle = _bundle(NOT_ANCHORED[0])
    bundle["external_anchor"]["state"] = "anchored"
    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check(bundle)
    assert excinfo.value.result_class == checker.MALFORMED_BUNDLE


# ---------------------------------------------------------------------------
# Pre-registered negatives that are properties of the source, not of a run.
# ---------------------------------------------------------------------------

def test_no_log_instance_url_is_hardcoded_anywhere_in_the_product():
    """
    Pre-registered negative 5. B1 found the public 2025 instance is
    scheduled for turndown and its URL rotates, so a URL written into the
    source would be a scheduled outage.

    The committed fixture and the spike's own artifacts do contain the URL -
    that is a record of where a real submission went, not a configuration
    this project reads - so the scan covers source and configuration, and
    names the exclusions rather than quietly skipping directories.
    """
    scanned = []
    offenders = []
    roots = ["provenance", "anchor_service", "control_plane", "verifier", "ledger",
             "decision_service", "tools"]
    for root in roots:
        for path in sorted((REPO_ROOT / root).rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            scanned.append(path)
            text = path.read_text(encoding="utf-8")
            for marker in ("rekor.sigstore.dev", "log2025-1", "log2026-1"):
                if marker in text:
                    offenders.append(f"{path.relative_to(REPO_ROOT)}: {marker}")
    for name in ("docker-compose.yml", "docker-compose.test.yml", "Makefile"):
        path = REPO_ROOT / name
        scanned.append(path)
        if "rekor.sigstore.dev" in path.read_text(encoding="utf-8"):
            offenders.append(f"{name}: rekor.sigstore.dev")

    assert scanned, "the scan matched no files, so it proved nothing"
    assert not offenders, (
        "a Rekor instance URL is hardcoded; it must be discovered from "
        f"Sigstore's own TUF-distributed configuration: {offenders}"
    )


def test_the_log_url_is_discovered_and_the_bundle_records_which_source_answered():
    """
    The other half of the same negative: not hardcoding is only meaningful
    if something did the discovering. The bundle records which of the two
    TUF-distributed documents supplied the URL, so a reader can tell whether
    SigningConfig advertised a v2 instance or the TrustedRoot's tlogs did.
    """
    sys.path.insert(0, str(REPO_ROOT))
    from provenance import rekor

    for record_type in ANCHORED:
        section = _bundle(record_type)["external_anchor"]
        assert section["log_url_source"] in (
            rekor.DISCOVERY_SIGNING_CONFIG,
            rekor.DISCOVERY_TRUSTED_ROOT,
        ), section["log_url_source"]
        assert section["log_url"] in json.dumps(
            json.loads(TRUSTED_ROOT.read_text(encoding="utf-8"))
        ), (
            "the URL the submission went to is not one the committed TrustedRoot "
            "names, so it was not discovered from it"
        )


def test_no_test_in_this_file_accepts_a_broad_exception():
    """Same enforcement tests/test_offline_verify.py applies to itself: a
    refusal test that accepted Exception would pass against a crash."""
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    this_function = "test_no_test_in_this_file_accepts_a_broad_exception"

    offenders = []
    unchecked = []
    for func in ast.walk(tree):
        if not isinstance(func, ast.FunctionDef) or func.name == this_function:
            continue
        raises_calls = [
            node for node in ast.walk(func)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "raises"
        ]
        for call in raises_calls:
            arg = call.args[0] if call.args else None
            named = (
                arg.attr if isinstance(arg, ast.Attribute)
                else arg.id if isinstance(arg, ast.Name)
                else repr(arg)
            )
            if named not in ("BundleCheckFailed", "NetworkAccessAttempted"):
                offenders.append(f"{func.name}: pytest.raises({named})")
        if raises_calls and "BundleCheckFailed" in ast.dump(func):
            if not any(
                isinstance(n, ast.Attribute) and n.attr == "result_class"
                for n in ast.walk(func)
            ):
                unchecked.append(func.name)

    assert not offenders, f"tests must name the specific failure they expect: {offenders}"
    assert not unchecked, f"these tests never assert which check failed: {unchecked}"
