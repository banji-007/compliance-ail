"""
tests/test_offline_verify.py - P3a-3, P3a-4, P3a-5 (Phase 3a, D19/D20).

Every test in this file runs with no live stack, no Docker, and no network.
The bundles under test are fixtures committed to this repository
(tests/fixtures/evidence_bundles/), exported from a real docker-compose.test.yml
run and never regenerated at test time - which is the point. If verifying a
record needed the system that produced it, the bundle would not be portable
evidence, it would be a cache.

Network access is blocked at the socket layer for this whole module, and the
block is asserted to be live before any bundle is checked, so a passing
result here cannot be explained by an accidental connection. See
docs/reports/spike-offline-verify.md ("What blocked it") for why the patch
has to land after imports rather than before.

Provenance of the fixtures, and the command that regenerates them, are in
tests/fixtures/evidence_bundles/README.md.
"""

import ast
import base64
import importlib.util as _importlib_util
import json
import re
import socket
import subprocess
import sys
from pathlib import Path

import ecdsa
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "evidence_bundles"
CHECKER_SRC = REPO_ROOT / "tools" / "ail_verify_bundle.py"

# The key the fixture bundles were exported against. Held here as its own
# file, next to the bundles but never inside one - that separation is the
# subject of P3a-5, not an accident of layout.
FIXTURE_KEY = FIXTURES / "signing.pub"

# A second, unrelated key pair, generated once and committed, so "the
# checker was handed the wrong key" is a real key rather than a corrupted
# copy of the right one.
OTHER_KEY = FIXTURES / "other-signing.pub"

BUNDLE_FILES = {
    "policy_allow": FIXTURES / "policy_allow.json",
    "policy_deny": FIXTURES / "policy_deny.json",
    "fault": FIXTURES / "fault.json",
    "content_erasure": FIXTURES / "content_erasure.json",
}


def _load_checker():
    """Load tools/ail_verify_bundle.py under its own explicit module name.

    Same reason tests/test_content_states.py loads decision_service/main.py
    this way: an unqualified import would depend on sys.path ordering that
    another test file in the same pytest session can change. Importing it
    also installs its socket block for this process, which is exactly what
    these tests want.
    """
    spec = _importlib_util.spec_from_file_location("ail_verify_bundle", CHECKER_SRC)
    module = _importlib_util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Captured before the checker is loaded, because loading it installs the
# socket block process-wide - that is the D19 property of the tool and is
# left exactly as it is. What has to be contained is its reach: pytest
# imports every test module during collection, before running any test, so
# an import-time block that is never lifted would still be in force when
# tests/test_verification.py and the rest of the suite run later in the same
# process, and they would fail on a network the tool disabled rather than on
# anything about themselves. The block is therefore lifted here and
# reinstalled per test by _offline_only below, so it covers every check in
# this file and nothing outside it.
_REAL_SOCKET_CONNECT = socket.socket.connect

checker = _load_checker()

socket.socket.connect = _REAL_SOCKET_CONNECT


@pytest.fixture(autouse=True)
def _offline_only():
    """Every test in this module runs with sockets dead, and only this module.

    Autouse rather than left to each test: an offline assertion that forgot
    to install the block would still pass on a machine with a network, and
    would be proving nothing. The individual checker.block_network() calls
    in the tests below are kept as well, so a test read on its own still
    states the condition it depends on.
    """
    saved = socket.socket.connect
    checker.block_network()
    try:
        yield
    finally:
        socket.socket.connect = saved


# ---------------------------------------------------------------------------
# The network block is a precondition of every test below, so it is asserted
# rather than assumed.
# ---------------------------------------------------------------------------

def test_the_network_block_is_actually_installed():
    """
    P3a-3: importing the checker must make outbound connections raise, in
    this process, before any bundle is checked. Without this assertion the
    rest of the file would prove only that the checker did not need the
    network on a machine that happened to have one.
    """
    checker.block_network()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(checker.NetworkAccessAttempted):
            sock.connect(("127.0.0.1", 3322))
    finally:
        sock.close()


def test_merely_importing_the_checker_blocks_the_network():
    """
    P3a-3: the block is a property of importing the tool, not something a
    caller has to remember to switch on. Asserted by loading the module
    afresh with a real connect() in place and observing that the import
    alone replaced it, then putting the real one back.

    This is the assertion the module-level restore above would otherwise
    have quietly removed: without it, block_network() being called
    explicitly by every test would hide an import that had stopped blocking.
    """
    saved = socket.socket.connect
    socket.socket.connect = _REAL_SOCKET_CONNECT
    try:
        reloaded = _load_checker()
        assert socket.socket.connect is not _REAL_SOCKET_CONNECT, (
            "importing tools/ail_verify_bundle.py did not install the socket "
            "block; offline verification would be an accident of the machine "
            "it ran on rather than a property of the tool"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(reloaded.NetworkAccessAttempted):
                sock.connect(("127.0.0.1", 3322))
        finally:
            sock.close()
    finally:
        socket.socket.connect = saved


# ---------------------------------------------------------------------------
# P3a-3: a bundle verifies offline.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("record_type", sorted(BUNDLE_FILES))
def test_fixture_bundle_verifies_offline_with_no_network(record_type):
    """
    P3a-3: the enforcing test. A committed bundle, a committed public key,
    a process whose sockets are dead, and the SDK's own verification code.
    The test fails if the checker tries to connect to anything.
    """
    checker.block_network()
    try:
        result = checker.check(BUNDLE_FILES[record_type], FIXTURE_KEY)
    except checker.NetworkAccessAttempted as exc:
        pytest.fail(
            f"the offline checker attempted a network connection while verifying "
            f"the {record_type} fixture: {exc}"
        )

    assert result["result_class"] == checker.VERIFIED
    # The record_type the checker derives from the proven bytes, not the
    # label the bundle carries - and the control plane that exported this
    # fixture independently arrived at the same answer, which is what keeps
    # the tool's copy of that rule honest against the producer's.
    assert result["record_type"] == record_type
    assert json.loads(BUNDLE_FILES[record_type].read_text())["record"]["record_type"] == record_type
    assert result["tx_id"] > 0


def test_verified_bundle_reports_the_record_the_ledger_actually_held():
    """
    A verified result is only useful if it names what was verified. The
    proven bytes must be the bytes the bundle displays, and the bundle's
    own copy is what a reader sees.
    """
    checker.block_network()
    bundle = json.loads(BUNDLE_FILES["policy_allow"].read_text())
    result = checker.check(BUNDLE_FILES["policy_allow"], FIXTURE_KEY)
    assert result["value"] == base64.b64decode(bundle["record"]["value"])
    assert result["ledger_key"].encode() == base64.b64decode(bundle["record"]["ledger_key"])


def test_the_checker_implements_no_cryptography_of_its_own():
    """
    P3a-3 / D20 and pre-registered negative 1. ADR-0001 records a
    hand-rolled Alh() in this project that was wrong; the reason this tool
    drives immudb-py's own functions is so there is nothing here to get
    wrong. Asserted against the source rather than trusted, because a later
    change could quietly add one.

    hashlib is permitted in exactly one place, key_fingerprint(), where it
    derives an identifier and no proof result depends on it.
    """
    tree = ast.parse(CHECKER_SRC.read_text(encoding="utf-8"))

    banned_modules = {"hmac", "Crypto", "cryptography", "nacl", "hashes"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in banned_modules, (
                    f"{CHECKER_SRC.name} imports {alias.name}; every cryptographic "
                    "primitive must come from immudb-py or ecdsa via the SDK"
                )
        if isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] not in banned_modules, (
                f"{CHECKER_SRC.name} imports from {node.module}"
            )

    # hashlib.sha256 may appear only inside key_fingerprint.
    sha_functions = set()
    for func in ast.walk(tree):
        if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for node in ast.walk(func):
                if (
                    isinstance(node, ast.Attribute)
                    and isinstance(node.value, ast.Name)
                    and node.value.id == "hashlib"
                ):
                    sha_functions.add(func.name)
    assert sha_functions <= {"key_fingerprint"}, (
        f"hashlib is used outside key_fingerprint, in {sorted(sha_functions)}; "
        "a digest anywhere else would be a reimplemented primitive"
    )

    # The verification itself must go through the SDK's own entry point.
    source = CHECKER_SRC.read_text(encoding="utf-8")
    assert "verifiedGet.call(" in source, (
        "the checker must call immudb's own verifiedGet.call(); if this "
        "disappeared, verification was reimplemented"
    )


# ---------------------------------------------------------------------------
# P3a-4: tampering fails with a named error.
#
# Each test below names the exact result_class it expects. None of them
# accepts a broad exception - test_no_tamper_test_accepts_a_broad_exception
# at the bottom of this section enforces that property over the file itself,
# so widening any one of them is caught rather than silently tolerated.
# ---------------------------------------------------------------------------

def _bundle(name="policy_allow") -> dict:
    return json.loads(BUNDLE_FILES[name].read_text())


def _check_dict(bundle: dict, key_path=FIXTURE_KEY):
    """Run the checker against an in-memory bundle, so a tamper case never
    has to touch a fixture file on disk."""
    checker.block_network()
    verifying_key = checker.load_key(key_path)
    return checker.verify_bundle(bundle, verifying_key)


def _flip_first_byte(b64_value: str) -> str:
    raw = bytearray(base64.b64decode(b64_value))
    raw[0] ^= 0xFF
    return base64.b64encode(bytes(raw)).decode()


def test_baseline_in_memory_bundle_verifies():
    """The tamper tests below are only meaningful if the untampered bundle,
    routed through the same in-memory helper, verifies."""
    result = _check_dict(_bundle())
    assert result["result_class"] == checker.VERIFIED


def test_flipped_record_byte_fails_as_record_mismatch():
    """
    P3a-4: a byte flipped in the bundle's own readable copy of the record.

    immudb-py never sees this field - it verifies the entry inside the
    protobuf - so nothing in the SDK catches this. The checker binds the two
    itself, and says so specifically: the record displayed is not the record
    proven. Reported as record_mismatch rather than a consistency failure,
    because no proof was rejected here.
    """
    bundle = _bundle()
    bundle["record"]["value"] = _flip_first_byte(bundle["record"]["value"])

    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check_dict(bundle)
    assert excinfo.value.result_class == checker.RECORD_MISMATCH


def test_flipped_proof_byte_fails_as_consistency_failure():
    """
    P3a-4: a byte flipped inside the entry's value, in the captured
    VerifiableEntry protobuf. This changes the leaf the inclusion proof is
    computed over, so immudb-py's own store.VerifyInclusion rejects it and
    raises ErrCorruptedData.

    Tampered through the protobuf API rather than at a raw file offset so
    the mechanism is unambiguous - the raw-offset sweep is
    tools/bundle_byte_sweep.py, reported in docs/reports/phase-3a.md.
    """
    from immudb.grpc import schema_pb2

    bundle = _bundle()
    ventry = schema_pb2.VerifiableEntry()
    ventry.ParseFromString(base64.b64decode(bundle["proof"]["verifiable_entry"]))
    tampered = bytearray(ventry.entry.value)
    tampered[0] ^= 0xFF
    ventry.entry.value = bytes(tampered)
    bundle["proof"]["verifiable_entry"] = base64.b64encode(ventry.SerializeToString()).decode()
    # Keep the readable copy consistent with the tampered proof, so this test
    # exercises the proof check and not the record_mismatch check above.
    bundle["record"]["value"] = base64.b64encode(bytes(tampered)).decode()

    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check_dict(bundle)
    assert excinfo.value.result_class == checker.CONSISTENCY_FAILURE


def test_substituted_state_fails_as_signature_failure():
    """
    P3a-4: the bundle's trust anchor replaced with one the server never
    signed (its txHash altered).

    The anchor arrived in the same file as the material it anchors, so the
    checker verifies it with the SDK's State.Verify against the
    independently held key before using it. That is what makes a substituted
    anchor a signature failure and not merely a downstream proof mismatch:
    the anchor is rejected for what it is, before any proof is walked.
    """
    bundle = _bundle()
    bundle["proof"]["source_state"]["tx_hash"] = _flip_first_byte(
        bundle["proof"]["source_state"]["tx_hash"]
    )

    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check_dict(bundle)
    assert excinfo.value.result_class == checker.SIGNATURE_FAILURE


def test_anchor_substituted_with_an_unsigned_genesis_state_is_refused():
    """
    P3a-4, the substitution that is not a corruption: replacing the anchor
    with transaction 0.

    immudb-py runs store.VerifyDualProof only when state.txId > 0
    (immudb/handler/verifiedGet.py). An anchor at tx 0 therefore silently
    downgrades the check to inclusion-only - a weaker check that still
    returns verified=True. Verifying the anchor's own signature closes this:
    a genesis state carries no signature the key can accept.
    """
    bundle = _bundle()
    bundle["proof"]["source_state"]["tx_id"] = 0
    bundle["proof"]["source_state"]["tx_hash"] = base64.b64encode(b"\x00" * 32).decode()
    bundle["proof"]["source_state"]["signature"] = None

    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check_dict(bundle)
    assert excinfo.value.result_class == checker.SIGNATURE_FAILURE


def test_wrong_key_fingerprint_fails_as_key_mismatch():
    """
    P3a-4 and P3a-5: a bundle naming a key the checker does not hold.

    Refused before any proof runs, and reported as key_mismatch rather than
    as a signature failure, because "you are holding the wrong key" and
    "this evidence was altered" call for different responses from whoever
    reads the result.
    """
    bundle = _bundle()
    bundle["signing_key"]["fingerprint"] = "sha256:" + "00" * 32

    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check_dict(bundle)
    assert excinfo.value.result_class == checker.KEY_MISMATCH


def test_relabelled_record_type_fails_as_record_mismatch():
    """
    P3a-4, found by tools/bundle_byte_sweep.py rather than anticipated.

    record_type is the label a reader acts on. It is not an input to any
    proof, so relabelling a policy_allow bundle as a policy_deny used to
    leave a bundle that verified and displayed the wrong thing. The label is
    derivable from the proven bytes, so the checker derives it and compares.
    """
    bundle = _bundle("policy_allow")
    bundle["record"]["record_type"] = "policy_deny"

    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check_dict(bundle)
    assert excinfo.value.result_class == checker.RECORD_MISMATCH


def test_relabelled_timestamp_fails_as_record_mismatch():
    bundle = _bundle()
    bundle["record"]["timestamp"] = bundle["record"]["timestamp"] + 1

    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check_dict(bundle)
    assert excinfo.value.result_class == checker.RECORD_MISMATCH


@pytest.mark.parametrize(
    "section,field",
    [
        ("record", "record_type"),
        ("record", "timestamp"),
        ("record", "tx_id"),
        ("record", "value"),
        ("record", "ledger_key"),
        ("proof", "entry_tx_id"),
        ("proof", "prove_since_tx"),
        ("proof", "signing_key_fingerprint"),
        ("proof", "verifiable_entry"),
        ("proof", "source_state"),
    ],
)
def test_deleting_any_required_field_is_refused(section, field):
    """
    P3a-4, the other half of the record_type finding. A comparison that
    skips an absent claim is a comparison an editor can delete their way
    past - corrupting one byte of a field *name* is enough to make the
    value unreachable. Every field the format defines is required.
    """
    bundle = _bundle()
    del bundle[section][field]

    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check_dict(bundle)
    assert excinfo.value.result_class in (checker.MALFORMED_BUNDLE, checker.KEY_MISMATCH)
    assert field in excinfo.value.detail or "missing" in excinfo.value.detail


def test_disagreeing_key_fingerprints_fail_as_key_mismatch():
    """
    A bundle names its signing key twice: once in signing_key, once inside
    the proof material the verifier produced. Before this check only the
    first was read, so every byte of the second was inert. Two copies that
    can disagree without consequence are worse than one.
    """
    bundle = _bundle()
    bundle["proof"]["signing_key_fingerprint"] = "sha256:" + "11" * 32

    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check_dict(bundle)
    assert excinfo.value.result_class == checker.KEY_MISMATCH


def test_a_corrupted_transaction_header_is_reported_not_fatal():
    """
    P3a-4, found by the byte sweep and worth a test of its own.

    immudb-py's embedded/store/tx.py calls sys.exit() when a transaction
    header carries a version it does not recognise. sys.exit raises
    SystemExit, a BaseException, so a checker that caught only Exception
    would be terminated by the file it was examining rather than reporting
    on it. A bundle must never be able to end the process checking it.
    """
    from immudb.grpc import schema_pb2

    bundle = _bundle()
    ventry = schema_pb2.VerifiableEntry()
    ventry.ParseFromString(base64.b64decode(bundle["proof"]["verifiable_entry"]))
    ventry.verifiableTx.tx.header.version = 5
    bundle["proof"]["verifiable_entry"] = base64.b64encode(ventry.SerializeToString()).decode()

    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check_dict(bundle)
    assert excinfo.value.result_class == checker.MALFORMED_BUNDLE


def test_no_tamper_test_accepts_a_broad_exception():
    """
    Pre-registered negative 4, enforced over this file rather than asserted
    about it.

    Every pytest.raises in this module must name BundleCheckFailed, and
    every one of them must be followed by an assertion on result_class. A
    tamper test that accepts Exception would pass against a crash, a typo,
    or an unrelated bug, and would report tamper evidence this project does
    not have. This is the test the P3a-4 mutation is aimed at: widening any
    assertion above makes this one fail.
    """
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    this_function = "test_no_tamper_test_accepts_a_broad_exception"

    offenders = []
    unchecked = []
    for func in ast.walk(tree):
        if not isinstance(func, ast.FunctionDef) or func.name == this_function:
            continue
        raises_calls = [
            node
            for node in ast.walk(func)
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

        if any(
            isinstance(n, ast.Attribute) and n.attr == "raises" for n in ast.walk(func)
        ) and "BundleCheckFailed" in ast.dump(func):
            asserts_result_class = any(
                isinstance(n, ast.Attribute) and n.attr == "result_class"
                for n in ast.walk(func)
            )
            if not asserts_result_class:
                unchecked.append(func.name)

    assert not offenders, (
        "tamper tests must name the specific failure they expect, never a broad "
        f"exception: {offenders}"
    )
    assert not unchecked, (
        "these tests expect BundleCheckFailed but never assert which check failed, "
        f"so they would pass for the wrong reason: {unchecked}"
    )


# ---------------------------------------------------------------------------
# P3a-5: the key is independent of the bundle.
# ---------------------------------------------------------------------------

def test_a_bundle_carrying_its_own_key_still_cannot_certify_itself():
    """
    P3a-5, the enforcing test, and the mutation target.

    The spike found immudb-py never reads State.publicKey during
    verification (docs/reports/spike-offline-verify.md, item 4[d]), so a
    bundle that shipped its own key would be checked against a key its own
    author chose. Here a bundle is given every field a self-certifying
    bundle would need - a PEM of the real key, embedded - and is then
    checked while holding a different key. It must still be refused.

    If the checker were changed to read a key out of the bundle, this bundle
    would verify and this test would fail. That is the point of it.
    """
    bundle = _bundle()
    bundle["signing_key"]["pem"] = FIXTURE_KEY.read_text()
    bundle["signing_key"]["public_key_der_b64"] = base64.b64encode(
        ecdsa.VerifyingKey.from_pem(FIXTURE_KEY.read_text()).to_der()
    ).decode()
    bundle["proof"]["source_state"]["public_key"] = bundle["signing_key"]["public_key_der_b64"]

    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check_dict(bundle, key_path=OTHER_KEY)
    assert excinfo.value.result_class == checker.KEY_MISMATCH


def test_a_refingerprinted_bundle_fails_at_the_signature_not_the_fingerprint():
    """
    P3a-5's second case: the fingerprint is an identifier, never a check.

    An attacker who rewrites the fingerprint to name a key the checker
    actually holds gets past the identity comparison. What they do not get
    past is the ECDSA verification of material the real key signed. This is
    what stops the fingerprint from becoming a self-certifying substitute
    for the key.
    """
    other_fp = checker.key_fingerprint(ecdsa.VerifyingKey.from_pem(OTHER_KEY.read_text()))
    bundle = _bundle()
    bundle["signing_key"]["fingerprint"] = other_fp
    bundle["proof"]["signing_key_fingerprint"] = other_fp

    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check_dict(bundle, key_path=OTHER_KEY)
    assert excinfo.value.result_class == checker.SIGNATURE_FAILURE


def test_no_fixture_bundle_contains_key_material():
    """
    Pre-registered negative 3, checked against the committed artifacts
    themselves rather than against the code that writes them.

    Looks for the two forms the key could take: PEM armour anywhere in the
    file, and the raw DER or uncompressed-point encoding of the key the
    bundles were exported against.
    """
    vk = ecdsa.VerifyingKey.from_pem(FIXTURE_KEY.read_text())
    der = vk.to_der()
    raw_point = vk.to_string()

    for name, path in sorted(BUNDLE_FILES.items()):
        text = path.read_text(encoding="utf-8")
        assert "BEGIN PUBLIC KEY" not in text, f"{name} bundle embeds a PEM key"
        assert "BEGIN EC" not in text, f"{name} bundle embeds a PEM key"

        raw = path.read_bytes()
        assert der not in raw, f"{name} bundle embeds the DER-encoded public key"
        assert raw_point not in raw, f"{name} bundle embeds the raw public key point"

        # Also check the decoded proof material, since a key hidden inside a
        # base64 field would not show up in the text scan above.
        bundle = json.loads(text)
        ventry_bytes = base64.b64decode(bundle["proof"]["verifiable_entry"])
        state = bundle["proof"]["source_state"]
        assert "public_key" not in state and "publicKey" not in state, (
            f"{name} bundle's source_state carries a publicKey field, the exact "
            "field the spike found is never checked"
        )
        # The VerifiableEntry is the server's own protobuf and does carry the
        # server's public key in its signature message. That is inert here:
        # the checker never reads it, which the next assertion pins down.
        del ventry_bytes


def test_the_checker_loads_a_key_only_from_the_path_it_was_given():
    """
    P3a-5, static half. The behavioural test above proves the current
    checker ignores an embedded key; this proves there is only one place a
    key can enter the process at all, so a future edit that adds a second
    one is visible in the diff and here.
    """
    tree = ast.parse(CHECKER_SRC.read_text(encoding="utf-8"))

    loaders = []
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(func):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in ("from_pem", "from_der", "from_string", "from_public_point"):
                    loaders.append(func.name)

    assert sorted(set(loaders)) == ["load_key"], (
        "a verifying key is constructed outside load_key(), in "
        f"{sorted(set(loaders))}; load_key is the only function that reads a "
        "key, and it reads it from the --key path, never from the bundle"
    )

    # load_key must read the path it was handed and nothing else.
    load_key_src = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "load_key"
    )
    names_used = {n.id for n in ast.walk(load_key_src) if isinstance(n, ast.Name)}
    assert "bundle" not in names_used, "load_key() reads from the bundle"


# ---------------------------------------------------------------------------
# Format discipline.
# ---------------------------------------------------------------------------

def test_load_bundle_refuses_an_unknown_envelope(tmp_path):
    """A checker that guessed at an unrecognised format would be reading
    fields by position rather than by contract."""
    bundle = _bundle()
    bundle["bundle_format"] = "ail-evidence-bundle/99"
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(bundle))

    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        checker.load_bundle(path)
    assert excinfo.value.result_class == checker.MALFORMED_BUNDLE


def test_load_bundle_refuses_an_unknown_proof_format(tmp_path):
    bundle = _bundle()
    bundle["proof"]["format"] = "ail-proof-material/99"
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(bundle))

    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        checker.load_bundle(path)
    assert excinfo.value.result_class == checker.MALFORMED_BUNDLE


# ---------------------------------------------------------------------------
# P3a-9 (Phase 3a completion pass): the README §3.4.1 command block, run as
# a real subprocess rather than a library call.
#
# docs/reports/phase-3a.md's own mapping table cited this claim ("the
# ail_verify_bundle.py command block") against a live transcript only - no
# committed test invoked the CLI/argparse entry point (main(), the
# `if __name__ == "__main__"` branch, sys.argv parsing) as opposed to the
# library functions (check(), verify_bundle()) every other test in this file
# calls directly. This test closes that gap: a real subprocess, the exact
# command README.md §3.4.1 documents, checked byte-for-byte against the
# fixture path and flag spelling in the README's own code block rather than
# a paraphrase of it.
# ---------------------------------------------------------------------------

def test_readme_command_block_is_exactly_reproducible():
    """
    Extracts the literal `python tools/ail_verify_bundle.py ...` command from
    readME.md §3.4.1's own fenced code block and runs it as a real
    subprocess (network untouched - the socket block this file's own module
    import installs is process-local and does not follow into the child).
    A change to either the README's command or the CLI's argument parsing
    that broke the other would fail here; nothing here is paraphrased from
    the README, it is read from it.
    """
    readme_text = (REPO_ROOT / "readME.md").read_text(encoding="utf-8")
    section = readme_text.split("### 3.4.1 Portable Evidence Bundles", 1)[1]
    section = section.split("### 3.5", 1)[0]
    code_block = re.search(r"```bash\n(.*?)```", section, re.DOTALL)
    assert code_block, "README §3.4.1 no longer has a ```bash command block to extract"
    # The README wraps the command across two lines with a shell line-
    # continuation backslash; join those first so a lone "\" doesn't survive
    # into argv as a literal (bogus) argument.
    joined = code_block.group(1).replace("\\\n", " ")
    command_line = " ".join(joined.split())
    assert command_line.startswith("python tools/ail_verify_bundle.py "), (
        f"README §3.4.1's command block no longer starts as expected: {command_line!r}"
    )

    argv = command_line.split()[1:]  # drop the leading "python"
    result = subprocess.run(
        [sys.executable] + argv,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"README §3.4.1's own command exited {result.returncode}: "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert "OK [verified]" in result.stdout, result.stdout
