"""
tests/test_writer_signing.py - P3b-2 and P3b-3 (Phase 3b, D22).

Every test in this file runs with no live stack, no Docker, and no network.
The bundles under test are the committed fixtures
(tests/fixtures/evidence_bundles/), exported from a real
docker-compose.test.yml run, and the writer public keys sit beside them as
their own files - never inside a bundle, which is the subject of P3b-3
rather than an accident of layout.

The live half of D22 is tests/test_anchored_export.py: a real record signed
by the real decision service, and a record deliberately signed over the
wrong bytes, both written to a real ledger and exported through the real
route.

What this file establishes
--------------------------
1. The signer and the checker agree on which bytes are signed, without
   sharing code. provenance/record_signature.py is what writers use;
   tools/ail_verify_bundle.py holds its own copy of the same rule so an
   auditor needs nothing but immudb-py and the public keys. Two copies that
   could drift are held in agreement here by signing through one and
   verifying through the other, rather than by an import.
2. The signature is deterministic, so "sign the same record twice" is a
   comparison and not a coin flip.
3. Each of the four ways a writer check can refuse names its own result
   class. A checker that collapsed "you do not hold this key" into "this
   evidence was altered" would tell an auditor to do the wrong thing.
"""

import ast
import base64
import importlib.util as _importlib_util
import json
import socket
import sys
from pathlib import Path

import ecdsa
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "evidence_bundles"
CHECKER_SRC = REPO_ROOT / "tools" / "ail_verify_bundle.py"

FIXTURE_KEY = FIXTURES / "signing.pub"
WRITER_KEYS = [FIXTURES / "writer-decision.pub", FIXTURES / "writer-control-plane.pub"]
ANCHOR_KEYS = [FIXTURES / "anchor-signing.pub"]
TRUSTED_ROOT = FIXTURES / "trusted_root.json"

# An unrelated P-256 public key, committed since Phase 3a for exactly this
# purpose: "the checker was handed the wrong key" has to be a real different
# key rather than a corrupted copy of the right one.
OTHER_KEY = FIXTURES / "other-signing.pub"

BUNDLE_FILES = {
    "policy_allow": FIXTURES / "policy_allow.json",
    "policy_deny": FIXTURES / "policy_deny.json",
    "fault": FIXTURES / "fault.json",
    "content_erasure": FIXTURES / "content_erasure.json",
}

sys.path.insert(0, str(REPO_ROOT))
from provenance import record_signature as signer  # noqa: E402


def _load_checker():
    spec = _importlib_util.spec_from_file_location("ail_verify_bundle", CHECKER_SRC)
    module = _importlib_util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Captured before the checker is loaded, because loading it installs the
# socket block process-wide. Same containment tests/test_offline_verify.py
# documents: the block covers every check in this file and nothing outside
# it, so a later test module does not fail on a network this one disabled.
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


def _bundle(name="policy_allow") -> dict:
    return json.loads(BUNDLE_FILES[name].read_text(encoding="utf-8"))


def _proven_record(name="policy_allow") -> dict:
    """The record as the ledger holds it, from a committed bundle.

    Read out of record.value rather than reconstructed, so what these tests
    check the signature of is the same object the checker checks: by the
    time verify_writer_signature runs, record.value has already been shown
    to be byte-identical to the value inside the proof.
    """
    return json.loads(base64.b64decode(_bundle(name)["record"]["value"]).decode())


def _writer_keys(*paths):
    return checker.load_writer_keys([str(p) for p in (paths or WRITER_KEYS)])


def _check(bundle: dict, writer_key_paths=None, deny_list=None):
    return checker.verify_bundle(
        bundle,
        checker.load_key(FIXTURE_KEY),
        _writer_keys(*(writer_key_paths or WRITER_KEYS)),
        deny_list=deny_list or {},
        trusted_root_path=TRUSTED_ROOT,
        anchor_keys=_writer_keys(*ANCHOR_KEYS),
    )


# ---------------------------------------------------------------------------
# P3b-2: the record carries a signature over its own canonical bytes.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("record_type", sorted(BUNDLE_FILES))
def test_every_committed_record_carries_a_writer_signature(record_type):
    """
    P3b-2. Every record shape the ledger holds is signed - the three the
    decision service writes and the tombstone the control plane writes.
    A shape that was exempt would be a shape no one can be shown to have
    written, and P3b-3's checker refuses those, so an exemption would not
    be a softer rule but a broken export path.
    """
    record = _proven_record(record_type)
    assert record[signer.SIGNATURE_FIELD], f"{record_type} record carries no signature"
    assert record[signer.FINGERPRINT_FIELD].startswith("sha256:")
    assert record[signer.FORMAT_FIELD] == signer.RECORD_SIGNATURE_FORMAT


def test_the_signature_covers_the_recorded_bytes_and_not_some_other_sequence():
    """
    P3b-2, the enforcing test and the mutation target.

    The mutation is: make provenance/record_signature.py::sign_record sign a
    different byte sequence than the one that ends up in the record. Nothing
    about the record's shape would change - it would still carry a
    well-formed signature, a fingerprint, and a format - so only a test that
    recomputes the canonical bytes from the recorded record and verifies
    against them catches it.

    Recomputed here through the CHECKER's copy of the canonicalization rule,
    not the signer's, so the two implementations are held in agreement by
    this assertion rather than by an import that would make agreement
    tautological.
    """
    record = _proven_record("policy_allow")
    fingerprint = record[signer.FINGERPRINT_FIELD]
    keys = _writer_keys()
    assert fingerprint in keys, "the fixture names a writer key not committed beside it"

    signed_bytes = checker.canonical_record_bytes(record)
    checker._ecdsa_verify(
        keys[fingerprint],
        base64.b64decode(record[signer.SIGNATURE_FIELD]),
        signed_bytes,
    )

    # And the two canonicalizations are the same bytes, not merely both
    # acceptable to the same key.
    assert signed_bytes == signer.canonical_record_bytes(record)


def test_signing_the_same_record_twice_produces_identical_bytes():
    """
    P3b-2: "show the canonicalization is deterministic by signing the same
    record twice and comparing".

    Two separate things have to hold for that comparison to mean anything,
    and both are asserted separately here: the canonical bytes must be
    stable across dict ordering, and the ECDSA signature over them must be
    deterministic. Plain ECDSA is randomised - a nonce per signature - so
    without RFC 6979 deterministic signing the second signature would differ
    while still being valid, and "identical" would be the wrong test to
    write. sign_deterministic is what makes it the right one.
    """
    signing_key, verifying_key = signer.load_signing_key(
        REPO_ROOT / "keys" / "writer-decision.key"
    ) if (REPO_ROOT / "keys" / "writer-decision.key").exists() else (None, None)
    if signing_key is None:
        pytest.skip("keys/writer-decision.key not present; run 'make keygen'")

    record = {
        "record_type": "decision",
        "agent_id": "determinism_probe",
        "timestamp": "2026-08-24T00:00:00",
        "reasons": [],
        "content_state": "present",
    }
    reordered = dict(reversed(list(record.items())))
    assert list(record) != list(reordered)

    first = signer.sign_record(record, signing_key, verifying_key)
    second = signer.sign_record(reordered, signing_key, verifying_key)

    assert signer.canonical_record_bytes(first) == signer.canonical_record_bytes(second)
    assert first[signer.SIGNATURE_FIELD] == second[signer.SIGNATURE_FIELD]


def test_the_signer_and_the_checker_hold_the_same_rule_without_sharing_code():
    """
    P3b-2/P3b-3. tools/ail_verify_bundle.py deliberately does not import
    provenance/ - ADR-0010's reasoning, applied again: an auditor checking a
    bundle from a system they do not operate cannot be asked to obtain that
    system's source. Two copies of a canonicalization rule that can drift
    apart are worse than one, so this is what holds them together.
    """
    assert checker.RECORD_SIGNATURE_FORMAT == signer.RECORD_SIGNATURE_FORMAT
    assert checker.SIGNATURE_FIELD == signer.SIGNATURE_FIELD
    assert checker.FINGERPRINT_FIELD == signer.FINGERPRINT_FIELD
    assert checker.SIGNATURE_FORMAT_FIELD == signer.FORMAT_FIELD

    # A record with awkward content: unicode, nesting, a null, a float, and
    # keys that sort differently from insertion order.
    record = {
        "z": "é中",
        "a": {"nested": [1, 2, {"deep": None}]},
        "m": 1.5,
        signer.FINGERPRINT_FIELD: "sha256:" + "ab" * 32,
        signer.FORMAT_FIELD: signer.RECORD_SIGNATURE_FORMAT,
        signer.SIGNATURE_FIELD: "ignored",
    }
    assert signer.canonical_record_bytes(record) == checker.canonical_record_bytes(record)
    # The signature's own value is excluded (it cannot sign itself) while
    # everything else, the fingerprint and the format string included, is
    # inside. Asserted on the value rather than on the field name, because
    # "writer_signature" is a prefix of "writer_signature_format" and a
    # name-based check would pass for the wrong reason.
    assert b"ignored" not in signer.canonical_record_bytes(record)
    assert signer.FINGERPRINT_FIELD.encode() in signer.canonical_record_bytes(record)
    assert signer.FORMAT_FIELD.encode() in signer.canonical_record_bytes(record)


def test_the_fingerprint_rule_is_the_same_in_all_three_implementations():
    """verifier/main.py, provenance/, and the checker each derive a
    fingerprint over the key's DER, and a bundle is matched to a key by
    comparing them. Three copies of one rule, checked against each other."""
    verifying_key = ecdsa.VerifyingKey.from_pem(WRITER_KEYS[0].read_text())
    assert signer.key_fingerprint(verifying_key) == checker.key_fingerprint(verifying_key)


# ---------------------------------------------------------------------------
# P3b-3: the checker verifies the writer, and the key stays out of the bundle.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("record_type", sorted(BUNDLE_FILES))
def test_a_bundle_verifies_against_the_correct_writer_key(record_type):
    """P3b-3, the pass case. The result names which writer key signed the
    record, because "verified" without an attribution is not what this phase
    added."""
    checker.block_network()
    result = _check(_bundle(record_type))
    assert result["result_class"] == checker.VERIFIED
    assert result["writer_key_fingerprint"] == _proven_record(record_type)[
        signer.FINGERPRINT_FIELD
    ]


def test_the_two_writers_are_distinguishable_by_the_key_that_signed():
    """
    P3b-3. Two writer keys rather than one is what makes a bundle say which
    service wrote the record. A single shared key would verify all four
    fixtures identically and name nothing.
    """
    decision_fp = _proven_record("policy_allow")[signer.FINGERPRINT_FIELD]
    tombstone_fp = _proven_record("content_erasure")[signer.FINGERPRINT_FIELD]
    assert decision_fp != tombstone_fp, (
        "the decision service and the control plane signed with the same key; "
        "a bundle then cannot say which of them wrote the record"
    )
    held = _writer_keys()
    assert {decision_fp, tombstone_fp} <= set(held)


def test_a_record_naming_a_writer_key_the_checker_does_not_hold_is_refused():
    """
    P3b-3: distinct from a tamper, deliberately.

    "You do not hold this key" and "this evidence was altered" call for
    different responses - the first is answerable by obtaining a key, the
    second never is. A checker that reported them the same way would send an
    auditor down the wrong path.
    """
    bundle = _bundle("policy_allow")
    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check(bundle, writer_key_paths=[OTHER_KEY])
    assert excinfo.value.result_class == checker.WRITER_KEY_UNKNOWN


def test_a_record_signed_by_a_revoked_writer_key_is_refused(tmp_path):
    """
    P3b-3 and D22's revocation requirement. Long-lived does not mean no
    lifecycle: a compromised writer key has to be answerable without
    reissuing every record it ever signed, and the only party who can hold
    that answer is the checker, out of band, exactly like the key itself.

    Refused whether or not the signature checks out - it does, here. That is
    the point: a revoked key's signatures are still cryptographically valid,
    which is precisely why validity cannot be the whole test.
    """
    revoked_fp = _proven_record("policy_allow")[signer.FINGERPRINT_FIELD]
    deny_path = tmp_path / "revoked-writers.json"
    deny_path.write_text(json.dumps({
        "revoked": [{
            "fingerprint": revoked_fp,
            "revoked_at": "2026-08-24T00:00:00Z",
            "reason": "test: suspected compromise of the decision service writer key",
        }]
    }), encoding="utf-8")

    deny_list = checker.load_deny_list(deny_path)
    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        _check(_bundle("policy_allow"), deny_list=deny_list)
    assert excinfo.value.result_class == checker.WRITER_KEY_REVOKED
    assert revoked_fp in excinfo.value.detail


def test_the_deny_list_is_refused_rather_than_skipped_when_malformed(tmp_path):
    """A deny-list with a row the checker cannot read is a deny-list with a
    hole in it, and a hole in a revocation list is indistinguishable from
    not having revoked the key at all."""
    path = tmp_path / "bad-deny-list.json"
    path.write_text(json.dumps({"revoked": [{"reason": "no fingerprint here"}]}), encoding="utf-8")
    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        checker.load_deny_list(path)
    assert excinfo.value.result_class == checker.MALFORMED_BUNDLE


def test_a_record_with_no_writer_signature_is_refused_not_accepted():
    """
    P3b-3: "a record without a signature is rejected rather than treated as
    unsigned-and-fine".

    This is the case a lenient checker gets wrong most naturally - the field
    is absent, so there is nothing to fail, so nothing fails. What comes out
    of that is a bundle reported as verified whose writer is unknown, which
    is exactly the claim this phase exists to stop making.
    """
    record = _proven_record("policy_allow")
    del record[signer.SIGNATURE_FIELD]
    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        checker.verify_writer_signature(record, _writer_keys(), {})
    assert excinfo.value.result_class == checker.WRITER_SIGNATURE_MISSING


def test_a_record_with_no_fingerprint_is_refused():
    record = _proven_record("policy_allow")
    del record[signer.FINGERPRINT_FIELD]
    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        checker.verify_writer_signature(record, _writer_keys(), {})
    assert excinfo.value.result_class == checker.WRITER_SIGNATURE_MISSING


def test_a_modified_record_fails_the_writer_signature():
    """
    P3b-2's "a modified record fails".

    Reached through verify_writer_signature directly rather than through a
    whole bundle, because a record edited inside a bundle is caught earlier,
    by the D19 binding between the bundle's readable copy and the proven
    entry (record_mismatch). The signature check has to be shown to reject
    an altered record on its own merits, not to inherit a refusal from a
    check that ran before it.
    """
    record = _proven_record("policy_allow")
    record["outcome_type"] = "policy_deny"
    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        checker.verify_writer_signature(record, _writer_keys(), {})
    assert excinfo.value.result_class == checker.WRITER_SIGNATURE_FAILURE


def test_adding_a_field_to_a_record_fails_the_writer_signature():
    """The canonical bytes are the whole record minus the signature, so a
    field appended after signing is covered too - a signature over a subset
    would let a forger add whatever the subset left out."""
    record = _proven_record("policy_allow")
    record["approved_by"] = "someone who never approved it"
    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        checker.verify_writer_signature(record, _writer_keys(), {})
    assert excinfo.value.result_class == checker.WRITER_SIGNATURE_FAILURE


def test_repointing_the_fingerprint_at_a_key_you_hold_fails_at_the_signature():
    """
    P3b-3's second case, and the reason the fingerprint is inside the signed
    bytes.

    A forger who rewrites writer_key_fingerprint to name a key the checker
    actually holds gets past the key lookup. What they do not get past is
    the signature, because the fingerprint they rewrote is itself part of
    what was signed. This is what stops the fingerprint from becoming a
    self-certifying substitute for the key.
    """
    other_fp = checker.key_fingerprint(ecdsa.VerifyingKey.from_pem(OTHER_KEY.read_text()))
    record = _proven_record("policy_allow")
    record[signer.FINGERPRINT_FIELD] = other_fp
    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        checker.verify_writer_signature(record, _writer_keys(OTHER_KEY), {})
    assert excinfo.value.result_class == checker.WRITER_SIGNATURE_FAILURE


def test_a_record_declaring_an_unknown_signature_format_is_refused():
    """The format string says which bytes were signed. A checker that
    ignored it would verify a future format's record under this format's
    rule and report the result as if it meant something."""
    record = _proven_record("policy_allow")
    record[signer.FORMAT_FIELD] = "ail-record-signature/99"
    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        checker.verify_writer_signature(record, _writer_keys(), {})
    assert excinfo.value.result_class == checker.MALFORMED_BUNDLE


# ---------------------------------------------------------------------------
# P3b-3, the mutation: the checker must never take a key from the bundle.
# ---------------------------------------------------------------------------

def test_no_fixture_bundle_contains_writer_or_anchor_key_material():
    """
    Pre-registered negative 2, checked against the committed artifacts
    rather than against the code that writes them. Both forms a key could
    take: PEM armour anywhere in the file, and the raw DER or
    uncompressed-point encoding of any key these bundles are checked
    against.
    """
    key_paths = WRITER_KEYS + ANCHOR_KEYS + [FIXTURE_KEY]
    encodings = []
    for path in key_paths:
        verifying_key = ecdsa.VerifyingKey.from_pem(path.read_text())
        encodings.append((path.name, verifying_key.to_der(), verifying_key.to_string()))

    for name, path in sorted(BUNDLE_FILES.items()):
        text = path.read_text(encoding="utf-8")
        raw = path.read_bytes()
        assert "BEGIN PUBLIC KEY" not in text, f"{name} bundle embeds a PEM key"
        assert "BEGIN EC" not in text, f"{name} bundle embeds a PEM key"
        for key_name, der, point in encodings:
            assert der not in raw, f"{name} bundle embeds {key_name} in DER"
            assert point not in raw, f"{name} bundle embeds {key_name} as a raw point"


def test_the_checker_still_loads_every_key_only_from_a_path_it_was_given():
    """
    P3b-3's mutation target, static half: "let the checker take the key from
    the bundle" must be visible in the diff and fail here.

    Phase 3a asserted this for the one key a bundle needed. Phase 3b adds
    two more kinds - writer keys and the anchoring key - and the assertion
    is unchanged rather than widened: every one of them still enters the
    process through load_key(), and load_key() still reads a path and
    nothing else.
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
        f"{sorted(set(loaders))}"
    )

    load_key_src = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "load_key"
    )
    names_used = {n.id for n in ast.walk(load_key_src) if isinstance(n, ast.Name)}
    assert "bundle" not in names_used, "load_key() reads from the bundle"
    assert "record" not in names_used, "load_key() reads from the record"


def test_the_writer_check_reads_its_keys_from_the_supplied_map_only():
    """
    The behavioural half of the same mutation. verify_writer_signature is
    handed a fingerprint -> key map built from --writer-key paths. If it
    were changed to fall back to a key inside the record, this record - which
    carries a PEM of the real key in a plausible field - would verify against
    a checker holding nothing.
    """
    record = _proven_record("policy_allow")
    record["writer_public_key_pem"] = WRITER_KEYS[0].read_text()
    record["writer_public_key_der_b64"] = base64.b64encode(
        ecdsa.VerifyingKey.from_pem(WRITER_KEYS[0].read_text()).to_der()
    ).decode()

    with pytest.raises(checker.BundleCheckFailed) as excinfo:
        checker.verify_writer_signature(record, {}, {})
    assert excinfo.value.result_class == checker.WRITER_KEY_UNKNOWN


def test_no_test_in_this_file_accepts_a_broad_exception():
    """
    Enforced over this file rather than asserted about it, the same way
    tests/test_offline_verify.py does. A refusal test that accepted
    Exception would pass against a crash, a typo, or an unrelated bug, and
    would report evidence this project does not have.
    """
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
        if raises_calls:
            asserts_result_class = any(
                isinstance(n, ast.Attribute) and n.attr == "result_class"
                for n in ast.walk(func)
            )
            if not asserts_result_class:
                unchecked.append(func.name)

    assert not offenders, f"tests must name the specific failure they expect: {offenders}"
    assert not unchecked, (
        f"these tests expect a failure but never assert which check failed: {unchecked}"
    )
