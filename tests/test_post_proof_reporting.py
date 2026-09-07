"""R6: a sound proof is never reported as failed, at any post-proof site.

`POST /verify` decided `verified` inside a `try` that also contained
everything which reports the verdict. Six things ran in that block after
`sdk_verified_get.call` had already returned a verified entry:

    head_state(client)                    # the unanchored path's state_id
    client._rs.get()                      # the anchored path's state_id
    base64.b64encode(resp.value)          # and three more encodes
    ventry.SerializeToString()
    signing_key_fingerprint()             # reads and parses the public key

None of them has any bearing on whether the proof ran, and all of them shared
that block's handlers. A `BadSignatureError` out of any one was reported as
`error_class="signature_failure"`, which `control_plane/main.py` renders as
`state: "failed"` - a positive tamper claim, on every record of a sound page,
on the read path an auditor uses. A system asserting tampering it has not
detected is worse than one failing to detect tampering.

**These tests drive the property, not the line.** The red team named the head
read. Fixing the head read alone would leave the same defect at five other
sites, and would reproduce D40's own failure mode - an enforcing test written
pointing at the route that was already correct - inside the fix for a finding
about D40. So every site in `POST_PROOF_SITES` is driven, and the mutation
this file is validated against is applied at two different sites for that
reason.

**The demonstration is in process, and that is pre-authorised rather than a
substitution.** Making only the head read fail on a live stack while
`VerifiableGet` still answers is not reachable with the existing fixtures:
corrupting `IMMUDB_SIGNING_PUBKEY` fails `sdk_verified_get.call` first, so the
page is not sound, and the cut proxy arms on a byte marker in the request
while `CurrentState` takes an `Empty` carrying no marker. Aiming the relay per
RPC is new fixture mechanism and belongs to a red-team pass. The `/audit` half
is demonstrated by composition, exactly as the red team established it: the
verifier route driven here, and the body it returns fed to
`control_plane/main.py::_verification_from_200`.

**Stated limit.** `POST_PROOF_SITES` is a hand-list. Nothing derives it, and a
seventh site added to the region later is outside this file until someone adds
it here. The fix itself does not share that limit - the post-proof region has
no handler in scope that can answer `verified=False`, so a new site inherits
the guarantee - but this file's coverage of it does. Recorded rather than
hidden; see docs/reports/r6-headstate.md.
"""
import base64
import importlib.util
import os
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

KEY = b"ail_audit:r6-post-proof"
VALUE = b'{"call_id": "r6-post-proof"}'
RECORD_TX = 42
ANCHOR_BELOW_RECORD_TX = 40
ANCHOR_ABOVE_RECORD_TX = 50
HEAD_TX = 55


# ---------------------------------------------------------------------------
# The two modules, each under its own name.
# ---------------------------------------------------------------------------

def _load(name: str, relative: str):
    """One module under its own name; same reasoning as
    tests/test_bounded_reads.py::_load - a bare `import main` clobbers
    whichever main.py another test file loaded first."""
    sys.path.insert(0, str(REPO_ROOT / "control_plane"))
    os.environ.setdefault("VERIFIER_READ_KEY", "test-verifier-read-key")
    os.environ.setdefault("VERIFIER_WRITE_KEY", "test-verifier-write-key")
    os.environ.setdefault("CONTROL_PLANE_READ_KEY", "test-read-key")
    os.environ.setdefault("CONTROL_PLANE_WRITE_KEY", "test-write-key")
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def verifier():
    previous = os.environ.get("AIL_WRITER_SIGNING_KEY")
    os.environ["AIL_WRITER_SIGNING_KEY"] = str(
        REPO_ROOT / "keys" / "writer-verifier.key")
    try:
        return _load("r6_verifier", "verifier/main.py")
    finally:
        if previous is None:
            os.environ.pop("AIL_WRITER_SIGNING_KEY", None)
        else:
            os.environ["AIL_WRITER_SIGNING_KEY"] = previous


@pytest.fixture(scope="module")
def control_plane():
    return _load("r6_control_plane", "control_plane/main.py")


# ---------------------------------------------------------------------------
# A ledger that answers, and a proof that succeeds. Every case below starts
# from this and breaks exactly one thing that runs after the proof.
# ---------------------------------------------------------------------------

class _Resp:
    """What `sdk_verified_get.call` returns for a record that verified."""

    verified = True
    id = RECORD_TX
    value = VALUE
    timestamp = 1757000000


class _Ventry:
    def SerializeToString(self):
        return b"serialized-verifiable-entry"


class _CurrentState:
    """`CurrentState`'s gRPC reply, in the shape `State.FromGrpc` reads."""

    class _Sig:
        publicKey = b""
        signature = b"s" * 8

    def __init__(self, tx):
        self.db = "defaultdb"
        self.txId = tx
        self.txHash = b"h" * 32
        self.signature = _CurrentState._Sig()


class _VerifyingKey:
    """Accepts every signature, unless told to reject.

    Rejecting here is how the head read is made to fail: it is the failure
    `head_state` actually raises, from the line that checks ImmuDB's signature
    over the head, rather than a stand-in for it.
    """

    def __init__(self, raises=None):
        self.raises = raises

    def verify(self, *args, **kwargs):
        if self.raises is not None:
            raise self.raises
        return True


class _Rs:
    """The persisted trust anchor, or a refusal to report it."""

    def __init__(self, raises=None):
        self.raises = raises

    def get(self):
        if self.raises is not None:
            raise self.raises
        from immudb.rootService import State
        return State(db="defaultdb", txId=ANCHOR_BELOW_RECORD_TX,
                     txHash=b"h" * 32, publicKey=b"", signature=b"s" * 8)


class _Stub:
    def __init__(self, ventry=None):
        self._ventry = ventry or _Ventry()

    def VerifiableGet(self, req):
        return self._ventry

    def CurrentState(self, _empty):
        return _CurrentState(HEAD_TX)


# `vk=None` is a deployment with no IMMUDB_SIGNING_PUBKEY, which is one of
# the conditions under test, so it cannot double as "use the default".
_UNSET = object()


class _Client:
    def __init__(self, rs=None, stub=None, vk=_UNSET):
        self._rs = rs if rs is not None else _Rs()
        self._stub = stub or _Stub()
        self._vk = _VerifyingKey() if vk is _UNSET else vk


def _drive(verifier, client, resp=None, anchor_tx=None, fingerprint=None):
    """One `POST /verify`, with the proof forced to succeed."""
    from immudb.handler import verifiedGet as sdk_verified_get

    original_call = sdk_verified_get.call
    original_client = verifier._get_client
    original_fingerprint = verifier.signing_key_fingerprint
    try:
        verifier._get_client = lambda: client
        answer = resp if resp is not None else _Resp()
        sdk_verified_get.call = (
            lambda stub, rs, key, verifying_key=None: answer)
        if fingerprint is not None:
            verifier.signing_key_fingerprint = fingerprint

        anchor = None
        if anchor_tx is not None:
            anchor = verifier.AnchorState(
                db="defaultdb", tx_id=anchor_tx,
                tx_hash=base64.b64encode(b"h" * 32).decode(),
                signature=base64.b64encode(b"s" * 8).decode(),
            )
        payload = verifier.VerifyRequest(
            key=base64.b64encode(KEY).decode(), anchor=anchor)
        return verifier.verify(payload).model_dump()
    finally:
        sdk_verified_get.call = original_call
        verifier._get_client = original_client
        verifier.signing_key_fingerprint = original_fingerprint


# ---------------------------------------------------------------------------
# The sites. Each entry breaks one thing that runs after the proof succeeded.
# ---------------------------------------------------------------------------

def _break_head_state(verifier):
    from ecdsa.keys import BadSignatureError
    return dict(client=_Client(
        vk=_VerifyingKey(raises=BadSignatureError("the head is not signed"))))


def _break_anchor_state_read(verifier):
    from ecdsa.keys import BadSignatureError
    # The anchored path reads `_rs.get()` for state_id after the proof, and
    # the anchor must not precede the record or D23's own refusal - which is
    # a deliberate verdict, not an incidental failure - fires first.
    return dict(client=_Client(rs=_Rs(raises=BadSignatureError("anchor read"))),
                anchor_tx=ANCHOR_ABOVE_RECORD_TX)


def _break_value_encode(verifier):
    from ecdsa.keys import BadSignatureError

    class _BadValue(_Resp):
        @property
        def value(self):
            raise BadSignatureError("the value encode site")

    return dict(client=_Client(), resp=_BadValue())


def _break_entry_serialize(verifier):
    from ecdsa.keys import BadSignatureError

    class _BadVentry:
        def SerializeToString(self):
            raise BadSignatureError("the entry serialisation site")

    return dict(client=_Client(stub=_Stub(ventry=_BadVentry())))


def _break_fingerprint(verifier):
    from ecdsa.keys import BadSignatureError

    def _raise():
        raise BadSignatureError("the configured public key did not parse")

    return dict(client=_Client(), fingerprint=_raise)


POST_PROOF_SITES = {
    "head_state": _break_head_state,
    "anchored_rs_get": _break_anchor_state_read,
    "value_b64encode": _break_value_encode,
    "ventry_serialize": _break_entry_serialize,
    "signing_key_fingerprint": _break_fingerprint,
}


# ---------------------------------------------------------------------------
# R6-1
# ---------------------------------------------------------------------------

def test_the_control_verifies(verifier, control_plane):
    """Nothing broken: the record verifies and /audit says so.

    Without this the assertions below would hold against a driver that
    cannot produce a verified response at all.
    """
    body = _drive(verifier, _Client(), fingerprint=lambda: "sha256:control")
    assert body["verified"] is True, body
    assert body["tx_id"] == RECORD_TX, body
    assert body["state_id"] == HEAD_TX, body
    rendered = control_plane._verification_from_200(body)
    assert rendered["state"] == "verified", rendered


@pytest.mark.parametrize("site", sorted(POST_PROOF_SITES))
def test_a_failure_after_the_proof_does_not_change_the_verification_state(
        site, verifier, control_plane):
    """R6-1. The proof succeeded; one thing that runs after it raises.

    The record's verification state is what the proof decided, at every site,
    and `/audit` renders it as such. `BadSignatureError` is the injected
    failure because it is the one that produced the worst answer: it is the
    exception `error_class="signature_failure"` was derived from, and that is
    the class `/audit` renders as a positive tamper claim.
    """
    kwargs = POST_PROOF_SITES[site](verifier)
    kwargs.setdefault("fingerprint", lambda: "sha256:control")
    body = _drive(verifier, **kwargs)

    assert body["verified"] is True, (
        f"a failure at the post-proof site {site!r} turned a record whose "
        f"proof succeeded into verified={body['verified']} "
        f"error_class={body['error_class']!r}. The proof ran and returned a "
        f"verified entry; nothing that runs after it may say otherwise. "
        f"Response: {body}"
    )
    assert body["error_class"] is None, (
        f"{site!r}: a post-proof failure was given one of the verdict's own "
        f"error classes ({body['error_class']!r}). Those name which proof "
        f"failed, and no proof failed here. Response: {body}"
    )
    assert body["tx_id"] == RECORD_TX, (
        f"{site!r}: the record's transaction is not reported. Response: {body}")

    rendered = control_plane._verification_from_200(body)
    assert rendered["state"] == "verified", (
        f"{site!r}: /audit renders this record as state={rendered['state']!r}. "
        f"A page whose proofs all succeeded is presented to an auditor as "
        f"tampered or unverifiable because something that reports the verdict "
        f"failed. Rendered: {rendered}"
    )


# ---------------------------------------------------------------------------
# R6-2
# ---------------------------------------------------------------------------

def test_a_failed_head_read_is_reported_rather_than_swallowed(
        verifier, control_plane):
    """R6-2. The opposite failure is equally wrong.

    Taking the head read out of the proof's `try` must not make its failure
    invisible: a null `state_id` with nothing saying why is a different defect
    on the same field.
    """
    body = _drive(verifier, **_break_head_state(verifier),
                  fingerprint=lambda: "sha256:control")

    assert body["verified"] is True, body
    assert body["state_id"] is None, (
        "the head read failed, so there is no head to report; state_id should "
        f"be null rather than a number nothing read. Response: {body}")

    state_read = body.get("state_read")
    assert state_read is not None, (
        "the head read failed and left no trace on the response. state_id is "
        f"null with nothing saying why. Response: {body}")
    assert state_read["source"] == "head", state_read
    assert state_read["status"] == verifier.STATE_READ_UNAVAILABLE, (
        f"a head read that could not run is reported as {state_read['status']!r}. "
        f"Response: {body}")
    assert state_read["detail"], (
        f"the failure is flagged but not explained: {state_read}")

    rendered = control_plane._verification_from_200(body)
    assert rendered["state"] == "verified", rendered
    assert rendered["state_read"] == state_read, (
        "/audit dropped the sibling field, so an operator sees a verified row "
        f"with a null state_id and the explanation stranded at the verifier. "
        f"Rendered: {rendered}")


def test_the_sibling_field_is_carried_by_every_audit_branch(control_plane):
    """R6-2, the /audit half. All four of D2's states carry it through.

    Asserted over the branches rather than the one that matters, because a
    field carried on the verified branch alone is a field an operator loses
    exactly when a row is already confusing.
    """
    sibling = {"source": "head", "status": "unavailable", "detail": "why"}
    cases = {
        "verified": {"verified": True, "state_read": sibling},
        "not_found": {"verified": False, "error_class": "not_found",
                      "state_read": sibling},
        "failed": {"verified": False, "error_class": "consistency_failure",
                   "state_read": sibling},
        "unverifiable": {"verified": False, "error_class": "unknown",
                         "state_read": sibling},
    }
    for expected_state, vdata in cases.items():
        rendered = control_plane._verification_from_200(vdata)
        assert rendered["state"] == expected_state, rendered
        assert rendered["state_read"] == sibling, (
            f"the {expected_state!r} branch does not carry state_read: "
            f"{rendered}")


def test_every_constructor_of_a_verification_object_agrees_on_its_shape(
        control_plane):
    """R6-2. One shape, from all five constructors.

    `/audit` builds this object in five places: the four branches of
    `_verification_from_200`, the two literals in `_verify_one_key` (the
    verifier unreachable, and the verifier answering non-200), and
    `_deferred_verification`. Adding a field to one of them splits the shape
    in two, and a row where the key is absent rather than null is a second
    shape that a reader has to know about.

    CI caught exactly this: `tests/test_deferred_verification.py` asserts the
    key set of a verified row exactly, and it failed when only
    `_verification_from_200` carried the new field. That assertion sees one
    row from one constructor, on a live stack. This one compares all five, in
    process, so the next field added is caught before CI rather than by it.
    """
    shape = set(control_plane._verification_from_200({"verified": True}))

    built = {
        "not_found": control_plane._verification_from_200(
            {"verified": False, "error_class": "not_found"}),
        "failed": control_plane._verification_from_200(
            {"verified": False, "error_class": "consistency_failure"}),
        "unverifiable": control_plane._verification_from_200(
            {"verified": False, "error_class": "unknown"}),
        "deferred": control_plane._deferred_verification(),
    }

    class _Unreachable:
        def __enter__(self):
            raise RuntimeError("verifier unreachable")

        def __exit__(self, *exc):
            return False

    class _NonHttp200:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def post(self, *args, **kwargs):
            class _R:
                status_code = 503
            return _R()

    original = control_plane.httpx.Client
    try:
        control_plane.httpx.Client = lambda *a, **k: _Unreachable()
        built["verifier_unreachable"], _ = control_plane._verify_one_key("a2V5")
        control_plane.httpx.Client = lambda *a, **k: _NonHttp200()
        built["verifier_non_200"], _ = control_plane._verify_one_key("a2V5")
    finally:
        control_plane.httpx.Client = original

    for name, verification in built.items():
        assert set(verification) == shape, (
            f"the {name!r} constructor builds a different shape from the "
            f"verified branch. /audit would carry two row shapes, and a "
            f"reader would have to know which rows can be missing a key. "
            f"Expected {sorted(shape)}, got {sorted(verification)}")

    assert "state_read" in shape, (
        f"the sibling field is not part of the shape at all: {sorted(shape)}")


def test_a_failed_head_read_is_not_a_verification_state(verifier):
    """R6-2. The sibling's vocabulary cannot be mistaken for D2's.

    A state read that could not run is not tamper evidence. If it ever
    borrowed the word "failed" from the four verification states, the two
    would be conflated by anything reading either field as text.
    """
    vocabulary = {verifier.STATE_READ_OK, verifier.STATE_READ_UNCHECKED,
                  verifier.STATE_READ_UNAVAILABLE}
    assert "failed" not in vocabulary, (
        "the state read borrowed the verification vocabulary's word for a "
        f"positive tamper claim: {vocabulary}")


def test_the_anchored_state_read_reports_the_anchor_and_reports_it_as_ok(
        verifier):
    """P3c3h-3 (Phase 3c-3h). The anchored half of `state_read`, asserted.

    **The gap this closes.** `_state_read` builds a `StateRead` at five sites
    and three of them can carry `source="anchor"`. Every assertion in this
    file about the field drove the head. The 3c-3g red team put
    `status="failed"` - the one word R6's vocabulary deliberately excludes,
    because `/audit` renders it as a positive tamper claim about a record - on
    each of the three anchored constructions in turn, and this module read
    `12 passed` all three times. The same edit on the head branch read
    `1 failed`, which is what says the file asserts something and not that the
    field is unasserted everywhere.

    **Why this pins the member and not the vocabulary.** All five
    constructions sit inside `_state_read`'s `try`, so with `StateRead`'s
    fields typed as `Literal` a mutated construction raises `ValidationError`
    there, the `except Exception` catches it, and the caller gets a
    well-formed `unavailable`. The forbidden word never reaches the wire -
    that is the type working - and a test asserting only "the value is in the
    vocabulary" would read green through exactly that. So this asserts the
    value this path is supposed to produce: `anchor`, and `ok`.

    Named mutation: `status="failed"` at the anchored OK construction
    (`verifier/main.py`, the `return state.txId, StateRead(...)` after the
    `_vk` check). This test must fail on the value moving to `unavailable`.
    """
    body = _drive(verifier, _Client(), anchor_tx=ANCHOR_ABOVE_RECORD_TX,
                  fingerprint=lambda: "sha256:anchored")

    assert body["verified"] is True, (
        "the proof did not succeed, so this test is not exercising the "
        f"post-proof read it describes: {body}")
    state_read = body["state_read"]
    assert state_read is not None, (
        f"the anchored path reported no state read at all: {body}")
    assert state_read["source"] == "anchor", (
        "the anchor was supplied and a working `_rs.get()` answered, and the "
        f"read reports it came from somewhere else: {state_read}")
    assert state_read["status"] == verifier.STATE_READ_OK, (
        "an anchored read that succeeded with a verifying key configured is "
        f"`ok`; this reports {state_read['status']!r}. If it reports "
        "'unavailable' with a ValidationError in the detail, a construction "
        f"on this path is outside StateRead's vocabulary: {state_read}")
    assert body["state_id"] == ANCHOR_BELOW_RECORD_TX, (
        "state_id on the anchored path is the anchor this service persists, "
        f"which the stub puts at {ANCHOR_BELOW_RECORD_TX}: {body}")


def test_the_anchored_state_read_names_its_source_on_every_outcome(verifier):
    """P3c3h-3. The other two anchored constructions, driven.

    The `Literal` closes the vocabulary and does not, on its own, make a
    mutated construction fail anything. All five sites are inside
    `_state_read`'s `try`, so `status="failed"` at the anchored *unchecked*
    construction raises `ValidationError` there, `except Exception` catches
    it, and the caller gets a well-formed `unavailable`: the forbidden word
    never reaches the wire, which is the type working, and the run reads
    green. Measured that way in this phase - `14 passed` on that mutation with
    only the pinned-member test above present. That is silence about the
    mutated site, not about the property, so the two remaining anchored
    constructions are driven here.

    **One of them is not reachable through the route, and that is measured
    rather than assumed.** `_state_read`'s anchored branch reports
    `unchecked` when `client._vk is None`, and `POST /verify` refuses a
    supplied anchor outright on exactly that condition
    (`error_class="anchor_signature_failure"`, "no ImmuDB signing key is
    configured, so a supplied anchor cannot be checked and will not be used")
    before `_state_read` is called at all. `_state_read` has one call site,
    `_state_read(client, payload.anchor)`, below that refusal. So the anchored
    unchecked construction is dead on this head, and driving it through
    `_drive` produces the route's refusal instead - which is what happened
    when this test was first written the other way. It is driven at the
    function, and the fact that it is unreachable from the route is the
    finding, recorded here rather than papered over by an assertion that
    quietly measures something else.
    """
    # Anchored, no verifying key: the construction, at the function.
    unchecked_client = _Client(vk=None)
    state_id, state_read = verifier._state_read(
        unchecked_client, object())      # any non-None anchor selects the path
    assert state_read.source == "anchor", state_read
    assert state_read.status == verifier.STATE_READ_UNCHECKED, (
        "an anchored read with no IMMUDB_SIGNING_PUBKEY configured was "
        f"checked by nothing and does not say so: {state_read}")
    assert "IMMUDB_SIGNING_PUBKEY" in (state_read.detail or ""), (
        f"the read does not name what is missing: {state_read}")
    assert state_id == ANCHOR_BELOW_RECORD_TX, state_id

    # And the route does refuse this combination, so the paragraph above is
    # a measurement and not a reading of the source.
    refused = _drive(verifier, _Client(vk=None),
                     anchor_tx=ANCHOR_ABOVE_RECORD_TX)
    assert refused["verified"] is False, refused
    assert refused["error_class"] == "anchor_signature_failure", (
        "the route no longer refuses an anchor it cannot check, so the "
        "anchored unchecked construction may now be reachable through "
        f"POST /verify and should be driven there: {refused}")

    # The anchor read itself fails, driven through the route. R6's rule: this
    # is not a claim about the record, whose proof already succeeded, and the
    # row still says which read it was that could not run.
    from ecdsa.keys import BadSignatureError
    unavailable = _drive(verifier,
                         _Client(rs=_Rs(raises=BadSignatureError("anchor read"))),
                         anchor_tx=ANCHOR_ABOVE_RECORD_TX,
                         fingerprint=lambda: "sha256:anchored-unavailable")
    assert unavailable["verified"] is True, (
        "a failed post-proof state read changed the verification verdict, "
        f"which is R6-1: {unavailable}")
    assert unavailable["state_id"] is None, unavailable
    assert unavailable["state_read"]["source"] == "anchor", (
        "the anchored read failed and the row attributes the failure to the "
        f"other read: {unavailable['state_read']}")
    assert unavailable["state_read"]["status"] == verifier.STATE_READ_UNAVAILABLE, (
        f"{unavailable['state_read']}")


def test_the_state_read_vocabulary_is_closed_by_the_type(verifier):
    """P3c3h-3. The other half: a word outside the vocabulary is refused at
    construction, not merely absent from the constants.

    `test_a_failed_head_read_is_not_a_verification_state` above asserts that
    `"failed"` is not among three module constants, which is a statement about
    the constants. This asserts it about the model, which is what the five
    construction sites actually go through, and it is the assertion that does
    not have to enumerate them.
    """
    import pydantic

    assert verifier.StateRead(source="anchor",
                              status=verifier.STATE_READ_OK).status == "ok"

    for bad in ("failed", "OK", "", "unknown"):
        with pytest.raises(pydantic.ValidationError):
            verifier.StateRead(source="anchor", status=bad)

    for bad in ("moon", "head_state", ""):
        with pytest.raises(pydantic.ValidationError):
            verifier.StateRead(source=bad, status=verifier.STATE_READ_OK)


# ---------------------------------------------------------------------------
# R6-3
# ---------------------------------------------------------------------------

def test_with_no_verifying_key_neither_function_presents_unchecked_as_checked(
        verifier):
    """R6-3. One rule, two correct expressions.

    `head_state` and `_VerifiedRootService._checked` are the two places a
    state reaches this service from `CurrentState`. They cannot behave
    identically - one reports and one gates a persist, and they have
    different return contracts - so the rule they share is stated as a
    behaviour: with no verifying key configured, neither presents an
    unchecked state as a checked one.
    """
    client = _Client(vk=None)

    # The reporting half: the head is returned, and marked as unchecked.
    head = verifier.head_state(client)
    assert head.state.txId == HEAD_TX, head
    assert head.checked is False, (
        "head_state returned a head with no key configured to check it and "
        f"reported it as checked: {head}")

    # The gating half: the persist is refused outright.
    rs = verifier._VerifiedRootService("unused.state", verifying_key=None)
    rs._dbname = "defaultdb"
    from immudb.rootService import State
    unchecked = State(db="defaultdb", txId=HEAD_TX, txHash=b"h" * 32,
                      publicKey=b"", signature=b"s" * 8)
    with pytest.raises(verifier.UnverifiedState):
        rs._checked(unchecked, "CurrentState")


def test_an_unchecked_head_is_reported_as_unchecked_on_the_response(
        verifier, control_plane):
    """R6-3, at the response. The rule survives the trip to the caller.

    A `checked` flag that no caller reports is the asymmetry moved one level
    out, so the reporting half is asserted where an auditor would see it.
    """
    body = _drive(verifier, _Client(vk=None),
                  fingerprint=lambda: "sha256:control")

    assert body["verified"] is True, body
    assert body["state_id"] == HEAD_TX, body
    assert body["state_read"]["status"] == verifier.STATE_READ_UNCHECKED, (
        "with no ImmuDB signing key configured, the head this response "
        f"reports was checked by nothing and does not say so: {body}")
    assert "IMMUDB_SIGNING_PUBKEY" in (body["state_read"]["detail"] or ""), (
        f"the response does not name what is missing: {body['state_read']}")

    rendered = control_plane._verification_from_200(body)
    assert rendered["state"] == "verified", (
        "an unchecked head is not a tamper claim and must not enter D2's four "
        f"verification states: {rendered}")
