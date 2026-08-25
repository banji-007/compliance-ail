#!/usr/bin/env python3
"""
bundle_byte_sweep.py - rerun the spike's tamper methodology against the
evidence bundle format instead of the raw VerifiableEntry protobuf.

    python tools/bundle_byte_sweep.py [BUNDLE.json] [--key signing.pub] \
        [--writer-key writer-decision.pub ...] [--trusted-root trusted_root.json] \
        [--anchor-key anchor-signing.pub]

Defaults to the committed policy_allow fixture and every key committed
beside it, so the sweep exercises the same full check an auditor runs -
D22's writer signature and D23's transparency log entry included - rather
than the Phase 3a subset of it.

docs/reports/spike-offline-verify.md item 4 swept 794 bytes of ventry.pb and
reported honestly that 251 of them had no detectable effect. A bundle is not
that protobuf: it is a JSON envelope wrapping the protobuf, a trust anchor,
a key fingerprint, and human-readable metadata. Some of that envelope is
covered by a proof or a signature and some of it is a label. This sweep is
how the report says which is which, per byte, rather than claiming the whole
file is protected.

Runs offline, like everything else in the checker's path.

Three passes:

  1. Every byte of the bundle FILE, XORed with 0xFF, one at a time.
     This is the "someone edited the file they were emailed" case, and it is
     the pass whose numbers the report quotes.

  2. Every byte of the decoded VerifiableEntry, re-encoded back into the
     bundle. Directly comparable to the spike's 794-byte sweep, so the
     report can say whether wrapping the proto in a bundle changed what the
     proto's own bytes are worth.

  3. Targeted field-level tamper, one field at a time through the JSON API,
     so the mechanism behind each category is unambiguous.
"""

import argparse
import base64
import copy
import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUNDLE = REPO_ROOT / "tests" / "fixtures" / "evidence_bundles" / "policy_allow.json"
_FIXTURES = REPO_ROOT / "tests" / "fixtures" / "evidence_bundles"
DEFAULT_KEY = _FIXTURES / "signing.pub"
DEFAULT_WRITER_KEYS = [_FIXTURES / "writer-decision.pub", _FIXTURES / "writer-control-plane.pub"]
DEFAULT_ANCHOR_KEYS = [_FIXTURES / "anchor-signing.pub"]
DEFAULT_TRUSTED_ROOT = _FIXTURES / "trusted_root.json"


def _load_checker():
    spec = importlib.util.spec_from_file_location(
        "ail_verify_bundle", REPO_ROOT / "tools" / "ail_verify_bundle.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = _load_checker()   # importing it blocks the network for this process

NO_EFFECT = "no_effect"
NOT_JSON = "not_json"


class _Keys:
    """Everything a full check needs, so this sweeps the real check
    rather than a reduced one. Passed as one object because Phase 3b's
    checker takes four kinds of trust input, and threading them through
    every call site separately would invite one being quietly dropped
    from a pass - which would report bytes as inert that are not.
    """

    def __init__(self, verifying_key, writer_keys, anchor_keys, trusted_root):
        self.verifying_key = verifying_key
        self.writer_keys = writer_keys
        self.anchor_keys = anchor_keys
        self.trusted_root = trusted_root


def try_bundle_bytes(raw: bytes, verifying_key) -> tuple[str, str]:
    """Categorize one mutated bundle file."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return NOT_JSON, f"not valid UTF-8: {exc}"
    try:
        bundle = json.loads(text)
    except json.JSONDecodeError as exc:
        return NOT_JSON, f"not valid JSON: {exc}"
    return try_bundle(bundle, verifying_key)


def try_bundle(bundle, verifying_key) -> tuple[str, str]:
    if not isinstance(bundle, dict):
        return checker.MALFORMED_BUNDLE, "bundle is not a JSON object"
    if bundle.get("bundle_format") != checker.BUNDLE_FORMAT:
        return checker.MALFORMED_BUNDLE, f"unsupported bundle_format {bundle.get('bundle_format')!r}"
    proof = bundle.get("proof")
    if not isinstance(proof, dict) or proof.get("format") != checker.PROOF_MATERIAL_FORMAT:
        return checker.MALFORMED_BUNDLE, "unsupported or missing proof.format"
    try:
        result = checker.verify_bundle(
            bundle,
            verifying_key.verifying_key,
            verifying_key.writer_keys,
            trusted_root_path=verifying_key.trusted_root,
            anchor_keys=verifying_key.anchor_keys,
        )
    except checker.BundleCheckFailed as exc:
        return exc.result_class, exc.detail
    except checker.NetworkAccessAttempted:
        raise
    except BaseException as exc:  # noqa: BLE001 - the sweep must classify, not crash
        # BaseException, not Exception: immudb-py calls sys.exit() on an
        # unknown transaction header version. Anything the checker lets
        # through uncategorised is a finding for the report, which is why
        # this branch names it loudly rather than folding it into a failure
        # class it is not.
        return "escaped_the_checker", f"{type(exc).__name__}: {exc}"
    return NO_EFFECT, f"verified=True tx={result['tx_id']}"


def _byte_ranges(raw: bytes, offsets: list[int]) -> str:
    """Collapse a list of offsets into readable ranges."""
    if not offsets:
        return "(none)"
    ranges = []
    start = prev = offsets[0]
    for off in offsets[1:]:
        if off == prev + 1:
            prev = off
            continue
        ranges.append((start, prev))
        start = prev = off
    ranges.append((start, prev))
    return ", ".join(f"{a}" if a == b else f"{a}-{b}" for a, b in ranges[:24]) + (
        f" (+{len(ranges) - 24} more ranges)" if len(ranges) > 24 else ""
    )


def _region_of(raw: bytes, offset: int) -> str:
    """Name the JSON field an offset falls inside, for the report's table.

    Located by scanning the pretty-printed text for each top-level key's
    span, which is enough because the exporter always writes indent=2.
    """
    text = raw.decode("utf-8", errors="replace")
    regions = [
        ("bundle_format", '"bundle_format"'),
        ("exported_at", '"exported_at"'),
        ("exported_by", '"exported_by"'),
        ("record.ledger_key", '"ledger_key"'),
        ("record.value", '"value"'),
        ("record.tx_id", '"tx_id"'),
        ("record.timestamp", '"timestamp"'),
        ("record.record_type", '"record_type"'),
        ("proof.format", '"format"'),
        ("proof.sdk", '"sdk"'),
        ("proof.source_state.db", '"db"'),
        ("proof.source_state.tx_id", '"tx_id"'),
        ("proof.source_state.tx_hash", '"tx_hash"'),
        ("proof.source_state.signature", '"signature"'),
        ("proof.verifiable_entry", '"verifiable_entry"'),
        ("proof.prove_since_tx", '"prove_since_tx"'),
        ("proof.entry_tx_id", '"entry_tx_id"'),
        ("proof.signing_key_fingerprint", '"signing_key_fingerprint"'),
        ("signing_key.fingerprint", '"fingerprint"'),
        # D22/D23 (Phase 3b). The writer signature lives inside record.value,
        # so its bytes fall under that span already; these are the envelope
        # fields the external_anchor section adds.
        ("external_anchor.state", '"state"'),
        ("external_anchor.detail", '"detail"'),
        ("external_anchor.log_url", '"log_url"'),
        ("external_anchor.log_url_source", '"log_url_source"'),
        ("external_anchor.log_index", '"log_index"'),
        ("external_anchor.anchor_key_fingerprint", '"anchor_key_fingerprint"'),
        ("external_anchor.anchor_payload_format", '"anchor_payload_format"'),
        ("external_anchor.entry.canonicalizedBody", '"canonicalizedBody"'),
        ("external_anchor.entry.rootHash", '"rootHash"'),
        ("external_anchor.entry.treeSize", '"treeSize"'),
        ("external_anchor.entry.hashes", '"hashes"'),
        ("external_anchor.entry.checkpoint", '"checkpoint"'),
        ("external_anchor.entry.logId", '"logId"'),
        ("external_anchor.entry.kindVersion", '"kindVersion"'),
        ("external_anchor.entry.integratedTime", '"integratedTime"'),
        ("external_anchor.entry.inclusionPromise", '"inclusionPromise"'),
        ("external_anchor.transparency_log_entry", '"transparency_log_entry"'),
    ]
    spans = []
    for name, needle in regions:
        idx = text.find(needle)
        while idx != -1:
            end = text.find("\n", idx)
            spans.append((idx, end if end != -1 else len(text), name))
            idx = text.find(needle, idx + 1)
    spans.sort()
    for start, end, name in spans:
        if start <= offset < end:
            return name
    return "json_structure"


def _rotate_printable(b: int) -> int:
    """Replace one byte with a different one that keeps the file text.

    XOR 0xFF is the right operator for a binary protobuf and the wrong one
    for a JSON file: every printable ASCII byte XORed with 0xFF is an
    invalid UTF-8 start byte, so that sweep reports "caught" for all of them
    and says nothing about which fields matter. Rotating within printable
    ASCII is what an actual edit to an emailed file looks like, and it is
    the pass whose per-field numbers are worth reading.
    """
    if 0x20 <= b <= 0x7E:
        return 0x20 + ((b - 0x20 + 1) % 95)
    return ord("X")  # newlines and any other control byte


def sweep_file(raw: bytes, verifying_key, mutate=_rotate_printable, label="printable rotation") -> dict:
    print(
        f"\n=== Pass 1 ({label}): byte-by-byte sweep over the bundle file "
        f"({len(raw)} bytes) ==="
    )
    counts = Counter()
    examples = {}
    by_category_offsets = {}
    region_counts = {}

    buf = bytearray(raw)
    for offset in range(len(buf)):
        original = buf[offset]
        buf[offset] = mutate(original)
        category, detail = try_bundle_bytes(bytes(buf), verifying_key)
        buf[offset] = original

        counts[category] += 1
        by_category_offsets.setdefault(category, []).append(offset)
        if category not in examples:
            examples[category] = (offset, detail)
        if category == NO_EFFECT:
            region = _region_of(raw, offset)
            region_counts[region] = region_counts.get(region, 0) + 1

    for category, n in counts.most_common():
        off, detail = examples[category]
        print(f"  {category:22s} {n:5d}  (e.g. offset {off}: {detail[:88]})")

    caught = sum(n for cat, n in counts.items() if cat != NO_EFFECT)
    print(f"\n  {caught}/{len(buf)} single-byte flips were caught.")
    if counts[NO_EFFECT]:
        print(f"  {counts[NO_EFFECT]} had no detectable effect, by field:")
        for region, n in sorted(region_counts.items(), key=lambda kv: -kv[1]):
            print(f"      {region:34s} {n:5d}")
        print(f"  no_effect offsets: {_byte_ranges(raw, by_category_offsets[NO_EFFECT])}")
    return {"counts": dict(counts), "regions": region_counts, "total": len(buf)}


def sweep_verifiable_entry(bundle: dict, verifying_key) -> dict:
    ventry_bytes = base64.b64decode(bundle["proof"]["verifiable_entry"])
    print(
        f"\n=== Pass 2: byte-by-byte sweep over the decoded VerifiableEntry "
        f"({len(ventry_bytes)} bytes), re-encoded into the bundle each time ==="
    )
    counts = Counter()
    examples = {}
    buf = bytearray(ventry_bytes)
    for offset in range(len(buf)):
        original = buf[offset]
        buf[offset] = original ^ 0xFF
        mutated = copy.deepcopy(bundle)
        mutated["proof"]["verifiable_entry"] = base64.b64encode(bytes(buf)).decode()
        buf[offset] = original

        category, detail = try_bundle(mutated, verifying_key)
        counts[category] += 1
        if category not in examples:
            examples[category] = (offset, detail)

    for category, n in counts.most_common():
        off, detail = examples[category]
        print(f"  {category:22s} {n:5d}  (e.g. offset {off}: {detail[:88]})")
    caught = sum(n for cat, n in counts.items() if cat != NO_EFFECT)
    print(f"\n  {caught}/{len(buf)} single-byte flips were caught.")
    return {"counts": dict(counts), "total": len(buf)}


def _flip_b64_first_byte(value: str) -> str:
    raw = bytearray(base64.b64decode(value))
    raw[0] ^= 0xFF
    return base64.b64encode(bytes(raw)).decode()


def targeted(bundle: dict, verifying_key):
    print("\n=== Pass 3: targeted field-level tamper ===")

    cases = []

    def case(label, mutate):
        mutated = copy.deepcopy(bundle)
        mutate(mutated)
        category, detail = try_bundle(mutated, verifying_key)
        cases.append((label, category, detail))
        print(f"  {label:46s} -> {category:22s} {detail[:70]}")

    case("record.value, byte 0 flipped",
         lambda b: b["record"].update(value=_flip_b64_first_byte(b["record"]["value"])))
    case("record.ledger_key, byte 0 flipped",
         lambda b: b["record"].update(ledger_key=_flip_b64_first_byte(b["record"]["ledger_key"])))
    case("record.tx_id, incremented",
         lambda b: b["record"].update(tx_id=b["record"]["tx_id"] + 1))
    case("record.record_type, relabelled",
         lambda b: b["record"].update(record_type="policy_deny"))
    case("record.timestamp, incremented",
         lambda b: b["record"].update(timestamp=(b["record"].get("timestamp") or 0) + 1))
    case("exported_at, rewritten",
         lambda b: b.update(exported_at="1999-01-01T00:00:00Z"))
    case("exported_by, rewritten",
         lambda b: b.update(exported_by="someone-else"))
    case("proof.verifiable_entry entry.value, byte 0 flipped",
         _tamper_entry_value)
    case("proof.source_state.tx_hash, byte 0 flipped",
         lambda b: b["proof"]["source_state"].update(
             tx_hash=_flip_b64_first_byte(b["proof"]["source_state"]["tx_hash"])))
    case("proof.source_state.signature, byte 0 flipped",
         lambda b: b["proof"]["source_state"].update(
             signature=_flip_b64_first_byte(b["proof"]["source_state"]["signature"])))
    case("proof.source_state.tx_id, set to 0 (genesis)",
         lambda b: b["proof"]["source_state"].update(tx_id=0))
    case("proof.source_state.db, renamed",
         lambda b: b["proof"]["source_state"].update(db="otherdb"))
    case("proof.prove_since_tx, incremented",
         lambda b: b["proof"].update(prove_since_tx=b["proof"]["prove_since_tx"] + 1))
    case("proof.entry_tx_id, incremented",
         lambda b: b["proof"].update(entry_tx_id=b["proof"]["entry_tx_id"] + 1))
    case("proof.sdk, rewritten",
         lambda b: b["proof"].update(sdk="immudb-py==9.9.9"))
    case("signing_key.fingerprint, byte flipped",
         lambda b: b["signing_key"].update(fingerprint="sha256:" + "00" * 32))

    # --- D22 (Phase 3b). The writer signature is a field INSIDE
    # record.value, so it is part of the leaf the inclusion proof covers.
    # Each case below rewrites the protobuf as well as the readable copy,
    # so the D19 binding between them does not fire first - and the result
    # is still consistency_failure, from immudb-py's own store.VerifyInclusion.
    #
    # That is the finding, not a limitation of the sweep: a writer signature
    # cannot be edited inside a bundle at all, because editing it edits the
    # record, and the record is what the ledger committed to. The D22 check
    # is what catches a bad signature that was committed to the ledger in
    # the first place, which is a thing no bundle-level tamper can produce -
    # it needs a writer that signed the wrong bytes. That case is exercised
    # live, against a real ledger, in
    # tests/test_anchored_export.py::test_a_record_signed_over_different_
    # bytes_is_refused_end_to_end.
    case("record writer_signature, byte 0 flipped", _tamper_writer_signature)
    case("record writer_key_fingerprint, repointed", _tamper_writer_fingerprint)
    case("record outcome_type, relabelled inside the signed bytes",
         lambda b: _tamper_record_field(b, "outcome_type", "policy_deny"))
    case("record writer_signature, removed entirely", _remove_writer_signature)

    # --- D23 (Phase 3b), the anchor section.
    if bundle.get("external_anchor", {}).get("state") == "anchored":
        case("external_anchor.state, downgraded to not_anchored",
             lambda b: b["external_anchor"].update(state="not_anchored", detail="claims nothing"))
        case("external_anchor.log_url, rewritten",
             lambda b: b["external_anchor"].update(log_url="https://example.invalid"))
        case("external_anchor.log_index, incremented",
             lambda b: b["external_anchor"].update(
                 log_index=str(int(b["external_anchor"]["log_index"]) + 1)))
        case("external_anchor.anchor_key_fingerprint, repointed",
             lambda b: b["external_anchor"].update(anchor_key_fingerprint="sha256:" + "00" * 32))
        case("entry.inclusionProof.rootHash, byte 0 flipped", _tamper_root_hash)
        case("entry.inclusionProof.hashes[0], byte 0 flipped", _tamper_first_audit_hash)
        case("entry.checkpoint.envelope, one label changed", _tamper_checkpoint)
        case("entry.canonicalizedBody, byte 0 flipped",
             lambda b: b["external_anchor"]["transparency_log_entry"].update(
                 canonicalizedBody=_flip_b64_first_byte(
                     b["external_anchor"]["transparency_log_entry"]["canonicalizedBody"])))
    else:
        case("external_anchor, removed entirely", lambda b: b.pop("external_anchor"))
        case("external_anchor.state, upgraded to anchored",
             lambda b: b["external_anchor"].update(state="anchored"))
        case("external_anchor.detail, rewritten",
             lambda b: b["external_anchor"].update(detail="anything at all"))
    return cases


def _proven_record(bundle):
    return json.loads(base64.b64decode(bundle["record"]["value"]).decode())


def _rewrite_record(bundle, record):
    """Put an edited record back into BOTH the protobuf and the readable copy.

    Without this the D19 binding between them fires first, and the sweep
    would report record_mismatch for every writer-signature case and never
    reach the check it is supposed to be measuring.
    """
    from immudb.grpc import schema_pb2

    raw = json.dumps(record, separators=(",", ":")).encode()
    ventry = schema_pb2.VerifiableEntry()
    ventry.ParseFromString(base64.b64decode(bundle["proof"]["verifiable_entry"]))
    ventry.entry.value = raw
    bundle["proof"]["verifiable_entry"] = base64.b64encode(ventry.SerializeToString()).decode()
    bundle["record"]["value"] = base64.b64encode(raw).decode()


def _tamper_writer_signature(bundle):
    record = _proven_record(bundle)
    record["writer_signature"] = _flip_b64_first_byte(record["writer_signature"])
    _rewrite_record(bundle, record)


def _tamper_writer_fingerprint(bundle):
    record = _proven_record(bundle)
    record["writer_key_fingerprint"] = "sha256:" + "00" * 32
    _rewrite_record(bundle, record)


def _remove_writer_signature(bundle):
    record = _proven_record(bundle)
    record.pop("writer_signature", None)
    _rewrite_record(bundle, record)


def _tamper_record_field(bundle, field, value):
    record = _proven_record(bundle)
    record[field] = value
    _rewrite_record(bundle, record)


def _tamper_root_hash(bundle):
    proof = bundle["external_anchor"]["transparency_log_entry"]["inclusionProof"]
    proof["rootHash"] = _flip_b64_first_byte(proof["rootHash"])


def _tamper_first_audit_hash(bundle):
    proof = bundle["external_anchor"]["transparency_log_entry"]["inclusionProof"]
    proof["hashes"][0] = _flip_b64_first_byte(proof["hashes"][0])


def _tamper_checkpoint(bundle):
    checkpoint = (bundle["external_anchor"]["transparency_log_entry"]
                  ["inclusionProof"]["checkpoint"])
    checkpoint["envelope"] = checkpoint["envelope"].replace("log2025", "log2026", 1)


def _tamper_entry_value(bundle):
    from immudb.grpc import schema_pb2

    ventry = schema_pb2.VerifiableEntry()
    ventry.ParseFromString(base64.b64decode(bundle["proof"]["verifiable_entry"]))
    tampered = bytearray(ventry.entry.value)
    tampered[0] ^= 0xFF
    ventry.entry.value = bytes(tampered)
    bundle["proof"]["verifiable_entry"] = base64.b64encode(ventry.SerializeToString()).decode()
    bundle["record"]["value"] = base64.b64encode(bytes(tampered)).decode()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("bundle", nargs="?", default=str(DEFAULT_BUNDLE))
    parser.add_argument("--key", default=str(DEFAULT_KEY))
    parser.add_argument("--writer-key", action="append", default=None)
    parser.add_argument("--anchor-key", action="append", default=None)
    parser.add_argument("--trusted-root", default=str(DEFAULT_TRUSTED_ROOT))
    args = parser.parse_args(argv)

    raw = Path(args.bundle).read_bytes()
    bundle = json.loads(raw.decode("utf-8"))
    verifying_key = _Keys(
        checker.load_key(args.key),
        checker.load_writer_keys(
            args.writer_key or [str(k) for k in DEFAULT_WRITER_KEYS]
        ),
        checker.load_writer_keys(
            args.anchor_key or [str(k) for k in DEFAULT_ANCHOR_KEYS]
        ),
        args.trusted_root,
    )

    baseline_category, baseline_detail = try_bundle(copy.deepcopy(bundle), verifying_key)
    print(f"Baseline (untampered): {baseline_category} - {baseline_detail}")
    if baseline_category != NO_EFFECT:
        print("Baseline does not verify; sweeping would be meaningless.")
        return 1

    sweep_file(raw, verifying_key)
    sweep_file(
        raw,
        verifying_key,
        mutate=lambda b: b ^ 0xFF,
        label="XOR 0xFF, the spike's operator",
    )
    sweep_verifiable_entry(bundle, verifying_key)
    targeted(bundle, verifying_key)
    return 0


if __name__ == "__main__":
    sys.exit(main())
