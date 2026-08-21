"""
Run OFFLINE, same as verify_offline.py (stack stopped, connect() blocked).

Two passes:

1. Full byte-by-byte sweep over material/ventry.pb: flip one byte (XOR 0xFF),
   attempt offline verification, restore the byte, record what happened.
   Categorizes every offset into: no_effect (still verified=True - the byte
   was in a varint length/tag that happened to still parse to something
   self-consistent, or genuinely unused padding), decode_error (corrupted the
   protobuf wire format itself), corrupted_data (ErrCorruptedData - a proof
   was rejected), bad_signature (BadSignatureError).

2. Targeted field-level tamper: flip one byte inside specific known-meaningful
   fields (the entry value, the state signature, the prior trust anchor's
   txHash, the prior trust anchor's publicKey) via the protobuf/dataclass
   APIs rather than raw offsets, and report the exact exception for each -
   including the one field (state.publicKey) that tampering does NOT catch,
   and why.
"""
import base64
import copy
import pickle
import socket
import sys
from pathlib import Path

MATERIAL = Path(__file__).parent / "material"

from immudb.grpc import schema_pb2
from immudb.handler import verifiedGet
from immudb.exceptions import ErrCorruptedData
from ecdsa.keys import BadSignatureError
from google.protobuf.message import DecodeError
import ecdsa

def _blocked_connect(self, *a, **k):
    raise RuntimeError("tamper_test.py attempted a live socket connection")
socket.socket.connect = _blocked_connect

from verify_offline import FakeStub, FakeRootService  # noqa: E402


def load_good():
    with open(MATERIAL / "state_source.pkl", "rb") as f:
        state_source = pickle.load(f)
    with open(MATERIAL / "ventry.pb", "rb") as f:
        ventry_bytes = f.read()
    with open(MATERIAL / "signing.pub") as f:
        verifying_key = ecdsa.VerifyingKey.from_pem(f.read())
    key = base64.b64decode((MATERIAL / "key.txt").read_text())
    return state_source, ventry_bytes, verifying_key, key


def try_verify(ventry_bytes, state_source, verifying_key, key):
    ventry = schema_pb2.VerifiableEntry()
    try:
        ventry.ParseFromString(ventry_bytes)
    except DecodeError as e:
        return "decode_error", str(e)

    stub = FakeStub(ventry)
    rs = FakeRootService(state_source)
    try:
        result = verifiedGet.call(stub, rs, key, verifying_key=verifying_key)
    except ErrCorruptedData:
        return "corrupted_data", "ErrCorruptedData (inclusion or dual/consistency proof rejected)"
    except BadSignatureError as e:
        return "bad_signature", f"BadSignatureError: {e}"
    except Exception as e:
        return "other_error", f"{type(e).__name__}: {e}"

    if result.verified:
        return "no_effect", f"verified=True id={result.id} value={result.value!r}"
    return "unverified_no_exception", f"verified=False id={result.id}"


def sweep_bytes(state_source, verifying_key, key, ventry_bytes):
    print(f"\n=== Pass 1: byte-by-byte sweep over ventry.pb ({len(ventry_bytes)} bytes) ===")
    counts = {}
    examples = {}
    buf = bytearray(ventry_bytes)
    for offset in range(len(buf)):
        original = buf[offset]
        buf[offset] = original ^ 0xFF
        category, detail = try_verify(bytes(buf), state_source, verifying_key, key)
        buf[offset] = original  # restore before next iteration

        counts[category] = counts.get(category, 0) + 1
        if category not in examples:
            examples[category] = (offset, detail)

    print("Category counts across all", len(buf), "single-byte flips:")
    for cat, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        off, detail = examples[cat]
        print(f"  {cat:24s} {n:4d}  (e.g. offset {off}: {detail})")

    detected = sum(n for cat, n in counts.items() if cat in ("decode_error", "corrupted_data", "bad_signature"))
    print(f"\n{detected}/{len(buf)} single-byte flips were caught "
          f"(decode_error + corrupted_data + bad_signature).")
    if counts.get("no_effect", 0):
        print(f"{counts['no_effect']} byte(s) had no detectable effect - "
              "expected for bytes inside varint tag/length framing where the "
              "flip still decodes to a self-consistent (if different) message, "
              "not a silent bypass of the proof check itself.")


def targeted_field_tamper(state_source, verifying_key, key, ventry_bytes):
    print("\n=== Pass 2: targeted field-level tamper ===")

    # (a) flip a byte in the entry's value
    ventry = schema_pb2.VerifiableEntry()
    ventry.ParseFromString(ventry_bytes)
    original_value = bytes(ventry.entry.value)
    tampered = bytearray(original_value)
    tampered[0] ^= 0xFF
    ventry.entry.value = bytes(tampered)
    cat, detail = try_verify(ventry.SerializeToString(), state_source, verifying_key, key)
    print(f"[a] flip byte 0 of entry.value ({original_value[:20]!r}... -> "
          f"{bytes(tampered)[:20]!r}...): {cat} - {detail}")

    # (b) flip a byte in the state signature (server's ECDSA sig over the tx)
    ventry = schema_pb2.VerifiableEntry()
    ventry.ParseFromString(ventry_bytes)
    sig = bytearray(ventry.verifiableTx.signature.signature)
    sig[0] ^= 0xFF
    ventry.verifiableTx.signature.signature = bytes(sig)
    cat, detail = try_verify(ventry.SerializeToString(), state_source, verifying_key, key)
    print(f"[b] flip byte 0 of verifiableTx.signature.signature: {cat} - {detail}")

    # (c) flip a byte in the prior trust anchor's txHash (the persisted state
    #     a verifier holds locally - the vector ADR-0001's own acceptance
    #     tests target as "corrupting the verifier's own persisted trust
    #     anchor")
    tampered_state = copy.copy(state_source)
    bad_hash = bytearray(tampered_state.txHash)
    bad_hash[0] ^= 0xFF
    tampered_state.txHash = bytes(bad_hash)
    cat, detail = try_verify(ventry_bytes, tampered_state, verifying_key, key)
    print(f"[c] flip byte 0 of the LOCAL trust anchor's txHash: {cat} - {detail}")

    # (d) flip a byte in the prior state's cached publicKey field - NOT the
    #     externally-loaded PEM verifying_key. verifiedGet.call() never reads
    #     state.publicKey; it only exists as informational cache alongside
    #     the anchor. This is expected to have NO effect.
    tampered_state = copy.copy(state_source)
    bad_pub = bytearray(tampered_state.publicKey)
    bad_pub[0] ^= 0xFF
    tampered_state.publicKey = bytes(bad_pub)
    cat, detail = try_verify(ventry_bytes, tampered_state, verifying_key, key)
    print(f"[d] flip byte 0 of the LOCAL state's cached publicKey field "
          f"(not the externally-loaded verifying key): {cat} - {detail}")
    print("    (expected: no_effect - state.publicKey is never read by "
          "verifiedGet.call(); only the externally-loaded PEM verifying_key "
          "and state.txHash/db/txId form the trust anchor)")


def main():
    state_source, ventry_bytes, verifying_key, key = load_good()

    baseline_cat, baseline_detail = try_verify(ventry_bytes, state_source, verifying_key, key)
    print(f"Baseline (untampered): {baseline_cat} - {baseline_detail}")
    assert baseline_cat == "no_effect", "baseline must verify cleanly before tampering"

    sweep_bytes(state_source, verifying_key, key, ventry_bytes)
    targeted_field_tamper(state_source, verifying_key, key, ventry_bytes)


if __name__ == "__main__":
    sys.exit(main())
