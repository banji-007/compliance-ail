"""
P3b-1 escalation gate probe.

Question: does immudb-py 1.5.0 expose a consistency proof between two
ARBITRARY transactions (source A, target B, neither of them the caller's
current head), reusing only the SDK's own verification code?

Run ONLINE against localhost:3322 (compose project ail-p3b1-gate).
"""
import copy
import sys
from pathlib import Path

from immudb import ImmudbClient
from immudb.rootService import State
from immudb.grpc import schema_pb2
from immudb.handler import verifiedtxbyid
from immudb.embedded import store
from immudb import exceptions
import immudb.schema as schema

REPO = Path(__file__).resolve().parent.parent.parent
PUB = REPO / "keys" / "signing.pub"

N = 6


class FixedRootService:
    """Returns a caller-chosen State. Same seam the offline-verify spike used."""

    def __init__(self, state):
        self._state = state
        self.new_state = None

    def init(self, dbname, service):
        pass

    def get(self):
        return copy.deepcopy(self._state)

    def set(self, s):
        self.new_state = s


def main():
    c = ImmudbClient("localhost:3322", publicKeyFile=str(PUB))
    c.login(b"immudb", b"immudb", database=b"defaultdb")

    anchors = []
    for i in range(N):
        r = c.verifiedSet(f"p3b1:e{i}".encode(), f'{{"i":{i}}}'.encode())
        st = c._rs.get()
        anchors.append((r.id, st.txHash, st.db))
        print(f"write {i}: tx={r.id} verified={r.verified} alh={st.txHash.hex()[:16]}...")

    head_tx = anchors[-1][0]
    src_tx, src_alh, db = anchors[1]
    tgt_tx = anchors[4][0]
    print(f"\nhead tx = {head_tx}")
    print(f"arbitrary pair: source tx={src_tx}  target tx={tgt_tx}  (both strictly < head)\n")

    src_state = State(db=db, txId=src_tx, txHash=src_alh,
                      publicKey=b"", signature=b"")

    # --- Probe 1: raw wire. Does the server honour an arbitrary proveSinceTx? ---
    req = schema_pb2.VerifiableTxRequest(tx=tgt_tx, proveSinceTx=src_tx)
    vtx = c._stub.VerifiableTxById(req)
    dp = schema.DualProofFromProto(vtx.dualProof)
    print("PROBE 1 (wire): VerifiableTxById(tx=%d, proveSinceTx=%d)" % (tgt_tx, src_tx))
    print("  dualProof.sourceTxHeader.iD =", dp.sourceTxHeader.iD)
    print("  dualProof.targetTxHeader.iD =", dp.targetTxHeader.iD)
    print("  vtx.tx.header.id            =", vtx.tx.header.id)
    print("  sourceAlh matches recorded  =", dp.sourceTxHeader.Alh() == src_alh)
    print("  serialized bytes            =", len(vtx.SerializeToString()))

    # --- Probe 2: SDK's own VerifyDualProof over that arbitrary pair ---
    ok = store.VerifyDualProof(dp, src_tx, tgt_tx,
                               dp.sourceTxHeader.Alh(), dp.targetTxHeader.Alh())
    print("\nPROBE 2 (SDK store.VerifyDualProof, arbitrary pair): %s" % ok)

    # --- Probe 3: through the unmodified public handler, vk=None ---
    rs = FixedRootService(src_state)
    try:
        keys = verifiedtxbyid.call(c._stub, rs, tgt_tx, None)
        print("\nPROBE 3 (verifiedtxbyid.call, vk=None): OK keys=%r" % (keys,))
        print("  new state txId=%d alh=%s" % (rs.new_state.txId, rs.new_state.txHash.hex()[:16]))
    except Exception as e:
        print("\nPROBE 3 (verifiedtxbyid.call, vk=None): FAILED %r" % (e,))

    # --- Probe 4: same, with the server signing key checked ---
    rs2 = FixedRootService(src_state)
    try:
        keys = verifiedtxbyid.call(c._stub, rs2, tgt_tx, c._vk)
        print("\nPROBE 4 (verifiedtxbyid.call, vk=signing.pub): OK keys=%r" % (keys,))
        print("  new state txId=%d" % rs2.new_state.txId)
    except Exception as e:
        print("\nPROBE 4 (verifiedtxbyid.call, vk=signing.pub): FAILED %r" % (e,))

    # --- Probe 5: negative control. Corrupt the source anchor by one byte. ---
    bad = bytearray(src_alh)
    bad[0] ^= 0x01
    bad_state = State(db=db, txId=src_tx, txHash=bytes(bad),
                      publicKey=b"", signature=b"")
    rs3 = FixedRootService(bad_state)
    try:
        verifiedtxbyid.call(c._stub, rs3, tgt_tx, None)
        print("\nPROBE 5 (corrupt source alh): NO ERROR  <-- proof not actually bound to source")
    except Exception as e:
        print("\nPROBE 5 (corrupt source alh): refused %s" % type(e).__name__)

    # --- Probe 6: is there any PUBLIC client method taking a source tx? ---
    import inspect
    hits = []
    for name, fn in inspect.getmembers(ImmudbClient, inspect.isfunction):
        if name.startswith("_"):
            continue
        params = list(inspect.signature(fn).parameters)
        if any(p.lower() in ("provesincetx", "provensincetx", "sourcetx", "fromtx") for p in params):
            hits.append((name, params))
    print("\nPROBE 6 (public ImmudbClient methods exposing a source/proveSince tx): %r" % (hits,))


if __name__ == "__main__":
    sys.exit(main())
