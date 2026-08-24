"""P3b-1 gate, part 2: the direction D23 actually needs.

The anchored checkpoint is NEWER than the record (you anchor periodically,
after records land). So the caller holds a trusted state at tx B and wants a
proof that record tx A < B is in that ledger. Does the SDK produce and check
that, with A and B both arbitrary and B not the head?
"""
import copy, sys
from pathlib import Path
from immudb import ImmudbClient
from immudb.rootService import State
from immudb.handler import verifiedtxbyid, verifiedGet
from immudb.grpc import schema_pb2
import immudb.schema as schema

REPO = Path(__file__).resolve().parent.parent.parent
PUB = REPO / "keys" / "signing.pub"


class FixedRootService:
    def __init__(self, state):
        self._state = state
        self.new_state = None
    def init(self, dbname, service): pass
    def get(self): return copy.deepcopy(self._state)
    def set(self, s): self.new_state = s


def main():
    c = ImmudbClient("localhost:3322", publicKeyFile=str(PUB))
    c.login(b"immudb", b"immudb", database=b"defaultdb")

    # existing ledger from part 1 is at tx 6; add more so the anchor is not head
    anchors = {}
    for i in range(6, 12):
        r = c.verifiedSet(f"p3b1:e{i}".encode(), f'{{"i":{i}}}'.encode())
        st = c._rs.get()
        anchors[r.id] = (st.txHash, st.db)
    head = max(anchors)
    print("head tx =", head)

    record_tx = 3          # a record written long ago
    anchor_tx = max(k for k in anchors if k < head)   # checkpoint, newer than record, older than head
    anchor_alh, db = anchors[anchor_tx]
    print(f"record tx={record_tx}, anchor tx={anchor_tx}, head={head}\n")

    anchor_state = State(db=db, txId=anchor_tx, txHash=anchor_alh,
                         publicKey=b"", signature=b"")

    # 7a: prove an OLD record tx against a NEWER trusted anchor
    rs = FixedRootService(anchor_state)
    try:
        keys = verifiedtxbyid.call(c._stub, rs, record_tx, None)
        print("PROBE 7a (record older than anchor, verifiedTxById): OK keys=%r" % (keys,))
        print("   resulting state txId=%d (unchanged anchor: %s)"
              % (rs.new_state.txId, rs.new_state.txId == anchor_tx))
    except Exception as e:
        print("PROBE 7a: FAILED %r" % (e,))

    # 7b: same shape via verifiedGet, which is what a bundle export uses
    rs2 = FixedRootService(anchor_state)
    try:
        res = verifiedGet.call(c._stub, rs2, b"p3b1:e2", None, c._vk)
        print("PROBE 7b (verifiedGet against arbitrary anchor): OK id=%d verified=%s"
              % (res.id, res.verified))
        print("   resulting state txId=%d" % rs2.new_state.txId)
    except Exception as e:
        print("PROBE 7b: FAILED %r" % (e,))

    # 7c: negative control, corrupt the anchor alh
    bad = bytearray(anchor_alh); bad[0] ^= 0x01
    rs3 = FixedRootService(State(db=db, txId=anchor_tx, txHash=bytes(bad),
                                 publicKey=b"", signature=b""))
    try:
        verifiedtxbyid.call(c._stub, rs3, record_tx, None)
        print("PROBE 7c (corrupt anchor alh): NO ERROR  <-- anchor not binding")
    except Exception as e:
        print("PROBE 7c (corrupt anchor alh): refused %s" % type(e).__name__)

    # 7d: does the server SIGN a state at an arbitrary (non-head) tx?
    req = schema_pb2.VerifiableTxRequest(tx=anchor_tx, proveSinceTx=record_tx)
    vtx = c._stub.VerifiableTxById(req)
    st = State(db=db, txId=anchor_tx,
               txHash=schema.DualProofFromProto(vtx.dualProof).targetTxHeader.Alh(),
               publicKey=vtx.signature.publicKey, signature=vtx.signature.signature)
    try:
        st.Verify(c._vk)
        print("PROBE 7d (server signature over state at non-head tx %d): VALID" % anchor_tx)
    except Exception as e:
        print("PROBE 7d: signature INVALID %r" % (e,))


if __name__ == "__main__":
    sys.exit(main())
