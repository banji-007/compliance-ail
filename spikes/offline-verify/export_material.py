"""
Run ONLINE against the live test stack (docker-compose.test.yml, immudb on
localhost:3322) to export the full proof material for one real ledger entry.

Writes to ./material/:
  state_source.pkl   - pickled immudb.rootService.State: the trust anchor
                        BEFORE the read (what a verifier holds prior to the
                        verifiedGet call)
  ventry.pb           - raw serialized schema_pb2.VerifiableEntry returned by
                        the server's VerifiableGet RPC (the only network
                        response the whole verification depends on)
  signing.pub          - copy of the ECDSA public key used to check the
                        server's state signature (already-exported material,
                        not fetched over the wire per call)
  key.txt / value.txt  - the raw key/value bytes (base64), so the offline
                        checker can print what it verified
  manifest.json        - txids and hex digests for the report
"""
import base64
import json
import pickle
import shutil
import sys
from pathlib import Path

from immudb import ImmudbClient
from immudb.grpc import schema_pb2

HERE = Path(__file__).parent
OUT = HERE / "material"
OUT.mkdir(exist_ok=True)

REPO_ROOT = HERE.parent.parent
PUBKEY_SRC = REPO_ROOT / "keys" / "signing.pub"

KEY1 = b"spike-offline-verify:entry-1"
VAL1 = b'{"tool":"spike-offline-verify","note":"first entry, will be proven"}'
KEY2 = b"spike-offline-verify:entry-2"
VAL2 = b'{"tool":"spike-offline-verify","note":"second entry, advances state past entry-1"}'


def main():
    client = ImmudbClient("localhost:3322", publicKeyFile=str(PUBKEY_SRC))
    client.login(b"immudb", b"immudb", database=b"defaultdb")

    # 1. Write entry 1, then entry 2. Two writes so the read below has a
    #    non-trivial dual proof: the trust anchor (state after entry 2) sits
    #    at a later tx than the entry being proven (entry 1), exercising the
    #    "state.txId > vTx" branch of verifiedGet.call().
    r1 = client.verifiedSet(KEY1, VAL1)
    print(f"wrote entry-1: tx={r1.id} verified={r1.verified}")
    r2 = client.verifiedSet(KEY2, VAL2)
    print(f"wrote entry-2: tx={r2.id} verified={r2.verified}")

    # 2. Capture the trust anchor as it stands right now (after both writes).
    #    This is exactly what client._rs.get() would hand to verifiedGet.call()
    #    as `state` if we called client.verifiedGet(KEY1) next.
    state_source = client._rs.get()
    print(f"source state: db={state_source.db} txId={state_source.txId} "
          f"txHash={state_source.txHash.hex()}")

    # 3. Make the exact same request verifiedGet.call() would make for
    #    KEY1, and capture the RAW response before any parsing/verification
    #    touches it. This is the only network round trip in the whole
    #    exercise; everything downstream of `ventry` is pure computation.
    req = schema_pb2.VerifiableGetRequest(
        keyRequest=schema_pb2.KeyRequest(key=KEY1),
        proveSinceTx=state_source.txId,
    )
    ventry = client._stub.VerifiableGet(req)

    # 4. Sanity check: run the real (online) verifiedGet through the normal
    #    client path too, so the report can show the offline result matches
    #    what the live SDK says right now, from the same starting state.
    live_result = client.verifiedGet(KEY1)
    print(f"live verifiedGet: id={live_result.id} verified={live_result.verified} "
          f"value={live_result.value!r}")

    # --- persist exported material -----------------------------------
    with open(OUT / "state_source.pkl", "wb") as f:
        pickle.dump(state_source, f)

    with open(OUT / "ventry.pb", "wb") as f:
        f.write(ventry.SerializeToString())

    shutil.copyfile(PUBKEY_SRC, OUT / "signing.pub")

    (OUT / "key.txt").write_text(base64.b64encode(KEY1).decode())
    (OUT / "value.txt").write_text(base64.b64encode(VAL1).decode())

    manifest = {
        "source_state": {
            "db": state_source.db,
            "txId": state_source.txId,
            "txHash_hex": state_source.txHash.hex(),
            "publicKey_hex": state_source.publicKey.hex(),
            "signature_hex": state_source.signature.hex(),
        },
        "entry1_tx": r1.id,
        "entry2_tx": r2.id,
        "ventry_serialized_len": len(ventry.SerializeToString()),
        "live_verifiedGet": {
            "id": live_result.id,
            "verified": live_result.verified,
            "timestamp": live_result.timestamp,
        },
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print("\nexported material to", OUT)
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    sys.exit(main())
