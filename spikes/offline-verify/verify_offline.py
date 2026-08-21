"""
Run OFFLINE. No immudb import of grpc.insecure_channel, no socket connect
attempted anywhere in this file. Loads only files under ./material/ (written
by export_material.py while the stack was up) plus the installed immudb-py
1.5.0 package's own verification code.

Calls immudb.handler.verifiedGet.call() UNMODIFIED - the exact function the
real client uses - by handing it fake stub/rootservice objects that return
the pre-captured material instead of making an RPC. Nothing here
reimplements Merkle hashing, dual-proof walking, or ECDSA verification;
that all happens inside immudb.embedded.store.verification and
immudb.rootService.State.Verify, imported straight from the SDK.

To prove no live connection is used, run this with the test stack stopped
(docker compose -f docker-compose.test.yml down) - it still works, or fails
with a socket error if something in the SDK secretly reaches out (it does
not).
"""
import base64
import pickle
import socket
import sys
from pathlib import Path

MATERIAL = Path(__file__).parent / "material"

from immudb.grpc import schema_pb2          # noqa: E402  (pure protobuf, no I/O)
from immudb.handler import verifiedGet       # noqa: E402  (the SDK's own logic)
from immudb.exceptions import ErrCorruptedData  # noqa: E402
from ecdsa.keys import BadSignatureError     # noqa: E402
import ecdsa                                 # noqa: E402

# Belt-and-suspenders: fail loudly if anything in this process tries to open
# an outbound connection after imports finish, so a passing result can't be
# silently explained by an accidental live connection. Patched after imports
# because ssl.py subclasses socket.socket at import time (grpc pulls in ssl).
def _blocked_connect(self, *a, **k):
    raise RuntimeError("verify_offline.py attempted a live socket connection")
socket.socket.connect = _blocked_connect


class FakeStub:
    """Stands in for the gRPC ImmuServiceStub. Returns the pre-captured
    VerifiableEntry response instead of making an RPC."""
    def __init__(self, ventry):
        self._ventry = ventry

    def VerifiableGet(self, req):
        return self._ventry


class FakeRootService:
    """Stands in for immudb.rootService.RootService. get() returns the
    pre-captured trust anchor; set() just records what the SDK computed
    instead of persisting it (there is nothing to persist offline)."""
    def __init__(self, state):
        self._state = state
        self.new_state = None

    def get(self):
        return self._state

    def set(self, new_state):
        self.new_state = new_state


def load_material(material_dir=MATERIAL):
    with open(material_dir / "state_source.pkl", "rb") as f:
        state_source = pickle.load(f)

    ventry = schema_pb2.VerifiableEntry()
    with open(material_dir / "ventry.pb", "rb") as f:
        ventry.ParseFromString(f.read())

    with open(material_dir / "signing.pub") as f:
        verifying_key = ecdsa.VerifyingKey.from_pem(f.read())

    key = base64.b64decode((material_dir / "key.txt").read_text())
    expected_value = base64.b64decode((material_dir / "value.txt").read_text())

    return state_source, ventry, verifying_key, key, expected_value


def verify(material_dir=MATERIAL):
    state_source, ventry, verifying_key, key, expected_value = load_material(material_dir)

    stub = FakeStub(ventry)
    rs = FakeRootService(state_source)

    result = verifiedGet.call(
        stub, rs, key, verifying_key=verifying_key,
    )
    return result, rs


def main():
    print("loading exported material from", MATERIAL)
    try:
        result, rs = verify()
    except ErrCorruptedData:
        print("RESULT: FAILED - ErrCorruptedData (inclusion or consistency proof rejected)")
        return 1
    except BadSignatureError:
        print("RESULT: FAILED - BadSignatureError (state signature rejected)")
        return 1

    print(f"RESULT: verified={result.verified} id={result.id} "
          f"value={result.value!r} timestamp={result.timestamp}")
    print(f"new trust anchor computed offline: txId={rs.new_state.txId} "
          f"txHash={rs.new_state.txHash.hex()}")
    return 0 if result.verified else 1


if __name__ == "__main__":
    sys.exit(main())
