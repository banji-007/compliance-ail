"""tests/anchor_helpers.py - Phase 3c-3d.

The verifier's trust-anchor surgery, in one place.

Why it moved here. Phase 3c-3c put it in tests/test_ledger_faults.py, which
was the only module that needed a live ADR-0006 `consistency_failure`. Phase
3c-3d needs the same condition in two more modules, and this project has
already paid twice for a rule with two copies and nothing comparing them
(tests/test_ledger_vocabulary.py's own docstring, and the Compose
project-name rule that cost a CI run). One copy, imported.

The surgery runs inside the verifier container because the state file lives
on its volume, and PersistentRootService reads it only at init - which is why
every mode is followed by a restart.
"""

from __future__ import annotations

import os

from compose_helpers import COMPOSE_PROJECT, compose, wait_for_health

VERIFIER_URL = os.getenv("VERIFIER_URL", "http://localhost:8003")

ANCHOR_SCRIPT = r'''
import pickle, shutil, sys
P = "/data/verifier-state/immudb.state"
B = "/data/verifier-state/immudb.state.p3c3c-bak"
mode = sys.argv[1] if len(sys.argv) > 1 else "show"
if mode == "corrupt":
    shutil.copyfile(P, B)
    with open(P, "rb") as f:
        states = pickle.load(f)
    for db, st in states.items():
        h = bytearray(st.txHash)
        h[0] ^= 0xFF
        st.txHash = bytes(h)
    with open(P, "wb") as f:
        pickle.dump(states, f)
    print("corrupted")
elif mode == "restore":
    shutil.copyfile(B, P)
    print("restored")
'''


def anchor(mode: str) -> None:
    """Corrupt or restore the verifier's persisted trust anchor, and restart."""
    result = compose("exec", "-T", "verifier", "python", "-", mode,
                     stdin=ANCHOR_SCRIPT, check=False)
    assert result.returncode == 0, (
        f"could not {mode} the trust anchor in project {COMPOSE_PROJECT!r}: "
        f"{result.stdout[-400:]} {result.stderr[-400:]}"
    )
    compose("restart", "verifier")
    assert wait_for_health(f"{VERIFIER_URL}/health"), (
        "the verifier did not come back after a restart; every later test in "
        "this session would fail against a dead service"
    )
