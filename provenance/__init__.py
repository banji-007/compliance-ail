"""
provenance/ - writer signing and external anchoring (Phase 3b, D22/D23).

Two small, dependency-light modules shared by every service that either
writes a ledger record or anchors a ledger state:

  record_signature.py - the canonical byte form of a record and the ECDSA
                        signature over it (D22)
  anchor.py           - the canonical byte form of an ImmuDB signed state
                        and the digest submitted to Rekor (D23)

Deliberately not shared with tools/ail_verify_bundle.py. That checker has to
stay runnable by an auditor with nothing installed but immudb-py and this
project's public keys, so it holds its own copy of both canonicalization
rules - the same discipline docs/adr/0010-portable-evidence-bundles.md
already applies to the stub shim and the record_type rule. The copies are
held in agreement by tests/test_writer_signing.py, which signs through this
module and verifies through the checker's copy, rather than by an import
that would tie an auditor to this repository's layout.

Nothing here implements a cryptographic primitive. Signing and verification
are ecdsa's own functions (the library immudb-py already depends on, and the
one this project's ImmuDB state signatures already go through); the only
hashing is hashlib.sha256, called to produce a digest that is compared or
handed to ecdsa as its hashfunc, never assembled into a construction of this
project's own. docs/adr/0001-immudb-rest-migration.md records what happened
the one time this project wrote its own.
"""
