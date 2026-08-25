# Phase 3b red-team report

**Run id:** `rt-p3b-a`.

## 1. Run identity, environment, developer-state confirmation

**Working directory (this session):** `/home/user/compliance-ail` (primary), branch `claude/phase-3b-redteam-brief-dhf1ux`. `git status --short` unchanged from session start to end (clean tree throughout); nothing in the primary directory was touched by any attack. All attacks and analysis ran from a separate scratch clone (below), per review-protocol §1's "sessions never run in the primary working directory."

**Base audited:** PR #10, branch `phase-3b-provenance`. Resolved live via `pull_request_read`: `state: OPEN`, `merged: false`, `head.sha: 4c2dc7c6c3e44f77fb2992928a87c8a6cdd449d2`. **Audited: this live tip, `4c2dc7c`**, confirmed identical to the base branch's `git rev-parse HEAD` after clone and checkout (below). PR **not merged**; not merged by this session.

**Scratch clone:** `rt-p3b-a-9589ad00`, under this session's scratchpad (`/home/user/scratch/rt-p3b-a-9589ad00/repo`) — an unused directory name. `git clone` from `https://github.com/banji-007/compliance-ail`, `git fetch origin phase-3b-provenance main`, `git checkout phase-3b-provenance`. `git rev-parse HEAD` → `4c2dc7c6c3e44f77fb2992928a87c8a6cdd449d2`, matching the PR's reported head exactly.

**Read in full:** `docs/reports/phase-3b.md`, `docs/reports/spike-signing-anchor.md`, `docs/reports/spike-consistency-proof.md`, `docs/adr/0010-portable-evidence-bundles.md`, `docs/adr/0012-writer-signing-and-external-anchoring.md`, `docs/process/review-protocol.md` §4, `readME.md` §3.4.2 and §5 (Residual Limits, full text), `provenance/record_signature.py`, `provenance/anchor.py`, `provenance/rekor.py`, `anchor_service/main.py`, `tools/ail_verify_bundle.py` (in full, 1155 lines), `ledger/immudb_ledger.py`, `verifier/main.py`'s `/verify` endpoint, `control_plane/main.py`'s `get_audit_bundle`/`/anchors` routes, `docker-compose.test.yml`, plus the four prior red-team reports (phase-1-2, phase-1-3, phase-2, phase-3a) for Y8.

**Docker / live stack: unavailable, not a choice.** This sandboxed session has no network route to Docker Hub or to PyPI (`docker pull python:3.11-slim` → `403 Forbidden`; `pip install immudb-py==1.5.0` → `403` from `pypi.org` and `files.pythonhosted.org`, confirmed via the environment's own agent-proxy status endpoint, which reported no relay failure and no selective/standalone scoping — i.e. this is an organization egress-policy denial, not a transient fault). `dockerd` itself starts and runs in this environment, but every image pull it attempts is blocked identically. Per this environment's own operating instructions ("do not retry or route around a 403"), no attempt was made to work around this. **Consequence: `make test-integration`, `docker compose up`, pytest, and every attack requiring `immudb-py`, `sigstore`, `ecdsa`, `httpx`, or `fastapi` as installed packages were not run.** This is the dominant constraint on this session and is why a large share of the verdicts below are `HOLDS WITH READING ONLY` or note a specific untested leg rather than `HOLDS`.

**What was run instead, and why it is more than reading.** The OS ships `python3-cryptography==41.0.7` (importable only via `/usr/bin/python3.12`; the project's own `python3`/venv-python3.11 has a broken `_cffi_backend` and cannot import it). ECDSA P-256/SHA-256 and Ed25519 signatures are standard and interoperate regardless of which library produced them, so a toolkit built on `cryptography` can verify signatures the real `ecdsa`/`sigstore-python` stack produced without needing those packages installed. Built and used, all in `/home/user/scratch/rt-p3b-a-9589ad00/attacks/`:

- `redteam_lib.py` — verbatim ports of `canonical_record_bytes`/`canonical_anchor_bytes`, ECDSA P-256/SHA-256 verify via `cryptography`, and a from-scratch RFC 6962 Merkle-inclusion-proof verifier and C2SP checkpoint/note Ed25519-signature verifier (independent of `sigstore-python`, since that package is also unavailable).
- `verify_ground_truth.py` — before attacking anything, ran this toolkit against the four genuine, untampered committed bundles and confirmed it **independently reproduces** every real cryptographic fact the build report claims: writer signatures verify, the anchor payload digest matches the log entry, the RFC 6962 Merkle audit path recomputes the real root hash, and the Ed25519 checkpoint signature verifies against the real log key from `trusted_root.json`. This established the toolkit agrees with genuine evidence before it was used to attack anything.
- `anchor_check.py` — a faithful standalone port of `tools/ail_verify_bundle.py::verify_external_anchor`, same field reads, same order of checks, same result classes, using `redteam_lib.py` in place of `sigstore`/`ecdsa`.
- `y1_attacks.py`, `y2_attacks.py`, `y3_y4_y5_attacks.py`, `y6_failopen_loop.py`, `y7_attacks.py` — the attacks themselves, detailed under each claim below.
- `y6_failopen_loop.py` imports and drives the **real, unmodified** `anchor_service/main.py::run_forever()` (not a reimplementation), with only `httpx` (a stub module, since the real package is uninstallable here) and `time.sleep` (to avoid a literal 300s wait and to serve as the external stop signal) replaced.
- `provenance/rekor.py::discover_log_url` was imported and driven directly — it is pure Python with no external dependency, so this required no stub at all.

A background research agent (Task tool, `general-purpose`) was used in parallel for Y8's "re-run prior attacks" and "changed-claim mapping completeness" sub-tasks, since these are large cross-referencing tasks over the four prior red-team reports and the full diff rather than crypto-execution tasks; its findings were independently spot-checked against source (line numbers below) before being included.

**Developer-state confirmation at the end:** Primary working directory `git status --short` empty, `HEAD` and branch unchanged from session start. Scratch clone, scratch venv (`/home/user/scratch/rt-p3b-a-9589ad00/venv`, created for an immudb-py install attempt that failed per the network constraint above and was never used), and all attack scripts under `/home/user/scratch/rt-p3b-a-9589ad00/` were removed via `rm -rf` at the end of this session; removal confirmed via a follow-up `ls` on the parent scratchpad directory returning empty. No Docker state was created in the primary account beyond the `dockerd` process itself (no images pulled, no containers run — every pull was refused before any container could start), so there was nothing to tear down there.

---

## 2. Verdict table

| Claim | Verdict | One-line reason |
| :--- | :--- | :--- |
| Y1 — writer signature cannot be stripped, forged, or ignored | **HOLDS** | Strip/null/empty signature and fingerprint, cross-record signature substitution, every named-field tamper (`outcome_type`, `policy_revision`, `profile`, plus seven others), an additive `exclusivity` tamper, and a Unicode-normalization substitution were all refused, executed against a verbatim port of the real check; canonicalization does not collide across int/float/string or dict key order |
| Y2 — the signing key cannot be redirected by bundle content | **HOLDS** | Fingerprint lookup and deny-list lookup are both exact-string, case- and whitespace-sensitive, executed and confirmed with a dozen malformed/loose variants; the ImmuDB, anchor, and writer keys cannot be substituted for one another; deny-list refusal happens unconditionally on fingerprint match, before signature validity is even considered |
| Y3 — the dual proof runs from the record to a genuinely anchored state | **HOLDS WITH READING ONLY** | The digest-binding leg (bundle ↔ Rekor entry) was executed and holds under every tamper tried; the direction-rejection leg (`anchor_precedes_record`) lives in `verifier/main.py`, is enforced online, and its own `@requires_stack` test additionally asserts no proof material is ever returned on that refusal — read, not executed, no live stack available |
| Y4 — the `external_anchor` fields are bound | **HOLDS** | Multi-byte/coordinated edits to `log_index`/`log_url`, whole-block swaps between bundles, real-entry-for-a-different-state substitution, and rewriting the entry's own `logIndex` were all executed against a from-scratch RFC 6962 Merkle re-verification (not the checker's own byte sweep) and all refused |
| Y5 — the downgrade residual is accurate and only ever removes a claim | **REFUTED** (documentation), **UNTESTABLE** (composed forgery) | The pure downgrade and the forbidden direction both behave as disclosed at the bundle-check layer (executed) — but `readME.md` §5 does not contain the downgrade disclosure the build report's own claim-mapping table cites it for; separately, splicing a genuine anchor+state pair from one bundle into another's unanchored record passes the D23-specific check alone (executed), and completing that into a real forgery needs `immudb-py`'s `VerifyDualProof`, unavailable here |
| Y6 — fail-open on the write path, fail-closed on the claim | **HOLDS** | The real `run_forever()` loop was executed and survives every named failure mode (Rekor 5xx/429, malformed body, timeout, real `LogDiscoveryFailed`, missing key, lost submission, mixed sequences); `run_once()` is confirmed by reading to fail closed by design; no bundle can claim corroboration it lacks (Y4/Y5); a spot check (not exhaustive) of other subsystems' exception handling found no second fail-open path |
| Y7 — no reimplemented crypto, and the meta-test is not vacuous | **HOLDS**, with a coverage caveat | The real ast-based meta-test was re-executed against the real source: a hand-rolled primitive under a new name is caught, both added assertions genuinely fail when their target is removed, banned-module imports are caught regardless of disguise; caveat — the `hashlib` allowlist is scoped by function name only, so a second hashlib call smuggled inside an already-allowed function is invisible to it (executed, demonstrated) |
| Y8 — artifacts reproduce, prior attacks fail, mapping is complete | **REFUTED** | Artifact reproduction: HOLDS, strongly, by independent execution (below). Prior attacks: none found to regress, within what a network-blocked environment could check. Mapping completeness: REFUTED twice — `/anchors`'/`/anchors/latest`'s credential split is a real, tested, undisclosed-in-the-table claim, and the table's own citation of `readME.md` §5 for the downgrade disclosure is false |

---

## 3. Evidence

### Y1 — HOLDS

**Attack.** `y1_attacks.py` ports `tools/ail_verify_bundle.py::verify_writer_signature` verbatim (same field names, same order of checks, same exception classes) and runs it against the real `writer-decision.pub`/`writer-control-plane.pub` and the real `policy_allow.json` record, first establishing the genuine record verifies, then attacking it.

```
$ python3.12 y1_attacks.py
=== baseline: genuine record must verify ===
[genuine] *** ACCEPTED *** -> {'writer_key_fingerprint': 'sha256:c770706648326c5c1d13656e63a4de08c1020fcbddd332e978c75655be30560f'}

=== 1. strip / null / empty signature ===
[signature field removed entirely] refused: writer_signature_missing: no writer signature/fingerprint
[signature = null] refused: writer_signature_missing
[signature = empty string] refused: writer_signature_missing
[fingerprint field removed (signature present)] refused: writer_signature_missing
[fingerprint = null] refused: writer_signature_missing

=== 2. well-formed signature over DIFFERENT bytes ===
[cross-record signature substitution (same writer key, different record)] refused: writer_signature_failure

=== 3. canonicalization: field tampering after a valid signature ===
[tamper outcome_type / policy_revision / profile / agent_id / tool_name / call_id /
 input_sha256 / reasons / content_state / fault_class] -> refused: writer_signature_failure (all ten)

=== 3b. add a field the signature never saw ===
[add exclusivity field not present in signed record] refused: writer_signature_failure

=== 4. canonicalization edge cases ===
[unicode NFC->NFD substitution while reusing NFC's signature] refused: writer_signature_failure
canonical bytes for n=1 (int)  : b'{"n":1}'
canonical bytes for n=1.0(float): b'{"n":1.0}'
canonical bytes for n='1'(str) : b'{"n":"1"}'
int/float/str collide: False False False
key-order independence: True
[trailing whitespace appended to a signed string field] refused: writer_signature_failure

=== 5. malformed / adversarial signature encodings ===
[signature is not valid base64] refused: writer_signature_failure
[signature is valid base64 but not a DER ECDSA signature] refused: writer_signature_failure

=== 6. ECDSA signature malleability (s -> n-s) ===
[malleated signature (s -> n-s) over the SAME genuine bytes] *** ACCEPTED ***
```

**Result.** Every attack that changes what is asserted is refused, correctly, as `writer_signature_missing` (the unsigned-and-fine case Y1 names explicitly) or `writer_signature_failure`. Canonicalization does not collide: int/float/string representations of the same logical value produce different byte strings, dict key order is normalized away by `sort_keys=True`, and a Unicode-normalization substitution (NFC → NFD, byte-different, visually identical) is caught because it changes the signed bytes. `exclusivity` — the field Y1 names by name — is confirmed by reading `ledger/immudb_ledger.py:205-209` to be added to the record dict *before* `_sign()` is called when present, so it is inside the signed bytes when it exists; attack 3b confirms empirically that adding it afterward breaks the signature.

The one accepted case (§6) is ECDSA signature malleability: `(r, s)` and `(r, n−s)` are both valid signatures over the *same* message under the *same* key for any standard (non-low-S-enforcing) ECDSA verifier, `ecdsa` (the real library) included. This does not let an attacker assert anything the signer did not sign — the message and the signer are unchanged, only the signature's alternate valid encoding — so it does not meet Y1's own REFUTED condition. Noted under §6 (Findings) as a minor, non-refuting technical observation.

### Y2 — HOLDS

**Attack.** `y2_attacks.py`, same harness, targeting fingerprint/key-selection logic specifically.

```
$ python3.12 y2_attacks.py
real writer fingerprint: sha256:c770706648326c5c1d13656e63a4de08c1020fcbddd332e978c75655be30560f

=== 1. fingerprint names a key the checker does not hold ===
[checker holds only the wrong writer key] refused: writer_key_unknown
[checker holds no writer keys at all] refused: writer_key_unknown

=== 2. malformed / non-matching fingerprint strings (loose comparison?) ===
[UPPERCASE, "SHA256:" prefix, trailing/leading space, truncated, extended,
 all-zero, empty, null] -> refused: writer_key_unknown or writer_signature_missing (all eight)

=== 3. fingerprint dict key exactness ===
[checker's own key map keyed with UPPERCASE fingerprint (genuine record, real signature)]
  refused: writer_key_unknown

=== 4. deny-list: checked before or after signature validity; any bypass? ===
[genuine, cryptographically VALID record, key is deny-listed] refused: writer_key_revoked
[deny-list entry differs from real fingerprint only in case (operator typo)] *** ACCEPTED ***
[deny-list entry has trailing whitespace vs real fingerprint] *** ACCEPTED ***

=== 5. tampered record from a denied key ===
refused: writer_key_revoked (revoked-checked-before-signature: True)

=== 6. ImmuDB key / writer key / anchor key cross-confusion ===
[ImmuDB signing key filed under the writer's real fingerprint] refused: writer_signature_failure
[anchor-signing key filed under the writer's real fingerprint] refused: writer_signature_failure
  signing.pub (ImmuDB)      : sha256:772cc0d3...
  anchor-signing.pub        : sha256:9f3d885a...
  writer-decision.pub       : sha256:c7707066...
  writer-control-plane.pub  : sha256:e528c08d...
  other-signing.pub         : sha256:48063d6c...
  any fingerprint collisions among the five project keys: False
```

**Result.** Every named attack in Y2 is refused. Fingerprint lookup (`writer_keys.get(fingerprint)`) and deny-list lookup (`fingerprint in deny_list`) are both ordinary Python dict operations over exact strings — case, whitespace, and prefix variants all miss, which closes the "loosely compares" and "fingerprint-influenced path" questions the brief names: there is no path, because there is no fuzzy matching anywhere in the lookup. The deny-list check runs and refuses **before** the signature is even attempted (`writer_key_revoked` fires ahead of any `ecdsa_verify` call in `tools/ail_verify_bundle.py`'s `verify_writer_signature`, confirmed both by source order and by attack §4's genuinely-valid-but-denied case), so "whether a denied key can still produce a pass on any path" is closed structurally, not by luck. None of the five project keys (ImmuDB, anchor, two writers, and a fifth unrelated test key) collide in fingerprint, and swapping any one key's PEM into another's slot in the checker's own key map produces a clean signature failure, never a pass.

One case in §4 is worth separating from the rest: a deny-list entry that differs from the real fingerprint only by case or trailing whitespace does **not** revoke the key. This is not bundle-content-driven (the fingerprint a record carries is fixed inside its signature and cannot be altered by an attacker without breaking that signature — confirmed in Y1), so it does not meet Y2's REFUTED condition, which is specifically about redirection *by bundle content*. It is a genuine, real, previously-undisclosed limitation of the deny-list's string matching against an *operator's own transcription*, reported under §6 (Findings).

### Y3 — HOLDS WITH READING ONLY

**Attack, digest-binding leg (executed).** `y3_y4_y5_attacks.py`, using `anchor_check.py` (a faithful standalone port of `verify_external_anchor`, validated against genuine bundles first — see `verify_ground_truth.py`'s output in §1).

```
=== Y3: proof.source_state vs the Rekor entry it's supposed to describe ===
[proof.source_state.tx_id changed]   refused: anchor_failure: log entry is not about this bundle's trust anchor
[proof.source_state.db changed]      refused: anchor_failure (same)
[proof.source_state.tx_hash zeroed]  refused: anchor_failure (same)
```

Every attempt to make the bundle's declared anchor state disagree with the Rekor entry it points at is caught, because `verify_external_anchor` recomputes the anchor payload digest from `proof.source_state` and compares it against the digest the log actually holds — confirmed with real cryptographic material, not simulated.

**Attack, direction-rejection leg (read only, could not execute).** The claim also names "try the rejected direction" — a record newer than its anchor. This rejection (`error_class: anchor_precedes_record`) is implemented in `verifier/main.py:598-620`, **online only**: the SDK's own dual-proof call (`sdk_verified_get.call(...)`, line 591) runs and succeeds first (the SDK happily produces a proof in the "wrong" direction — confirmed by reading `verify()`'s own logic, quoted verbatim in `docs/reports/spike-consistency-proof.md` item 1), and only afterward does an explicit `if int(resp.id) > int(source_state.txId):` guard refuse the response. This is a plain integer comparison over two values that are each independently cryptographically established (`resp.id` from a verified proof, `source_state.txId` from an ImmuDB-signature-verified anchor), so by reading alone it holds. Its enforcing test, `tests/test_anchored_export.py::test_an_anchor_older_than_the_record_is_refused_by_name` (`@requires_stack`), additionally asserts `result.get("proof_material") is None` on this refusal — meaning even a legitimate read-credential holder who deliberately asks `/verify` for this "wrong direction" pairing gets no captured proof material back to work with. Neither this test nor the guard itself could be executed in this environment (needs a live ImmuDB + verifier + gRPC stack, unavailable per §1).

**A related, deliberately separated finding is reported under Y5**, not here: the *offline* checker (`tools/ail_verify_bundle.py`) contains no independent copy of this `anchor_precedes_record` guard — grepped for `precedes`, `anchor.txId >`, and equivalents; none exist. Composing a working exploit from that gap requires a real `VerifyDualProof` call this session could not make; see Y5's evidence for exactly what was and was not shown.

### Y4 — HOLDS

**Attack.** Same harness as Y3, targeting the fields the byte sweep already found and bound (`log_index`, `log_url`), plus the ones the sweep's single-byte methodology could not reach.

```
=== Y4: multi-byte / coordinated edits across log_url, log_index, state ===
[log_index off-by-one, multi-digit]                    refused: anchor_failure
[log_url repointed at a REAL, different (v1) log]      refused: anchor_failure: real log is [...log2025-1...]
[log_index AND log_url changed together, consistently]  refused: anchor_failure
[attacker rewrites the claimed log_index AND the entry's OWN logIndex field to '1']
                                                         refused: anchor_failure: inclusion proof contains invalid root hash

=== Y4: substitute a real Rekor entry for a different state ===
[a real, fully-verifiable Rekor entry pasted in, for a source_state it doesn't describe]
                                                         refused: anchor_failure: log entry is not about this bundle's trust anchor

=== Y4: cross-bundle external_anchor swap ===
[external_anchor swapped policy_deny -> policy_allow, SAME underlying checkpoint tx=2]
                                                         *** ACCEPTED *** (both records legitimately anchor at tx=2; not a false claim)
[external_anchor swapped AND source_state tampered (real mismatch)]
                                                         refused: anchor_failure
```

**Result.** The multi-byte and coordinated attacks the brief specifically asks for (going beyond the build report's own single-byte sweep) were run against a *from-scratch, independently written* RFC 6962 Merkle-inclusion verifier and Ed25519 checkpoint verifier — not the checker's own byte-sweep tool, and not `sigstore-python` — and all were refused. The fourth attack (rewriting the entry's own `logIndex` to `1`) is the strongest form: it shows the binding does not rest merely on comparing two copies of a number, because forging *both* copies consistently still fails, since `logIndex` also determines which position in the Merkle audit path the leaf is checked against, and `1` is not the position the real proof was built for.

The cross-bundle swap that *was* accepted is not a counterexample: `policy_allow.json` and `policy_deny.json` genuinely anchor at the same real checkpoint (both `tx=2`, confirmed via `proof.source_state.tx_id` in both fixtures), so swapping the block asserts nothing false about either. Making the swap assert something false (second variant) is refused.

### Y5 — REFUTED (documentation), UNTESTABLE (composed forgery)

**Attack, bundle-layer behavior (executed).**

```
=== Y5: downgrade composed with other tampers ===
[pure downgrade: anchored -> not_anchored, with a detail string]      *** ACCEPTED *** (state: not_anchored, checked: False)
[not_anchored -> anchored: paste a real anchor block, KEEP the record's OWN (mismatched) source_state]
                                                                       refused: anchor_failure
[not_anchored -> anchored: paste a real anchor block AND its matching source_state]
                                                                       *** ACCEPTED *** (state: anchored, checked: True) -- see below
[downgrade to not_anchored but leaving the real transparency_log_entry/log_index alongside it]
                                                                       *** ACCEPTED *** (state: not_anchored, checked: False -- section's `state` value governs, extra fields are not read)
[not_anchored with no 'detail' field]                                  refused: malformed_bundle
[bare relabel not_anchored -> anchored, no other fields]               refused: malformed_bundle
[state field case/whitespace/type variants: 'ANCHORED', 'Anchored ', True, 1, None, '']
                                                                       refused: malformed_bundle (all seven)
```

**The pure downgrade direction behaves exactly as disclosed**, executed: `anchored → not_anchored` is accepted (nothing at the bundle-check layer can distinguish a genuinely-unanchored record from a downgraded one, because they are the same bytes by construction — this is not new information, it is the report's own disclosure, confirmed rather than merely trusted). The forbidden direction (bare relabel, or a relabel that leaves stale anchor fields lying around) is refused, correctly, as `malformed_bundle`.

**The third variant is the one that needs care.** Splicing a genuine, real, fully-verifiable `external_anchor` block **and** its matching `proof.source_state` — both copied verbatim from `policy_allow.json`, a legitimately anchored bundle — onto `fault.json` (a genuinely unanchored bundle) is **accepted by `verify_external_anchor` in isolation**. This is real, executed. It is not, by itself, a working forgery against the real checker: per ADR-0012's own chain table, "record's transaction to the anchored state" is a *separate* link (`store.VerifyDualProof`, inside `immudb.handler.verifiedGet.call()`), not something `verify_external_anchor` is responsible for or re-derives. Completing or refuting this composition against the real tool requires driving `verifiedGet.call()` with `fault.json`'s own captured `proof.verifiable_entry` against the substituted anchor — `immudb-py`, unavailable in this session. Tracing the SDK's own quoted logic (`docs/reports/spike-consistency-proof.md` item 1: `dualProof.sourceTxHeader`/`targetTxHeader` are baked into the captured proof at the transaction pair it was originally requested for) suggests this specific composition fails there, because `fault.json`'s embedded dual proof was captured for a different (source, target) pair than the substituted one — but this is inference from documented source, not something this session executed. **Marked UNTESTABLE, not REFUTED**: no bundle was produced that this session confirmed passes the real, complete checker end to end.

**Attack, documentation accuracy (executed by exhaustive reading).** The build report's byte-sweep section states plainly: *"[the downgrade] is reported rather than fixed... It is in Residual Limits"* (`docs/reports/phase-3b.md:449-454`), and the claim-mapping table's row for this exact claim cites `readME.md §5` as backing (`docs/reports/phase-3b.md:379`, kind: "Residual Limits + command"). `readME.md` §5 (`Residual Limits`, the full section, lines 506-524) was read in full and separately grepped for `downgrad`, `not_anchored`, and `relabel`: **zero matches**. The section contains exactly the three Phase-3b bullets P3b-6 itself claims were added (writer-signature/compromised-writer at line 521, log-turndown/permanence at line 522, library-seam at line 523) — and no fourth bullet about the downgrade. **This is REFUTED as characterized**: the report says a reader of `readME.md` will find this limitation documented; a reader will not. This is worse than the report's own disclosure, per the brief's own instruction to report exactly that.

### Y6 — HOLDS

**Attack.** `y6_failopen_loop.py` imports the real `anchor_service/main.py` (httpx stubbed since unavailable; `time.sleep` used as the external stop signal, since a sentinel exception raised *inside* `anchor_once()` would be swallowed by the very `except Exception` handler under test) and drives the real, unmodified `run_forever()` through eight named failure scenarios, three or more cycles past each.

```
$ python3.12 y6_failopen_loop.py
[Rekor 500]                                cycles requested=4 cycles actually run=4 survived: True
[Rekor 429 rate limited]                   cycles requested=4 cycles actually run=4 survived: True
[Rekor malformed body (KeyError)]          cycles requested=4 cycles actually run=4 survived: True
[submission times out]                     cycles requested=4 cycles actually run=4 survived: True
[TUF/log-discovery fails]                  cycles requested=4 cycles actually run=4 survived: True
[anchoring key missing/unreadable]         cycles requested=4 cycles actually run=4 survived: True
[control-plane /anchors POST lost]         cycles requested=4 cycles actually run=4 survived: True
[mixed: 3 fail, 1 success, 2 fail, repeat] cycles requested=9 cycles actually run=9 survived: True

time.sleep() observed 37 times total (loop paced itself between every cycle, never busy-looped, never exited)
ALL SCENARIOS SURVIVED (loop never stopped on a failed cycle): True
```

`stderr` from this run additionally shows the real `logger.error("Anchoring cycle failed (fail-open by D23, writes are unaffected): ...")` line firing once per induced failure (44 lines for the 37 cycles plus 7 startup lines), confirming the real exception path executed rather than being short-circuited by the test harness.

**The "TUF fetch fails" scenario was also driven directly**, independent of the loop test, against the real `provenance/rekor.py::discover_log_url` (pure Python, no stub needed):

```
EMPTY CONFIGS: raised LogDiscoveryFailed: no Rekor v2 instance is currently advertised...
V1-ONLY, EMPTY TRUSTED ROOT: raised LogDiscoveryFailed (same)
MALFORMED validFor (not a dict): raised LogDiscoveryFailed (same)
NO-START validFor: raised LogDiscoveryFailed (same)
```

None of the four malformed-configuration shapes silently returns a fabricated URL; all raise cleanly, which `anchor_once` does not catch and `run_forever`'s outer handler does (confirmed above).

**`run_once()` (read only).** `anchor_service/main.py:231-250`'s own docstring and structure confirm it is deliberately *not* fail-open — it returns exit code 2 (key missing) or 1 (nothing anchored) rather than looping, which is correct and distinct from the write-path claim Y6 is about (this is the operator-invoked `--once` command, not something in the decision path).

**No bundle can claim corroboration it lacks** was tested at the bundle-check layer under Y4/Y5 above and holds there.

**Other subsystems, spot-checked (not exhaustive; see §5).** `grep -n "except Exception"` across `control_plane/main.py`, `decision_service/main.py`, `verifier/main.py`, `ledger/immudb_ledger.py`, `interceptor/middleware.py` returns 25 handlers; two were read in full (`decision_service/main.py:170` — a non-security-relevant OPA-revision lookup that returns `None` on failure; `interceptor/middleware.py:100-124` — the SPIFFE SAN check, which returns `False` and denies on any exception). Both are fail-closed or non-security-relevant. The other ~23 were not individually read; see §5.

### Y7 — HOLDS, with a coverage caveat

**Attack.** `y7_attacks.py` re-implements `tests/test_offline_verify.py::test_the_checker_implements_no_cryptography_of_its_own`'s exact `ast`-based logic (stdlib `ast` only) and runs it against the real `tools/ail_verify_bundle.py` source, then against mutated copies.

```
$ python3.12 y7_attacks.py
=== baseline: real ail_verify_bundle.py must pass its own meta-test ===
baseline: True (all checks passed)

=== 1. hand-rolled primitive under a NEW function name ===
new function '_hand_rolled_merkle_leaf_hash' using hashlib directly: caught=True

=== 2. hand-rolled primitive smuggled into an ALREADY-ALLOWED function name ===
second, unrelated hashlib call added INSIDE key_fingerprint: caught=False
  ==> the allowlist is by function NAME only; it does not bound what an already-allowed
      function does with hashlib, or how many times/on what input.

=== 3. do the two 'added assertions' actually fail when their target is removed? ===
removing 'TransparencyLogEntry(raw_entry)._verify(keyring)': meta-test still passes=False (correct)
removing 'sigdecode=sigdecode_der': meta-test still passes=False (correct)

=== 4. banned-module import, various disguises ===
top-level 'import hmac': caught=True
'from cryptography... import hashes': caught=True
'import Crypto.Hash.SHA256' (submodule): caught=True
hmac imported inside an existing function body: caught=True
```

**Result.** The literal Y7 attacks all land as HOLDS: a genuinely new hand-rolled primitive is caught (test 1), both of the two assertions the build report added alongside the widened allowlist are demonstrably not vacuous — each independently fails the meta-test when its target string is removed (test 3) — and banned-module detection is robust to nesting and submodule tricks (test 4). Reading confirms `_ecdsa_verify` always hardcodes `hashfunc=hashlib.sha256` (never bundle-parameterized), and `key_fingerprint` is only ever called on locally-loaded key files (`--key`/`--writer-key`/`--anchor-key` paths), never on bundle-controlled bytes — so of the three allowlisted functions, only `anchor_payload_digest` operates on bundle-derived bytes, and its result is used purely as a byte-comparison gate that a real, independently-verified log entry must also match, not as a self-asserting security decision.

**Genesis-anchor skip (X3 carryover, read only).** `anchor.Verify(verifying_key)` at `tools/ail_verify_bundle.py:868` runs unconditionally, before `verifiedGet.call()` at line 896, on the single control-flow path both new Phase 3b checks (writer signature, external anchor) sit downstream of — unchanged in shape from Phase 3a, independently re-confirmed by the background agent's Task 1 (below).

**Test 2 is a genuine, real, executed finding, not a refutation.** The allowlist (`_HASHLIB_ALLOWED = {"key_fingerprint", "anchor_payload_digest", "_ecdsa_verify"}`) is checked by *function name* via an `ast.walk` over each `FunctionDef`; it does not, and structurally cannot, bound what an already-allowed function computes or how many times. A second `hashlib.sha256()` call added inside `key_fingerprint`'s body is invisible to it. This does not meet Y7's literal REFUTED bar (no working alternative-verification bypass was demonstrated — merely an unused extra hash call), so it is reported under §6 rather than flipping the verdict.

### Y8 — REFUTED

**Attack 1: committed artifacts reproduce (executed, independently, across every spike directory and fixture directory).**

Every text-typed committed file under `spikes/` and `tests/fixtures/` (39 of 60 files; the rest are binary protobuf/pickle/certificate files with no UTF-8 invariant to check) was checked for strict UTF-8 decodability — the exact damage class the build report found and repaired in `spikes/signing-anchor/submit_response.json`:

```
60 files total under spikes/ + tests/fixtures/, 39 are text-typed.
All text-typed committed files under spikes/ and tests/fixtures/ decode as strict UTF-8
-- no cp1252-class damage found anywhere in the repo.
```

(An earlier, cruder single-byte heuristic flagged several binary files and even `submit_response.json` itself as "suspicious" — direct inspection showed the flagged byte in `submit_response.json` is the *last* byte of a correctly-encoded 3-byte UTF-8 em-dash sequence, `\xe2\x80\x94`, i.e. a false positive from the heuristic, not a repeat of the bug. The corrected, decode-based check above is the one that matters and reports clean.)

Beyond encoding, the underlying cryptographic material was independently re-verified, not merely decoded:

```
$ python3.12 -c '... spikes/signing-anchor/submit_response.json ...'
Merkle inclusion (hand-rolled RFC6962): OK
checkpoint origin/size match inclusion proof: True True
checkpoint Ed25519 signature (hand-rolled): OK
log_index: 78995452 tree_size: 78995488
root_hash: f9df8c8f44f878d3275fe14c852c8811bbcb1b2ae2a1149b4ee5c6a14e829155
```

— matching the report's own transcript for this file exactly (log index, tree size, and root hash all identical). Question A's SVID material was independently re-verified too, using `cryptography`'s basic EC/X.509 primitives (not the full PKIX `verification` module, which needs `cryptography>=42` and is unavailable at the OS-packaged `41.0.7`):

```
leaf notBefore: 2026-08-24 19:28:01 notAfter: 2026-08-25 19:28:11
now (naive utc): 2026-08-25 09:55:58 -- currently within validity window: True
signature over record_bytes.bin verifies against leaf cert public key: OK
leaf SAN URIs: ['spiffe://ail.internal/workload/test']
leaf cert signature verifies against CA[0]: OK
```

As of this audit (2026-08-25, ~09:55 UTC), the leaf certificate is still within its validity window — about 9.5 hours remain before the report's own NO-GO demonstration reproduces itself on the clock, per the spike report's own framing.

The full genuine-fixture ground-truth pass (§1) additionally re-verified all four committed evidence bundles' writer signatures, anchor digests, Merkle inclusion, and checkpoint signatures, and a direct scan of all four bundle JSON files confirmed no PEM armor, raw DER, or base64-DER of any of the five project keys anywhere in their bytes (the "no key material in any bundle" pre-registered negative).

**Attack 2: prior attacks re-run (background agent, spot-checked).** A background research agent read all four prior red-team reports (phase-1-2, phase-1-3, phase-2, phase-3a) and checked each concrete attack against current source. Summary (full detail in the agent's own report, available on request; spot-checked line citations below confirmed accurate):

- **STILL HOLDS / STILL FIXED, unregressed:** U3, U4 (both combos), U5, V5, V6, W3, W6, and X3 (independently re-confirmed by this session directly: `tools/ail_verify_bundle.py:868` `anchor.Verify` unconditional-before-`verifiedGet.call`-at-line-896, unchanged in shape).
- **Structurally present but unchanged from prior phases (not a Phase 3b regression):** U1 (OPA revision trust, now in `decision_service/main.py:316-333`), U8 (OPA management-API reach) — both gated by the same production network topology (no host-published OPA port, `edge`/`backend` split) that closed them in Phase 2, untouched by this diff.
- **Could not check** (need a live stack this session cannot bring up): U7, V1-V4, V7-V8, W1-W2, W4-W5, W7-W8, X1/X2/X4/X6/X7/X8 beyond what the build report's own transcripts already show.
- **No prior attack was found to work against current source.**

**Attack 3: mapping completeness (background agent, spot-checked and independently confirmed by this session).**

`git diff main...phase-3b-provenance --stat`: 45 files, +6309/-201. Cross-referencing every changed file against `docs/reports/phase-3b.md`'s claim-mapping table (lines 335-379) found one uncovered, security-relevant, tested claim:

**`POST /anchors` and `GET /anchors/latest`'s credential split has no row in the mapping table**, despite being new, security-relevant, and enforced by a real committed test. Confirmed directly by this session:

- `control_plane/main.py:1040-1045` — `POST /anchors`, `Depends(_require_write_key)`, with a four-sentence docstring rationale for why this is not a new grant.
- `control_plane/main.py:1121-1122` — `GET /anchors/latest`, `Depends(_require_read_key)`.
- `tests/test_anchored_export.py:648-664` — `test_the_anchor_store_is_write_credentialled_and_the_latest_read_credentialled`, asserting 403 on both an unauthenticated write and an unauthenticated read.
- `docs/reports/phase-3b.md`: the only occurrence of `/anchors` anywhere in the file is an incidental log-transcript line (`:198`, inside a `$ python tools/export_evidence_fixtures.py` output block) — grepped for the test name and for `/anchors` as a claim; no mapping-table row references this route, this test, or this authorization decision.

Combined with Y5's finding that the mapping table's citation of `readME.md §5` for the downgrade-residual disclosure is false, this is the **second** distinct way the mapping fails to be complete/accurate, which is Y8's own REFUTED condition twice over.

No other uncovered security-relevant claim was found in the remaining changed files (`control_plane/models.py`'s new anchor table, the new `anchor_service` container and its credentials, the new `AIL_WRITER_SIGNING_KEY` mounts, and `docker-compose.test.yml`'s deliberate omission of `anchor-service` are each covered by an existing mapping-table row); Dockerfile/`.gitignore`/`Makefile` changes are mechanical and correctly out of scope per the brief's own framing.

---

## 4. Attacks attempted that failed

**Y1:** attempted a signature-encoding attack beyond malleability — feeding a syntactically-valid-but-non-canonical DER encoding (e.g. an oversized length byte) — did not find one `ecdsa`'s DER decoder (used indirectly via `cryptography`'s equivalent decode path in this harness) accepts; every non-canonical variant tried was refused as `writer_signature_failure`, not accepted. Did not find a JSON canonicalization collision across the four attempted axes (Unicode form, numeric type, key order, trailing whitespace) — all four correctly produce different signed bytes.

**Y2:** attempted to make the writer-key map's *value* rather than its *key* the confusable thing — swapping which PEM file is loaded for a correct fingerprint key in the map — and it fails identically to the fingerprint-substitution attacks (`writer_signature_failure`), as expected, since the map is fingerprint → key and the checker recomputes nothing from the map's key. Did not find any code path where a fingerprint string influences control flow beyond a single dict `.get()`/`in` — there is no parsing, decoding, or interpretation of the fingerprint string anywhere in `verify_writer_signature`.

**Y3/Y4:** attempted to find a *second* place besides `_hashedrekord_body`'s digest comparison where an entry's authenticity is asserted without a corresponding check — none found; every field read from `transparency_log_entry` in `verify_external_anchor` (`logIndex`, `logId.keyId`, the digest, the public key, the signature, the inclusion proof, the checkpoint) is either cryptographically checked or used only to locate a trust-root entry that is itself then checked. Attempted a coordinated `log_index` + entry-internal `logIndex` + inclusion-proof `logIndex` triple edit, all three set consistently to the same wrong value (§Y4 evidence, attack 4) — still refused, because the Merkle audit path is keyed to that same value and no longer matches the real root hash.

**Y5:** attempted to find a *second*, independent path by which a downgraded (`not_anchored`) bundle could still assert corroboration through some other bundle field (`proof.sdk`, `exported_by`, etc.) — none of those fields are read by `verify_external_anchor` or by anything downstream of it; they are the pre-existing, disclosed Phase-3a inert fields, unrelated to the anchor claim.

**Y6:** did not attempt to break `run_once()`'s fail-closed behavior (out of scope for the write-path claim; confirmed by reading only, see evidence). Did not exhaustively read all ~23 remaining `except Exception` handlers across `control_plane/main.py`/`decision_service/main.py`/`verifier/main.py`/`ledger/immudb_ledger.py` for a second fail-open path — two were spot-checked and both fail closed or are non-security-relevant; see §5 for what was not checked.

**Y7:** attempted the same "smuggled into an allowed function" trick against `_ecdsa_verify` and `anchor_payload_digest` specifically (not just `key_fingerprint`) — both equally invisible to the meta-test, confirming the gap is general to the allowlist mechanism rather than specific to one function. Did not find a way to make the meta-test's two string-presence assertions pass while the underlying call was actually removed (e.g. via a docstring or comment containing the same string) — the real source does not have the strings anywhere except at the real call sites, so this was not a live risk to demonstrate, only a theoretical one noted and not pursued further given the two assertions are plain substring checks over the whole file, not scoped to non-comment code.

**Y8:** did not attempt to independently regenerate `submit_response.json` or `trusted_root.json` from a live TUF/Rekor fetch to confirm the *fetch* mechanism still works today (network-blocked); confirmed only that the already-committed artifacts are internally consistent and cryptographically genuine. Did not re-run V1-V4/V7-V8/W1-W2/W4-W5/W7-W8/U7 (see §5) or attempt to reproduce any of them live.

---

## 5. Could not test

- **Everything requiring `docker compose up`, `pytest`, `immudb-py`, `sigstore`, `ecdsa`, `httpx`, or `fastapi` as installed packages.** This environment's outbound network policy denies PyPI and Docker Hub with a 403 (confirmed via direct `curl` and via the environment's own agent-proxy status endpoint, which reported no relay failure — i.e. a deliberate policy denial, not a transient fault); per this environment's own instructions, this was not retried or routed around. `dockerd` itself runs, but every `docker pull`/`docker run` against an upstream image fails identically. This blocks: the entire `make test-integration` suite (295 tests per the build report); every `@requires_stack`-decorated test in `tests/test_anchored_export.py` and `tests/test_external_anchor.py`; live submission to Rekor; and, most importantly for this brief, the real `immudb-py` Merkle/dual-consistency-proof machinery (`store.VerifyInclusion`, `store.VerifyDualProof`) that underlies the "record's transaction to the anchored state" link in ADR-0012's own chain table.
- **Y3's rejected-direction guard, live** (`verifier/main.py`'s `anchor_precedes_record` check and its `@requires_stack` test) — read and reasoned about, not executed. See Y3's evidence for exactly what is and is not established by reading alone.
- **Y5's composed-forgery attack, completed end to end** — the `verify_external_anchor`-layer half was executed; the `store.VerifyDualProof`-layer half (the actual defense, per ADR-0012's own chain table) needs `immudb-py` and was not executed. Neither confirmed nor refuted; see Y5's evidence for the structural reasoning available without execution.
- **Y6, exhaustive fail-open sweep.** Only `run_forever()`'s outer loop (the one D23 names) and two of ~23 other `except Exception` handlers project-wide were checked. A third, undisclosed fail-open path elsewhere in the ~5300 lines of `control_plane/main.py`/`decision_service/main.py`/`verifier/main.py`/`ledger/immudb_ledger.py` cannot be ruled out by this session's sampling.
- **Y7, whether `sigstore-python`'s real `TransparencyLogEntry._verify` has an X3-shaped skip of its own** (e.g. treating a missing `inclusionProof` as "nothing to check" rather than a failure). Probed against this session's own hand-rolled reimplementation only (which fails closed on a missing `inclusionProof`/`checkpoint`/empty audit path in every case tried) — this says something about the *shape* of the check, not about `sigstore-python`'s actual, unavailable implementation.
- **Y8, U7, V1-V4, V7-V8, W1-W2, W4-W5, W7-W8** — the remaining prior-report attacks not covered under "STILL HOLDS" above, all needing a live stack, live Docker networking, or dashboard files this session's background agent did not have loaded. See the agent's Task 1 summary (evidence §Y8) for the specific list.
- **Whether a working, end-to-end malicious bundle could be constructed for Y3/Y5's composed attack by an actor with direct gRPC/`RootService`-seam access** (as opposed to only bundle-file or read-credential access) — this session's analysis (Y5's evidence) argues the header-self-consistency requirement inside `store.VerifyDualProof` blocks it even then, but this is inference from `docs/reports/spike-consistency-proof.md`'s quoted source, not something demonstrated against a live server.

---

## 6. Findings outside Y1-Y8

1. **ECDSA signature malleability is accepted by the writer-signature check (Y1 §6).** `(r, s)` and `(r, n−s)` both verify for the same message under the real `ecdsa` library's standard (non-low-S) verification. This is a property of standard ECDSA verification generally (shared by `ecdsa`, `cryptography`, and most other libraries absent explicit low-S enforcement), not specific to this project's code, and does not let an attacker assert anything the signer did not — the message and attributed writer are unchanged. Noted because it was executed and found, not because it refutes anything.
2. **The writer-key deny-list's fingerprint matching is exact-string, with no case or whitespace normalization (Y2).** A deny-list entry that differs from the real fingerprint only by case or trailing whitespace silently fails to revoke — the record is not attacker-influenced (the fingerprint is fixed inside the writer signature), so this is an operator-transcription risk rather than a bundle-content attack, but it is real, executed, and undisclosed: `test_the_deny_list_is_refused_rather_than_skipped_when_malformed` (`tests/test_writer_signing.py`, referenced in `docs/reports/phase-3b.md:168-169`) covers a *structurally* malformed row (missing `fingerprint` key); it does not cover a syntactically well-formed but mismatched-by-case-or-whitespace fingerprint, which is a materially different failure mode with the same practical effect (the key is not actually revoked) and no test asserting against it either way.
3. **The offline checker has no independent copy of the online `anchor_precedes_record` guard (Y3).** `tools/ail_verify_bundle.py` was grepped for `precedes`, `anchor.txId >`/`anchor.txId <`, `resp.id`, and `result.id` in a comparison context; none exist. The online endpoint's own design (returning no proof material on this specific refusal, per `test_an_anchor_older_than_the_record_is_refused_by_name`'s own assertion) appears to close the practical exploitation path for anyone using the intended API, and this session's structural analysis of `store.VerifyDualProof`'s header-self-consistency requirement suggests the same class of attack fails independently at that layer even for an actor who somehow obtained a mismatched `(source_state, verifiable_entry)` pair — but neither of those two independent defenses was executed in this environment, and the offline checker's own lack of a redundant, defense-in-depth guard here is real, undisclosed, and asymmetric with the online path.
4. **The `hashlib` allowlist in `test_the_checker_implements_no_cryptography_of_its_own` is scoped by function name only (Y7 §6).** Demonstrated by execution: a second, unrelated `hashlib.sha256()` call added inside `key_fingerprint`'s existing body (an already-allowed function) is invisible to the meta-test's `ast`-based walk, which records only the *set* of function names using `hashlib`, never how many times or on what input. This is a real, executed, previously-undisclosed limitation of the meta-test's granularity — the allowlist bounds *which functions* may use `hashlib`, not *what those functions compute* with it.
5. **`readME.md` §5 does not contain the `external_anchor.state` downgrade disclosure the build report's own claim-mapping table cites it for (Y5/Y8).** The build report states plainly, twice, that this limitation "is in Residual Limits" and cites `readME.md §5` in its mapping table; `readME.md §5` was read in full and contains no such entry. A reader of the operator-facing documentation alone — as opposed to the internal phase report — would not learn that a genuinely anchored bundle can be silently downgraded to look unanchored.
6. **`POST /anchors`/`GET /anchors/latest`'s credential split — a new, tested, security-relevant claim — has no row in the claim-mapping table (Y8).** See Y8's evidence for the full citation trail.
