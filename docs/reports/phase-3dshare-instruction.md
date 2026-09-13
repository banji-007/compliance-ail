# Phase 3d-share: The front door

**Run id:** `p3dshare`. State run id, working directory, branch first. Not the primary working directory. Explicit Compose project name on every invocation. Remove your scratch directory before reporting and say what you removed or could not remove.

**Base:** `main` at its current head. Branch `p3dshare`, PR against `main`. This is the first phase after the 3c merge; the branch discipline is unchanged.

**Session closure:** this session is not closed until its report is committed and pushed.

**Session prerequisites, provisioned before the session starts.** Both were verified as hard dependencies against `main` at `86f32dc` and neither is optional given P3dshare-3:

- **A funded OpenAI API key.** `readME.md`'s own Prerequisites list names one, and sections 4.4 and 4.5 drive a live LangGraph agent whose verdicts P3dshare-3 requires reproducing. Without it the most visible item in this phase stalls.
- **Docker Desktop with 8 GB available**, per the same list. `docker-compose.yml` defines eighteen services; a cold build from a clean clone plus stack-up plus the demo plus bundle generation is a long session. Plan for it rather than splitting a transcript awkwardly in the middle.

## Objective

A stranger who lands on this repository can, within one reading of the README: understand what the system claims and does not claim, verify one claim without running anything, and bring the stack up from a clean clone by following the quickstart exactly. This phase gates the first public share.

## What this phase is not

No production code changes. No new mechanism, no new tests beyond what the walkthrough itself requires, no refactors passed off as documentation. The system's behaviour on close is byte-identical to `main` at base, with one narrow exception defined in P3dshare-4 (a walkthrough script, additive only). If a documentation claim turns out to be unwritable honestly because the code does not support it, that is an escalation, not a licence to change the code.

The roadmap's original 3d (policy as WASM, periodic anchoring, Docker-free Observed) is deferred to post-share phases with their own adversarial passes. P3dshare-5 records that reorder.

## Standing rules

Escalate rather than substitute. No em dashes. Claim edits get old text, new text, and reason, per site, in the report. Every command this phase publishes must have been run, from a clean clone, in this session, with its output captured in the report. A published command that was reasoned about rather than run is the failure mode this project's docs rules exist to prevent.

---

## Items

### P3dshare-1. The README leads with the claim

The closing paragraph of `docs/reports/phase-3c3h.md` ("What the system claims, in full, at the end of phase 3c") becomes the spine of the README's opening. Not pasted verbatim into marketing position, but restructured so the first screen of the README states: what is enforced, what is fail-closed, what the ledger's account of itself now guarantees, and, at the same resolution, what is not claimed. The existing Residual Limits section remains the detail; the opening must be consistent with it.

The current README opening (the system-prompt-is-not-a-boundary argument) stays, condensed if needed; it is the motivation, and it reads well. What moves up is the honest-claim statement, which currently lives at the bottom of a phase report nobody landing on the repo will find.

**Check against:** every sentence in the new opening traceable to a test, a command, or a Residual Limits entry, per the project's own rule. The report maps each sentence.

### P3dshare-2. Verify-without-running is the front door

The evidence bundle and offline verification (D18 through D21, the 3a spike, the `immuclient` reproduction path) are the share's core artifact: a stranger verifies a claim without running anything. Today that capability is documented across ADRs and phase reports.

Write the walkthrough: from a published example bundle (committed to the repo as a fixture, generated in this session from a real stack), a stranger with Python and no Docker verifies the bundle's proofs offline, and the walkthrough states exactly what that verification establishes and what it does not (tamper-evidence of the record, not truth of the policy decision; the bundle does not carry fault records, per the recorded limit).

**Resolve first, by measurement, before writing any of the walkthrough text: is the published fixture anchored or unanchored.** The two are materially different artifacts and the item does not decide it, deliberately. What is already established, from `tools/ail_verify_bundle.py` at `86f32dc` and `readME.md` section 3.4.1:

- The sigstore import is **local to the anchor check**, inside a `try`, and a missing sigstore raises `BundleCheckFailed(ANCHOR_UNCHECKED, ...)` rather than failing the bundle. So an unanchored bundle verifies with no sigstore at all, and the README already states the split correctly: "the base check needs nothing but `immudb-py==1.5.0`; a bundle that claims corroboration additionally needs `sigstore==4.5.0`".
- An **unanchored** fixture is runnable on this host and demonstrates the weaker artifact: inclusion and consistency proofs plus the writer signature, with the anchor section saying it is not anchored.
- An **anchored** fixture is the stronger demonstration and needs sigstore, which per the recorded environment facts cannot be installed into this host's Python: it upgrades `cryptography` past `spiffe==0.2.5`'s pin, and its TUF client calls `os.symlink`, which Windows refuses without elevation. Publishing that path therefore means running it inside a Linux container, which collides with this item's own "no Docker" framing for the transcript.

Whichever is chosen, the walkthrough text must say which one the fixture is and what the reader's own run will print, including `ANCHOR_UNCHECKED` if that is what they will see. A walkthrough whose transcript and whose reader diverge on that line is the failure mode this item exists to prevent.

**Check against:** run the walkthrough yourself, from a clean directory, following only the published text. Capture the transcript. If any step requires knowledge not in the text, the text is wrong.

### P3dshare-3. The quickstart is true

Run the README quickstart exactly as written, from a clean clone, on this machine. Every command, every expected output, the 60-second health-check claim, the 16-service count, the demo prompts and their expected verdicts. Correct what has drifted; seven sub-phases changed the system under these instructions and nobody has re-run them end to end since.

Known drift to check explicitly, each verified as a live question against `main` at `86f32dc` rather than assumed:

- **The service count.** `readME.md` section 7 says "Docker Compose | v2 (16 services)". `docker-compose.yml` defines eighteen. The README's number is the claim; eighteen is what is there.
- **The `/audit` response shapes quoted anywhere in docs.** D49 (the 3c completion pass) changed what `committed` reports on three branches, so any quoted response body is a candidate.
- **The tenant-isolation demo, section 4.5, and be specific about which half.** The 2026-08-16 audit live-verified two defects. The first, that setting `AIL_TENANT_ID` on the agent container leaves OPA serving the old bundle, has since been addressed in the text: 4.5 now recreates the `opa` container itself. The second has **not** been re-verified and is the one to drive: the README's verbatim Step 2 prompt never reached OPA at all, because Pydantic rejected it first (`cost_per_hour` defaults to 0.0 and the field requires `gt=0`), so the demo's denial came from the wrong stage of the pipeline. Drive the published prompt and record which stage refuses it.
- **The keys prerequisite, which is two separate traps and not one.** Keys must exist before anything passes, and `tests/test_route_parity.py` reads `1 failed` without them for environmental reasons; that one is recorded for sessions and a stranger hits it with no memory to warn them. Separately, **`make` is not on PATH on this machine** (verified again this session), and the README publishes `make keygen` and, in section 8, `make test-integration`. The standing rule that every published command must have been run in-session collides with that directly: either install make, or replicate the target's steps and say in the report that the published form was not the form run, or give the README a make-free path. A stranger on Windows hits the same wall, which makes this a P3dshare-3 fix candidate and not merely a session inconvenience.

**Check against:** the captured transcript, in the report. Any step that failed and was fixed gets its before and after.

### P3dshare-4. The walkthrough script (the one additive exception)

If P3dshare-2's walkthrough needs a driver (a `verify_bundle.py` invocation wrapper or similar) to be runnable by a stranger, it is additive, lives under `tools/`, imports the existing verification code rather than reimplementing any of it, and gets one test asserting it agrees with the library it wraps. No proof logic is written in this phase.

If the existing tooling already suffices, this item is a no-op and the report says so.

### P3dshare-5. The roadmap reflects the reorder

`docs/plan/ail-roadmap.md`: 3d is split. 3d-share (this phase) gates the share. WASM policy, periodic anchoring, and Docker-free Observed move to post-share phases, each requiring its own adversarial pass, with the WASM landmine (`data.system.bundles` undefined under WASM denies everything, per the spike) carried as the first named risk of that phase. Trajectory policy remains the post-share contribution. The reorder's reason is recorded: the share's definition of done is verify-without-running plus claims-match-reality, both of which exist; footprint is adoption, not truth.

`TODO.md` gains nothing from this phase unless an item above surfaces something; carried findings stay where 3c-3h put them.

### P3dshare-6. The share text

Draft the share itself: a short post (the project's first public statement) whose claims are a strict subset of the README's. It links the walkthrough as the do-this-first, states the residual limits in one honest paragraph rather than hiding them, and does not use the words "secure", "guaranteed", or "prevents prompt injection" anywhere. "Structurally constrained" is the ceiling, per the repo's own threat model.

The draft goes in the report for the operator's review, not into the repo; publishing is the operator's act, not this session's.

---

## Pre-registered negatives

- Any production behaviour change outside P3dshare-4's additive script.
- Any published command not run in this session from a clean clone.
- Any README sentence not traceable to a test, a command, or a Residual Limits entry.
- Any claim in the share draft stronger than the README's.
- Any walkthrough step requiring knowledge not in the walkthrough.

## Report

`phase-3dshare.md`, under `docs/reports/`. **The filename is written bare here deliberately.** `tests/test_docs_references_resolve.py` requires every literal `docs/` path in a committed file to resolve in that same commit, and this instruction is committed before the report it commissions exists. Do not helpfully restore the prefix; it turns CI red on a docs-only commit. The same rule applies to any other document this phase commissions before writing.

Per item: verdict, transcript or diff, and for claim edits the old and new text. The quickstart and walkthrough transcripts in full. The share draft. CI run id.

Close with the answer to one question, honestly: is there anything a stranger will hit in their first hour that this phase knew about and did not fix or state? If yes, it is either fixed, stated in the README, or this phase is not done.

**Two things already known to be in that first hour**, named here so they are answered rather than rediscovered:

- **Section 8 is part of the first-hour surface.** It publishes `make test-integration`, which is the most likely thing a stranger runs after the quickstart. On a non-Linux host the local full-suite profile is not the CI profile, for reasons already recorded and not about the code. Whatever the answer is, it is a "state it in the README" candidate rather than a fix, since fixing it is out of scope here.
- **The README carries deliberate prompt-injection strings** as threat-model fixtures. They are correct to be there. Check that a first-time reader meets them already framed as fixtures, because a stranger who meets them unframed reads them as something else.

---

## Corrections applied before handover

Raised against the instruction as drafted, verified against `main` at `86f32dc`, and applied here rather than left for the executing session to discover.

1. **The Report section violated the convention it states.** It named the report with its `docs/reports/` prefix attached, in a forward reference to a file that does not exist yet. That is precisely what `tests/test_docs_references_resolve.py` fails on, so the commit carrying this instruction would have gone red on its own rule. Written bare now. The prefixed form is deliberately not reproduced anywhere in this file, including in this sentence describing it, because the test reads literal paths and does not care that the surrounding prose is explaining the mistake.
2. **Two session prerequisites were unstated and are hard**, a funded OpenAI API key and 8 GB of Docker headroom. Both come from the README's own Prerequisites list and both are load-bearing for P3dshare-3.
3. **P3dshare-2 did not decide anchored versus unanchored**, and the two differ in dependency footprint, in what the walkthrough establishes, and in whether the session can run the published path on this host at all. Resolved-by-measurement-first, with the established facts recorded so the session does not re-derive them.
4. **The section 4.5 note was too broad.** Half of the 2026-08-16 finding has since been fixed in the text; the other half, the Pydantic rejection of the published Step 2 prompt, has not been re-verified and is the specific thing to drive.
5. **The keys prerequisite was one bullet covering two unrelated traps**, only one of which a stranger meets. The `make` half also collides with this phase's own standing rule about published commands.
6. **The closing question's surface was left implicit.** Section 8 and the injection fixtures are both known first-hour encounters and are named so the answer covers them.

One thing checked and found **not** to need correction: the "16-service count" reads as a quote of the README, and the README does say sixteen at section 7. The instruction was right to name it; the drift is real and it is eighteen.

One earlier finding checked and found **stale**: the 2026-08-16 audit recorded three silently dead test files (`tests/test_agent.py`, `tests/test_interceptor.py`, `tests/test_ledger.py`, uncollectable because their classes define `__init__`). None of the three exists at `86f32dc`. No action.
