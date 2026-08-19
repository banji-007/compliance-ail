# p13-merge

## 0. Run id, working directory, branch

- **Run id:** `p13-merge`
- **Working directory:** `C:\Users\banji\AppData\Local\Temp\claude\c--Users-banji-OneDrive-Documents-compliance-ail\28510ff8-b262-4fd8-a9b6-e42886db2535\scratchpad\phase-1-3-complete` (a git worktree, not the primary working directory, per this instruction's explicit requirement)
- **Branch:** `phase-1-3-complete`
- **Start SHA:** `ae5840bafc46559c27d91b7bae744930ef6a7cf6`

---

## 1. Verdict table

| Item | Verdict |
| :--- | :--- |
| 1. Fix ADR-0002's stale `/audit` response-shape description; add to mapping table | **Done** |
| 2. Move `/audit` O(n) verification cost into a named Phase 3 TODO item | **Done** |
| 3. `pytest tests/` green; push; CI green on PR #5 | **Done** |
| 4. Merge PR #5 into `phase-1-1-remediation` | **Done** |
| 5. Merge PR #2 into `main` with a merge commit, enumerated message | **Done** |
| 6. Confirm CI green on `main`; report run id | **Done** |
| 7. Per-branch diff check and conditional delete (4 branches) | **Done - 2 of 4 branches did not exist to check** |

---

## 2. Item 1 - ADR-0002's stale `/audit` response-shape description

**Before:** ADR-0002's Decision section described `/audit` as returning `verified: true|false` and a `state_id`. This predates the five-state `verification` object (`verified | failed | unverifiable | asserted | not_found`), `payload_state`, and `profile` fields that `control_plane/main.py::get_audit` has actually returned since Phase 1.1/1.2/1.3. The Constraints section made the same stale claim about the verifier-unreachable fallback (`verified: false` instead of the real `unverifiable`/`asserted` split). This gap was found and explicitly disclosed as out-of-scope in `docs/reports/phase-1-3-complete.md` section 13 - this pass closes it.

**Fix:** rewrote both paragraphs to match `get_audit`'s current docstring and return shape exactly, including the `record_type` tombstone-exclusion mechanism (a separate scan over `content_erasure:` keys keeps tombstones out of the decision entries, rather than `record_type` being a field on the response itself).

**Evidence:**

```
$ git diff -- docs/adr/0002-fastapi-immudb-proxy.md
--- a/docs/adr/0002-fastapi-immudb-proxy.md
+++ b/docs/adr/0002-fastapi-immudb-proxy.md
@@ -14,7 +14,7 @@ The FastAPI control plane exposes `GET /audit`, which:
 1. Scans ImmuDB via its REST API for `tool_call:` key listing (a plain scan needs no SDK-level proof).
 2. For each entry found, calls the verifier service's `POST /verify` (which performs `verifiedGet` - see ADR-0001) to get a real, per-entry proof result.
-3. Returns each entry with `verified: true|false` and the `state_id` it was checked against, ...
+3. Returns each entry with a `verification` object (`state`, `state_id`, `detail`, `error_class`); `state` is one of five values - `verified`, `failed`, `unverifiable`, `asserted`, `not_found` ... Each entry also carries `payload_state` (...) and `profile` ... A separate scan over `content_erasure:` keys identifies tombstones by `record_type` and keeps them structurally out of the decision entries returned here (D11).
@@ -28,7 +28,7 @@ CORS is restricted to `http://localhost:3001` ...
-- If the verifier becomes unreachable partway through a scan, the endpoint stops calling it for the remainder of that scan and defaults the remaining entries to `verified: false` ...
+- If the verifier becomes unreachable partway through a scan, the entry where the failure was observed gets `verification.state: "unverifiable"`; the endpoint then stops calling the verifier for the remainder of that scan, and every entry after that gets `verification.state: "asserted"` ...
```

Confirmed against the live implementation, `control_plane/main.py` lines 543-590 (docstring) and 655-736 (the actual `entries.append({...})` and verifier-unreachable branch) - the ADR text now matches the code verbatim on field names and the five-state set.

**Mapping table:** `docs/reports/phase-1-3-complete.md` row for `docs/adr/0002-fastapi-immudb-proxy.md, Decision/Consequences` updated from "found, not fixed" to "Corrected in `p13-merge` (item 1)", citing this report. Section 13 ("Could not verify") entry for the same gap struck through and marked resolved, citing this report.

---

## 3. Item 2 - `/audit` O(n) verification cost as a named Phase 3 item

**Before:** the O(n) per-entry verifier round trip on `/audit` was noted only in ADR-0001 and ADR-0002 prose ("consider lazy verification... if audit pages grow large") and in three separate red-team reports (`phase-1-1-redteam.md` finding #3, `phase-1-2.md`, `phase-1-3-redteam.md`) as a recurring, disclosed-but-untracked observation. It was not itemized in `TODO.md` at all under any name.

**Fix:** added a one-line, no-design item to `TODO.md`'s "Structural Expansions (v1.1.0+)" section:

```
$ git diff -- TODO.md
--- a/TODO.md
+++ b/TODO.md
@@ -49,6 +49,9 @@ ## Structural Expansions (v1.1.0+)
+### Phase 3: `/audit` O(n) Verification Cost
+Per-entry synchronous verifier round trip on `GET /audit` is O(n) against ledger size; confirmed to time out tests at ~200 ledger entries (`docs/reports/phase-1-3-redteam.md`).
```

No scope beyond the one line was added - no new **Scope:** subsection, no design proposal, matching the instruction's "one line, no design."

---

## 4. Item 3 - full suite green, push, CI green on PR #5

**First full-suite run** (before the item 1/2 commit, against `docker-compose.test.yml` under a non-default Compose project name `phase13merge`): 3 failures. Investigated: 2 of the 3 (`test_content_states.py::test_direct_sqlite_delete_produces_lost_not_erased`, `::test_erasure_refused_when_tombstone_write_fails`) were an artifact of my own setup, not a real regression - those tests shell out to `docker compose -f docker-compose.test.yml stop/start verifier` with no `-p` flag, matching the Makefile's own convention of relying on the directory-derived default project name. Because I had started the stack under an explicit `-p phase13merge`, the tests' own compose calls targeted a different (non-existent) default-named project and failed to find containers to stop/start. This is disclosed rather than silently redone, per the project's own "disclose false positives" convention (`docs/reports/phase-1-3-complete.md` section on the host.docker.internal false positive).

**Re-run**, stack brought up with no `-p` flag (default project `phase-1-3-complete`, matching the Makefile exactly):

```
$ docker compose -f docker-compose.test.yml up -d --build --wait
... all 5 services Healthy, project "phase-1-3-complete"
$ python -m pytest tests/ -v
... 107 passed, 1 failed in 716.92s (0:11:56)
FAILED tests/test_docs_references_resolve.py::test_every_referenced_docs_path_exists_in_this_commit
  docs/reports/p13-merge.md referenced by ['docs/reports/phase-1-3-complete.md', 'docs/reports/phase-1-3-complete.md']
```

The single failure is the dangling-reference guard (`cleanup-p13-b`'s test) correctly catching that this report was not yet committed at scan time - the same expected, working-as-designed failure the prior pass hit and resolved by committing. Resolved by this commit, which adds `docs/reports/p13-merge.md` itself.

**Push and CI:**

```
$ git push origin phase-1-3-complete
   ae5840b..e09f6c2  phase-1-3-complete -> phase-1-3-complete
$ gh run list --branch phase-1-3-complete --limit 5 --json databaseId,status,conclusion,headSha,event,createdAt
[{"conclusion":"success","createdAt":"2026-08-19T16:40:46Z","databaseId":32277277818,"event":"pull_request","headSha":"e09f6c279f688b35d13b65db6cdf3a2bff5db520","status":"completed"}, ...]
$ gh run view 32277277818 --json databaseId,headSha,status,conclusion,workflowName,url
{"conclusion":"success","databaseId":32277277818,"headSha":"e09f6c279f688b35d13b65db6cdf3a2bff5db520","status":"completed","workflowName":"Integration Tests","url":"https://github.com/banji-007/compliance-ail/actions/runs/32277277818"}
```

CI run id: **32277277818**, conclusion: **success**. Head SHA `e09f6c2` (includes items 1-2 of this pass).

---

## 5. Item 4 - merge PR #5 into `phase-1-1-remediation`

With CI confirmed green on the PR's head SHA (section 4), merged as a merge commit (not squash, not rebase - the default `--merge` strategy, preserving each of the two commits on `phase-1-3-complete` individually):

```
$ gh pr merge 5 --merge --subject "Merge pull request #5 from phase-1-3-complete" --body "..."
$ gh pr view 5 --json state,mergedAt,mergeCommit
{"mergeCommit":{"oid":"dcb2f78f2699b4743b5a3e5e0185ae883930bd83"},"mergedAt":"2026-08-19T16:54:01Z","state":"MERGED"}
```

`phase-1-1-remediation` now includes `phase-1-3-complete`'s full history (`ce38cd0`, `ae5840b`, `3b535ea`, `e09f6c2`) via merge commit `dcb2f78`.

---

## 6. Item 5 - merge PR #2 into `main` with a merge commit

Merged with `--merge` (a real merge commit, not a squash), message enumerating the phases it contains, exactly as instructed:

```
$ gh pr merge 2 --merge --subject "Merge pull request #2 from phase-1-1-remediation" --body "Phase 1 record truth, Phase 1.1 remediation, Phase 1.2 record integrity,
Phase 1.3 claims true, plus the WASM parity and MCP mediation spikes."
$ gh pr view 2 --json state,mergedAt,mergeCommit
{"mergeCommit":{"oid":"4fc80428544d5c995885fc0e94e655dee1b58027"},"mergedAt":"2026-08-19T16:54:56Z","state":"MERGED"}
```

`main` now includes the full chain: Phase 0/0.1 truth pass, Phase 1 record truth, Phase 1.1 remediation, Phase 1.2 record integrity, Phase 1.3 claims true (and this pass's items 1-2), plus the WASM parity spike (`18620ec`) and MCP mediation spike (`bc1f1ff`), via merge commit `4fc8042`.

---

## 7. Item 6 - CI green on `main`

The merge to `main` triggered two runs: the repo's own `ci.yml` ("Integration Tests", a `push` event) and GitHub's own auto-generated "Dependency Graph" workflow (a `dynamic` event, unrelated to this repo's test gate - not part of `.github/workflows/`, which contains only `ci.yml`). Watched the relevant one to completion:

```
$ gh run list --branch main --limit 5 --json databaseId,status,conclusion,headSha,event,createdAt
[{"conclusion":"","createdAt":"...","databaseId":32278639605,"event":"dynamic", ...},
 {"conclusion":"","createdAt":"...","databaseId":32278635309,"event":"push","headSha":"4fc80428544d5c995885fc0e94e655dee1b58027","status":"in_progress"}, ...]
$ gh run view 32278639605 --json workflowName,event,url
{"event":"dynamic","workflowName":"Dependency Graph", ...}
$ gh run watch 32278635309 --exit-status
... (exit 0)
$ gh run view 32278635309 --json databaseId,headSha,status,conclusion,workflowName,url
{"conclusion":"success","databaseId":32278635309,"headSha":"4fc80428544d5c995885fc0e94e655dee1b58027","status":"completed","workflowName":"Integration Tests","url":"https://github.com/banji-007/compliance-ail/actions/runs/32278635309"}
```

**CI run id on `main`: 32278635309, conclusion: success.**

Confirmed the checked commit includes this pass's item 1-2 fixes: `e09f6c2` (phase-1-3-complete's final commit) is an ancestor of `4fc8042` (`git merge-base --is-ancestor e09f6c2 origin/main` exited 0).

---

## 8. Item 7 - per-branch diff check and conditional delete

For each named branch, `git log --oneline main..<branch>` after PR #2 merges. Delete (remote and local) only if that command outputs nothing; if it outputs anything, stop and report rather than delete.

**`phase-1-3-complete`:**

```
$ git log --oneline origin/main..origin/phase-1-3-complete
(no output)
```

Empty. Deleted:

```
$ git worktree remove <this run's worktree path>
$ git branch -d phase-1-3-complete
Deleted branch phase-1-3-complete (was e09f6c2).
$ git push origin --delete phase-1-3-complete
 - [deleted]         phase-1-3-complete
```

**`phase-1-1-remediation`:**

```
$ git log --oneline origin/main..origin/phase-1-1-remediation
(no output)
```

Empty. Deleted:

```
$ git checkout main   # freed the primary directory's checkout of this branch
$ git branch -d phase-1-1-remediation
Deleted branch phase-1-1-remediation (was 0cf0f92).
$ git push origin --delete phase-1-1-remediation
 - [deleted]         phase-1-1-remediation
```

**`phase-0-truth-pass`:**

```
$ git log --oneline origin/main..origin/phase-0-truth-pass
fatal: ambiguous argument 'origin/main..origin/phase-0-truth-pass': unknown revision or path not in the working tree.
```

Does not exist, locally or on the remote (`git ls-remote --heads origin` before any deletion in this pass showed only `main`, `phase-1-1-remediation`, `phase-1-3-complete`). Not deleted because there was nothing to delete - reported per the instruction rather than silently skipped. Likely already deleted in an earlier session: its "Phase 0 truth pass" commit (`65dd365`'s message references it) is already on `main` directly, consistent with the branch having been merged and removed before this run started.

**`phase-1-record-truth`:**

```
$ git log --oneline origin/main..origin/phase-1-record-truth
fatal: ambiguous argument 'origin/main..origin/phase-1-record-truth': unknown revision or path not in the working tree.
```

Same as above: does not exist locally or on the remote. Not deleted, reported rather than skipped silently.

**Final state:**

```
$ git ls-remote --heads origin
4fc80428544d5c995885fc0e94e655dee1b58027	refs/heads/main
$ git branch -a
* main
  remotes/origin/HEAD -> origin/main
  remotes/origin/main
```

Only `main` remains, remote and local.

---

## 9. Could not verify

- Whether any local clone other than this run's own primary directory and worktree still holds a copy of `phase-1-3-complete` or `phase-1-1-remediation` - only this machine's state and the `origin` remote were checked.
- The exact reason `phase-0-truth-pass` and `phase-1-record-truth` no longer exist (already deleted in an earlier session vs. never pushed as a named branch) - inferred from `65dd365`'s commit message and `main`'s own history containing that work directly, not confirmed against reflog or any external record of a prior deletion.
- `git worktree remove` for this run's own worktree returned `error: failed to delete '.git/worktrees/phase-1-3-complete': Permission denied` on the first attempt; `git worktree list` immediately after showed the worktree gone regardless (the working-directory removal succeeded, only a metadata-directory cleanup step errored, likely a transient file handle on Windows). Not re-verified beyond confirming `git worktree list` no longer shows it and the local branch delete (which requires the worktree to be gone) succeeded cleanly.
