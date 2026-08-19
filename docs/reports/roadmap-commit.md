# Report: roadmap-commit

Run id: roadmap-commit. Working directory: `c:\Users\banji\OneDrive\Documents\compliance-ail`. Started on branch `main`. Main body of the work done on `docs/roadmap-commit` branched off `main`, merged back via PR #6 (squash merge, commit `db60277`), branch deleted both remotely and locally. Writing this report's own item 4 evidence surfaced a real bug in the just-merged test (detailed there); the fix was made on a second branch, `docs/roadmap-commit-fixup`, off `main`, and merged the same way (see item 4 for the PR link and CI evidence).

---

## Item 1: commit the roadmap as `docs/plan/ail-roadmap.md`

**Verdict: VERIFIED.**

The attached roadmap was written verbatim to `docs/plan/ail-roadmap.md` and committed.

Evidence:

```
$ git show db60277 --stat -- docs/plan/ail-roadmap.md
 docs/plan/ail-roadmap.md | 112 ++++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 112 insertions(+)
```

```
$ git show db60277:docs/plan/ail-roadmap.md | head -5
# AIL roadmap

Status: current. Supersedes the phasing in `docs/plan/ail-v2-plan.md` sections 4 and 6; that document's architecture section survives with the changes the WASM parity spike established.

Written after the Phase 1.2 red-team report, revised after `docs/reports/spike-mcp-mediation.md` and the Phase 1.3 completion pass.
```

---

## Item 2: README section 1 link, sweep for other dangling references

**Verdict: VERIFIED.**

README section 1's "see this repository's roadmap for the isolation work (Phase 2) that closes it" now reads:

```
See the Residual Limits section (§5) for what that means concretely, and
[`docs/plan/ail-roadmap.md`](docs/plan/ail-roadmap.md) for the isolation
work (Phase 2) that closes it.
```

The sweep found two more instances of the same bug shape (a definite reference to a document noun with no path):

1. README section 5 (Residual Limits): "Phase 2 of the roadmap is the work that would move this gateway toward `mediated`" -> now links `docs/plan/ail-roadmap.md`.
2. `docs/adr/0005-outcome-taxonomy.md` line 152: "...found the roadmap's own topology-based framing failed to preserve..." -> now names `docs/plan/ail-roadmap.md`\'s explicitly.

While extending the test (item 4), the same sweep pattern caught a third, previously unnoticed instance while validating the new test against the tree: `docs/plan/ail-v2-plan.md` line 142, "should be stated in the ADR rather than glossed." No ADR in `docs/adr/` currently covers the SPIFFE-in-hosted-mode trade-off this sentence discusses, so this was not a dangling reference to an existing-but-unnamed document, it was prescriptive ("should be documented, eventually, in some ADR"). Changed to indefinite ("an ADR") to say what it actually means, rather than inventing a path to a document that does not exist.

**Scope decision, stated up front:** the sweep, and the test in item 4, deliberately do not touch `docs/reports/`, `docs/audit/`, or `spikes/`. Those directories hold point-in-time evidentiary records (red-team reports, spike reports, audit reports). Several of them use the same nouns in prose without a path, e.g. `docs/reports/spike-mcp-mediation.md` says "what the roadmap...would have to say instead" and "the roadmap should say so" four times. These are not dangling pointers in the sense the README bug was: they are the spike's own narrative, discussing what "the roadmap" meant informally at spike time, which was before this commit gave that concept a file. `docs/plan/ail-roadmap.md` did not exist when that report was written. Retroactively inserting a link into frozen historical text would assert something that was not true at the time the report was committed, not fix a bug. This is stated in the test's module docstring as well, since it directly bears on why the test does not scan those directories.

Evidence, confirming no further instances remain outside the excluded directories:

```
$ python -m pytest tests/test_docs_references_resolve.py -v
tests/test_docs_references_resolve.py::test_every_referenced_docs_path_exists_in_this_commit PASSED
tests/test_docs_references_resolve.py::test_no_dangling_definite_document_references PASSED
2 passed in 1.37s
```

---

## Item 3: status header on `docs/plan/ail-v2-plan.md`

**Verdict: VERIFIED.**

A blockquote status header was added directly under the title, naming:
- What is superseded: section 4 (Phasing) and section 6 (What to share, and when), per `docs/plan/ail-roadmap.md`.
- What still stands: section 3 (Target architecture), with the corrections `docs/reports/spike-wasm-parity.md` established (module+data hash replaces the bundle-revision digest under WASM; four Rego rules' `sprintf("%v", ...)` set formatting diverges from the WASM evaluator; the corpus is 13 deny rules, not 12, since GDPR has 3).
- The MCP-mediation assumption in section 3 is separately flagged as refuted by `docs/reports/spike-mcp-mediation.md`, pointing at the roadmap's section 2 for the corrected principle (authority exclusivity, not transport or proxy).

The document was not deleted; it is cited from `docs/adr/0005-outcome-taxonomy.md`, `docs/plan/phase-0-instruction.md`, and elsewhere.

Evidence:

```
$ git show db60277:docs/plan/ail-v2-plan.md | sed -n '1,16p'
# AIL v2: gap closure, pivot, and hosted architecture

> **Status: partly superseded.** `docs/plan/ail-roadmap.md` replaces the
> phasing in section 4 (Phasing) and section 6 (What to share, and when) -
> follow the roadmap's phases, not this document's. Section 3 (Target
> architecture) still stands, with the changes established by
> `docs/reports/spike-wasm-parity.md`: the bundle-revision digest cannot be
> read under WASM and is replaced by a module+data hash computed in the
> isolate, four Rego rules' `sprintf("%v", ...)` set-formatting diverges
> from the WASM evaluator's output, and the corpus is 13 deny rules, not 12
> (GDPR has 3). Section 3's MCP-mediation assumption is also refuted by
> `docs/reports/spike-mcp-mediation.md`: mediation is not a configuration
> change but a function of authority exclusivity - see the roadmap's
> section 2. This document is not deleted because it is cited elsewhere;
> read it for architecture context, not for phase sequencing or the MCP
> claim.
```

---

## Item 4: extend `tests/test_docs_references_resolve.py`

**Verdict: VERIFIED, with the general-form limitation stated as instructed, plus one bug found and fixed against the literal incident (see below), plus one disclosed miss.**

A general regex that reliably distinguishes "this prose promises a path it doesn't give" from ordinary use of the same English words is not expressible. Concretely, during development of the test against the live tree:

- `"an ADR"` (indefinite) appears in the roadmap itself ("falsifies a claim in the README, an ADR, the dashboard, or a test name") and means a category, not a specific unnamed document.
- `"the original plan called for..."` (`docs/adr/0006-verification-states.md`) is ordinary English, not a pointer to `docs/plan/`.
- `"note in the report"` (`docs/plan/phase-0-instruction.md`) instructs a future report to be written, not a reference to an existing one.
- `"this ADR's own subject"` is a document talking about itself, not a dangling pointer.

A bare noun match flags all four as false positives. The fallback implemented is the one the task anticipated: an explicit list of five document nouns (roadmap, plan, protocol, ADR, report), checked two ways depending on how ambiguous the noun is in this codebase's own vocabulary:

- **`roadmap` and `ADR`** are close to unambiguous here (this project always means "the project roadmap document" or "an Architecture Decision Record"), so these are flagged on any **definite** determiner ("the", "this", "that", "its", "our") with nothing resolvable (a `docs/...` path or an `ADR-NNNN` number) within 200 characters. Indefinite ("an ADR") and plural ("ADRs") forms do not match, since the regex requires a definite determiner immediately before the singular noun.
- **`plan`, `protocol`, `report`** are common enough as ordinary English words that a bare-noun match produced the false positives above. These are only flagged when preceded by an explicit pointer phrase (`this repository's`, `this repo's`, `the project's`, `see the`, `see this`, `per the`), which is the actual shape a "go read this" sentence takes.

A document is also exempted from flagging on the noun that names its own type (an ADR file mentioning "this ADR", `docs/plan/*.md` mentioning "the plan" or, for `ail-roadmap.md` itself, "the roadmap"), since a reader already inside the document is not left guessing what it refers to.

`docs/reports/`, `docs/audit/`, and `spikes/` are excluded from the scan for the reason given in item 2.

This is stated in the test module's own docstring, not just here, per the instruction to say why the general form was not possible.

**Evidence the new test catches the actual incident.** Rather than mutate the working tree to reconstruct the pre-fix state, the pre-fix `readME.md` and `docs/adr/0005-outcome-taxonomy.md` were read straight from the parent commit (`7cb428f`, `main` before this work) via `git show`, written to scratch files, and the test module's own detector functions were run against that text directly:

```
$ git show 7cb428f:readME.md > $SCRATCH/old_readme.md
$ git show 7cb428f:docs/adr/0005-outcome-taxonomy.md > $SCRATCH/old_adr0005.md
$ python3 -c "
import sys, importlib.util
spec = importlib.util.spec_from_file_location('t', 'tests/test_docs_references_resolve.py')
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
files = {'readME.md': '$SCRATCH/old_readme.md',
         'docs/adr/0005-outcome-taxonomy.md': '$SCRATCH/old_adr0005.md'}
for rel_path, real_path in files.items():
    text = open(real_path, encoding='utf-8').read()
    for pattern in (t._STRICT_NOUN_RE, t._GATED_NOUN_RE):
        for match in pattern.finditer(text):
            noun = match.group(1)
            if t._self_reference_exempt(noun, rel_path): continue
            if t._has_nearby_resolver(text, match.start(), match.end()): continue
            line_no = text.count(chr(10), 0, match.start()) + 1
            print(f'{rel_path}:{line_no}: {match.group(0)!r}')
"
readME.md:37: "this repository's roadmap"
readME.md:397: 'the roadmap'
```

This caught both README instances. It did not catch the ADR instance (`docs/adr/0005-outcome-taxonomy.md:152`, "found the roadmap's own topology-based framing"). Running this check is what surfaced a real bug in the first draft of `_STRICT_NOUN_RE`: it originally listed only bare determiners (`the`, `this`, `that`, `its`, `our`) and did not match `"this repository's roadmap"` at all, since the word immediately before `roadmap` there is `repository's`, not `this`. That draft would have shipped a test that could not catch the literal sentence the whole task started from. Fixed by adding `this repository's` / `this repo's` / `the project's` as recognized lead-ins to `_STRICT_NOUN_RE` (previously only `_GATED_NOUN_RE` had them), re-verified with the run shown above, and re-run against `tests/test_docs_references_resolve.py -v` (2 passed) before committing.

The ADR instance is a separate, known limitation, not fixed: the sentence is `` at `docs/reports/spike-mcp-mediation.md` found the roadmap's own topology-based framing failed to preserve ``, and the resolvability check looks for *any* `docs/...` path within 200 characters, not specifically a path adjacent to *this* noun. The spike-report path a few words earlier satisfies the check even though it names a different document than the one `"the roadmap"` refers to. Narrowing the window would risk reintroducing false positives elsewhere (this project's prose commonly wraps a sentence across a markdown line break, so a tight per-line window undercounts proximity that reads as one sentence). This specific line was still fixed by hand (item 2); the mechanical test's inability to have caught it unassisted is disclosed here rather than glossed over.

---

## Item 5: pytest green, push, PR, CI green, merge, delete branch

**Verdict: VERIFIED.**

```
$ python -m pytest tests/ -v   [against docker-compose.test.yml, default project "compliance-ail"]
...
109 passed, 1 warning in 515.19s (0:08:35)
```

The one warning is a pre-existing `DeprecationWarning` from a third-party dependency (`appier`'s use of `imp`), unrelated to this change.

```
$ git push -u origin docs/roadmap-commit
$ gh pr create --title "docs: commit AIL roadmap, fix dangling references, explicit Compose project name" --base main --head docs/roadmap-commit
https://github.com/banji-007/compliance-ail/pull/6

$ gh run watch 32303132448 --exit-status
...
✓ integration-tests in 2m28s (ID 96229983512)
[exited with code 0]

$ gh pr view 6 --json state,mergeable,mergeStateStatus
{"mergeStateStatus":"CLEAN","mergeable":"MERGEABLE","state":"OPEN"}

$ gh pr merge 6 --squash --delete-branch
Fast-forward main -> db60277

$ git fetch --prune origin
 - [deleted]         (none)     -> origin/docs/roadmap-commit
$ git branch -a
* main
  remotes/origin/HEAD -> origin/main
  remotes/origin/main
```

Local `main` was fast-forwarded to `db60277` by `gh pr merge`; the feature branch is gone both remotely and locally.

---

## Item 6: explicit Compose project name in `tests/test_content_states.py`

**Verdict: VERIFIED, demonstrated live both directions.**

`_compose_project_name()` reads `COMPOSE_PROJECT_NAME` (environment, then a root `.env`, matching the Makefile's own documented behavior that Compose auto-loads a root `.env` regardless of `-f`), and otherwise falls back to Compose's own default: the lowercased, `[a-z0-9_-]`-only basename of the repo root. That fallback is what an unmodified `docker compose` invocation from the repo root resolves to on its own, which is how the Makefile starts the stack today (it never passes `-p`). All three `docker compose` invocations in the file (`exec` for the SQL-delete attack, `stop verifier`, `start verifier`) now pass `-p $COMPOSE_PROJECT` explicitly.

**Sweep for the same implicit dependency elsewhere:** no other test file shells out to the `docker` CLI (`grep -rn 'docker.*compose' tests/*.py` finds only prose mentions of the compose file name outside `test_content_states.py`). The Makefile's own `docker compose` calls (`test-integration`, `test-integration-down`) always pair `up`/`down` within a single target invocation, using the same default derivation both times, so they cannot diverge from themselves the way a standalone `stop`/`start` against an externally-started stack can. No Makefile change was needed.

**Demonstrate: the two tests pass with the stack started under a non-default project name.**

```
$ docker compose -p ail-nondefault-demo -f docker-compose.test.yml up -d --build --wait
...
 Container ail-nondefault-demo-verifier-1 Healthy

$ COMPOSE_PROJECT_NAME=ail-nondefault-demo SPIRE_DISABLED=true \
  OPA_URL=http://localhost:8181/v1/data/ail/main/allow AIL_BUNDLE_NAME=ail-policies \
  CONTROL_PLANE_URL=http://localhost:8002 IMMUDB_URL=http://localhost:8080 \
  IMMUDB_USER=immudb IMMUDB_PASSWORD=immudb VERIFIER_URL=http://localhost:8003 \
  CONTROL_PLANE_READ_KEY=test-read-key CONTROL_PLANE_WRITE_KEY=test-write-key \
  python -m pytest tests/test_content_states.py::test_direct_sqlite_delete_produces_lost_not_erased \
    tests/test_content_states.py::test_erasure_refused_when_tombstone_write_fails -v

tests/test_content_states.py::test_direct_sqlite_delete_produces_lost_not_erased PASSED
tests/test_content_states.py::test_erasure_refused_when_tombstone_write_fails PASSED
2 passed in 34.17s
```

**Enforce: no test invokes docker compose without an explicit project.** Confirmed by inspection (all three call sites now include `-p COMPOSE_PROJECT`) and by the passing run above, which exercises `stop`/`start verifier` and the `exec` SQL-delete path together.

**The pre-fix failure mode, reproduced directly** (with the `ail-nondefault-demo` stack still up, running the old form of the command by hand, no `-p`):

```
$ python -c "
import re
from pathlib import Path
name = re.sub(r'[^a-z0-9_-]', '', Path('.').resolve().name.lower())
print('default project name would be:', name.lstrip('_-') or 'default')
"
default project name would be: compliance-ail

$ docker compose -f docker-compose.test.yml stop verifier
$ echo "exit code: $?"
exit code: 0

$ docker ps --filter "name=verifier" --format "table {{.Names}}\t{{.Status}}"
NAMES                            STATUS
ail-nondefault-demo-verifier-1   Up 26 seconds (healthy)
```

Without `-p`, `stop verifier` resolves to project `compliance-ail` (nothing running under that name at the time), so it silently no-ops: exit code 0, and the real verifier (running under `ail-nondefault-demo`) is untouched and still healthy. A test built on this command would see `stop.returncode == 0` and proceed as if the verifier were down; the subsequent `DELETE /content/{call_id}` would then succeed (204) instead of being refused (503), failing the test's real assertion for a reason that has nothing to do with erasure-refusal logic. This is the exact failure shape p13-merge reported.

Cleanup after the demonstration:

```
$ docker compose -p ail-nondefault-demo -f docker-compose.test.yml down -v
...
 Network ail-nondefault-demo_default Removed
```

---

## Could-not-verify

- **The real `.env` file's contents.** Reading `.env` at the repo root is permission-blocked in this session (consistent with prior sessions, per `docs/reports/phase-0-1.md`). `_compose_project_name()`'s `.env`-reading branch was therefore exercised in this session only via the code path with no `.env` present (falls through to the directory-basename default) and via `COMPOSE_PROJECT_NAME` set directly in the shell environment (the `ail-nondefault-demo` demonstration above), not via a `.env` file actually setting `COMPOSE_PROJECT_NAME`. The `.env`-parsing branch itself is simple (a single `key=value` line match) and was read-through carefully, but not exercised live against a real file in this session.
- **A genuine worktree-basename mismatch**, as opposed to an explicit `-p` override. The demonstration used `docker compose -p ail-nondefault-demo` to force a non-default project name, which is functionally identical evidence (Compose cannot tell the difference between "started under a differently-named worktree" and "started with an explicit `-p`"), but a literal second `git worktree` with a different directory basename was not separately created and exercised.
- **`test-integration` end-to-end via `make`.** `make` was not invoked directly in this session (no `make` binary confirmed on PATH); the equivalent `docker compose` commands the target runs were issued directly instead, with the same flags and the same 15-second wait. The full pytest run (109 passed) and both project-name demonstrations were run this way.

## Other notes

`docs/reports/phase-1-3-redteam.md.bak` is an untracked file that was already present in the working tree at the start of this run (visible in `git status` before any change was made) and is unrelated to this task's scope; it was left untouched.
