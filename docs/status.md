# Status and backlog

Last updated 2026-11-11. Update this file whenever the deployment or the code's capabilities change. IDs for the live deployment are in `deploy/terraform/ENVIRONMENT.local.md`, and scan results stay on the instance. Neither goes in this repo.

## Deployed

- **Where:** one t3.large Spot instance (x86_64, Amazon Linux 2023) in the staging AWS account, us-west-2a, in its own subnet of a reused, otherwise empty VPC. Created by `deploy/terraform`; state is on the operator's machine.
- **What's running:** the image is built on the instance from `main` of the public GitHub repo, by `vulnscan-build`.
- **What it scans:** repos in two GitHub orgs (`github_org` in `terraform.tfvars`).
- **Tokens:** one classic GitHub PAT and one Claude Code `setup-token`, both in Parameter Store under `/vulnscan/`. Stage 2 adds `/vulnscan/openrouter-token` (an OpenRouter key for Strix + GLM 5.3): created by the next `terraform apply` and set by hand.
- **Cost:** about $29 a month. The instance is about $23 at the current Spot price, disks $2, the public IPv4 address $3.65. The Claude subscription is separate; validation spends against the OpenRouter key, capped by `--budget` (default $25 per pass of 20 critical/high findings, so a scan with 100 of them can cost up to $125).
- **Stage 2 (validation):** the code, the image (Strix 1.7.0, sandbox 1.3.0) and the wrapper wiring are done, but nothing is on the instance yet: the owner pushes, `vulnscan-build` rebuilds, `terraform apply` adds the parameter, the key is set, and the first validation is run. None of that has happened.
- **Stage 3 (`vulnscan fix`):** the code is done. It needs no image, wrapper, Terraform or token change, because it uses the existing GitHub PAT (`repo` scope, plus `workflow` since 2026-11-05) and Claude token. It reaches the instance with the next `vulnscan-build`, and it can only run after a validation has.
- **Dashboard (`vulnscan dashboard`):** the code, the wrapper refusal and the `vulnscan-build` wiring are done. No Terraform, IAM or cost change. On 2026-11-05 the instance built `b3bc583`, so the image has the dashboard code and the new wrapper. The container didn't start, because the installed `vulnscan-build` was still the first-boot copy without the dashboard step. `vulnscan-build` now reinstalls itself; the instance needs the one-time manual install in [operations.md](operations.md#build-or-update-the-scanner). Port forwarding to it isn't checked yet.
- **Changes of 2026-11-10/11 aren't on the instance yet.** They cover:
  - LLM proof criteria in Strix's instructions;
  - Strix's `standard` mode by default (it was `deep` from 2026-11-10 until 2026-11-11);
  - validate and fix re-runs from scratch;
  - fix branches named by stage-1 id, with PRs updated rather than duplicated;
  - issues for findings Claude can't fix;
  - `vulnscan purge`;
  - progress logging.

  These are code and docs only, tested locally with stand-ins. Most were committed as `21cfa87` on 2026-11-11, and later doc fixes followed. They reach the instance once pushed to `main` and `vulnscan-build` runs. No Terraform, IAM, wrapper, image or token change is needed: the classic PAT's `repo` scope already covers issues. Backlog item 3 lists what to check for real.

## Verified

- **Hardening, checked on the live instance (2026-11-03/04):**
  - IMDSv2 required, hop limit 1, no SSH key;
  - no inbound rules; outbound HTTPS works and plain HTTP is blocked;
  - the role reads its own parameters but gets AccessDenied everywhere else in Parameter Store;
  - Terraform state holds no token values;
  - first boot completes cleanly;
  - the reports volume keeps its filesystem when the instance is replaced (checked when switching to Spot).
- **Image:** builds on arm64 and amd64, every pinned checksum passes, and all scanners run as the non-root user. apt works with port 80 blocked.
- **Tokens:** the GitHub token reads private repos in both orgs, and the Claude token is set.
- **Detached scans:** they survive the session ending (SIGHUP), Ctrl-C leaves them running, exit codes come through, and leftover containers are cleaned up.
- **Grouped, batched triage:**
  - Unit-tested with a stand-in Claude.
  - End to end with real Claude: 3 batches, every item got a verdict, no permission denials.
  - Replayed over a real 7,751-finding scan: every critical issue that a manual review had found moved into batches 1–2. Under the old triage none of them were reviewed.
- **`report.csv`:** written, with formula escaping checked.
- **Validation stage (local):** unit-tested with a stand-in Strix — selection and ordering of open findings, seeding files, parsing of `vulnerabilities.json` (both location shapes) with SARIF fallback, PoC/fix/id extraction, coverage lists, CSV formula escaping, the nothing-to-validate path, and the failure paths (missing key, exit 1, unparseable artifacts). Not yet run with real Strix or real OpenRouter credits.

- **Fix stage (local, 2026-11-04):**
  - Tested with a stand-in Claude and GitHub against a local bare repo: every status, the guards, idempotency, the commit identity, and that stray files from a "not fixed" attempt never get committed.
  - Dry-run end to end with real Claude on OWASP/railsgoat: a correct one-line fix and no permission denials.
  - Real restricted Claude was confirmed to edit files in `--add-dir` and to be refused a write to `.git/hooks`.
  - First real run on a private repo, 12 draft PRs: the push and PR flow worked, but several fixes would have broken deployments if merged as they were. The prompt was then tightened ([decisions.md](decisions.md)).
  - The tightened prompt was re-run as a dry run on OWASP/railsgoat. A SQL injection fix kept the existing behaviour, and a committed secret became an environment variable with the old value as fallback, with "rotate" and "set it everywhere" in `before_merging`.
  - PRs from the earlier run keep the old prompt's output. To regenerate one, close it, delete its branch and re-run `fix`.

- **Dashboard (local, 2026-11-04):**
  - Tested over fabricated run folders: a complete run, an unfinished one, a corrupt `report.json`, and a label with a space.
  - Pages: the funnel and the F → V → PR joins are right, `<script>` and attribute-breaking titles come out escaped, no PoC appears, and the only links are https PR links.
  - Requests: a non-localhost `Host` gets a 403, path traversal and raw-file paths get a 404, and POST gets a 501.
  - Container, run with the `vulnscan-build` flags on Docker Desktop: uid 10001, read-only scans and root filesystem, no tokens, about 15 MB of memory. It's unreachable from a default-bridge container both directly and through the bridge gateway.
- **`fix.json` merging (local, 2026-11-04):** tested with stand-ins against a local bare repo:
  - `--only V001`, then `--only V002`, keeps both.
  - A full re-run keeps V001's PR over `skipped`.
  - After a re-validation, the stale V001 is dropped.

- **Two fixes (local, 2026-11-05):**
  - Claude's own findings in mixed order now get the same `C…` ids in `report.json`, `report.csv`, `report.md` and `validate.open_items`.
  - With a stand-in Strix and a local bare repo, `validate` refuses when the run has `vulnscan/fix-<run>-*` branches, before Strix starts. It runs when there are none, or only another run's, and skips the check for a local folder.
- **`validate --only` (local, 2026-11-05):** tested with a stand-in Strix and a local bare repo (26 checks):
  - Unknown IDs and false positives exit 2 before cloning.
  - Earlier `V…` ids are kept and new ones appended, and coverage merges, including from a `validation.json` without `coverage.sent`.
  - It runs past a fix branch while a full re-validation is still refused, and the dashboard reads the merged file.
  - Not yet run with real Strix.
- **Validation in passes of 20, critical and high only (local, 2026-11-06):** tested with a stand-in Strix over a fabricated report of 44 critical/high findings plus medium, low, info, false-positive, re-rated and grouped ones:
  - Only critical and high (by final severity) were sent, in passes of 20, 20 and 4, worst first with the dependency last and one hit per group.
  - A pass that failed (exit 1) stopped the command with exit 2. Its one validated finding was kept, and the next run re-sent its other 19, with pass numbers and `V…` ids continuing.
  - Once everything was sent, a re-run changed nothing. `--only` with a medium id added a fifth pass.
  - Each pass's artifacts are in `raw/strix/pass-<n>/`, and `validation.md` lists the passes and the total cost. The dashboard renders the merged file.
  - The fix-branch guard refuses with no `validation.json` and is skipped with one. A missing key and an unknown `--only` id still exit 2 before cloning.
  - Not yet run with real Strix.
- **LLM proof criteria in Strix's instructions (local, 2026-11-10), stand-in only:** the `deep review: LLM` label reaches `strix-findings.json` and the findings list, the LLM section names Strix's two LLM skills, the no-live-target note appears only without `--url`, and other findings' lines are unchanged. Not yet run with real Strix.
- **Re-runs from scratch, fix branches by stage-1 id, and `vulnscan purge` (local, 2026-11-11), stand-ins only:** 48 checks, using a fake strix, a patched Claude and in-memory GitHub, and a local bare repo. The checks for each part:
  - **Validate:** a re-run sends every critical/high finding again, replaces the results with `V001…`, and removes the fix files and old Strix artifacts. A failed pass doesn't stop the next one. `--only` adds and keeps `fix.json`.
  - **Fix:** a re-run calls Claude for every finding, force-pushes to the same branches and updates their PRs, with no duplicates. That holds after a re-validation renumbers the ids too. A `[new]` finding keeps its branch. A failed PR update leaves an existing branch alone.
  - **Purge:** it previews without `--yes`, removes the later stages with each stage, defaults to the newest run with results, and refuses `--run` outside the repo's folder.

  Not yet run against GitHub or with real Strix.
- **Issues for findings Claude can't fix (local, 2026-11-11), stand-ins only:** more checks in the same harness, 62 in all.
  - An issue is opened with the reason, the steps and the marker, and without the PoC. `fix.md` shows its link.
  - When two findings share stage-1 ids, the first keeps its branch and issue.
  - A re-run updates it rather than duplicating it, including after a re-validation.
  - No issue is opened when the code no longer has the problem, on a dry run, or while an earlier PR is still open.
  - HTTP 410 is only noted; other API errors fail the finding.
  - The dashboard links the issues and counts them.

  Not yet run against GitHub.
- **Progress logging (local, 2026-11-11):** 22 checks with stand-ins:
  - Claude's tool calls are logged as they happen, without Grep patterns or file contents. `claude-<n>.json` keeps only the result event. Timeouts and errors behave as before.
  - Strix's agents, reports and errors are relayed from `strix.log` while it runs, and a timeout stops it with SIGTERM.
  - Scanners log "still running".

  The `stream-json` format was checked with one real Claude Code 2.1.267 call (Haiku), and real brakeman still runs through the new scanner code. Not yet seen on the instance (Claude Code 2.1.311).
- **Strix 1.7.0 still the latest (2026-11-10):** on PyPI and GitHub, with sandbox 1.3.0 as its default. `vulnscan validate` ran Strix's `deep` mode by default from then until 2026-11-11, when the default went back to `standard`.

- **Prompt and logic review, and the prompt-injection check (local, 2026-11-05):** not yet on the instance.
  - **Triage, with a stand-in Claude:**
    - samples are spread across app folders, with `spec/` and `vendor/` last;
    - a sample's own verdict detaches it from its group;
    - mutual duplicates leave one `needs_review`;
    - a skipped item is listed in `errors`;
    - the review is its own call, without dependencies in its list.
  - **Validation, with a stand-in Strix:**
    - a 15-hit group is sent once, dependencies come last, and `info` is refused;
    - `[F1234]` and `[new]` tags parse;
    - `--only` takes a non-first group member;
    - the dashboard shows "grouped with F…".
  - **Fix, with stand-ins against a local bare repo:** a failed PR call deletes the pushed branch and the re-run opens the PR. The prompt carries the stage-1 finding and the secret rule.
  - **Real pinned scanners in the image, on a planted repo:** every suppression in [testing.md](testing.md) check 16 behaved as expected.
  - **The prompt-injection check:** it caught every planted case. After tuning, it reported nothing on the largest local Rails monolith (24 s) or on vulnscan itself.
  - **Real Claude on OWASP/railsgoat (30 items, 2 batches and the review):**
    - Batches: every item got a verdict, there were no permission denials, and all 7 duplicates named their pair in `duplicate_of`. A gem used only in development and tests was rated low.
    - Review: 10 issues, each naming its entry point and who can reach it, with no repeats of scanner findings. Its summary ends with what it didn't review and says it found no planted prompt injection.
    - No output quotes any part of the committed `secret_key_base`.
    - Cost at API rates: $0.92 for the batches, plus $1.67 for the review (61 turns, 342 s). The separate review costs more than it did inside batch 1 (the whole 2026-11-04 run was $0.90).

- **Claude pinned to Opus 5.5 (2026-11-06):** every call passes `--model claude-opus-5-5` (checked with a stand-in). It hasn't run with real Claude yet: the local CLI (2.1.267) is older than the 2.1.280 that Opus 5.5 needs, and the image has 2.1.311. Earlier real runs used Claude Code's default, which was `claude-opus-5[1m]` locally (2.1.267) and `claude-sonnet-5-5` on the instance (2.1.311).
- **`--deep-review` and `--claude-budget` (2026-11-06):**
  - **First full run on the instance, scaler-hq/backend, on Sonnet 5.5 before the pin:** 11 calls (2 triage batches, the review, 4 SSRF and 4 access-control batches), 5–36 turns each, no permission denials. $2.90 at API rates, about 1% of the weekly limit.
  - **The same scan with Opus 5.5 pinned:** $10.95 at API rates, 3.8× the Sonnet run. Claude Code also has an Opus-specific limit, so watch for usage-limit failures in long deep reviews.
    - **Compared with Sonnet:** decisive where Sonnet deferred (`needs_review` went from 11 to 1), and it rated leaked credentials critical. The general review found 10 issues (its cap) instead of 2. No dependencies were rated high, against 112 for Sonnet: 52 pillow and 41 aiohttp advisories, plus python-multipart, starlette and weasyprint. Opus's reasons were specific.
    - **Gaps found and fixed in the prompts (2026-11-06):** DoS had no place on the severity scale, and the SSRF pass couldn't see content renderers ([decisions.md](decisions.md)). WeasyPrint rendering user-derived content needs a person's look and `validate --only`.
    - **Still on Opus:** the general review now hits its 10-issue cap.
  - **Stand-ins:** the budget stops at the right call, both in triage and in the deep review, and every skip is reported. Deep findings get `C…` ids, "Found in" and validation. The CLI guards exit 2.
  - **Listing on the largest local Rails app:** 6 s, giving 220 call sites in 94 files and 1,358 handler files, which makes 10 SSRF and 37 access-control batches.
  - **LLM pass (2026-11-06), stand-in only:**
    - Listing gives 60 LLM call sites in 31 files on the largest Rails app (3 batches), and 212 in 79 files on a local copy of the scaler backend (9 batches). The backend's include the interview feedback services, `claude_client.py` and the Zendesk provider.
    - A stand-in run on that copy checked the rest: the order is SSRF, LLM, access; the prompt is filled in; the budget skips the remaining LLM and access batches and the report lists them; findings get `C…` ids and "Found in: deep review: LLM".
    - It hasn't run with real Claude yet.
  - **On by default (2026-11-06):** `--no-deep-review` turns it off. With a stub `scan`, the CLI gives `deep_review=True` with no flags and `False` with `--no-deep-review` or `--no-llm`. `--deep-review --no-llm`, `--deep-path` with the deep review off, and `--claude-budget 0` exit 2.
  - **Real Claude, $3.73 at API rates in all:**
    - pygoat's SSRF lab: the SSRF was found and traced ($0.46). The access pass found an `X-Forwarded-For` bypass and named a hardcoded key without quoting it ($0.59).
    - railsgoat's 17 controllers: every one reviewed. The first run (no scanner findings passed) reported 24 issues, half of them other classes, so the prompt was tightened. The rerun, with the 150 scanner findings as context, reported 13 issues, all access control apart from two high or critical injections whose sinks are outside the batch ($1.28, 337 s).

## Scans run

- **The largest Rails monolith (63k files, about 7,700 findings):** one complete scan, with the **old** triage (first 150 by severity), on 2026-11-03.
  - Every scanner completed.
  - The scanners caught every issue on a later manual-review list (committed private keys, SQL injection, open redirects, `eval`/`YAML.load` on params, unsafe `constantize`, Ransack), but Claude never reviewed them. That led to the grouping and batching change.
- **Next:** re-run it with the new triage, using `VULNSCAN_TOOL_TIMEOUT=3600`, and review `report.csv`.

## Known issues

| Issue | Impact | Notes |
|---|---|---|
| Claude marked an unused dependency `confirmed`, at a lower severity, even when its reason said the package isn't imported | Dependency noise in the confirmed list | Seen in testing (`requests`, `urllib3`). The prompt now says never loaded → `false_positive`, development or tests only → low (2026-11-05). Check on the next real scan. |
| Claude's own review is shallow on large repos | Issues no scanner flags (IDOR, authz, SSRF) are mostly missed in monoliths | The deep review (2026-11-06, on by default since) covers every outbound HTTP call for SSRF, every LLM call and prompt-building line for LLM misuse, and every handler file for access control, at a large quota cost. Without it, the general review still samples. Other classes Claude might find (business logic, for one) stay out of reach on a monolith |
| `--deep-review` finds only what its patterns list | An HTTP client or routing style its patterns don't know is never deep-reviewed | The patterns cover the common clients and frameworks of the org's stacks. Add to `_HTTP_CALL`, `_LLM_CALL` or `_HANDLER` in `deep_review.py` when a repo uses another |
| Grouped rules are judged from 5 samples | A confirmed group may include false positives, and a dismissed group may hide a real hit | `reviewed_as` in the CSV marks these. Since 2026-11-05 the samples are spread across app folders (tests and vendored code last), and Claude can give a sample its own verdict |
| Some suppressions in the scanned repo can't be switched off | gitleaks honours `.gitleaksignore`, checkov `.checkov.yaml`, semgrep `.semgrepignore`, whatever the flags | The first two become findings that point Claude at the file; `.semgrepignore` doesn't ([decisions.md](decisions.md)) |
| The prompt-injection check matches patterns | A payload worded differently, or encoded some other way, gets past it; an app's own LLM prompts can match | Claude's review also looks for planted instructions, and triage dismisses the app's own prompts |
| More than 400 items on the biggest repo (637 critical/high items there) | The least severe dependency items stay untriaged | `--max-triage 700` covers them, at the cost of time and quota |
| semgrep's full runtime on the biggest repo hasn't been measured | It may need more than 30 minutes | Use `VULNSCAN_TOOL_TIMEOUT=3600`; note the time after the next run |
| The `instance_type` variable defaults to `t4g.large`, but the deployment uses `t3.large` (set in `terraform.tfvars`) | A fresh deployment without tfvars gets t4g, which had no Spot capacity | Consider changing the default |
| Terraform state exists only on the operator's machine | If that machine is lost, the deployment can only be managed by hand | Back up, or move to an S3 backend with locking |
| A single classic GitHub PAT has write access to every repo its user can reach | If leaked, it allows pushing to org repos, including their GitHub Actions workflows (`workflow` scope). `vulnscan fix` now relies on that write access (branches, PRs and issues) | Fine-grained per-org tokens (already supported) with Contents, Pull requests, Issues and Workflows set to read and write, or a GitHub App (which would also need the issue lookup changed, see below) |
| `vulnscan fix` lets Claude write to a clone of untrusted code | Repo content could steer Claude into writing a harmful change into a PR. A workflow Claude changes that has `push` or `pull_request` triggers runs from the fix branch, with the repo's secrets, before anyone reviews it | Draft PRs only, no shell or token for Claude, `--restricted` blocks `.git` and settings writes, and the PR needs human review before merging ([decisions.md](decisions.md)) |
| `fix` PRs are authored by the PAT's user, and commits by `vulnscan <vulnscan@noreply.invalid>` | Commits are unverified and unlinked. A ruleset that restricts commit emails or requires signed commits will reject the push or block the merge | Use a GitHub App (signed bot commits), or set the identity to the PAT user's noreply address |
| `fix` can't regenerate lockfiles | Dependency findings are usually "not fixed": Claude changes versions only when it can keep the manifest and lockfile consistent by hand | Bump dependencies with Dependabot or by hand |
| Claude runs on one person's subscription token | Usage limits are shared with that person's own use, and the token stops working if they leave | Switch to Bedrock (the instance role) or an API key; no code change needed |
| `vulnerabilities.json` has no documented schema | A Strix release could change field names and validation reports would come out empty | Parsed defensively with a SARIF fallback, and exit 2 with nothing parsed is an error, not "no findings"; raw artifacts are always kept under `raw/strix/pass-<n>/` for a fix |
| Strix's findings are matched back to stage 1 by the `[F012]` tag it's asked to start each title with | Coverage lists can undercount (a finding validated but not tagged stays "not referenced"). An untagged title falls back to every id in its text, which can over-count | Treat the coverage list as best effort. Not yet run with real Strix |
| Validation runs only where Docker and an OpenRouter key exist | The instance can't run it yet | Wiring is done (image, wrapper, parameter); first run pending |
| Validate containers get the host Docker socket | A Strix sandbox manipulated through repo content could control the host daemon, i.e. the instance (~root); it could then read the three tokens via the instance role | Deliberate, documented exception ([decisions.md](decisions.md)): PoC validation needs sibling containers. Only the `validate` subcommand gets the socket; `--budget` and `VULNSCAN_VALIDATE_TIMEOUT` bound each pass; the GitHub/Claude/OpenRouter tokens are the only secrets reachable, and the instance has no other AWS rights |
| A validate run copies the repo into the run folder | The reports volume (5 GB) briefly holds a second copy of the repo; a 1.6 GB monolith needs ~3.2 GB free | Grow `data_volume_gb`, or validate big repos at a smaller `--ref`; the copy is removed when the run ends |
| The dashboard shows PR links, not whether they're merged | Merged or closed PRs still show `pr opened` | Deliberate: live state would need the PAT in a long-running server. Open the link. |
| Scanner env-var stripping isn't a hard boundary | A compromised scanner, running as the same user, could read the parent process's environment, which holds the tokens | The container limits what it can reach to those two tokens and the internet. Separating users would close it. |
| Only the default branch's latest commit is scanned | Secrets removed in later commits, and other branches, are missed | Backlog: history scan |
| No scheduling or alerting | New CVEs in existing lockfiles go unnoticed until someone scans | Backlog: nightly scans and alerts |
| A Strix pass run with `--scan-mode deep` may run past the 2-hour `VULNSCAN_VALIDATE_TIMEOUT` | That pass counts as failed, and its findings show as not sent | Raise it for the run (`VULNSCAN_VALIDATE_TIMEOUT=21600`). Set a better default once real passes have been timed |
| `vulnscan fix` force-pushes to `vulnscan/fix-*` branches on every run | Commits people added to such a branch are lost on the next run | Deliberate (the owner chose updating PRs). Move a fix someone is changing to a branch of their own |
| PRs opened before 2026-11-11 have branches named after `V…` ids | A re-run doesn't match them, so it opens new PRs next to them | Close the old ones by hand |
| Fix branches, PRs and issues are matched by the stage-1 ids a finding validates | After a re-validation, a finding that validates a different set of ids gets a new PR or issue, and the old one stays open. When several validated findings share the same ids, the plain-key branch, PR and issue go to whichever is first in `V…` order. So after a re-validation, a different one of them can take them over: its fix is force-pushed there, and the title and body are rewritten for it. They're the same stage-1 finding, reached in different ways | Close a stale PR or issue. Check a PR's body still matches its branch after a re-validation |
| A `[new]` finding's branch is matched by its title and location | After a re-validation, Strix usually words it differently, so it gets a new PR and the old one stays open | Close the stale one. Findings with stage-1 ids don't have this problem |
| vulnscan doesn't close the issues it opens | When a later run fixes the finding, its issue stays open next to the new PR | Close the issue when the PR is merged |
| Finding earlier issues calls `GET /user` | A GitHub App token can't call it, so with one every finding that needs an issue would fail | Production uses a classic PAT; switching to a GitHub App means changing this lookup |
| `purge` takes no lock | Purging a run while a stage writes to it leaves that stage's files half there | Don't purge a run while a scan, validate or fix is running on it |
| The Strix progress feed reads `strix.log`, whose format isn't documented | A Strix release could change it; the feed would then go quiet, but validation results wouldn't change | Update `_StrixWatch` in `validate.py` |

## Backlog (suggested order)

1. **Re-scan the largest repo with the new triage**, and agree with the owner how results are read and acted on.
2. **Bring stage 2 to the instance and run it once, for real:**
   - the owner pushes, then on the instance `vulnscan-build` (rebuilds the image with Strix, pre-pulls the sandbox, installs the wrapper);
   - `terraform apply` from the operator machine (adds `/vulnscan/openrouter-token` as a placeholder — no other change, no instance replacement), then set the OpenRouter key by hand ([deploy/README.md](../deploy/README.md#add-the-tokens));
   - run one small validation — e.g. one pass with `--only` and a few critical or high ids from a modest stage-1 scan, `--scan-mode quick --budget 5` — and review `validation.md` before letting it run every pass on anything bigger. The Strix sandbox image is multi-GB, so the first `vulnscan-build` is slower than usual.
3. **Check the 2026-11-10/11 changes for real,** after item 2, on a private test repo:
   - run a full `vulnscan fix` twice. The second run updates the same PRs and issues (`pr updated`, `issue updated`) instead of opening new ones;
   - re-validate that scan and run `fix` again. The PRs and issues are still found, by their stage-1 ids;
   - in the instance's log, check that Claude's tool calls appear as they happen (not yet seen with Claude Code 2.1.311's `stream-json`), and that Strix's agents and reports appear during a pass;
   - time a Strix pass in `standard` mode (the default) and one with `--scan-mode deep` on the same findings, compare their `validation.md`, and set `VULNSCAN_VALIDATE_TIMEOUT`'s default from them;
   - close the PRs opened before 2026-11-11, whose branches are named after `V…` ids.
4. **Nightly scans with alerts:**
   - a systemd timer on the instance runs `vulnscan scan` for a list of repos;
   - it compares each run with the previous `report.json`;
   - it posts new confirmed critical/high findings to Slack.
   This is what would have caught HttpToShell-style exposures. Needs a webhook and approval.
5. **Run `--deep-review` on a real repo:** start with `--deep-path` on one area of a monolith and a `--claude-budget`. Note how much of the plan's allowance it used (the claude.ai usage page before and after), how long it took and what it found, before running it on a whole app.
6. **Terraform state to S3,** with DynamoDB locking or S3 native locking.
7. **An optional full-history secret scan** (`gitleaks git` on a full clone).
8. **Move Claude to Bedrock** (`CLAUDE_CODE_USE_BEDROCK=1`). The container would then need AWS credentials: raise the hop limit to 2, or have the wrapper pass in short-lived credentials.
9. **Fine-grained per-org tokens or a GitHub App** instead of the classic PAT.
10. **An automated test suite,** turning [testing.md](testing.md) checks 3, 7, 10, 12, 15, 16, 19 and 20 into scripts. The stand-in scripts used on 2026-11-10/11 (re-runs, purge, issues, progress logging) weren't kept in the repo; those sections describe them.
11. **Validate LLM findings against staging:** run `validate --only <C id> --url <staging>` with a test login ([operations.md](operations.md#logging-in-to-a-live-target)) for the deep review's LLM findings. Strix 1.7.0 ships `llm_prompt_injection` and `llm_applications` skills, which vulnscan now tells it to load, and it can install Promptfoo inside its sandbox. If it still falls short, add Promptfoo (MIT; OpenAI bought it in March 2026 and kept the licence), aimed at the endpoints the LLM pass names. garak probes the model rather than the app, and PyRIT needs code for each target.
12. **Open question for the owner: Strix login credentials.** Today they go in `--instruction`, which puts them on the container's command line and in `strix-instructions.md` (they must reach the model either way). A dedicated option could read them from a file or Parameter Store instead.
