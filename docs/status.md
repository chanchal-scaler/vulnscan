# Status and backlog

Last updated 2026-11-04. Update this file whenever the deployment or the code's capabilities change. IDs for the live deployment are in `deploy/terraform/ENVIRONMENT.local.md`, and scan results stay on the instance. Neither goes in this repo.

## Deployed

- **Where:** one t3.large Spot instance (x86_64, Amazon Linux 2023) in the staging AWS account, us-west-2a, in its own subnet of a reused, otherwise empty VPC. Created by `deploy/terraform`; state is on the operator's machine.
- **What's running:** the image is built on the instance from `main` of the public GitHub repo, by `vulnscan-build`.
- **What it scans:** repos in two GitHub orgs (`github_org` in `terraform.tfvars`).
- **Tokens:** one classic GitHub PAT and one Claude Code `setup-token`, both in Parameter Store under `/vulnscan/`. Stage 2 adds `/vulnscan/openrouter-token` (an OpenRouter key for Strix + GLM 5.3): created by the next `terraform apply` and set by hand.
- **Cost:** about $29 a month. The instance is about $23 at the current Spot price, disks $2, the public IPv4 address $3.65. The Claude subscription is separate; validation spends against the OpenRouter key, capped by `--budget` (default $25 a run).
- **Stage 2 (validation):** the code, the image (Strix 1.7.0, sandbox 1.3.0) and the wrapper wiring are done, but nothing is on the instance yet: the owner pushes, `vulnscan-build` rebuilds, `terraform apply` adds the parameter, the key is set, and the first validation is run. None of that has happened.
- **Stage 3 (`vulnscan fix`):** the code is done. It needs no image, wrapper, Terraform or token change, because it uses the existing GitHub PAT (`repo` scope, plus `workflow` since 2026-11-05) and Claude token. It reaches the instance with the next `vulnscan-build`, and it can only run after a validation has.
- **Dashboard (`vulnscan dashboard`):** the code, the wrapper refusal and the `vulnscan-build` wiring are done. No Terraform, IAM or cost change. On 2026-11-05 the instance built `b3bc583`, so the image has the dashboard code and the new wrapper. The container didn't start, because the installed `vulnscan-build` was still the first-boot copy without the dashboard step. `vulnscan-build` now reinstalls itself; the instance needs the one-time manual install in [operations.md](operations.md#build-or-update-the-scanner). Port forwarding to it isn't checked yet.

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

## Scans run

- **The largest Rails monolith (63k files, about 7,700 findings):** one complete scan, with the **old** triage (first 150 by severity), on 2026-11-03.
  - Every scanner completed.
  - The scanners caught every issue on a later manual-review list (committed private keys, SQL injection, open redirects, `eval`/`YAML.load` on params, unsafe `constantize`, Ransack), but Claude never reviewed them. That led to the grouping and batching change.
- **Next:** re-run it with the new triage, using `VULNSCAN_TOOL_TIMEOUT=3600`, and review `report.csv`.

## Known issues

| Issue | Impact | Notes |
|---|---|---|
| Claude marks an unused dependency `confirmed`, at a lower severity, even when its reason says the package isn't imported | Dependency noise in the confirmed list | Tighten the prompt: unused → `false_positive`. Seen in testing (`requests`, `urllib3`). |
| Claude's own review is shallow on large repos | Issues no scanner flags (IDOR, authz, SSRF) are mostly missed in monoliths | Backlog: deep review. On 2026-11-05 the batch-1 prompt gained sink-first SSRF tracing and an LLM-app checklist, after a manual review found issues the scan missed ([decisions.md](decisions.md)). Not yet run with real Claude. |
| Grouped rules are judged from 5 samples | A confirmed group may include false positives, and a dismissed group may hide a real hit | `reviewed_as` in the CSV marks these |
| More than 400 items on the biggest repo (637 critical/high items there) | The least severe dependency items stay untriaged | `--max-triage 700` covers them, at the cost of time and quota |
| semgrep's full runtime on the biggest repo hasn't been measured | It may need more than 30 minutes | Use `VULNSCAN_TOOL_TIMEOUT=3600`; note the time after the next run |
| The `instance_type` variable defaults to `t4g.large`, but the deployment uses `t3.large` (set in `terraform.tfvars`) | A fresh deployment without tfvars gets t4g, which had no Spot capacity | Consider changing the default |
| Terraform state exists only on the operator's machine | If that machine is lost, the deployment can only be managed by hand | Back up, or move to an S3 backend with locking |
| A single classic GitHub PAT has write access to every repo its user can reach | If leaked, it allows pushing to org repos, including their GitHub Actions workflows (`workflow` scope). `vulnscan fix` now relies on that write access (branches and PRs) | Fine-grained per-org tokens (already supported) with Contents, Pull requests and Workflows set to read and write, or a GitHub App |
| `vulnscan fix` lets Claude write to a clone of untrusted code | Repo content could steer Claude into writing a harmful change into a PR. A workflow Claude changes that has `push` or `pull_request` triggers runs from the fix branch, with the repo's secrets, before anyone reviews it | Draft PRs only, no shell or token for Claude, `--restricted` blocks `.git` and settings writes, and the PR needs human review before merging ([decisions.md](decisions.md)) |
| `fix` PRs are authored by the PAT's user, and commits by `vulnscan <vulnscan@noreply.invalid>` | Commits are unverified and unlinked. A ruleset that restricts commit emails or requires signed commits will reject the push or block the merge | Use a GitHub App (signed bot commits), or set the identity to the PAT user's noreply address |
| `fix` can't regenerate lockfiles | Dependency findings are usually "not fixed": Claude changes versions only when it can keep the manifest and lockfile consistent by hand | Bump dependencies with Dependabot or by hand |
| Claude runs on one person's subscription token | Usage limits are shared with that person's own use, and the token stops working if they leave | Switch to Bedrock (the instance role) or an API key; no code change needed |
| `vulnerabilities.json` has no documented schema | A Strix release could change field names and validation reports would come out empty | Parsed defensively with a SARIF fallback, and exit 2 with nothing parsed is an error, not "no findings"; raw artifacts are always kept under `raw/strix/` for a fix |
| Strix's findings are matched back to stage 1 by the ids it names in its text | Coverage lists can undercount (a finding validated but not labelled stays "not referenced") | The instruction file asks Strix to name ids; treat the coverage list as best effort |
| Validation runs only where Docker and an OpenRouter key exist | The instance can't run it yet | Wiring is done (image, wrapper, parameter); first run pending |
| Validate containers get the host Docker socket | A Strix sandbox manipulated through repo content could control the host daemon, i.e. the instance (~root); it could then read the three tokens via the instance role | Deliberate, documented exception ([decisions.md](decisions.md)): PoC validation needs sibling containers. Only the `validate` subcommand gets the socket; `--budget` and `VULNSCAN_VALIDATE_TIMEOUT` bound a run; the GitHub/Claude/OpenRouter tokens are the only secrets reachable, and the instance has no other AWS rights |
| A validate run copies the repo into the run folder | The reports volume (5 GB) briefly holds a second copy of the repo; a 1.6 GB monolith needs ~3.2 GB free | Grow `data_volume_gb`, or validate big repos at a smaller `--ref`; the copy is removed when the run ends |
| The dashboard shows PR links, not whether they're merged | Merged or closed PRs still show `pr opened` | Deliberate: live state would need the PAT in a long-running server. Open the link. |
| Scanner env-var stripping isn't a hard boundary | A compromised scanner, running as the same user, could read the parent process's environment, which holds the tokens | The container limits what it can reach to those two tokens and the internet. Separating users would close it. |
| Only the default branch's latest commit is scanned | Secrets removed in later commits, and other branches, are missed | Backlog: history scan |
| No scheduling or alerting | New CVEs in existing lockfiles go unnoticed until someone scans | Backlog: nightly scans and alerts |

## Backlog (suggested order)

1. **Re-scan the largest repo with the new triage**, and agree with the owner how results are read and acted on.
2. **Bring stage 2 to the instance and run it once, for real:**
   - the owner pushes, then on the instance `vulnscan-build` (rebuilds the image with Strix, pre-pulls the sandbox, installs the wrapper);
   - `terraform apply` from the operator machine (adds `/vulnscan/openrouter-token` as a placeholder — no other change, no instance replacement), then set the OpenRouter key by hand ([deploy/README.md](../deploy/README.md#add-the-tokens));
   - run one small validation — e.g. a repo with a modest stage-1 scan, `--scan-mode quick --budget 5` — and review `validation.md` before pointing it at anything bigger. The Strix sandbox image is multi-GB, so the first `vulnscan-build` is slower than usual.
3. **Nightly scans with alerts:**
   - a systemd timer on the instance runs `vulnscan scan` for a list of repos;
   - it compares each run with the previous `report.json`;
   - it posts new confirmed critical/high findings to Slack.
   This is what would have caught HttpToShell-style exposures. Needs a webhook and approval.
4. **A `--deep-review` mode:** after triage, split the app by entry points (e.g. one Claude call per controller directory), each with a stack-specific checklist. For Rails: authorization in every action, unscoped `find` (IDOR), strong params, `send_file`/redirects, Ransack, outbound HTTP (SSRF). This trades time and quota for coverage of issues scanners can't see.
5. **Prompt fix for unused dependencies** (see Known issues).
6. **Terraform state to S3,** with DynamoDB locking or S3 native locking.
7. **An optional full-history secret scan** (`gitleaks git` on a full clone).
8. **Move Claude to Bedrock** (`CLAUDE_CODE_USE_BEDROCK=1`). The container would then need AWS credentials: raise the hop limit to 2, or have the wrapper pass in short-lived credentials.
9. **Fine-grained per-org tokens or a GitHub App** instead of the classic PAT.
10. **An automated test suite,** turning [testing.md](testing.md) checks 3, 7 and 10 into scripts.
