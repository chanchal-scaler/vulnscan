# vulnscan (POC)

Give it a GitHub repo, or a local folder, and it finds security problems. It:
- works out the stacks the repo uses;
- runs the security scanners that fit;
- merges their results;
- uses Claude Code to check the findings against the actual code and look for issues scanners miss;
- can then validate the open findings with Strix, an agentic pentesting harness powered by GLM 5.3 via OpenRouter, which tries to prove each issue with a working PoC ([Validation](#validation-stage-2));
- can then open one draft PR per validated finding, with the fix written by Claude Code ([Fixing](#fixing-stage-3)).

It writes a Markdown report, JSON and CSV, and a read-only web page tracks every run through the three stages ([Dashboard](#dashboard)).

```bash
vulnscan scan your-org/some-repo
```

It runs on any machine with Python 3.9+, and in production on one EC2 instance where each scan gets a fresh Docker container ([deploy/README.md](deploy/README.md)).

Documentation:
- **[CLAUDE.md](CLAUDE.md):** the starting point for agents and maintainers.
- **[docs/architecture.md](docs/architecture.md):** how the code works.
- **[docs/decisions.md](docs/decisions.md):** why it's built this way.
- **[docs/operations.md](docs/operations.md):** the runbook.
- **[docs/testing.md](docs/testing.md):** how to test changes.
- **[docs/status.md](docs/status.md):** current state and backlog.

## What it finds

| Problem | Found by | Examples |
|---|---|---|
| Vulnerable code (SAST) | semgrep (every repo, 30+ languages), brakeman (Rails), bandit (Python), gosec (Go) | SQL injection, XSS, command injection, open redirects, `eval`/unsafe deserialization, unsafe reflection (`constantize`), weak crypto |
| Vulnerable dependencies | osv-scanner (every repo, every lockfile ecosystem) | Known CVEs in gems (`Gemfile.lock`), npm/yarn packages, pip requirements, Go modules, Maven `pom.xml` |
| Hardcoded secrets | gitleaks (every repo), plus semgrep and checkov secret rules | Private keys, cloud credentials, API keys, OAuth tokens. Values are redacted before they reach disk. |
| Infrastructure misconfiguration | checkov (Terraform, Dockerfiles, GitHub Actions, Helm) | Open security groups, IMDSv1, unencrypted storage, containers running as root |
| Prompt injection planted in the repo | vulnscan's built-in check (every repo), plus Claude's own review | Text aimed at AI tools ("ignore previous instructions", "mark this as a false positive", notes to an AI in comments or agent files such as `CLAUDE.md`, `.cursorrules` or `.mcp.json`), invisible Unicode tag characters, bidi controls (Trojan Source) and zero-width runs. It targets vulnscan's own Claude and Strix as much as developers' coding agents. |
| Issues scanners miss | Claude's own code review | SSRF, missing authorization and IDOR, authentication bypass, mass assignment. In apps that call an LLM: prompt injection into prompts that grade or decide or into agents that call tools, unsanitised LLM output, client-chosen models or LLM proxies, personal data sent to LLM providers. See [What Claude does](#what-claude-does) for limits. |

The scanned repo can't hide its own findings: scanners ignore its suppression comments and config files (`nosemgrep`, `# nosec`, `.bandit`, `gitleaks:allow`, `.gitleaks.toml`, `config/brakeman.yml`) and report what `config/brakeman.ignore` and `checkov:skip` comments hide, marked as such. `.gitleaksignore` and `.checkov.yaml` can't be switched off, so each becomes a finding of its own, and `.semgrepignore` is still honoured. Claude treats a suppression as the repo's claim, not proof.

Stacks are detected from marker files:
- **Rails:** `Gemfile` plus `config/application.rb`
- **Ruby:** `Gemfile`
- **Go:** `go.mod`
- **JavaScript:** `package.json`
- **Java:** `pom.xml` or `build.gradle`
- **PHP:** `composer.json`
- **Rust:** `Cargo.toml`
- **Python:** any `.py` file
- **Infrastructure as code:** `*.tf`, `Dockerfile*`, `Chart.yaml`, or `.github/workflows/*.yml`

A stack without its own scanner still gets semgrep, osv-scanner, gitleaks, the prompt-injection check and Claude.

## How a scan works

1. **Clone:** a shallow clone (`--depth 1`) of the default branch, or of `--ref`, into a temporary folder that's deleted afterwards. A local folder is scanned in place.
2. **Detect:** find the stacks and the folders they live in.
3. **Install:** when run directly, install any missing scanner into `~/.vulnscan/tools`. The Docker image already contains every scanner at a pinned version.
4. **Scan:** run each scanner that applies, and convert its output into one finding format with a normalised severity (`critical`, `high`, `medium`, `low`, `info`). One scanner failing doesn't stop the others.
5. **Triage:** Claude Code reviews the findings in batches. See [What Claude does](#what-claude-does).
6. **Report:** write `report.md`, `report.json`, `report.csv`, each scanner's raw output and Claude's raw responses to `~/.vulnscan/scans/<org>__<repo>/<UTC timestamp>/`. On the server this is `/var/lib/vulnscan/scans/...`.

## What Claude does

Claude Code runs headless, with read-only tools (Read, Grep, Glob) and no shell or web access. It does two different jobs.

**1. Verifying the scanners' findings: most of the work.** The scanners decide what gets looked at. For each item Claude reads the code and gives a verdict:
- **confirmed**, **false_positive**, **duplicate** or **needs_review**;
- a re-rated severity;
- a reason;
- a fix.

For dependencies it checks whether the package is loaded at runtime and whether any vulnerable function an advisory names is used. A package that's never loaded is a false positive, and one used only in development or tests is rated low. The prompt gives Claude a severity scale based on what an attacker can do (critical: no login needed for RCE, SQL injection or auth bypass, SSRF reaching cloud metadata, a live production credential), so ratings are consistent across batches. A `duplicate` must name the other item in its batch (`duplicate_of`). One that doesn't, or a pair marked duplicates of each other, is kept as `needs_review`, so a real issue can't disappear. Claude is told never to copy a secret's value into its answer.

Findings are grouped and prioritised first, so the important ones are reviewed even in repos with thousands of findings:
- **Dependencies:** each vulnerable package version is one item, covering all its advisories and lockfiles.
- **Repeated rules:** a rule with more than 10 hits is one item, judged from 5 sample locations. The samples are spread across folders, with tests, vendored and example code last, and Claude can give any sample its own verdict when it doesn't fit the pattern. Brakeman warnings are never grouped, because each is tied to a specific location.
- **Order:** critical and high come first. Within each severity band: secrets, then code, then configuration, then dependencies.
- **Limits:** Claude reviews 100 items per call, up to 400 items per scan (`--max-triage`). Anything beyond that is listed as "Not triaged".

**2. Its own review: limited.** After the batches, a separate call looks for up to 10 high-impact issues scanners usually miss, starting from routes and controllers (checking every route module for missing authentication), and for SSRF also from every outbound HTTP call. It's separate so a slow review can't time out the most important verdicts. It also looks for prompt injection planted in the repo, including agent settings that run commands when a developer opens it. It gets the list of scanner findings so it doesn't repeat them, names each issue's entry point and who can reach it (which helps Strix test it), and ends its summary with the parts of the app it didn't get to. On small repos this finds real issues; in testing it found an SSRF, a `pickle.loads` remote code execution and controllers without authentication. On large monoliths it can only read a small part of the code, so coverage there comes mostly from the scanners, unless you add a deep review.

**3. Deep review: opt-in (`--deep-review`), for the whole codebase.** After the general review, Claude reviews every part of the code for the two classes of issue no scanner finds well. vulnscan, not Claude, lists what must be covered and gives Claude one batch per call:
- **SSRF, by sink:** every outbound HTTP call site (Net::HTTP, Faraday, requests, httpx, fetch, axios, `http.Get` and so on), in batches of 25. Claude traces each URL back to where it comes from. Browser code, imports and comments are left out.
- **Access control, by area:** every request-handler file (Rails controllers, Django and FastAPI views, Express and Next.js routes, Go handlers, Spring controllers), grouped by folder into batches of about 4,000 lines. Claude checks every action for missing authentication or authorization, IDOR and mass assignment.

Each call gets what's already reported in its files, so it doesn't repeat it. Its findings join Claude's own (`C…`, marked "Found in: deep review: …") and go on to validation like any other. SQL injection, command injection, deserialization, XSS and open redirects are left to the scanners, which find their sinks already. Tests, vendored, example and docs code is skipped. `--deep-path` limits it to part of the repo, and the report lists any batch that was skipped or failed, so you know what wasn't covered.

It costs far more Claude quota than a normal scan. Your largest local Rails app (1,358 handler files, 220 call sites) makes 47 calls, and it runs one call at a time, so expect hours. Use `--claude-budget` to cap it.

**The Claude budget (`--claude-budget USD`)** caps a scan's Claude usage, counted as `total_cost_usd` at API rates. With the subscription token nothing is billed, so it really caps how much of the plan's allowance one scan can use. It's checked before each call, in priority order: triage batches, then the general review, then deep-review batches. Calls after the cap is reached are skipped and listed in the report. A call already running isn't stopped, so the total can go past the cap by one call.

Claude never runs code, never tests the live app, and its results can differ between runs.

## Validation (stage 2)

Detection is only the first stage. `vulnscan validate` re-checks a finished scan's **open findings** (confirmed, needs review and not triaged — not Claude's false positives or duplicates) with [Strix](https://github.com/usestrix/strix), an open-source agentic pentesting harness. Strix runs inside its own Docker sandbox, where it reads the code, stands the app up and probes it, reporting only what it can validate with a working proof-of-concept. Its LLM is GLM 5.3 via OpenRouter.

- **Seeding:** the open findings from the scan's `report.json` become an instruction file and a workspace file, so Strix validates *your* detected issues (worst first, capped by `--max-validate`) instead of re-scanning from scratch. A rule or package Claude judged as one group is sent once, as its first hit outside tests and vendored code, so a noisy rule can't crowd out the rest. Dependencies come after everything else, and `info` findings aren't sent. Strix is asked to start each title with the ids it validates, like `[F012, C03]`, or `[new]`, and to work through the list in order.
- **Targets:** the repo is cloned by vulnscan itself and passed to Strix as a local directory, so the GitHub token never reaches Strix or its sandbox. `--url` adds a live target (e.g. the staging deployment) — only systems you are authorised to test.
- **Model:** `--model`, or `STRIX_LLM`, defaults to `openrouter/z-ai/glm-5.3`; the OpenRouter key goes in `LLM_API_KEY` (or `OPENROUTER_API_KEY`). Strix only reports a finding it could actually reproduce.
- **Outputs:** `validation.md`, `validation.json` and `validation.csv` in the same run folder, plus Strix's raw artifacts (`vulnerabilities.json`, `findings.sarif`, `penetration_test_report.md`, `run.json`) under `raw/strix/`. Validated findings get `V001…` ids and list the stage-1 ids they confirm.
- **Re-validating** the same scan writes new `V…` ids. That's refused once `vulnscan fix` has pushed branches for the scan, because they're named after the old ids. Run a new scan instead, which is also what checks the fixes.
- **`--only F003`** validates just that open finding (repeat it for several; `C01` works too, and so does any hit of a group). It adds to `validation.json` instead of replacing it: earlier validated findings keep their `V…` ids and new ones get the next ids, so it still works after fix PRs exist. A false positive, duplicate, `info` finding or unknown ID is an error (exit 2), caught before anything is cloned. Validating the same finding again adds a second `V…` id rather than replacing the first. Run one validate per scan at a time.
- **On the instance:** it runs like a scan. The wrapper gives **validate containers only** the Docker socket (Strix starts its pentest sandbox on the host daemon — the one deliberate exception to the hardened container), reads the OpenRouter key from Parameter Store, and refuses to run while it's still the placeholder. The repo copy Strix tests is placed in the run folder, on the path mounted on both sides.

```bash
vulnscan validate your-org/repo                          # latest scan, repo + GLM 5.3
vulnscan validate your-org/repo --url https://staging.example.com
vulnscan validate your-org/repo --scan-mode deep --max-validate 200
vulnscan validate your-org/repo --instruction "login: user/pass" --budget 10
vulnscan validate your-org/repo --only F003              # just one open finding (repeat --only for more)
```

Validation needs Docker running and, locally, the `strix` CLI (`curl -sSL https://strix.ai/install | bash`) and `LLM_API_KEY`. A `quick` mode run takes minutes; `deep` can take hours. On the instance the image contains Strix at a pinned version and the wrapper fetches the key from Parameter Store (`/vulnscan/openrouter-token`, [deploy/README.md](deploy/README.md#add-the-tokens)); see [docs/operations.md](docs/operations.md#run-a-validation-stage-2).

## Fixing (stage 3)

`vulnscan fix` takes the latest run with a `validation.json` (or `--run`) and opens **one draft pull request per Strix-validated finding** (`V001…`):
1. vulnscan clones the repo (org allowlist and token handling as in stage 1) and creates a branch `vulnscan/fix-<run>-<V id>` from the default branch, or from `--ref`, which must be a branch.
2. Claude Code fixes that one finding. It runs restricted, as in triage, but with **Edit and Write added**. It still has no shell, web or MCP and no GitHub token, and `--restricted` refuses writes to `.git` and settings files. It's told to make the smallest change that removes the vulnerability, and to change nothing if it can't fix it safely.
3. If Claude reports a fix and files changed, vulnscan commits as `vulnscan <vulnscan@noreply.invalid>` (git hooks never run), pushes the branch and opens a **draft** PR. The PR has Claude's summary, **steps to reproduce**, review notes and an "untested" warning. The steps are written from the validated PoC and the code, and end with the behaviour before and after the fix. They're a `curl` command against `$BASE_URL` when the issue is reachable over HTTP, and numbered steps otherwise. Hosts, credentials and secret values are always placeholders. Strix's raw PoC stays in `validation.md`.

Claude is told that a fix which breaks the app is worse than no fix:
- It must check how the app is configured and deployed before touching anything that depends on that, and prefer backwards-compatible changes. For example, it reads a secret from the environment and keeps the current value as the fallback, rather than deleting the secret.
- If the only fix can break callers or deployments, such as removing an endpoint or requiring auth, the PR is titled `[vulnscan][breaking] …` and opens with a warning.
- Steps that must happen before merging, such as "set X in every environment" or "rotate the leaked key", appear as a checklist at the top of the PR.

The rules it follows:
- **One finding per branch.** A finding Claude can't fix gets no PR.
- **Re-runs are safe.** A finding whose branch already exists on GitHub is skipped, so re-running on the same run folder never opens duplicate PRs. If opening the PR fails after the push, vulnscan deletes the branch again, so a re-run retries that finding rather than skipping it.
- **Claude sees both stages.** Besides Strix's finding and PoC, the prompt has the stage-1 findings it validates (scanner rule, location, and the triage's reason and fix). If the issue is no longer in the code, Claude changes nothing.
- **The fixes are untested.** Claude can't run the repo's code or tests, which is why the PRs are drafts.
- **Public repos are refused** unless you pass `--dry-run`, because a public branch or PR would disclose the vulnerability before the fix is merged. Fix those through a private security advisory instead.
- **`--dry-run`** commits the fixes in the throwaway clone and saves them as patches in `fix/`. It pushes nothing and opens no PRs.
- **`--only V003`** fixes just that finding; repeat it for several. An ID that isn't in the run's `validation.json` is an error (exit 2), caught before anything is cloned.
- **`fix.md` and `fix.json` keep earlier fix runs' results** on the same scan, one row per finding with the time of its fix run. A later `skipped` never replaces an earlier result, such as its PR link. If the scan is re-validated and an ID now names a different finding, that earlier result is dropped.

```bash
vulnscan fix your-org/repo                 # latest validated run, PRs against the default branch
vulnscan fix your-org/repo --dry-run       # patches only, nothing pushed
vulnscan fix your-org/repo --only V003     # just one validated finding (repeat --only for more)
vulnscan fix your-org/repo --ref release-2026-11 --model opus --run ~/.vulnscan/scans/your-org__repo/20261104-114804
```

The GitHub token must be able to push branches and open PRs: a classic PAT with `repo` and `workflow` scopes, or a fine-grained token with Contents, Pull requests and Workflows set to read and write. Without `workflow`, GitHub rejects the push of any fix that changes a file under `.github/workflows/`. On the instance the wrapper passes the same two tokens as for `scan`, and nothing else.

## Dashboard

`vulnscan dashboard` serves a read-only web page built from every run folder's `report.json`, `validation.json` and `fix.json`, read again on every request:
- **All runs:** grouped by repo, newest first. Each shows what was discovered, what's open after triage, what Strix validated, and the fixes.
- **One run:** the funnel (discovered → open → sent to Strix → validated → PRs opened), the validated `V…` findings with their fix status and PR link, and every open stage-1 finding with the `V…` ids that confirm it, or `not validated` / `not sent`.

It never shows Strix's PoCs or serves raw files, and it has no write actions. PR status is the link only; open it on GitHub to see whether it's merged.

```bash
vulnscan dashboard                 # http://localhost:8080, from $VULNSCAN_HOME/scans
vulnscan dashboard --port 9000
```

On the instance it isn't run through the wrapper. `vulnscan-build` starts it as its own container, reachable only on the instance's loopback, and you open it through Session Manager port forwarding ([docs/operations.md](docs/operations.md#view-the-dashboard)).

## Outputs

Every scan writes these files to its own folder:

| File | Contents |
|---|---|
| `report.md` | The human-readable report, in order: scan details and triage status, tool status, Claude's summary, confirmed findings (a table, then details), Claude's own findings, findings needing manual review, findings not triaged, and findings dismissed as false positive or duplicate |
| `report.csv` | One row per finding, with Claude's own findings first. For spreadsheets. |
| `report.json` | Everything: scan metadata, tool status, triage metadata, Claude's summary, every finding with its triage result, and Claude's own findings |
| `raw/<tool>.json` | Each scanner's original output |
| `claude-<n>.json`, `claude-review.json` | Claude's raw response for batch *n* and for its own review of the code, kept for audit (includes `total_cost_usd` and `num_turns`) |
| `claude-deep-ssrf-<n>.json`, `claude-deep-access-<n>.json` | With `--deep-review`: Claude's raw response for each deep-review batch. `report.json` → `deep_review` has each pass's coverage, the batches skipped or failed, and every batch's summary |
| `validation.md` / `.json` / `.csv` | Stage 2, after `vulnscan validate`: Strix's PoC-validated findings, with the stage-1 ids they confirm and a best-effort coverage list of what wasn't validated |
| `strix-instructions.md`, `strix-findings.json` | What was sent to Strix: the generated instructions and the open findings payload |
| `raw/strix/` | Strix's own artifacts for the validation run (`vulnerabilities.json`, `findings.sarif`, `penetration_test_report.md`, `run.json`) |
| `fix.md` / `fix.json` | Stage 3, after `vulnscan fix`: one row per validated finding that any fix run on this scan handled, with its status (`pr opened`, `committed (dry run)`, `not fixed`, `skipped`, `failed`), its PR link or the reason, and when it ran |
| `fix/` | Each fix's commit as `<V id>.patch`, and Claude's raw response as `claude-<V id>.json` |

`report.csv` columns:

| Column | Meaning |
|---|---|
| `id` | `F001`… for scanner findings and `C01`… for Claude's own, each in severity order. The same ids appear in `report.md`, `report.json` and the later stages. |
| `verdict` | `confirmed`, `false_positive`, `duplicate`, `needs_review`, `not triaged`, or `found by Claude` |
| `severity` | The final severity: Claude's re-rating if there is one, otherwise the scanner's |
| `scanner_severity` | The scanner's own severity, normalised |
| `tool`, `rule` | The scanner and its rule ID (for dependencies, the advisory ID, usually a CVE) |
| `category` | `code`, `dependency`, `secret` or `config` |
| `file`, `line` | Location, relative to the repo root |
| `title` | The scanner's title |
| `package`, `version`, `fixed_version` | Dependency findings only |
| `reviewed_as` | Empty when Claude reviewed this finding on its own, including a sample it judged apart from its group. Otherwise `rule-level review of N hits from 5 samples` or `package-level review of N advisories`: the verdict covers the whole group, and not every hit was checked. |
| `reason`, `fix` | Claude's explanation and suggested fix. For Claude's own findings, `reason` is the description. |
| `reference` | A link, e.g. the osv.dev advisory |

Cells that would start with `=`, `+`, `-` or `@` get a leading `'`, so spreadsheets don't run them as formulas.

## Running it locally

Requirements: Python 3.9+, git, and the [Claude Code CLI](https://code.claude.com/docs/en/setup) signed in, or `CLAUDE_CODE_OAUTH_TOKEN`. To install brakeman you also need Ruby 3.2+, and to run gosec the Go toolchain. Without those, the report shows those tools as failed and the rest still runs.

```bash
cd ~/development/vulnscan
python3 -m venv .venv && .venv/bin/pip install -e .
source .venv/bin/activate
vulnscan tools --install   # optional: install every scanner up front
```

### Commands

```bash
vulnscan scan your-org/repo                          # default branch
vulnscan scan https://github.com/your-org/repo --ref release-2026-11
vulnscan scan ~/development/some-app --no-llm        # local folder, scanners only
vulnscan scan your-org/repo --model opus             # pick Claude's model
vulnscan scan your-org/repo --max-triage 600         # let Claude review more items (default 400)
vulnscan scan your-org/repo --keep-clone             # keep the clone for debugging
vulnscan scan your-org/repo --deep-review --claude-budget 40               # whole-codebase SSRF and access-control review, capped
vulnscan scan your-org/repo --deep-review --deep-path app/controllers/api  # deep-review only part of the repo
vulnscan tools                                       # which scanners are installed
```

`repo` accepts `org/repo`, `https://github.com/org/repo`, `git@github.com:org/repo.git`, or a local path.

Exit codes:
- **0:** the scan completed, whatever it found. (Also `validate`: Strix ran and its findings were read, whatever it found. And `fix`: every finding got a PR, a dry-run commit, or was skipped or not fixable.)
- **2:** bad input, a repo outside the allowed orgs, a failed clone, or (for `validate`) no scan to validate, a missing key, or a failed Strix run. For `fix`: no validated run, a local folder, a public repo without `--dry-run`, no GitHub token, or any finding that failed (`fix.md` is still written).
- **130:** interrupted.

### Settings (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `GITHUB_TOKEN` | none | Token that can read the repos. A classic PAT with `repo` scope covers every org its user can read; a fine-grained or GitHub App token with read-only Contents covers one owner. `vulnscan fix` also needs write access to Contents and Pull requests, plus the `workflow` scope (fine-grained: Workflows) to push fixes to GitHub Actions workflows. Passed to git through the environment, never written to `.git/config`. |
| `GITHUB_TOKEN_<ORG>` | none | Per-org token, used instead of `GITHUB_TOKEN` for that org's repos. The name is the org in upper case with `-` changed to `_`, e.g. `GITHUB_TOKEN_SCALER_HQ`. |
| `VULNSCAN_GITHUB_ORG` | none (any owner) | Comma-separated orgs whose repos may be scanned; anything else is refused. Not case-sensitive. |
| `CLAUDE_CODE_OAUTH_TOKEN` | none | Claude authentication on a server (`claude setup-token`). Not needed where Claude Code is already signed in. |
| `VULNSCAN_HOME` | `~/.vulnscan` | Where tools, clones and reports go |
| `VULNSCAN_TOOL_TIMEOUT` | `1800` | Seconds before each scanner is stopped |
| `VULNSCAN_TRIAGE_TIMEOUT` | `3600` | Seconds before each Claude batch, or each `fix` of one finding, is stopped |
| `VULNSCAN_TRIAGE_BATCH` | `100` | Items per Claude call. Smaller values mean more calls. |
| `LLM_API_KEY` | none | OpenRouter key for stage-2 validation (Strix + GLM 5.3). `OPENROUTER_API_KEY` also works. |
| `STRIX_LLM` | `openrouter/z-ai/glm-5.3` | Model id for Strix, LiteLLM format. `--model` overrides it. |
| `VULNSCAN_VALIDATE_TIMEOUT` | `7200` | Seconds before a Strix validation run is stopped |
| `VULNSCAN_VALIDATE_BUDGET` | `25` | Max LLM spend in USD for one validation run (`--budget`, `0` = no cap) |

## How long a scan takes

- **Small repo** (about 100 findings): scanners take about 15 s, Claude 3–5 minutes.
- **Large Rails monolith** (63k files, 1.6 GB, about 7,700 findings):
  - clone: about 3.5 minutes;
  - semgrep: more than 10 minutes on 2 vCPUs, so raise `VULNSCAN_TOOL_TIMEOUT`;
  - Claude: 4 batches of 100 items. Not yet timed on a repo this size; in testing, a batch with the code review took 2.5 minutes for 15 items.

## Coverage limits

- **Only one branch,** the default or `--ref`, and only its latest commit. Secrets that were committed and later deleted are still in git history but aren't found.
- **Validation coverage is best effort.** Strix only reports what it could reproduce, which is the point; but an issue it couldn't reach (an app it couldn't stand up, a URL that needs auth you didn't supply) stays unvalidated. The stage-1 findings it references come from the `[F012]` tag in its titles; a title without one falls back to any id in its text.
- **The prompt-injection check matches patterns.** It finds the common phrasings and hidden characters, not every way to word an instruction, and an app's own LLM prompts can match (Claude dismisses those). Claude's review covers the rest as far as it reads.
- **Static analysis only.** Nothing is run or tested against a live app, and business-logic flaws are mostly out of reach.
- **Claude's verdicts are judgements, not proof.** A grouped rule is judged from 5 samples.
- **Claude's own review is capped at 10 issues** and is shallow on large repos ([What Claude does](#what-claude-does)). `--deep-review` covers the whole codebase, but only for SSRF and access control, and only the call sites and handler files its patterns recognise.
- **When run directly, scanner versions are unpinned (latest).** The Docker image pins them.
- **No scheduling or alerting yet** ([docs/status.md](docs/status.md)).

## Security model

The scanner holds read access to your code and produces a list of its weaknesses, so it's locked down:
- **It never runs the scanned repo's code.** No `bundle install` or `npm install`; scanners read source and lockfiles only.
- **Scanners get a stripped-down environment.** `GITHUB_TOKEN*`, `CLAUDE_CODE_OAUTH_TOKEN`, `AWS_*` and anything else not on the allowlist in `config.py` are withheld.
- **Claude is read-only.** `claude -p --restricted --tools Read,Grep,Glob --strict-mcp-config`: no shell, no file writes, no web, no MCP servers. Its working directory is the scan's output folder, so the repo's `.claude/` settings and hooks never load. The prompt tells it to treat repo content as untrusted data. GitHub tokens are removed from its environment.
- **Except in `vulnscan fix`,** where Claude may also Edit and Write, inside a throwaway clone and the run's `fix/` folder only. It still has no shell, web, MCP or token, and `--restricted` refuses writes to `.git` and settings files. vulnscan commits and pushes. Repo content could still steer the change Claude writes, which is why every PR is a draft that a person must review. The PRs never go to public repos. They include reproduction steps with placeholders, but never Strix's raw PoC.
- **Secret values are redacted** by gitleaks before they reach disk, and every Claude prompt forbids copying a secret's value, even partly, into its answer.
- **Prompt injection aimed at vulnscan itself:** Claude and Strix are told to treat repo content as data, and the prompt-injection check reports text in the repo that tries to steer them.
- **Files are private.** Everything is created readable by the current user only (umask 077).
- **The org restriction** (`VULNSCAN_GITHUB_ORG`) stops it being pointed at arbitrary repos.
- **Validation runs inside Strix's own Docker sandbox,** which is the one place the scanned repo's code may run — deliberately, because PoC validation needs it. vulnscan clones the repo itself and passes a local directory, so the GitHub token never reaches Strix; Strix gets only its own `LLM_API_KEY`, and `--url` targets are the operator's responsibility to authorise. Local folders and stage-1 clones are copied first, because Strix mounts targets writable.
- **The dashboard can't change anything and holds no tokens.**
  - Findings quote repo content, so every value is escaped and the page has no JavaScript. A Content-Security-Policy blocks scripts and loads from anywhere else.
  - Requests whose `Host` isn't localhost are refused, which stops DNS rebinding from another site in your browser.
  - On the instance it's published on the loopback only, so seeing it takes the same Session Manager access as a shell.
- **In production:** each scan runs in a container with no AWS credentials or Linux capabilities, on an instance that has no inbound access, allows outbound HTTPS only, and can read only its own three tokens ([deploy/README.md](deploy/README.md)). Validate containers additionally get the host Docker socket — the exception above, given to no other run.

## Adding a scanner

Create a module in `vulnscan/tools/` and add an instance to `ALL_TOOLS` in `vulnscan/tools/__init__.py`. To use it in production, also install it at a pinned version in the `Dockerfile`. See [docs/architecture.md](docs/architecture.md#scanners) for the full contract.

```python
class Pipaudit(Tool):
    name = "pip-audit"
    command = "pip-audit"
    install = [("pip", "pip-audit")]
    applies_to = "Python"

    def targets(self, repo, stacks):
        return stacks.get("python", [])        # [] = skip this repo

    def args(self, exe, target, report):
        return [exe, "-r", "requirements.txt", "-f", "json", "-o", str(report)]

    def parse(self, data, repo, target):
        return [Finding(...) for dep in data["dependencies"] for v in dep["vulns"]]
```
