# vulnscan (POC)

Give it a GitHub repo, or a local folder, and it finds security problems. It:
- works out the stacks the repo uses;
- runs the security scanners that fit;
- merges their results;
- uses Claude Code to check the findings against the actual code and look for issues scanners miss.

It writes a Markdown report, JSON and CSV.

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
| Issues scanners miss | Claude's own code review | SSRF, missing authorization and IDOR, authentication bypass, mass assignment. See [What Claude does](#what-claude-does) for limits. |

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

A stack without its own scanner still gets semgrep, osv-scanner, gitleaks and Claude.

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

For dependencies it checks whether the package, and any vulnerable function an advisory names, is actually used.

Findings are grouped and prioritised first, so the important ones are reviewed even in repos with thousands of findings:
- **Dependencies:** each vulnerable package version is one item, covering all its advisories and lockfiles.
- **Repeated rules:** a rule with more than 10 hits is one item, judged from 5 sample locations. Brakeman warnings are never grouped, because each is tied to a specific location.
- **Order:** critical and high come first. Within each severity band: secrets, then code, then configuration, then dependencies.
- **Limits:** Claude reviews 100 items per call, up to 400 items per scan (`--max-triage`). Anything beyond that is listed as "Not triaged".

**2. Its own review: limited.** In the first batch only, Claude also looks for up to 10 high-impact issues scanners usually miss, starting from routes and controllers. On small repos this finds real issues; in testing it found an SSRF, a `pickle.loads` remote code execution and controllers without authentication. On large monoliths it can only read a small part of the code, so coverage there comes mostly from the scanners.

Claude never runs code, never tests the live app, and its results can differ between runs.

## Outputs

Every scan writes these files to its own folder:

| File | Contents |
|---|---|
| `report.md` | The human-readable report, in order: scan details and triage status, tool status, Claude's summary, confirmed findings (a table, then details), Claude's own findings, findings needing manual review, findings not triaged, and findings dismissed as false positive or duplicate |
| `report.csv` | One row per finding, with Claude's own findings first. For spreadsheets. |
| `report.json` | Everything: scan metadata, tool status, triage metadata, Claude's summary, every finding with its triage result, and Claude's own findings |
| `raw/<tool>.json` | Each scanner's original output |
| `claude-<n>.json` | Claude's raw response for batch *n*, kept for audit (includes `total_cost_usd` and `num_turns`) |

`report.csv` columns:

| Column | Meaning |
|---|---|
| `id` | `F001`… for scanner findings, in severity order; `C01`… for Claude's own findings |
| `verdict` | `confirmed`, `false_positive`, `duplicate`, `needs_review`, `not triaged`, or `found by Claude` |
| `severity` | The final severity: Claude's re-rating if there is one, otherwise the scanner's |
| `scanner_severity` | The scanner's own severity, normalised |
| `tool`, `rule` | The scanner and its rule ID (for dependencies, the advisory ID, usually a CVE) |
| `category` | `code`, `dependency`, `secret` or `config` |
| `file`, `line` | Location, relative to the repo root |
| `title` | The scanner's title |
| `package`, `version`, `fixed_version` | Dependency findings only |
| `reviewed_as` | Empty when Claude reviewed this finding on its own. Otherwise `rule-level review of N hits from 5 samples` or `package-level review of N advisories`: the verdict covers the whole group, and not every hit was checked. |
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
vulnscan tools                                       # which scanners are installed
```

`repo` accepts `org/repo`, `https://github.com/org/repo`, `git@github.com:org/repo.git`, or a local path.

Exit codes:
- **0:** the scan completed, whatever it found.
- **2:** bad input, a repo outside the allowed orgs, or a failed clone.
- **130:** interrupted.

### Settings (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `GITHUB_TOKEN` | none | Token that can read the repos. A classic PAT with `repo` scope covers every org its user can read; a fine-grained or GitHub App token with read-only Contents covers one owner. Passed to git through the environment, never written to `.git/config`. |
| `GITHUB_TOKEN_<ORG>` | none | Per-org token, used instead of `GITHUB_TOKEN` for that org's repos. The name is the org in upper case with `-` changed to `_`, e.g. `GITHUB_TOKEN_SCALER_HQ`. |
| `VULNSCAN_GITHUB_ORG` | none (any owner) | Comma-separated orgs whose repos may be scanned; anything else is refused. Not case-sensitive. |
| `CLAUDE_CODE_OAUTH_TOKEN` | none | Claude authentication on a server (`claude setup-token`). Not needed where Claude Code is already signed in. |
| `VULNSCAN_HOME` | `~/.vulnscan` | Where tools, clones and reports go |
| `VULNSCAN_TOOL_TIMEOUT` | `1800` | Seconds before each scanner is stopped |
| `VULNSCAN_TRIAGE_TIMEOUT` | `3600` | Seconds before each Claude batch is stopped |
| `VULNSCAN_TRIAGE_BATCH` | `100` | Items per Claude call. Smaller values mean more calls. |

## How long a scan takes

- **Small repo** (about 100 findings): scanners take about 15 s, Claude 3–5 minutes.
- **Large Rails monolith** (63k files, 1.6 GB, about 7,700 findings):
  - clone: about 3.5 minutes;
  - semgrep: more than 10 minutes on 2 vCPUs, so raise `VULNSCAN_TOOL_TIMEOUT`;
  - Claude: 4 batches of 100 items. Not yet timed on a repo this size; in testing, a batch with the code review took 2.5 minutes for 15 items.

## Coverage limits

- **Only one branch,** the default or `--ref`, and only its latest commit. Secrets that were committed and later deleted are still in git history but aren't found.
- **Static analysis only.** Nothing is run or tested against a live app, and business-logic flaws are mostly out of reach.
- **Claude's verdicts are judgements, not proof.** A grouped rule is judged from 5 samples.
- **Claude's own review is capped at 10 issues** and is shallow on large repos ([What Claude does](#what-claude-does)).
- **When run directly, scanner versions are unpinned (latest).** The Docker image pins them.
- **No scheduling or alerting yet** ([docs/status.md](docs/status.md)).

## Security model

The scanner holds read access to your code and produces a list of its weaknesses, so it's locked down:
- **It never runs the scanned repo's code.** No `bundle install` or `npm install`; scanners read source and lockfiles only.
- **Scanners get a stripped-down environment.** `GITHUB_TOKEN*`, `CLAUDE_CODE_OAUTH_TOKEN`, `AWS_*` and anything else not on the allowlist in `config.py` are withheld.
- **Claude is read-only.** `claude -p --restricted --tools Read,Grep,Glob --strict-mcp-config`: no shell, no file writes, no web, no MCP servers. Its working directory is the scan's output folder, so the repo's `.claude/` settings and hooks never load. The prompt tells it to treat repo content as untrusted data. GitHub tokens are removed from its environment.
- **Secret values are redacted** by gitleaks before they reach disk.
- **Files are private.** Everything is created readable by the current user only (umask 077).
- **The org restriction** (`VULNSCAN_GITHUB_ORG`) stops it being pointed at arbitrary repos.
- **In production:** each scan runs in a container with no AWS credentials or Linux capabilities, on an instance that has no inbound access, allows outbound HTTPS only, and can read only its own two tokens ([deploy/README.md](deploy/README.md)).

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
