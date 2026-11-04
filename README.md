# vulnscan (POC)

Point it at one of your org's GitHub repos. It works out the stack, installs the right security scanners, runs them, then has Claude Code check every finding against the actual code and look for issues scanners miss. The report is saved on the machine.

```
vulnscan scan your-org/some-repo
```

## How it works

1. **Clone**: shallow, read-only clone into `~/.vulnscan/work`, deleted after the scan. A local directory also works.
2. **Detect**: finds stacks from marker files (`Gemfile` + `config/application.rb` means Rails, `go.mod` means Go, `*.tf`/`Dockerfile` means IaC, and so on).
3. **Install**: installs any scanner that's missing into `~/.vulnscan/tools`, isolated from the rest of the system (pip tools get their own virtualenv, gems go to their own directory, GitHub release binaries are checked against the release checksums).
4. **Scan**: runs every scanner that applies and converts their output into one finding format.
5. **Triage**: Claude Code gives each finding a verdict (confirmed / false positive / duplicate / needs review), re-rates its severity, suggests a fix, and reviews entry points for SSRF, missing authorization, IDOR and similar issues. On big repos the findings are first grouped and prioritised:
   - **Dependencies:** each vulnerable package version is one item, covering all its advisories and lockfiles.
   - **Repeated rules:** a rule with more than 10 hits is one item, judged from 5 sample locations. Brakeman warnings are never grouped.
   - **Order:** critical/high secrets and code first, then config, then dependencies.
   - **Batches:** Claude reviews 100 items per call. Only the first call also reviews the code for issues the scanners missed.
6. **Report**: writes to `~/.vulnscan/scans/<org>__<repo>/<timestamp>/`:
   - `report.md`: for people
   - `report.json`: every finding with its triage result
   - `report.csv`: the same, one row per finding, for spreadsheets
   - `raw/`: each scanner's original output
   - `claude-<batch>.json`: the raw Claude responses, for audit

| Scanner | Runs on | Installed via |
|---|---|---|
| semgrep | every repo (code, 30+ languages) | pip |
| osv-scanner | every repo (dependency lockfiles, all ecosystems) | GitHub release |
| gitleaks | every repo (hardcoded secrets) | GitHub release |
| checkov | Terraform, Dockerfiles, GitHub Actions, Helm | pip |
| brakeman | Rails apps | gem |
| bandit | Python | pip |
| gosec | Go modules | GitHub release |

A stack with no specific scanner still gets semgrep, osv-scanner, gitleaks and Claude's review.

## Setup

Requirements: Python 3.9+, git, and the [Claude Code CLI](https://code.claude.com/docs/en/setup). Ruby is needed to install Brakeman (Rails repos), and the Go toolchain for gosec (Go repos).

```bash
cd ~/development/vulnscan
python3 -m venv .venv && .venv/bin/pip install -e .
source .venv/bin/activate

vulnscan tools --install   # optional: install every scanner up front
```

### Credentials

| Variable | Purpose |
|---|---|
| `CLAUDE_CODE_OAUTH_TOKEN` | Claude auth on a server. Generate it with `claude setup-token`. Not needed on a machine already logged in to Claude Code. |
| `GITHUB_TOKEN` | Token that can read the repos to scan. A classic PAT with `repo` scope covers every org its user can read; a fine-grained or GitHub App token with **read-only Contents** covers one owner. Passed to git through the environment, never written to `.git/config`. |
| `GITHUB_TOKEN_<ORG>` | Per-org token, used instead of `GITHUB_TOKEN` for that org's repos. The name is the org in upper case with `-` changed to `_`: `GITHUB_TOKEN_SCALER_HQ` for `scaler-hq`. Needed for more than one org, because a fine-grained token only reaches one owner's repos. |
| `VULNSCAN_GITHUB_ORG` | Refuses to scan repos outside these orgs (comma-separated, e.g. `KingsGambitLab,scaler-hq`). |

Other settings: `VULNSCAN_HOME` (default `~/.vulnscan`), `VULNSCAN_TOOL_TIMEOUT` (default 1800s per scanner), `VULNSCAN_TRIAGE_TIMEOUT` (default 3600s).

On a server, keep these in a root-owned env file with mode `600` (or fetch them from Parameter Store under a path only this instance's role can read), not in shell history.

## Usage

```bash
vulnscan scan your-org/repo                          # default branch
vulnscan scan https://github.com/your-org/repo --ref release-2026-11
vulnscan scan ~/development/some-app --no-llm        # local dir, scanners only
vulnscan scan your-org/repo --model opus             # pick the triage model
vulnscan scan your-org/repo --max-triage 600         # let Claude review more items (default 400)
vulnscan tools                                       # what's installed
```

A scan of a small multi-stack repo takes about 5 minutes; nearly all of that is Claude reading code.

## Security model

The scanner holds read access to your code and a list of your weaknesses, so it's locked down:

- **Never runs the repo's code.** No `bundle install` or `npm install`; the scanners read source and lockfiles only.
- **Scanners get a stripped-down environment.** `GITHUB_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN`, `AWS_*` and anything else not on the allowlist in `config.py` are withheld from them.
- **Claude runs read-only.** It runs `claude -p --restricted --tools Read,Grep,Glob --strict-mcp-config`: no shell, no file writes, no web, no MCP servers. Its working directory is the scan output folder and the repo is added with `--add-dir`, so the repo's `.claude/` settings and hooks are never loaded. The prompt tells Claude to treat repo content as untrusted data.
- **Gitleaks redacts secrets**, so secret values never reach disk.
- **Private files.** Everything is created readable by the current user only (umask 077).

## Adding a scanner

Create a module in `vulnscan/tools/` and add an instance to `ALL_TOOLS` in `vulnscan/tools/__init__.py`:

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

## Known limitations (POC)

- **Scanner versions are unpinned (latest) when run directly.** The Docker image pins every scanner by version and checksum; see [deploy/README.md](deploy/README.md) for the EC2 setup.
- **Scanners run on the host when run directly.** The EC2 deployment runs each scan in a fresh container with no AWS access.
- **Claude auth uses a personal subscription token.** It's tied to one person's plan and usage limits. Switching to Amazon Bedrock (`CLAUDE_CODE_USE_BEDROCK=1` plus the instance IAM role, so there's no static secret) or an Anthropic API key needs no code change, because Claude Code reads both from the environment.
- **No scheduling or alerting yet.** Nightly re-scans are what catch newly published CVEs in existing lockfiles. A stopgap is a cron job running `vulnscan scan`, followed by grepping `report.json` for confirmed `critical`/`high` findings.
- **Claude reviews at most 400 items per scan.** Raise the limit with `--max-triage`; items beyond it appear in the report as "Not triaged". A grouped rule is judged from 5 samples, so a confirmed group doesn't mean every hit was checked. Its `reviewed_as` column in `report.csv` says so.
