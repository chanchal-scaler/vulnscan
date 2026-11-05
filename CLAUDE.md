# vulnscan: guide for agents

vulnscan is a Python CLI that scans one GitHub repo for security issues:
- It detects the repo's stacks and runs the scanners that fit (semgrep, osv-scanner, gitleaks, checkov, brakeman, bandit, gosec), plus its own built-in check for prompt injection planted in the repo.
- It merges their output into one finding format.
- It uses Claude Code (headless, read-only), pinned to Claude Opus 5.5 (`config.CLAUDE_MODEL`), to verify the findings and look for issues scanners miss. With `--deep-review` (opt-in, costly in quota), Claude also checks every outbound HTTP call for SSRF and every request handler for access control, in batches vulnscan decides. `--claude-budget` caps a scan's Claude usage.
- `vulnscan validate` (stage 2) re-checks a scan's open findings with Strix, whose agents run in Strix's own Docker sandbox and report only findings with a working PoC; its LLM is GLM 5.3 via OpenRouter.
- `vulnscan fix` (stage 3) has Claude Code fix each Strix-validated finding in a throwaway clone, then opens one draft PR per finding.
- It writes `report.md`, `report.json` and `report.csv` (plus `validation.*` after stage 2 and `fix.*` after stage 3).
- `vulnscan dashboard` serves a read-only web page that tracks each run's findings through the three stages. On the instance it runs in its own container, reached through Session Manager port forwarding.

It runs as a proof of concept on one EC2 Spot instance in a staging AWS account, with each scan in a throwaway Docker container.

## Read before changing anything

| Doc | Contents |
|---|---|
| [README.md](README.md) | What it finds, Claude's role, outputs and CSV columns, CLI and settings, security model, limits |
| [docs/architecture.md](docs/architecture.md) | Code layout, how a scan flows, the triage pipeline, the validation stage, report formats, image and Terraform contents |
| [docs/decisions.md](docs/decisions.md) | Why things are the way they are, including approaches that were tried and rejected. Check here before "improving" something. |
| [deploy/README.md](deploy/README.md) | What Terraform creates, first-time deployment, maintenance |
| [docs/operations.md](docs/operations.md) | Runbook: connect, build, scan, read and copy results, health checks, troubleshooting |
| [docs/testing.md](docs/testing.md) | How to test a change at each level before it reaches the instance |
| [docs/status.md](docs/status.md) | What's deployed and verified, known issues, backlog |
| `deploy/terraform/ENVIRONMENT.local.md` | Account, AWS profile and resource IDs for the live deployment. Gitignored, and only on the operator's machine. If it's missing, ask the owner. |

## Working agreements (from the owner)

- **Never commit or push.** The owner commits. When you finish, list the changed files.
- **Ask before any infrastructure or data change:** `terraform apply`, AWS write calls, changes on the instance beyond running vulnscan, and edits to shared account settings. Read-only work needs no approval: `terraform plan`, `describe-*`/`get-*` calls, and read-only commands on the instance.
- **Keep changes minimal.** Don't refactor or add features nobody asked for. Ask a clarifying question when a request is vague.
- **The GitHub repo is public.** Never commit account IDs, resource IDs, tokens, `terraform.tfvars`, Terraform state, `*.local.md`, or scan results. Scan results describe vulnerabilities in private company code.

## How a change reaches production

1. Edit and test locally ([docs/testing.md](docs/testing.md)).
2. The owner pushes to `main` on GitHub.
3. On the instance, `vulnscan-build` clones `main` and rebuilds the Docker image. It restarts the dashboard container and reinstalls the `vulnscan` wrapper and itself from `deploy/host/`. A change to `vulnscan-build` takes effect from the run after the one that installs it.
4. Terraform changes are planned and, after the owner approves, applied from the operator's machine. Its state is local there.

The first-boot script (`user_data.sh.tftpl`) only runs when an instance is created. Changes to it need `terraform apply -replace=aws_instance.this`, which keeps the reports volume.

## Common commands

```bash
python3 -m venv .venv && .venv/bin/pip install -e .   # local setup (Python 3.9+, stdlib only)
.venv/bin/python -m compileall -q vulnscan             # syntax check
.venv/bin/vulnscan scan OWASP/railsgoat --no-llm       # scanners only, on a public vulnerable app
LLM_API_KEY=sk-or-… .venv/bin/vulnscan validate OWASP/railsgoat   # stage 2 (needs Docker + strix CLI)
.venv/bin/vulnscan fix OWASP/railsgoat --dry-run       # stage 3; public repos only with --dry-run (no push, no PR)
.venv/bin/vulnscan dashboard                           # read-only tracking page on http://localhost:8080
docker build -t vulnscan:test .                        # the production image
cd deploy/terraform && terraform fmt && terraform validate
AWS_PROFILE=<profile> terraform plan                   # read-only; profile is in ENVIRONMENT.local.md
```

## Invariants: don't break these

- **Scanners never get secrets.** They run with `config.scanner_env()`, an allowlist of environment variables. The built-in prompt-injection check (`tools/prompt_injection.py`) is our own code and runs in-process, but only reads files.
- **The scanned repo can't switch off its own findings.** Scanners ignore its suppression comments and config (`nosemgrep`, `# nosec` and `.bandit`, `gitleaks:allow` and `.gitleaks.toml`, `config/brakeman.yml`), and report what its ignore files hide (`config/brakeman.ignore`, `checkov:skip`). Where no flag exists (`.gitleaksignore`, `.checkov.yaml`), the file itself becomes a finding. Claude treats a suppression as the repo's claim, not proof.
- **Never copy a secret's value into Claude's output.** Every prompt says so: report.md, report.csv, the dashboard and PRs quote what Claude writes.
- **Claude runs restricted.** It runs as `claude -p --restricted --strict-mcp-config --tools Read,Grep,Glob`, with the run folder (not the repo) as its working directory, so the repo's `.claude/` settings and hooks never load. Every `GITHUB_TOKEN*` and `GH_TOKEN*` variable is removed from its environment. **Exception:** `vulnscan fix` adds `Edit,Write` and `--permission-mode acceptEdits`, on a throwaway clone, and still gives Claude no shell, web or MCP and no token. `--restricted` still refuses writes to `.git` and settings files. vulnscan, not Claude, commits, pushes and opens the PR.
- **`vulnscan fix` opens draft PRs only, never on public repos** (a branch would disclose the vulnerability before the fix is merged), and never runs git hooks (`core.hooksPath=/dev/null`). The PR body has Claude's reproduction steps, with placeholders for hosts, credentials and secret values. Strix's raw PoC stays out, because it can carry operator-supplied credentials or live URLs.
- **The scanned repo's code and dependencies are never run or installed** in the vulnscan process or its container. No `bundle install` or `npm install`. The one deliberate exception: stage-2 validation, where Strix runs the code inside **Strix's own Docker sandbox** — never in the vulnscan container — against a throwaway clone or copy (Strix mounts targets writable).
- **The GitHub token never reaches Strix.** `vulnscan validate` clones the repo itself (org allowlist, `GIT_CONFIG_*`) and passes a local directory; Strix's environment holds only `STRIX_LLM`, `LLM_API_KEY` and what it needs to reach Docker.
- **GitHub tokens reach git only through `GIT_CONFIG_*` environment variables,** never in a URL, on a command line or in `.git/config`. The one other use is `fix.py`'s in-process GitHub API calls (`Authorization` header).
- **Container hardening.** The container has no AWS access (IMDS hop limit 1). It runs with `--cap-drop ALL` and `no-new-privileges`, as uid 10001, with only the reports directory mounted. **Exception:** `vulnscan validate` containers also get the host Docker socket (with its group id), because Strix must start its sandbox containers on the host daemon. The wrapper gives it to no other subcommand.
- **The dashboard is read-only and has no tokens.**
  - Its container, started by `vulnscan-build`, mounts the scans read-only and has the usual hardening plus `--read-only`.
  - It's on its own Docker network and published on the host's `127.0.0.1` only, never on an inbound rule.
  - It refuses any `Host` but localhost, escapes every value, sends a CSP that allows no scripts, serves no raw files and never shows Strix's PoCs.
  - The wrapper refuses to run it, because the wrapper would hand it the tokens.
- **Instance role.** Session Manager plus `ssm:GetParameter` on `/vulnscan/*`, nothing else. Never attach `AmazonSSMManagedInstanceCore`: it can read every parameter in the account.
- **Outbound traffic from the instance is TCP 443 only.** Everything a build or scan downloads must use HTTPS.
- **Token parameters use `value_wo`,** so their values never enter Terraform state.
- **Every binary in the Dockerfile is pinned** by version and SHA-256 for both amd64 and arm64.
- **CSV values go through `report._csv_value`,** which guards against spreadsheet formula injection, because findings quote repo content.

## Gotchas

- The operator's shell is zsh, where `$VAR` holding several words isn't split. Use arrays, or run the snippet under `bash`.
- Session Manager:
  - Running commands on the instance non-interactively from a script needs a pseudo-terminal.
  - The commands run without a shell, so wrap any shell syntax in `bash -c '...'`.
  - The pattern is in [docs/operations.md](docs/operations.md#running-commands-on-the-instance-from-a-script).
- Session Manager sessions end after 60 minutes, so scans run in detached containers. Never make the wrapper run scans in the foreground.
- T3/T4g instances get no launch credits. In `standard` credit mode a new instance is throttled to 30% CPU, which is why it's `unlimited`.
