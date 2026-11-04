# Architecture

How the code works, from one scan's point of view, plus the container image, host scripts and Terraform. For the reasons behind each choice, see [decisions.md](decisions.md).

## Repository layout

```
vulnscan/                  Python package (stdlib only, Python 3.9+)
  cli.py                   argparse entry point: `vulnscan scan`, `vulnscan tools`; sets umask 077
  scan.py                  orchestration: checkout → detect → run scanners → triage → reports
  repo.py                  parse org/repo or URL, enforce the org allowlist, shallow clone with token, cleanup
  detect.py                stack detection from marker files
  installer.py             finds scanners on PATH or installs them (pip venv, gem, GitHub release with checksum)
  findings.py              Finding dataclass, severity normalisation, sort order
  triage.py                groups findings into items, batches them, runs headless Claude, maps verdicts back
  validate.py              stage 2: seeds a scan's open findings into Strix (GLM via OpenRouter), collects its artifacts, writes validation reports
  fix.py                   stage 3: Claude fixes each validated finding on its own branch; vulnscan pushes it and opens a draft PR
  report.py                writes report.json, report.csv and report.md
  config.py                paths, timeouts, batch size, scanner environment allowlist, logging
  tools/                   one module per scanner, all built on tools/base.py
Dockerfile                 production image: every runtime and scanner pinned by version and SHA-256
deploy/host/vulnscan       wrapper on the instance: fetch tokens, run a detached hardened container, stream logs
deploy/host/vulnscan-build fetch the vulnscan source from GitHub, build the image, install the wrapper
deploy/terraform/          AWS: subnet, route, security group, IAM, Spot instance, reports volume, token parameters
docs/                      this documentation
```

## One scan, step by step (`scan.scan`)

1. **Checkout** (`repo.checkout`):
   - A local folder is used as it is.
   - Otherwise `parse_github` accepts `org/repo`, an `https://github.com/...` URL or a `git@github.com:...` URL. Repos outside `VULNSCAN_GITHUB_ORG` are rejected with `RepoError`, which exits with code 2.
   - The repo is cloned with `git clone --depth 1 [--branch REF]` into `mkdtemp()` under `$VULNSCAN_HOME/work`, and deleted at the end unless `--keep-clone` is set.
   - **Auth:** the token is `GITHUB_TOKEN_<OWNER>` (owner upper-cased, non-word characters changed to `_`) or else `GITHUB_TOKEN`. It reaches git as a Basic `x-access-token` header through `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_0`/`GIT_CONFIG_VALUE_0`.
   - `GIT_TERMINAL_PROMPT=0` and `GIT_LFS_SKIP_SMUDGE=1` are always set.
2. **Run folder:** `$VULNSCAN_HOME/scans/<label with / replaced by __>/<UTC %Y%m%d-%H%M%S>/raw/`.
3. **Detect** (`detect.detect_stacks`):
   - It walks the tree, skipping `.git`, `node_modules`, `vendor`, virtualenvs, `dist`, `build`, `tmp`, `log`, `coverage`, `.terraform`, `target` and `.next`.
   - It returns `{stack: [folders]}`. `ruby`, `go`, `javascript`, `java`, `php`, `rust` and `rails` map to each project root; `python` and `iac` map to the repo root.
4. **Scanners** (`scan._run_tools`):
   - For each tool in `tools.ALL_TOOLS`: `targets()` returns the folders to scan, and an empty list means "not applicable".
   - `installer.ensure()` finds or installs the executable.
   - `Tool.run()` runs it once per target, writing `raw/<tool>[__<relative path>].json`.
   - Exceptions are caught for each target, so one broken tool never stops the scan.
   - Each tool's status (`ok`, `failed`, `not applicable` or `install failed`), count and errors go into the report.
5. **Sort and number:** findings are sorted by `findings.sort_key` (final severity, then file, then line) and numbered `F001…`.
6. **Triage** (unless `--no-llm`): `triage.triage(non-info findings, …, max_items)` sets `f.triage` on each reviewed finding and returns the summary, Claude's own findings and the triage metadata. Findings are then re-sorted, since severities may have changed.
7. **Reports:** `report.write_reports()` writes the three report files. The CLI prints open counts by severity (from `severity_counts`, which excludes false positives and duplicates and includes Claude's own findings) and the report path.

## Findings (`findings.py`)

`Finding` fields:

| Field | Meaning |
|---|---|
| `tool`, `rule_id`, `title` | Which scanner, which rule, and its message |
| `severity` | `critical`, `high`, `medium`, `low` or `info` |
| `category` | `code`, `dependency`, `secret` or `config` |
| `file`, `line` | Location relative to the repo root |
| `description`, `references` | Extra detail and links |
| `package`, `version`, `fixed_version` | Dependency findings only |
| `id` | `F001`… |
| `triage` | Claude's verdict (see below), or `None` |

Supporting functions:
- **`normalize_severity`** maps scanner words to the scale: `error`→high, `warning`/`moderate`→medium, `note`/`weak`→low, `none`→info. Anything unknown becomes medium.
- **`severity_from_cvss`** maps scores: ≥9 critical, ≥7 high, ≥4 medium, otherwise low.
- **`final_severity`** is Claude's severity if set, otherwise the scanner's.

## Scanners

The `tools/base.py` contract a scanner class fills in:

| Attribute or method | Meaning |
|---|---|
| `name`, `command` | Display name, and the executable to find or install |
| `install` | `[(strategy, spec)]`, tried in order: `("pip", "pkg")`, `("gem", "pkg")`, `("github", "owner/repo")` |
| `applies_to` | Text shown by `vulnscan tools` |
| `ok_exit_codes` | Exit codes that mean success. Many scanners exit 1 when they find something. |
| `nothing_to_scan_codes` | Exit codes that mean "nothing for me here"; these return no findings |
| `stdout_is_report` | The tool prints JSON to stdout instead of writing a file |
| `targets(repo, stacks)` | Folders to scan; `[]` means skip |
| `args(exe, target, report)` | The command line |
| `parse(data, repo, target)` | Parsed JSON → `[Finding]` |

How `run()` behaves:
- It runs the command with `cwd=target`, the allowlisted environment from `config.scanner_env()`, and `TOOL_TIMEOUT`.
- It raises `ToolError` on an unexpected exit code, or if no report was produced. A missing report usually means a missing runtime, e.g. gosec without Go.
- JSON with log lines in front of it is tolerated.

| Tool | Runs on | Command | Severity from | Category |
|---|---|---|---|---|
| semgrep | repo root | `semgrep scan --config p/default --json --output R --metrics off --quiet --disable-version-check T` | rule severity | code |
| osv-scanner | repo root | `osv-scanner scan source --recursive --format json --output-file R T`; exit 128 means no lockfiles | CVSS `max_severity`, else the database severity | dependency |
| gitleaks | repo root | `gitleaks dir T --report-format json --report-path R --redact --no-banner --exit-code 0 --log-level error` | always high | secret |
| checkov | repo root, if `iac` detected | `checkov -d T -o json --quiet --compact --soft-fail --skip-download` (stdout) | check severity, else medium | config |
| brakeman | each Rails root | `brakeman T -f json -o R -q --no-pager --no-exit-on-warn --no-exit-on-error` | confidence: High→high, Medium→medium, Weak→low | code |
| bandit | repo root, if `python` detected | `bandit -r T -f json -o R -q -x <node_modules, venvs, tests>` | issue severity | code |
| gosec | each Go module root | `gosec -fmt=json -out=R -no-fail -quiet ./...` (needs Go) | severity | code |

Details per scanner:
- **osv-scanner:** one finding per advisory group. The ID is the CVE alias if there is one; the title is `package version: summary`; the fix version comes from the `affected` ranges.
- **gosec:** line ranges such as `12-14` keep their first line.

**Installer** (`installer.py`), used for local runs:
- `find()` looks in `$VULNSCAN_HOME/tools/bin` first, then on `PATH`. In the Docker image every scanner is already on `PATH`, so nothing is installed at scan time.
- **pip:** a virtualenv per tool, linked into `tools/bin`.
- **gem:** `gem install --install-dir tools/gems --bindir tools/bin`.
- **github:** the latest release asset for this OS and architecture (`.tar.gz` or a bare binary), checked against the release's checksums file.

## Triage pipeline (`triage.py`)

### Building items (`build_items`)

Findings are turned into **items**: the units Claude reviews. Each item is a pair `(item_json, member_findings)`.
- **Dependencies:** grouped by `(package, version)` across all lockfiles into one `D###` item: `package`, `version`, `locations` (up to 10 lockfiles), and `advisories` (unique by ID, up to 20, each with ID, severity, title and fixed version).
- **Repeated rules:** any rule from any tool except brakeman with more than `GROUP_MIN = 10` hits becomes one `G###` item: `rule`, `title`, `hits`, `samples` (up to `SAMPLES = 5` locations, one per file, worst first) and `description`.
- **Everything else:** one item per finding, using its `F###` ID and `_compact()` fields (ID, tool, rule, severity, category, title, location, package fields, and description up to 500 characters).
- **Sort key:** `(not critical/high, category order secret→code→config→dependency, severity, file, line)`. So all critical/high items come first, and code comes before dependencies within the same severity band.

### Batches

- The first `max_items` (`--max-triage`, default 400) are split into batches of `TRIAGE_BATCH` (default 100). With no findings at all, there's still one empty batch, so the code review runs.
- Each batch is one `_run_claude` call:
  ```
  claude -p --restricted --strict-mcp-config --tools Read,Grep,Glob --add-dir <repo>
         --output-format json --json-schema <SCHEMA> [--model M]
  ```
  - The prompt goes in on stdin.
  - The working directory is the run folder.
  - The environment has `GITHUB_TOKEN*` and `GH_TOKEN*` removed.
  - The timeout is `TRIAGE_TIMEOUT` per batch.
  - Raw stdout is saved as `claude-<n>.json`, and the result is read from `structured_output`.
- **Prompt** (`PROMPT`):
  - It treats repo content as untrusted, asks for a verdict on every item, and explains `advisories` and `hits`/`samples` items.
  - Batch 1 gets `FIRST_STEPS`: find up to 10 issues scanners miss (SSRF, IDOR/authz, authentication bypass, deserialization, command injection, mass assignment), plus a 3–5 sentence summary.
  - Later batches get `LATER_STEPS`: no additional findings, and a 1–2 sentence summary.
  - With several batches, the prompt says "batch n of N".
- **`SCHEMA`** (the JSON schema Claude's output must match):
  - `summary`
  - `findings[]`: `{id, verdict ∈ confirmed|false_positive|duplicate|needs_review, severity, reason, fix}`
  - `additional_findings[]`: `{title, severity, file, line?, description, fix}`

### Mapping verdicts back

- **Single-finding items:** `f.triage = verdict`.
- **Group items:** every member gets `f.triage = verdict + {group: "D001"/"G001", scope: "package-level review of N advisories" / "rule-level review of N hits from K samples"}`.
- **A failed batch** (timeout, bad output, CLI error) is logged and recorded in `errors`; the other batches continue.

### Result and metadata

- **Result:** `{summary, additional_findings}`. The summary is batch 1's (or the first successful batch's), followed by "Other batches:" with the rest.
- **Metadata** (`report.json` → `triage`):
  - `status`: `done`, `partial` or `failed`
  - `cost_usd`: summed `total_cost_usd`. This is the API-rate figure; with a subscription token it's not billed.
  - `items`, `items_total`, `findings_covered`, `batches`, `errors`

## Validation stage (`validate.py`)

Stage 2, run with `vulnscan validate <repo>` after a scan. It re-checks the scan's **open findings** with Strix (https://github.com/usestrix/strix), whose agents run inside Strix's own Docker sandbox and only report a finding with a working proof-of-concept.

1. **Find the run:** the stage-1 run folder is the latest with a `report.json` for that repo label (or `--run`). Its open findings — confirmed, needs review, not triaged, plus Claude's own `C…` findings, but not false positives or duplicates — are sorted by (final severity, category secret→code→config→dependency, file, line) and capped at `--max-validate` (default 100). With nothing to validate, reports are written saying so and Strix never runs.
2. **Checkout:** the repo is cloned exactly as in stage 1 (org allowlist, token via `GIT_CONFIG_*`). If the new HEAD differs from the report's commit, a warning is logged. Strix mounts local targets **writable**, so a local folder is first copied to a throwaway directory under `work/`; our own clones are already throwaway.
3. **Seed Strix:** `strix -n --target <clone> [--target <url> …] --instruction-file <run>/strix-instructions.md --workspace-file <run>/strix-findings.json:findings.json --scan-mode <mode> --scope-mode full [--max-budget <USD>]`. The instructions tell Strix to validate each listed finding, to name the stage-1 id(s) it confirms, and to treat the finding texts as untrusted data; `--instruction` flags are appended as operator notes (e.g. credentials for a live target).
4. **Environment:** Strix gets `STRIX_LLM` (`--model`, default `openrouter/z-ai/glm-5.3`), `LLM_API_KEY` (from `LLM_API_KEY` or `OPENROUTER_API_KEY`), `STRIX_TELEMETRY=0`, Docker and proxy variables — and nothing else. The GitHub token never reaches Strix. The run is stopped after `VULNSCAN_VALIDATE_TIMEOUT` (default 7200 s). Headless exit codes: 0 clean, 2 findings found (both fine), 1 fatal.
5. **Artifacts:** Strix writes `strix_runs/<name>/` into the run folder's `strix/` scratch directory; the newest run is copied to `raw/strix/` and its output log kept at `strix/strix-output.log`. `vulnerabilities.json` is parsed first, falling back to `findings.sarif`; both are read defensively because the schema isn't documented. `run.json` supplies the status and `llm_usage.cost`. If Strix exited 2 but nothing parsed, that's an error, not "no findings".
6. **Reports:** findings are normalised (severity, title, PoC, fix, location), numbered `V001…`, and the stage-1 ids they reference (`F\d{3}`, `C\d{2}`) are extracted from their text into `validates`. `validation.md`, `validation.json` and `validation.csv` are written into the stage-1 run folder, with a best-effort coverage section listing what was and wasn't referenced. Values pass through `report._csv_value` like stage 1.

On the instance, the repo copy Strix tests (`strix-target/`) is placed inside the run folder, not under `work/`: the run folder sits on the scans volume, mounted at the same path on the host and in the vulnscan container, so the host's Docker daemon — which Strix asks to mount the target into its sandbox — can see it. The copy is removed when the run finishes.

## Fix stage (`fix.py`)

Stage 3 is run with `vulnscan fix <repo>` after a validation. It opens one draft PR per finding in `validation.json`.

1. **Find the run:** the latest run folder for that repo that has a `validation.json`, or `--run`. A local folder is refused, because PRs need a GitHub repo. With no validated findings, `fix.md` says so and nothing else runs. Otherwise it checks first that `claude` is on `PATH` and that a GitHub token exists (unless `--dry-run`).
2. **Checkout:** `repo.checkout` clones as in stage 1, which enforces the org allowlist. `GET /repos/{owner}/{name}` supplies `private` and `default_branch`. A public repo is refused unless `--dry-run`. The PR base is `--ref`, or the default branch. If the HEAD differs from the validation's commit, a warning is logged.
3. **For each finding** (`_fix_one`):
   - **Skip check:** if the branch `vulnscan/fix-<run>-<V id>` already exists on GitHub (`git ls-remote`), the finding is skipped. This happens before Claude runs.
   - **Branch:** `git checkout -f -B <branch> <base sha>`, then `git clean -fdx`, so each finding starts from a clean base.
   - **Claude:** `triage._run_claude` with `tools="Read,Grep,Glob,Edit,Write"`, which adds `--permission-mode acceptEdits`, and the fix `SCHEMA` (`fixed`, `title`, `summary`, `review_notes`). The working directory is `<run>/fix/` and the repo comes in through `--add-dir`. The prompt has the finding (with its PoC) and the untrusted-data rule. The raw response is saved as `fix/claude-<V id>.json`.
   - **No fix:** if `fixed` is false or `git status` shows no change, the status is `not fixed` and the reason comes from the review notes.
   - **Commit:** `git add -A` and a commit with the `vulnscan <vulnscan@noreply.invalid>` identity. Every git call adds `-c core.hooksPath=/dev/null -c commit.gpgsign=false`. The commit is saved as `fix/<V id>.patch`.
   - **Push and PR:** unless `--dry-run`, vulnscan pushes `HEAD:refs/heads/<branch>` with `repo.git_env` (the token through `GIT_CONFIG_*`). It then calls `POST /repos/{owner}/{name}/pulls` with `draft: true` and the title `[vulnscan] <title>`. The body has the finding, the stage-1 ids, the run and commit, Claude's summary and review notes, and an "untested" warning, but not the PoC. API calls use `urllib` with the token in the `Authorization` header.
   - **Errors:** a git, Claude or API error marks that finding `failed`, and the loop continues.
4. **Reports:** `fix.json` has the metadata (`base`, `commit`, `validation_commit`, `model`, `dry_run`, `cost_usd`) and one result per finding: `status`, `branch`, `pr_url` or `error`, and `detail`. `fix.md` shows the same as a table. If any finding failed, `FixError` is raised after the reports are written, so the exit code is 2.

The wrapper needs no special case for `fix`. It already passes `GITHUB_TOKEN` and `CLAUDE_CODE_OAUTH_TOKEN`, and the container gets no Docker socket.

## Reports (`report.py`)

- **`report.json`:** the scan metadata (`repo`, `commit`, `scanned_at`, `stacks`, `tools`, `triage`), plus `summary`, `findings` (each `Finding` as a dict, including `triage`) and `additional_findings`.
- **`report.csv`:** the columns in `CSV_COLUMNS` (described in the [README](../README.md#outputs)). Claude's own findings come first as `C01…`. Every value goes through `_csv_value`, which guards against formula injection.
- **`report.md`:**
  - It starts with the scan details, tool status and summary.
  - **Confirmed:** a table, then one details section per finding. Group members share one section headed with the group ID, saying "and N more (see report.csv)".
  - Then Claude's own findings (`C01…`), needs review (table with reason), not triaged (table), and dismissed (table with reason).

## Configuration (`config.py`)

- **Paths:** `HOME` (`$VULNSCAN_HOME` or `~/.vulnscan`) contains `tools/bin`, `tools/gems`, `tools/venvs`, `scans` and `work`.
- **Timeouts and batch size:** `TOOL_TIMEOUT`, `TRIAGE_TIMEOUT` and `TRIAGE_BATCH`, each from its environment variable.
- **`GITHUB_ORGS`:** the comma-separated `VULNSCAN_GITHUB_ORG`.
- **`scanner_env()`:** only `PATH`, `HOME`, `USER`, `SHELL`, `LANG`, `LC_ALL`, `TMPDIR`, proxy and CA variables, `GOPATH`, `GOROOT`, `GOCACHE`, `GOMODCACHE`, `GOPROXY`, `GOFLAGS`, `RBENV_*`, `GEM_PATH` and `PYENV_ROOT`.
  - `tools/bin` is put first on `PATH`.
  - `GEM_PATH` includes `tools/gems` when it exists.
  - Semgrep metrics and version checks are switched off.

## Container image (`Dockerfile`)

- **Base:** `python:3.12-slim-trixie`, i.e. Debian 13. Brakeman 8.1 needs Ruby 3.2 or newer, and trixie ships 3.3.
- **apt:** the sources are rewritten to `https://deb.debian.org`, because the instance only allows outbound 443.
- **Downloads pinned by version and SHA-256,** for amd64 and arm64, chosen with `dpkg --print-architecture`:

  | Tool | Version |
  |---|---|
  | Go | 1.27.3 |
  | Claude Code | 2.1.311 (the native binary from `downloads.claude.ai`) |
  | osv-scanner | 2.7.0 |
  | gitleaks | 8.30.1 |
  | gosec | 2.30.0 |
  | docker CLI | 29.9.2 (only the client from the static tarball; Strix refuses to start without it on `PATH`) |

- **Python tools,** pinned, each in its own virtualenv under `/opt/tools`: semgrep 1.183.0, checkov 3.4.3, bandit 1.9.4, and strix-agent 1.7.0 (stage 2; console script `strix`).
- **Ruby:** brakeman 8.1.0 (gem).
- **Strix's pentest sandbox** is not in the image: it runs as sibling containers on the **host's** Docker daemon, started by Strix at validate time. `STRIX_IMAGE` is `vulnscan-strix-sandbox:1.3.0`, which the wrapper builds on the first validate from the pinned `ghcr.io/usestrix/strix-sandbox:1.3.0` (pre-pulled by `vulnscan-build`) with the sandbox user set to uid 10001. `STRIX_DOCKER_SANDBOX_NETWORK=bridge` makes Strix reach the sandbox's Caido proxy by its bridge IP. `validate.py` passes both to Strix; see [decisions.md](decisions.md).
- **vulnscan** is installed into `/opt/vulnscan` from `pyproject.toml` and `vulnscan/`. `.dockerignore` excludes `deploy/`, `.git` and `.venv`.
- **User:** `scanner` (uid 10001), with `/var/lib/vulnscan` owned by it.
- **Environment:** `PATH` includes `/usr/local/go/bin`, `VULNSCAN_HOME=/var/lib/vulnscan`, and `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` (no auto-updater, no telemetry).
- **Entrypoint:** `vulnscan`.

To upgrade a tool, change its version and both checksums together; the build fails if they don't match.

## Host scripts (`deploy/host/`)

`/usr/local/bin/vulnscan`, run as root on the instance:
1. Source `/etc/vulnscan/config`.
2. Read `$SSM_PREFIX/github-token` and `claude-token` with the instance role; for the `validate` subcommand also `$SSM_PREFIX/openrouter-token` (which must not still be the placeholder).
3. Remove leftover containers labelled `vulnscan`.
4. Start the scan detached:
   ```
   docker run -d --init --label vulnscan --cap-drop ALL --security-opt no-new-privileges
              --memory 6g --pids-limit 1024
              -e GITHUB_TOKEN -e CLAUDE_CODE_OAUTH_TOKEN -e VULNSCAN_GITHUB_ORG
              -e VULNSCAN_TOOL_TIMEOUT -e VULNSCAN_TRIAGE_TIMEOUT -e VULNSCAN_VALIDATE_TIMEOUT
              [-e LLM_API_KEY --group-add <docker gid> -v /var/run/docker.sock:/var/run/docker.sock]
              -v /var/lib/vulnscan/scans:/var/lib/vulnscan/scans vulnscan:latest "$@"
   ```
   `-e NAME` without a value copies the host's value, so tokens never appear on a command line. The bracketed options are added **only for `vulnscan validate`**: Strix starts its sandbox containers on the host daemon, so the container needs the socket (with its group id added). This is the one deliberate exception to the hardened container; `scan` runs never get it.
5. Print the container ID and follow `docker logs -f`.
   - Ctrl-C prints how to reattach and exits with 130; the scan continues.
   - When the container finishes, it removes it and exits with the container's exit code.

Why the socket works for validate: the repo copy Strix tests lives in the run folder under `/var/lib/vulnscan/scans`, which is mounted at the same path on the host and in the container, so the host daemon can mount it into Strix's sandbox.

`/usr/local/bin/vulnscan-build`, run as root:
1. Read the optional `$SSM_PREFIX/source-token`. It's only needed if the vulnscan repo is private.
2. Clone, or fetch and hard-reset, `VULNSCAN_SOURCE_REPO@VULNSCAN_SOURCE_REF` into `/opt/vulnscan-src`.
3. `docker build --pull -t vulnscan:latest`.
4. Install `deploy/host/vulnscan` to `/usr/local/bin`.
5. Prune images and build cache.

`/etc/vulnscan/config` is written at first boot and holds `AWS_REGION`, `SSM_PREFIX`, `VULNSCAN_GITHUB_ORG`, `VULNSCAN_SOURCE_REPO` and `VULNSCAN_SOURCE_REF`.

## Terraform (`deploy/terraform/`)

**Data sources:**
- the caller identity and partition;
- the instance type's architecture, which picks the Amazon Linux 2023 AMI (x86_64 or arm64) from its public SSM parameter;
- the availability zones that offer the instance type (the first, sorted);
- the existing VPC (`vpc_id`) and its internet gateway.

| Resource | Notes |
|---|---|
| `aws_subnet.this`, `aws_route_table.this` (+ association) | vulnscan's own public subnet (`subnet_cidr`), with a default route to the existing internet gateway. Nothing of the VPC's own is modified. |
| `aws_security_group.this`, `aws_vpc_security_group_egress_rule.https` | No inbound rules; TCP 443 out to 0.0.0.0/0 |
| `aws_iam_role.this`, `aws_iam_role_policy.this`, `aws_iam_instance_profile.this` | Inline policy: the Session Manager actions (`ssm:UpdateInstanceInformation`, `ssmmessages:*Channel`) plus `ssm:GetParameter` on `parameter<ssm_prefix>/*` |
| `aws_ssm_parameter.token["github-token"\|"claude-token"]` | SecureString (`aws/ssm` key). The placeholder `todo update me` is set through write-only `value_wo`, version 1, so values never enter state and Terraform never overwrites them. |
| `aws_ebs_volume.data` + `aws_volume_attachment.data` | Encrypted gp3 reports volume (`data_volume_gb`, default 5), attached as `/dev/sdf` and mounted at `/var/lib/vulnscan` by user data |
| `aws_instance.this` | See below |

`aws_instance.this` settings:
- **Network:** public IP, for outbound traffic only.
- **Metadata:** IMDSv2 required, hop limit 1, instance tags off.
- **Root disk:** gp3, `root_volume_gb` (default 20), encrypted.
- **CPU:** `cpu_credits = "unlimited"`.
- **Spot:** persistent request; on interruption it **stops** rather than terminating.
- **Ignored changes:** `ami` and `user_data`, so updates don't replace it by accident.

The first-boot script (`user_data.sh.tftpl`):
1. `dnf install docker git` and start Docker.
2. Wait for the reports volume (`/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_<vol>`), format it as XFS **only if it's blank**, add it to fstab (`nofail`) and mount it.
3. Create `/var/lib/vulnscan/scans`, owned by 10001 with mode 700.
4. Write `/etc/vulnscan/config` and both host scripts.

**Variables:** `region`, `vpc_id`, `subnet_cidr`, `github_org` (comma-separated), `source_repo`, `source_ref` (`main`), `name` (`vulnscan`), `instance_type` (default `t4g.large`; the live deployment sets `t3.large`), `root_volume_gb` (20), `data_volume_gb` (5), `ssm_prefix` (`/vulnscan`).

**Outputs:** `instance_id`, `connect` (an `aws ssm start-session` command that opens a root shell and skips the account's shell profile) and `token_parameters`.

**Requirements:** Terraform 1.11 or later (for write-only arguments) and AWS provider `~> 6.0` (locked at 6.71.0). State is local.
