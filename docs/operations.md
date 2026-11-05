# Operations runbook

How to run and look after the deployed scanner. IDs, the AWS profile and the region for the live deployment are in `deploy/terraform/ENVIRONMENT.local.md`. Every command below assumes this setup:

```bash
export AWS_PROFILE=<profile> AWS_REGION=<region>
I=$(terraform -chdir=deploy/terraform output -raw instance_id)
```

What needs approval: the commands in this file only read state or run scans, except the steps marked **(change)**. Ask the owner before running those ([CLAUDE.md](../CLAUDE.md#working-agreements-from-the-owner)).

## Prerequisites

- AWS CLI v2, plus the [Session Manager plugin](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html) (`session-manager-plugin`).
- An SSO login, which expires after some hours: `aws sso login --profile <profile>`. A browser opens for approval.
- Terraform 1.11 or later, run from the machine that holds the state.

## Connect

```bash
aws ssm start-session --target $I --document-name AWS-StartInteractiveCommand \
  --parameters '{"command":["sudo -i"]}'
# same thing: eval "$(terraform -chdir=deploy/terraform output -raw connect)"
```

This opens a root shell. A plain `aws ssm start-session` also works, but it runs the account's shell profile, which prints harmless Rails errors (`cd /var/app/current`, `chown webapp`, `rails c`) and leaves you as `ec2-user`; from there, `sudo -i`.

Sessions end after **60 minutes**, or **40 minutes without output**. Scans keep running when that happens.

## Build or update the scanner

Run this the first time, after the owner pushes changes to `main`, and about once a month for base-image fixes:

```bash
vulnscan-build        # about 5 minutes: clone or update /opt/vulnscan-src, build vulnscan:latest, install the wrapper
```

To check what's built:

```bash
git -C /opt/vulnscan-src log --oneline -1
docker image inspect vulnscan:latest --format '{{.Created}}'
```

The image only changes when `Dockerfile`, `pyproject.toml` or `vulnscan/` change. Changes elsewhere (docs, `deploy/`) still need `vulnscan-build` to install the new wrapper. `vulnscan-build` also reinstalls itself, and the new copy runs from the next time, so run it twice after changing it.

An instance whose `vulnscan-build` predates the self-reinstall (`grep -c vulnscan-build.new /usr/local/bin/vulnscan-build` prints 0) needs one manual install after the build fetches the new source:

```bash
vulnscan-build && install -m 755 /opt/vulnscan-src/deploy/host/vulnscan-build /usr/local/bin/vulnscan-build && vulnscan-build
```

## Run a scan

```bash
vulnscan scan KingsGambitLab/<repo>                              # default branch
VULNSCAN_TOOL_TIMEOUT=3600 vulnscan scan KingsGambitLab/<repo>   # big repos: give semgrep longer than 30 minutes
vulnscan scan scaler-hq/<repo> --ref <branch> --max-triage 600   # other flags: see README
vulnscan scan KingsGambitLab/<repo> --deep-review --deep-path app/controllers/api --claude-budget 20
```

`--deep-review` adds Claude's whole-codebase SSRF and access-control review. It takes hours on a monolith and uses far more of the Claude plan's allowance, which the token owner shares, so narrow it with `--deep-path` and cap it with `--claude-budget`. The report's "Deep review" line and "batches not reviewed" section show what it covered. Because the scan runs in a detached container, the session ending doesn't stop it.

- The wrapper prints `running in container <id>` and streams the progress.
- **Ctrl-C** stops following the output, not the scan.
- **If the session ends,** reconnect and run:
  ```bash
  docker ps                 # running scans (label: vulnscan)
  docker logs -f <id>       # follow again; the log ends with "Report: …"
  ```
- **To stop a scan:** `docker stop <id>`.
- Containers left behind by an ended session are removed by the next `vulnscan` run.

## Run a validation (stage 2)

After a finished scan of the repo, `vulnscan validate` re-checks its open findings with Strix (PoC-driven validation, GLM 5.3 via OpenRouter). It needs `/vulnscan/openrouter-token` to be set ([deploy/README.md](../deploy/README.md#add-the-tokens)) and the image rebuilt since stage 2 was added.

```bash
vulnscan validate KingsGambitLab/<repo>                        # the repo's latest scan, standard mode, budget $25
vulnscan validate KingsGambitLab/<repo> --scan-mode quick --budget 5
vulnscan validate scaler-hq/<repo> --url https://staging.example.com --instruction "login: user/pass"
vulnscan validate scaler-hq/<repo> --only F003                 # just one open finding from report.md (repeat --only for more)
```

- Read `validation.md` in the same run folder as the scan (`/var/lib/vulnscan/scans/<org>__<repo>/<timestamp>/`): validated findings with PoCs, and the stage-1 ids they confirm. Strix's own artifacts are under `raw/strix/`.
- `quick` mode takes minutes, `deep` can take hours; the run is stopped after `VULNSCAN_VALIDATE_TIMEOUT` (default 2 h) and the LLM spend is capped by `--budget`.
- The wrapper gives **validate containers only** the Docker socket (Strix runs its sandbox on the host); a validate run also copies the repo into the run folder, which briefly doubles its disk use there.
- Stage 1 doesn't need re-running: validate reads the newest `report.json` for that repo and clones the repo itself.
- Re-validating the same scan is refused once `vulnscan fix` has pushed branches for it, because new `V…` ids wouldn't match them. Run a new scan instead.
- `--only` adds to `validation.md` and `validation.json` instead of replacing them: earlier findings keep their `V…` ids and new ones get the next ids, so it works even after fix PRs exist. Run one validate per scan at a time, because concurrent runs share the run folder's scratch files.
- Sessions still end after 60 minutes; validation is detached like a scan, so reattach with `docker logs -f <id>`.

## Fix validated findings (stage 3)

After a validation, `vulnscan fix` opens one **draft** PR per finding in `validation.md`. Claude Code writes each fix on its own branch, `vulnscan/fix-<run>-<V id>`, and vulnscan pushes the branch and opens the PR with the GitHub token. This writes to the org's GitHub repos, so try `--dry-run` first on a new repo.

```bash
vulnscan fix scaler-hq/<repo> --dry-run     # patches only, in <run>/fix/*.patch; nothing pushed
vulnscan fix scaler-hq/<repo>               # the latest validated run; PRs against the default branch
vulnscan fix scaler-hq/<repo> --only V003   # just one finding from validation.md (repeat --only for more)
vulnscan fix scaler-hq/<repo> --run /var/lib/vulnscan/scans/scaler-hq__<repo>/<timestamp> --ref <branch>
```

- Read `fix.md` in the run folder. It lists each finding's status and PR link, or why there's no PR.
- Every PR is a draft and **untested**. Claude can't run the repo's code or tests, so whoever owns the code reviews and tests it before merging.
- Re-running is safe. Findings whose branch already exists are skipped. To retry one, close its PR, delete its branch on GitHub, and run with `--only <V id>`.
- `fix.md` and `fix.json` keep earlier fix runs' results on the same scan, so `--only` and re-runs never lose a PR link. The PRs themselves are on GitHub: `gh pr list --repo scaler-hq/<repo> --search "[vulnscan] in:title"`.
- Public repos are refused. It needs no image rebuild beyond `vulnscan-build` and no new token: it uses the same GitHub PAT, which has the `repo` and `workflow` scopes.

## View the dashboard

The dashboard is a read-only page that tracks every run: discovered, validated by Strix, and fix PRs opened. `vulnscan-build` runs it as the container `vulnscan-dashboard`. The container has no tokens, mounts the scans read-only, and is published only on the instance's `127.0.0.1:8080`, so there's no inbound rule and no public address. To open it, forward the port from your machine:

```bash
aws ssm start-session --target $I --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["8080"],"localPortNumber":["8080"]}'
# then open http://localhost:8080 in a browser; Ctrl-C ends the forwarding
```

- **Session limits:** the account's 60-minute cap applies here too. When the page stops loading, run the command again.
- **Port in use:** if 8080 is busy on your machine, use another `localPortNumber` and open that port instead.
- **Opening it by another name** (not `localhost` or `127.0.0.1`) gets a 403. That's the DNS-rebinding guard.
- **Freshness:** the page reads the run folders on every request, so new results appear on reload.
- **What it leaves out:** Strix's PoCs. They're in `validation.md` ([Read the results](#read-the-results)).

On the instance:

```bash
docker ps --filter name=vulnscan-dashboard     # Up; restarts by itself after a Spot stop
docker logs --tail 20 vulnscan-dashboard       # one line per request
```

## Read the results

Reports are in `/var/lib/vulnscan/scans/<org>__<repo>/<UTC timestamp>/`. A folder **without** `report.md` is a scan that didn't finish.

```bash
ls -t /var/lib/vulnscan/scans/KingsGambitLab__<repo>/                                   # newest first
less "$(ls -td /var/lib/vulnscan/scans/KingsGambitLab__<repo>/*/ | head -1)report.md"  # newest report
```

`report.md` puts the useful parts first: the summary, confirmed findings, then Claude's own findings. `q` quits `less` and `/` searches.

To list the critical and high findings that are still open, i.e. not dismissed by Claude:

```bash
R="$(ls -td /var/lib/vulnscan/scans/KingsGambitLab__<repo>/*/ | head -1)report.json"
python3 -c "
import json; r=json.load(open('$R'))
for f in r['findings']:
    t=f.get('triage') or {}
    if t.get('verdict') in ('false_positive','duplicate'): continue
    sev=t.get('severity') or f['severity']
    if sev in ('critical','high'): print(sev, t.get('verdict','not triaged'), f['tool'], f'{f[\"file\"]}:{f[\"line\"]}', f['title'][:90])
" | less
```

The scan's settings and how triage went are in `report.json` under `tools` (status per scanner) and `triage` (`status`, `items`, `items_total`, `findings_covered`, `batches`, `errors`, `cost_usd`).

## Copy a report to your machine

There's no SSH, so files come back base64-encoded through a non-interactive session. This was tested on a 1.4 MB file: identical checksum, 7 seconds.

```bash
F=/var/lib/vulnscan/scans/<org>__<repo>/<timestamp>/report.csv
script -q /dev/null aws ssm start-session --target $I --document-name AWS-StartNonInteractiveCommand \
  --parameters "{\"command\":[\"sudo base64 -w0 $F\"]}" < /dev/null 2>/dev/null \
  | tr -d '\r' | grep -vE '^(Starting|Exiting) session|^\^D|^$' | base64 -d > report.csv
```

Reports describe vulnerabilities in private code. Keep the copies off shared drives and out of git.

## Running commands on the instance from a script

This is how an agent inspects the instance without an interactive session. Two things matter:
- **A pseudo-terminal:** wrap the call in `script -q /dev/null … < /dev/null`. Without it you get "Cannot perform start session: EOF".
- **A shell:** commands run without a shell, so pipes and `$(…)` are passed literally to the first program. Wrap them in `bash -c '…'`.

For anything with quotes or several lines, send the script base64-encoded:

```bash
CHECK=$(base64 <<'EOF'
cloud-init status
docker ps --format '{{.ID}} {{.Status}} {{.Command}}'
df -h / /var/lib/vulnscan | tail -2
EOF
)
script -q /dev/null aws ssm start-session --target $I --document-name AWS-StartNonInteractiveCommand \
  --parameters "command=[\"bash -c 'echo $CHECK | base64 -d | sudo bash'\"]" < /dev/null 2>&1 \
  | tr -d '\r' | grep -vE '^\s*$|^\^D|Starting session|Exiting session'
```

Commands run as `ec2-user` (the account's Run As setting); `sudo` works. Keep these checks read-only unless the owner has approved a change.

## Health checks

| Check | Command | Healthy |
|---|---|---|
| Instance and Spot | `aws ec2 describe-instances --instance-ids $I --query 'Reservations[0].Instances[0].[State.Name,InstanceType,InstanceLifecycle]'` | `running`, `t3.large`, `spot` |
| Spot request | `aws ec2 describe-spot-instance-requests --filters Name=instance-id,Values=$I --query 'SpotInstanceRequests[0].[State,Status.Code]'` | `active`, `fulfilled` |
| Session Manager | `aws ssm describe-instance-information --filters Key=InstanceIds,Values=$I --query 'InstanceInformationList[0].PingStatus'` | `Online` |
| CPU credit mode | `aws ec2 describe-instance-credit-specifications --instance-ids $I --query 'InstanceCreditSpecifications[0].CpuCredits'` | `unlimited` |
| CPU and credits | CloudWatch `AWS/EC2` metrics `CPUUtilization`, `CPUSurplusCreditBalance` and `CPUSurplusCreditsCharged` for the instance | Charges stay at 0 unless the 24-hour average CPU stays above 30% |
| Terraform drift | `terraform -chdir=deploy/terraform plan -detailed-exitcode` | `No changes` |
| On the instance | `cloud-init status`, `systemctl is-active docker`, `findmnt /var/lib/vulnscan`, `df -h / /var/lib/vulnscan`, `top` (watch `st`, steal time) | `done`, `active`, mounted, space left, `st` near 0 |

To check the tokens work, on the instance, without printing them:

```bash
t=$(aws ssm get-parameter --region <region> --name /vulnscan/github-token --with-decryption --query Parameter.Value --output text)
GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=http.https://github.com/.extraheader \
GIT_CONFIG_VALUE_0="AUTHORIZATION: basic $(printf 'x-access-token:%s' "$t" | base64 -w0)" \
  git ls-remote --heads https://github.com/<org>/<private-repo>.git >/dev/null && echo "github token OK"; unset t
```

For the Claude token, the value should start with `sk-ant-oat` and must not be `todo update me`. The same goes for `/vulnscan/openrouter-token` (it should start with `sk-or-`), which only `vulnscan validate` reads.

## Rotate a token (change)

1. Create the new token. For GitHub: a classic PAT with `repo` and `workflow` scopes, authorised for SSO on each org. For Claude: run `claude setup-token`.
2. Store it:
   ```bash
   read -rs V && aws ssm put-parameter --overwrite --name /vulnscan/<github-token|claude-token> --value "$V"; unset V
   ```
   Or in the console: Systems Manager → Parameter Store → the parameter → Edit → Value.
3. Nothing else changes; the next scan reads the new value. Revoke the old token afterwards.

## Spot interruptions

If AWS reclaims the capacity, the instance **stops**: the disks, the image and the reports are kept. It **restarts by itself** when capacity returns, usually within minutes. A scan running at that moment is lost; re-run it. The instance state shows `stopped` with the reason `Server.SpotInstanceShutdown`. Do **not** start it by hand, because the Spot request handles that.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `vulnscan-build`: `Unable to connect to deb.debian.org:http` | Plain HTTP is blocked; outbound is 443 only | Fixed in the Dockerfile with apt over HTTPS. Any new download in the Dockerfile must be HTTPS. |
| Scan very slow; `top` shows high `st` (steal) | CPU credits exhausted in `standard` mode | Must be `unlimited` (the Terraform default now). Check the credit mode above. |
| `terraform apply` hangs at "Creating…" on the instance; CloudTrail `RunInstances` shows `InsufficientInstanceCapacity` | No Spot capacity for that type in that zone | Interrupt Terraform gracefully: `pkill -INT -x terraform`. Check `aws ec2 get-spot-placement-scores`, then **(change)** pick another `instance_type`, or remove the Spot block for on-demand. |
| Session closes after about an hour | The account's 60-minute session cap | Expected. The scan continues; reconnect and `docker logs -f <id>`. |
| Shell starts with `cd: /var/app/current` and `rails c` errors | The account-wide shell profile | Connect with `AWS-StartInteractiveCommand` (above). |
| Script: `Cannot perform start session: EOF` | No pseudo-terminal | Wrap the call in `script -q /dev/null … < /dev/null`. |
| Script: the command is echoed back instead of run | Non-interactive commands run without a shell | Wrap the command in `bash -c '…'`. |
| `semgrep: failed: … timed out after 1800 seconds` | Large repo | Re-run with `VULNSCAN_TOOL_TIMEOUT=3600` or more. |
| `git clone failed: could not read Username` | The token is missing, wrong, expired or not SSO-authorised for that org; or the repo name is wrong | Check the token (above). Authorise it for SSO on GitHub. |
| `… is outside the allowed orgs` (exit 2) | The repo's owner isn't in `VULNSCAN_GITHUB_ORG` | Expected. To allow another org, **(change)** edit `/etc/vulnscan/config`, and `github_org` in `terraform.tfvars` to match. |
| Report says `Claude triage: partial` or `failed` | A batch or the review timed out, hit usage limits, or returned no structured output, or Claude left some items without a verdict ("no verdict for …") | Look at `errors` in `report.json` and at `claude-<n>.json` or `claude-review.json`. Re-run later, or raise `VULNSCAN_TRIAGE_TIMEOUT`. |
| `gosec: failed: produced no report` (local runs) | The Go toolchain isn't installed | Install Go. The image includes it. |
| `validate`: `/vulnscan/openrouter-token is still the placeholder` | The third parameter hasn't been set | Set it ([deploy/README.md](../deploy/README.md#add-the-tokens)) and re-run |
| `validate`: `strix CLI not found on PATH` | The image predates stage 2 | Run `vulnscan-build`, then retry |
| `validate`: `no finished scan for <repo>` | There's no run folder with a `report.json` for that repo | Run `vulnscan scan` first, or pass `--run <folder>` |
| `validate`: `permission denied … /var/run/docker.sock` | The socket's group wasn't added, or Docker restarted and changed its group id | Re-run; if it persists, check `stat -c %g /var/run/docker.sock` on the host and the wrapper's `--group-add` |
| `validate`: `… already has fix branches on GitHub` | `vulnscan fix` already opened branches or PRs for that scan's `V…` ids | Expected. Validate single findings with `--only`, which keeps the existing `V…` ids. Or run `vulnscan scan` again and validate the new run. Or, if those PRs are abandoned, close them and delete their branches first. |
| `validate` stops with a budget message | The `--max-budget` cap was reached; partial results are still written | Re-run with a higher `--budget`, or fewer items (`--max-validate`) |
| `report.json` says the volume is filling during `validate` | The repo copy (`strix-target/`) briefly doubles the repo's size on the reports volume | Grow `data_volume_gb` ([deploy/README.md](../deploy/README.md#maintenance)), or validate big repos one `--ref` at a time |
| `fix`: `no validated scan for <repo>` | No run folder has a `validation.json` | Run `vulnscan validate` first, or pass `--run <folder>` |
| `fix`: `<repo> is public` | PRs would disclose the vulnerability | Expected. Use `--dry-run` and fix it through a private security advisory |
| `fix`: `git push failed … 403` or `GitHub API POST …/pulls: HTTP 403/404` | The token can't push to or open PRs on that repo (read-only fine-grained token, missing SSO authorisation, or a push ruleset) | Check the token's scopes and SSO; for a ruleset (e.g. one restricting commit emails), ask the repo admins |
| `fix`: `git push failed … refusing to allow a Personal Access Token to create or update workflow … without workflow scope` | The fix changes a file under `.github/workflows/`, and the token has no `workflow` scope (e.g. a rotated token created with `repo` only) | Add the `workflow` scope on the token's page (a classic PAT keeps its value, so Parameter Store needs no change), then re-run with `--only <V id>`. The commit is also in `<run>/fix/<V id>.patch` |
| `fix`: `HTTP 422 … Draft pull requests are not supported` | Draft PRs need a paid plan on private repos | Not handled; the branch is pushed, so open the PR from it by hand |
| `fix`: a finding is `skipped: branch already exists` | An earlier `fix` run already handled it | Expected. Delete the branch to retry |
| Dashboard port forwarding: `Connection to destination port failed` | The `vulnscan-dashboard` container isn't running, e.g. the image predates the dashboard | On the instance: `docker ps -a --filter name=vulnscan-dashboard` and `docker logs vulnscan-dashboard`. `vulnscan-build` recreates it. |
| Dashboard says `Forbidden: Open this page through localhost` | The browser reached it under another host name | Open `http://localhost:<port>` |
| `vulnscan dashboard` on the instance exits 2 | The wrapper refuses it, because it would pass the tokens to a long-running server | Expected. The dashboard container is already running; see [View the dashboard](#view-the-dashboard). |
| A scan folder has no `report.md` | The scan was interrupted (old foreground wrapper, a Spot stop, or `docker stop`) | Re-run. |

## Infrastructure changes (change)

All of these need the owner's approval and run from the machine with the Terraform state. See [deploy/README.md](../deploy/README.md#maintenance) for growing disks, OS patches, replacing the instance, and switching Claude to Bedrock.
