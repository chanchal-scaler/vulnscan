# Status and backlog

Last updated 2026-11-04. Update this file whenever the deployment or the code's capabilities change. IDs for the live deployment are in `deploy/terraform/ENVIRONMENT.local.md`, and scan results stay on the instance. Neither goes in this repo.

## Deployed

- **Where:** one t3.large Spot instance (x86_64, Amazon Linux 2023) in the staging AWS account, us-west-2a, in its own subnet of a reused, otherwise empty VPC. Created by `deploy/terraform`; state is on the operator's machine.
- **What's running:** the image is built on the instance from `main` of the public GitHub repo, by `vulnscan-build`.
- **What it scans:** repos in two GitHub orgs (`github_org` in `terraform.tfvars`).
- **Tokens:** one classic GitHub PAT and one Claude Code `setup-token`, both in Parameter Store under `/vulnscan/`.
- **Cost:** about $29 a month. The instance is about $23 at the current Spot price, disks $2, the public IPv4 address $3.65. The Claude subscription is separate.

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

## Scans run

- **The largest Rails monolith (63k files, about 7,700 findings):** one complete scan, with the **old** triage (first 150 by severity), on 2026-11-03.
  - Every scanner completed.
  - The scanners caught every issue on a later manual-review list (committed private keys, SQL injection, open redirects, `eval`/`YAML.load` on params, unsafe `constantize`, Ransack), but Claude never reviewed them. That led to the grouping and batching change.
- **Next:** re-run it with the new triage, using `VULNSCAN_TOOL_TIMEOUT=3600`, and review `report.csv`.

## Known issues

| Issue | Impact | Notes |
|---|---|---|
| Claude marks an unused dependency `confirmed`, at a lower severity, even when its reason says the package isn't imported | Dependency noise in the confirmed list | Tighten the prompt: unused → `false_positive`. Seen in testing (`requests`, `urllib3`). |
| Claude's own review is shallow on large repos | Issues no scanner flags (IDOR, authz, SSRF) are mostly missed in monoliths | Backlog: deep review |
| Grouped rules are judged from 5 samples | A confirmed group may include false positives, and a dismissed group may hide a real hit | `reviewed_as` in the CSV marks these |
| More than 400 items on the biggest repo (637 critical/high items there) | The least severe dependency items stay untriaged | `--max-triage 700` covers them, at the cost of time and quota |
| semgrep's full runtime on the biggest repo hasn't been measured | It may need more than 30 minutes | Use `VULNSCAN_TOOL_TIMEOUT=3600`; note the time after the next run |
| The `instance_type` variable defaults to `t4g.large`, but the deployment uses `t3.large` (set in `terraform.tfvars`) | A fresh deployment without tfvars gets t4g, which had no Spot capacity | Consider changing the default |
| Terraform state exists only on the operator's machine | If that machine is lost, the deployment can only be managed by hand | Back up, or move to an S3 backend with locking |
| A single classic GitHub PAT has write access to every repo its user can reach | If leaked, it allows pushing to org repos | Fine-grained per-org tokens (already supported) or a GitHub App |
| Claude runs on one person's subscription token | Usage limits are shared with that person's own use, and the token stops working if they leave | Switch to Bedrock (the instance role) or an API key; no code change needed |
| Scanner env-var stripping isn't a hard boundary | A compromised scanner, running as the same user, could read the parent process's environment, which holds the tokens | The container limits what it can reach to those two tokens and the internet. Separating users would close it. |
| Only the default branch's latest commit is scanned | Secrets removed in later commits, and other branches, are missed | Backlog: history scan |
| No scheduling or alerting | New CVEs in existing lockfiles go unnoticed until someone scans | Backlog: nightly scans and alerts |

## Backlog (suggested order)

1. **Re-scan the largest repo with the new triage**, and agree with the owner how results are read and acted on.
2. **Nightly scans with alerts:**
   - a systemd timer on the instance runs `vulnscan scan` for a list of repos;
   - it compares each run with the previous `report.json`;
   - it posts new confirmed critical/high findings to Slack.
   This is what would have caught HttpToShell-style exposures. Needs a webhook and approval.
3. **A `--deep-review` mode:** after triage, split the app by entry points (e.g. one Claude call per controller directory), each with a stack-specific checklist. For Rails: authorization in every action, unscoped `find` (IDOR), strong params, `send_file`/redirects, Ransack, outbound HTTP (SSRF). This trades time and quota for coverage of issues scanners can't see.
4. **Prompt fix for unused dependencies** (see Known issues).
5. **Terraform state to S3,** with DynamoDB locking or S3 native locking.
6. **An optional full-history secret scan** (`gitleaks git` on a full clone).
7. **Move Claude to Bedrock** (`CLAUDE_CODE_USE_BEDROCK=1`). The container would then need AWS credentials: raise the hop limit to 2, or have the wrapper pass in short-lived credentials.
8. **Fine-grained per-org tokens or a GitHub App** instead of the classic PAT.
9. **An automated test suite,** turning [testing.md](testing.md) checks 3 and 7 into scripts.
