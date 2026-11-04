# Deploying vulnscan to EC2

One EC2 Spot instance (the live deployment uses t3.large) in its own subnet of an existing, otherwise empty VPC. Terraform creates the AWS side; the scanner runs in a fresh Docker container for every scan.

- Day-to-day operation and troubleshooting: [docs/operations.md](../docs/operations.md).
- Why it's built this way: [docs/decisions.md](../docs/decisions.md#deployment).
- IDs and the AWS profile for the live deployment: `terraform/ENVIRONMENT.local.md`, which is gitignored and only on the operator's machine.

```
deploy/
  terraform/   VPC, security group, IAM role, instance, reports volume
  host/        vulnscan-build (build the image) and vulnscan (run a scan), installed on the instance at first boot
Dockerfile     the scanner image: all runtimes and scanners at pinned versions and checksums
```

## What it creates

| | |
|---|---|
| Network | Its own public subnet and route table in the VPC given by `vpc_id`, using that VPC's existing internet gateway. Use a VPC with nothing else in it, so the scanner shares a network with nothing. No NAT gateway, to save about $32 a month. |
| Inbound | None. The security group has no ingress rules and there's no SSH key; you get a shell through SSM Session Manager. |
| Outbound | HTTPS (443) only. |
| IAM role | Session Manager, plus `ssm:GetParameter` on `/vulnscan/*` only. If the instance is compromised, that's all it can do. It deliberately doesn't use `AmazonSSMManagedInstanceCore`, because that policy can read every parameter in the account. |
| Metadata | IMDSv2 required, with a hop limit of 1, so containers can't get the instance role's credentials. |
| Disks | Encrypted gp3. Reports are on a separate 5 GB volume mounted at `/var/lib/vulnscan`, so they survive the instance being replaced. |
| Instance | `instance_type` (variable default `t4g.large`; the live deployment sets `t3.large` in `terraform.tfvars`, because t4g had no Spot capacity), Amazon Linux 2023 for the type's architecture.<br>**Spot:** a persistent request that **stops** the instance on interruption, keeping the disks, and restarts it when capacity returns.<br>**Unlimited CPU credits:** T-family instances get no launch credits, so `standard` mode throttles a new instance to 30% CPU. |
| Parameters | `/vulnscan/github-token`, `/vulnscan/claude-token` and `/vulnscan/openrouter-token` (stage-2 validation key), created as placeholders; you set the real values ([below](#add-the-tokens)) |

Cost is about $29 a month in us-west-2:
- **Instance:** about $23 at the current t3.large Spot price ($0.032/hr; on-demand would be $0.0832/hr).
- **Disks:** $2.00 for 25 GB of gp3 (20 GB root, 5 GB reports).
- **Public IPv4 address:** $3.65. It's used only for outbound traffic.

Unlimited CPU credits only cost extra ($0.05 per vCPU-hour) if the 24-hour average CPU stays above 30%. Before changing `instance_type`, check Spot capacity with `aws ec2 get-spot-placement-scores`.

## Deploy

The instance builds the image from your GitHub repo, so push this project to a repo in your org first.

```bash
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars   # set region, vpc_id, subnet_cidr, github_org, source_repo; optionally instance_type
terraform init
terraform plan
terraform apply
```

Requirements: Terraform 1.11 or later (for write-only arguments), and an existing VPC with an internet gateway attached.

State is kept locally in `terraform.tfstate`, and it's the only copy, so back it up or move it to an S3 backend. It holds no secrets: the token parameters use the write-only `value_wo`, so their values are never stored in state.

## Add the tokens

`terraform apply` creates `/vulnscan/github-token`, `/vulnscan/claude-token` and `/vulnscan/openrouter-token` with the placeholder value `todo update me`. Replace the placeholders by hand. Terraform won't overwrite your values, and they never reach its state file:

```bash
read -rs GH && aws ssm put-parameter --region <region> --overwrite \
  --name /vulnscan/github-token --value "$GH"; unset GH
read -rs CT && aws ssm put-parameter --region <region> --overwrite \
  --name /vulnscan/claude-token --value "$CT"; unset CT
# only if the vulnscan repo is private (not created by Terraform):
read -rs ST && aws ssm put-parameter --region <region> --type SecureString \
  --name /vulnscan/source-token --value "$ST"; unset ST
```

If the deployment predates stage 2, `terraform apply` first creates `openrouter-token` as a placeholder; then:

```bash
read -rs OR && aws ssm put-parameter --region <region> --overwrite \
  --name /vulnscan/openrouter-token --value "$OR"; unset OR
```

- **`github-token`**: a classic personal access token with the `repo` scope, from a user who can read every org in `github_org`. Used by `vulnscan scan`.
  - If an org uses SAML single sign-on, authorize the token for it (*Configure SSO* on the token's page).
  - `repo` also allows pushing to those repos, so give the token an expiry, and revoke it if the instance is ever suspected compromised.
- **`source-token`** (only if the vulnscan repo is private): a fine-grained token with read-only Contents on the vulnscan repo only. Used by `vulnscan-build`. It's separate because a fine-grained token can only reach one owner's repos.
- **`claude-token`**: the output of `claude setup-token`.
- **`openrouter-token`**: an OpenRouter API key (`sk-or-…`, [openrouter.ai/keys](https://openrouter.ai/keys)), used only by `vulnscan validate` as `LLM_API_KEY` for GLM 5.3. `vulnscan scan` doesn't read it.

## Build and scan

```bash
eval "$(terraform output -raw connect)"   # opens a root shell on the instance
vulnscan-build                      # clone the vulnscan repo and build the image; takes about 5 minutes
vulnscan scan your-org/some-repo    # also takes --ref, --no-llm and the other usual flags
```

The connect command starts the session with `sudo -i`. That skips the account-wide Session Manager shell profile, which a plain `aws ssm start-session` runs; the profile is written for the Rails app servers and only prints errors here.

Scans run in a detached container, so they keep going if the session ends. This account caps Session Manager sessions at 60 minutes, and ends them after 40 minutes without output.
- **Reattach:** run `docker logs -f <id>`; the wrapper prints the container ID when it starts.
- **Ctrl-C** only stops following the output, not the scan.
- **Big repos:** each scanner is stopped after 30 minutes by default. Raise the limit with `VULNSCAN_TOOL_TIMEOUT=3600 vulnscan scan ...`, and set `VULNSCAN_TRIAGE_TIMEOUT` the same way for Claude's review.

Reports are written to `/var/lib/vulnscan/scans/<org>__<repo>/<timestamp>/` as `report.md`, `report.json` and `report.csv`. The wrapper scans GitHub repos only; local paths on the instance aren't mounted into the container.

To read results, list the open critical and high findings, or copy a report to your machine, see [docs/operations.md](../docs/operations.md#read-the-results).

## Maintenance

- **Updating vulnscan or the scanners:** change the code or the pinned versions in the `Dockerfile`, push, then run `vulnscan-build` again.
  - Pinned scanners still find new issues, because OSV data and Semgrep rules are fetched on every scan.
  - `vulnscan-build` also pre-pulls Strix's sandbox image (`STRIX_IMAGE` in the Dockerfile), so the first `vulnscan validate` doesn't wait on it.
  - Rebuild about once a month anyway, to pick up the base image's security fixes.
- **Disk space:** each scan's report takes about 1 MB, so the 5 GB reports disk holds thousands of scans. To grow a disk, raise `root_volume_gb` or `data_volume_gb` and apply; the instance keeps running. Then, on the instance, run `xfs_growfs /var/lib/vulnscan` for the reports disk, or `growpart /dev/nvme0n1 1 && xfs_growfs /` for the root disk.
- **OS patches:** run `dnf upgrade --releasever=latest`, or run `terraform apply -replace=aws_instance.this` to move to the newest AMI. Replacing the instance keeps the reports volume. Run `vulnscan-build` afterwards, since the image lives on the root disk.
- **Switching Claude to Bedrock later:** the container will then need AWS credentials. Either raise `http_put_response_hop_limit` to 2, or have the wrapper pass in short-lived credentials.
- **Spot interruptions:** the instance stops and restarts by itself. Don't start it by hand. A scan running at that moment needs re-running.
- **Changing `instance_type` or the Spot settings** replaces the instance (the reports volume is kept). If the new type has no Spot capacity, the apply retries for a long time; see [docs/operations.md](../docs/operations.md#troubleshooting).
- **Troubleshooting:** see [docs/operations.md](../docs/operations.md#troubleshooting).
