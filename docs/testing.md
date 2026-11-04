# Testing changes

There's no automated test suite yet. These are the checks used during development, from cheapest to most expensive. Run the ones that match what you changed, before the owner pushes: the instance builds whatever is on `main`.

| You changed | Run |
|---|---|
| Any Python | 1, 2, and 5 without Claude |
| `triage.py` or `report.py` | 1, 2, 3, and 5 with Claude |
| `validate.py` or its docs | 1 and 10 (and 11 once Strix is installed) |
| `Dockerfile` | 6 |
| `deploy/host/*` | 7 |
| `deploy/terraform/*` | 8 (plan only; applying needs approval) |

## Test targets

Use public, intentionally vulnerable apps, not company repos:

| Repo | Stack |
|---|---|
| `OWASP/railsgoat` | Rails: brakeman, semgrep and gem CVEs |
| `OWASP/NodeGoat` | Node: semgrep and npm CVEs |
| `adeyosemanputra/pygoat` | Django: bandit, semgrep and pip CVEs |

Locally, leave `VULNSCAN_GITHUB_ORG` unset, or include `OWASP`, so they're allowed. Set `VULNSCAN_HOME` to a scratch folder so test tools and reports don't mix with real ones.

## 1. Syntax

```bash
.venv/bin/python -m compileall -q vulnscan
bash -n deploy/host/vulnscan && bash -n deploy/host/vulnscan-build
```

## 2. Scanners only, locally

```bash
VULNSCAN_HOME=/tmp/vs .venv/bin/vulnscan scan OWASP/railsgoat --no-llm
```

Check that:
- every tool reports `ok`, or `not applicable`;
- the open counts look plausible;
- `report.md`, `report.json` and `report.csv` all exist.

Without Go installed locally, gosec fails with "produced no report". That's expected.

## 3. Triage logic with a stand-in Claude (no quota used)

Replace `triage._run_claude` to test grouping, ordering, batching, verdict mapping, failure handling and report writing deterministically. This is the pattern used on 2026-11-04:

```python
# VULNSCAN_TRIAGE_BATCH=4 .venv/bin/python test_triage.py
import json, sys
from pathlib import Path
from unittest import mock
from vulnscan import triage as tr
from vulnscan.findings import Finding, sort_key
from vulnscan.report import write_reports

F = [Finding("osv-scanner", f"CVE-{i}", f"rails 5.1.4: adv {i}", "critical", "dependency",
             file="Gemfile.lock", package="rails", version="5.1.4") for i in range(5)]
F += [Finding("semgrep", "xss.var-in-href", "var in href", "medium", "code", file=f"app/v{i}.erb", line=1) for i in range(15)]
F += [Finding("brakeman", "SQL", "SQL injection", "high", "code", file="app/c.rb", line=l) for l in (62, 71)]
F += [Finding("gitleaks", "private-key", "=HYPERLINK(1) key", "high", "secret", file="k.pem", line=1)]
F.sort(key=sort_key)
for i, f in enumerate(F, 1): f.id = f"F{i:03d}"

def fake(prompt, repo, run_dir, model, name):
    if name == "claude-2.json":
        raise tr.TriageError("simulated failure")           # test partial runs
    ids = [i["id"] for i in json.loads(prompt.split("Items (JSON):\n", 1)[1])]
    return {"summary": name, "additional_findings": [],
            "findings": [{"id": i, "verdict": "confirmed", "severity": "high", "reason": "r", "fix": "f"} for i in ids]}, 0.1

out = Path("/tmp/out"); out.mkdir(exist_ok=True)
with mock.patch.object(tr, "_run_claude", fake):
    result, meta = tr.triage(F, Path("/repo"), ["rails"], out, max_items=400)
print(meta)
write_reports(out, {"repo": "x", "commit": "", "scanned_at": "", "stacks": {}, "tools": [], "triage": meta}, F, result)
```

What to verify:
- **Order:** the secret comes first, then the brakeman highs, before the critical dependency.
- **Grouping:** brakeman is never grouped; a rule with more than 10 hits becomes one `G` item with 5 samples, one per file; a dependency becomes one `D` item.
- **Batches:** only batch 1's prompt contains the code-review step. A failed batch gives `status: partial` and leaves its findings untriaged.
- **Reports:**
  - Group members carry `group` and `scope`, and `report.csv` has `reviewed_as` filled in.
  - The CSV escapes `=HYPERLINK…` as `'=HYPERLINK…`.
  - `report.md` has one details section per group.

## 4. Grouping on real results (read-only)

To see how a change to `build_items` would rank a real repo's findings, replay its logic over a finished scan's `report.json` on the instance. Use the pattern in [operations.md](operations.md#running-commands-on-the-instance-from-a-script). On the biggest repo, 7,751 findings became 2,024 items, 637 of them critical/high. Never copy those results into the repo.

## 5. End to end with real Claude (uses Claude quota)

```bash
VULNSCAN_HOME=/tmp/vs VULNSCAN_TRIAGE_BATCH=15 .venv/bin/vulnscan scan OWASP/railsgoat
```

This uses the local Claude Code login. A small batch size forces several batches. Check that:
- `report.json` → `triage.status` is `done`;
- every `claude-<n>.json` has `structured_output.findings` with as many entries as items sent;
- `permission_denials` is empty;
- grouped items have sensible reasons;
- `additional_findings` came only from batch 1.

On 2026-11-04 the deliberately vulnerable sample app took 4 min 46 s in total (3 batches, 42 items, 100 findings), cost $0.90 at API rates, and every item got a verdict.

## 6. Docker image

```bash
docker build -t vulnscan:test .                                   # native architecture
docker build --platform linux/amd64 -t vulnscan:test-amd64 .      # the instance's architecture (t3); emulated on Apple Silicon
docker run --rm --entrypoint sh vulnscan:test -c 'semgrep --version; brakeman --version; gosec -version; claude --version; go version; strix --help >/dev/null && echo strix-ok'
docker run --rm --init --cap-drop ALL --security-opt no-new-privileges --memory 4g \
  -e VULNSCAN_GITHUB_ORG=OWASP vulnscan:test scan OWASP/railsgoat --no-llm
```

Every `fetch` line in the build log must print `OK`; a wrong checksum fails the build. If you add downloads, make sure they work over HTTPS only. To mimic the instance's port-80 block for apt:

```bash
apt-get -o Acquire::http::Proxy=http://127.0.0.1:9 -o Acquire::https::Proxy=DIRECT update
```

## 7. Host scripts, with stand-in `aws` and real Docker

The wrapper reads `/etc/vulnscan/config` and mounts `/var/lib/vulnscan/scans`. Rewrite those paths into a scratch copy and put a fake `aws` on `PATH`:

```bash
S=/tmp/wrapper-test; mkdir -p $S/bin $S/scans; chmod 777 $S/scans
printf 'AWS_REGION=x\nSSM_PREFIX=/vulnscan\nVULNSCAN_GITHUB_ORG=OWASP\n' > $S/config
printf '#!/bin/bash\necho ""\n' > $S/bin/aws; chmod +x $S/bin/aws          # empty tokens: public repos only
docker tag vulnscan:test vulnscan:latest
sed -e "s#/etc/vulnscan/config#$S/config#" -e "s#-v /var/lib/vulnscan/scans:#-v $S/scans:#" deploy/host/vulnscan > $S/vulnscan
chmod +x $S/vulnscan
PATH=$S/bin:$PATH $S/vulnscan scan OWASP/railsgoat --no-llm; echo "exit $?"   # expect 0
PATH=$S/bin:$PATH $S/vulnscan scan someone/else --no-llm; echo "exit $?"      # expect 2
```

Also check:
- **Session loss:** start a long scan in the background and `kill -HUP` the wrapper. The container must keep running and finish.
- **Ctrl-C:** under `set -m`, `kill -INT -- -<pgid>`. Expect exit 130, the "scan continues" message, and the container still running.
- **Cleanup:** the next run removes leftover containers (`docker ps -a --filter label=vulnscan`).
- **The validate branch:** with a stubbed `docker` that prints its arguments (and a fake `aws` returning the placeholder for `openrouter-token`), check that `validate` exits 2 on the placeholder message, that a set token adds `-e LLM_API_KEY`, `--group-add <gid>` and the socket mount to `docker run`, and that `scan` gets none of them.

Clean up afterwards with `docker ps -aq --filter label=vulnscan | xargs -r docker rm -f`.

## 8. Terraform

```bash
cd deploy/terraform
terraform fmt && terraform validate
AWS_PROFILE=<profile> terraform plan            # read-only; review every "must be replaced"
```

To check the first-boot script renders and is valid bash, render it with test values. `terraform console` reads its input one line at a time, so keep the expression on one line. It also needs the required variables, which come from `terraform.tfvars` or `-var`.

```bash
echo 'templatefile("user_data.sh.tftpl", {region="x", github_org="a,b", source_repo="o/r", source_ref="main", ssm_prefix="/vulnscan", data_volume="vol0123", build_script=file("../host/vulnscan-build"), wrapper_script=file("../host/vulnscan")})' \
  | terraform console | sed '1d;$d' > /tmp/ud.sh && test -s /tmp/ud.sh && bash -n /tmp/ud.sh && wc -c < /tmp/ud.sh
```

User data must stay under 16 KB; it's about 4.4 KB now.

## 9. On the instance, after the owner pushes

Run `vulnscan-build`, then one small scan, then check the new behaviour in the report. Use the read-only checks in [operations.md](operations.md#health-checks).

## 10. Validation stage with a stand-in Strix (no Docker, no spend)

Fake `strix` on `PATH` and a fabricated stage-1 run folder; `validate.py` can't tell the difference. This is the pattern used on 2026-11-04:

```bash
# T=/tmp/vstest; mkdir -p $T/bin $T/scans/demo__app/20261104-120000/raw $T/target
# 1. fake strix: ignores its arguments, writes plausible artifacts, exits 2 (findings found)
cat > $T/bin/strix <<'EOF'
#!/bin/bash
mkdir -p strix_runs/fake-run/vulnerabilities
cat > strix_runs/fake-run/vulnerabilities.json <<'JSON'
{"vulnerabilities": [
 {"title": "SQL injection (validates F001)", "severity": "critical",
  "poc": "GET /users?id=1 OR 1=1 returns all users", "remediation": "parameterise",
  "location": "app/controllers/users_controller.rb:42"}]}
JSON
printf '{"status":"completed","llm_usage":{"cost":1.23}}' > strix_runs/fake-run/run.json
exit 2
EOF
chmod +x $T/bin/strix
# 2. a report.json with one confirmed, one needs_review, one untriaged, one
#    false_positive finding and one additional_findings entry (C01)
# 3. run it
PATH=$T/bin:$PATH VULNSCAN_HOME=$T LLM_API_KEY=fake \
  .venv/bin/vulnscan validate $T/target --url https://staging.example.com; echo "exit $?"   # expect 0
```

What to verify:
- **Selection:** false positives and duplicates are not sent; everything else is, worst first, capped by `--max-validate`; `C01` is included.
- **Seeding:** `strix-instructions.md` lists the findings with the untrusted-data warning, the live target and the operator instructions; `strix-findings.json` is the payload.
- **Parsing:** `V001…` findings carry the PoC, fix, and the `F001`/`C01` ids from their text (try a dict-shaped and a `file:line` location, and a `=HYPERLINK…` title — the CSV must show `'=HYPERLINK…`).
- **Coverage:** `validation.md` lists which sent findings Strix's findings reference.
- **Errors:** missing `LLM_API_KEY` exits 2 *before* anything is cloned; a strix that exits 1 still writes partial reports and exits 2; garbage artifacts with exit 2 are an error, not "no findings"; a report with everything dismissed writes "nothing to validate" and skips Strix.
- **Hygiene:** a local target is copied (Strix mounts targets writable) and the copy removed afterwards (`ls $VULNSCAN_HOME/work`).

## 11. Validation stage with real Strix (uses OpenRouter credits)

```bash
export LLM_API_KEY=sk-or-...            # OpenRouter
VULNSCAN_HOME=/tmp/vs .venv/bin/vulnscan scan OWASP/railsgoat --no-llm   # stage 1, cheap
VULNSCAN_HOME=/tmp/vs .venv/bin/vulnscan validate OWASP/railsgoat --scan-mode quick --budget 5
```

Check that: `validation.json` → `strix.status` is `completed`, `cost_usd` is under the budget, findings have PoCs and `validates` ids, `raw/strix/` holds Strix's own artifacts, and the "not referenced" coverage list makes sense.
