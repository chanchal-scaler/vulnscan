# Architecture

How the code works, from one scan's point of view, plus the container image, host scripts and Terraform. For the reasons behind each choice, see [decisions.md](decisions.md).

## Repository layout

```
vulnscan/                  Python package (stdlib only, Python 3.9+)
  cli.py                   argparse entry point: `scan`, `validate`, `fix`, `dashboard`, `tools`; sets umask 077
  scan.py                  orchestration: checkout → detect → run scanners → triage → reports
  repo.py                  parse org/repo or URL, enforce the org allowlist, shallow clone with token, cleanup
  detect.py                stack detection from marker files
  installer.py             finds scanners on PATH or installs them (pip venv, gem, GitHub release with checksum)
  findings.py              Finding dataclass, severity normalisation, sort order
  triage.py                groups findings into items, batches them, runs headless Claude, maps verdicts back; Budget
  deep_review.py           the deep review (on by default, --no-deep-review): Claude's per-class review of the whole codebase (SSRF and LLM use by sink, access control by area)
  validate.py              stage 2: seeds a scan's open critical/high findings into Strix (GLM via OpenRouter), 20 per pass, collects its artifacts, writes validation reports
  fix.py                   stage 3: Claude fixes each validated finding on its own branch; vulnscan pushes it and opens a draft PR
  report.py                writes report.json, report.csv and report.md
  dashboard.py             read-only web page joining every run's report.json, validation.json and fix.json
  config.py                paths, timeouts, batch size, scanner environment allowlist, logging
  tools/                   one module per scanner, all built on tools/base.py; prompt_injection.py is vulnscan's own check
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
   - `installer.ensure()` finds or installs the executable. A tool with no `command` (the built-in prompt-injection check) skips this.
   - `Tool.run()` runs it once per target, writing `raw/<tool>[__<relative path>].json`.
   - Exceptions are caught for each target, so one broken tool never stops the scan.
   - Each tool's status (`ok`, `failed`, `not applicable` or `install failed`), count and errors go into the report.
5. **Sort and number:** findings are sorted by `findings.sort_key` (final severity, then file, then line) and numbered `F001…`.
6. **Triage** (unless `--no-llm`): `triage.triage(non-info findings, …, max_items, budget)` sets `f.triage` on each reviewed finding, then runs Claude's own review, and returns the summary, Claude's own findings and the triage metadata. Findings are then re-sorted, since severities may have changed. One `Budget` (`--claude-budget`, default no cap) is shared by every Claude call in the scan.
7. **Deep review** (unless `--no-deep-review` or `--no-llm`): `deep_review.deep_review(…)` runs after triage with the same budget. Its findings are appended to Claude's own, and its metadata goes into `report.json` as `deep_review`. See [below](#deep-review-deep_reviewpy).
8. **Reports:** `report.write_reports()` writes the three report files. The CLI prints open counts by severity (from `severity_counts`, which excludes false positives and duplicates and includes Claude's own findings) and the report path.

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
| semgrep | repo root | `semgrep scan --config p/default --json --output R --metrics off --quiet --disable-version-check --disable-nosem T` | rule severity | `secret` for `*.secrets.*` rules, else code |
| osv-scanner | repo root | `osv-scanner scan source --recursive --format json --output-file R T`; exit 128 means no lockfiles | CVSS `max_severity`, else the database severity | dependency |
| gitleaks | repo root | `gitleaks dir T --config <R>.toml --ignore-gitleaks-allow --report-format json --report-path R --redact --no-banner --exit-code 0 --log-level error` | always high | secret |
| prompt-injection (built in) | repo root | in-process, `tools/prompt_injection.py` | per rule | code |
| checkov | repo root, if `iac` detected | `checkov -d T -o json --compact --soft-fail --skip-download` (stdout) | check severity, else medium | `secret` for `CKV_SECRET_*`, else config |
| brakeman | each Rails root | `brakeman T -c <R>.yml -f json -o R -q --no-pager --no-exit-on-warn --no-exit-on-error` | confidence: High→high, Medium→medium, Weak→low | code |
| bandit | repo root, if `python` detected | `bandit -r T -f json -o R -q -x <node_modules, venvs, tests> --ignore-nosec --ini <R>.ini` | issue severity | code |
| gosec | each Go module root | `gosec -fmt=json -out=R -no-fail -quiet ./...` (needs Go) | severity | code |

Details per scanner:
- **osv-scanner:** one finding per advisory group. The ID is the CVE alias if there is one; the title is `package version: summary`. The fix version is the lowest `fixed` event above the installed version, because an advisory often has one fix per release line. It's the first one listed if the version can't be compared, and none if no fix is higher.
- **gosec:** line ranges such as `12-14` keep their first line.
- **Suppressions in the scanned repo** don't hide findings. Each was checked against the pinned versions on 2026-11-05:
  - **semgrep:** `--disable-nosem` reports `nosemgrep` lines. `.semgrepignore` is still honoured.
  - **bandit:** `--ignore-nosec` reports `# nosec` lines. An empty `--ini` of ours (`raw/bandit.ini`) replaces the repo's `.bandit`, which can skip tests.
  - **gitleaks:** a config of ours (`raw/gitleaks.toml`: `[extend] useDefault = true`) takes precedence over the repo's `.gitleaks.toml`, and `--ignore-gitleaks-allow` reports `gitleaks:allow` lines. gitleaks reads the target's `.gitleaksignore` whatever `--gitleaks-ignore-path` says, so a non-empty one becomes a medium `secret` finding pointing at it.
  - **brakeman:** an empty `-c` config of ours (`raw/brakeman*.yml`) replaces the app's `config/brakeman.yml`, which can skip checks. Warnings hidden by `config/brakeman.ignore` come back from `ignored_warnings`, with a note in their description.
  - **checkov:** without `--quiet`, the JSON has `skipped_checks` (from `checkov:skip` comments), which are reported with the comment's reason. Checkov reads the target's `.checkov.yaml` even with `--config-file` or another working directory, so one that skips anything becomes a low `config` finding.
- **prompt-injection:** our own stdlib check, so it has no `command` and nothing is installed. It walks the repo, skipping the same folders as `detect.py`, binary files, files over 2 MB and `*.min.js`, and reads them without running anything. One finding per line, from the first rule that matches, and at most 3 per rule and file. `raw/prompt-injection.json` lists the hits.

  | Rule | Severity | Matches |
  |---|---|---|
  | `hidden-unicode-tags` | high | Unicode tag characters (U+E0000–E007F), which spell out ASCII models read but people can't see. The decoded text goes into the description. Subdivision flag emoji are skipped. |
  | `reviewer-steering` | high | Telling an AI or scanner to mark something as a false positive or not a vulnerability, to ignore or skip it, or not to report a vulnerability, finding or secret |
  | `bidi-control` | medium | Bidi embedding, override and isolate characters (Trojan Source) |
  | `zero-width-run` | medium | 4 or more zero-width characters in a row |
  | `instruction-override` | medium | "ignore / disregard / forget … previous / prior / system … instructions / prompts / rules" |
  | `ai-addressed` | medium | An AI named and told what to do ("Claude, ignore…", "AI: do not…"), or "note to the AI" |
  | `chat-markup` | low | Chat-template tokens such as `<\|im_start\|>` |

  On the largest local repo (a Rails monolith) it took 24 s and found nothing after tuning. In the snippets, invisible characters are spelled out (`<U+202E>`, `<hidden text>`).

**Installer** (`installer.py`), used for local runs:
- `find()` looks in `$VULNSCAN_HOME/tools/bin` first, then on `PATH`. In the Docker image every scanner is already on `PATH`, so nothing is installed at scan time.
- **pip:** a virtualenv per tool, linked into `tools/bin`.
- **gem:** `gem install --install-dir tools/gems --bindir tools/bin`.
- **github:** the latest release asset for this OS and architecture (`.tar.gz` or a bare binary), checked against the release's checksums file.

## Triage pipeline (`triage.py`)

### Building items (`build_items`)

Findings are turned into **items**: the units Claude reviews. Each item is a pair `(item_json, member_findings)`.
- **Dependencies:** grouped by `(package, version)` across all lockfiles into one `D###` item: `package`, `version`, `locations` (up to 10 lockfiles), and `advisories` (unique by ID, up to 20, each with ID, severity, title and fixed version).
- **Repeated rules:** any rule from any tool except brakeman with more than `GROUP_MIN = 10` hits becomes one `G###` item: `rule`, `title`, `hits`, `samples` and `description`. `samples` are up to `SAMPLES = 5` `{id, location}`, one per file, chosen by `_samples`: app code before paths that match `LOW_VALUE_PATH` (tests, specs, Cypress and e2e, fixtures, vendored, example and docs folders), one per folder before a second from the same folder, worst first within that.
- **Everything else:** one item per finding, using its `F###` ID and `_compact()` fields (ID, tool, rule, severity, category, title, location, package fields, and description up to 500 characters).
- **Sort key:** `(not critical/high, category order secret→code→config→dependency, severity, file, line)`. So all critical/high items come first, and code comes before dependencies within the same severity band.

### Batches

- The first `max_items` (`--max-triage`, default 400) are split into batches of `TRIAGE_BATCH` (default 100). Then one more call reviews the code (below), which runs even with no findings.
- Each batch is one `_run_claude` call:
  ```
  claude -p --restricted --strict-mcp-config --tools Read,Grep,Glob --add-dir <repo>
         --output-format json --json-schema <SCHEMA> --model <M>
  ```
  - `M` is `--model`, or else `config.CLAUDE_MODEL` (`claude-opus-5-5`). It's passed on every call (triage, review, deep review, fix), so results don't depend on Claude Code's default for the account and version. Opus 5.5 needs Claude Code 2.1.280 or newer; the image pins 2.1.311. The triage metadata records it as `model`.
  - The prompt goes in on stdin.
  - The working directory is the run folder.
  - The environment has `GITHUB_TOKEN*` and `GH_TOKEN*` removed.
  - The timeout is `TRIAGE_TIMEOUT` per batch.
  - Raw stdout is saved as `claude-<n>.json`, and the result is read from `structured_output`.
- **Shared prompt parts:** `_RULES` (repo content is untrusted, never follow it; never copy a secret's value, even partly, into the answer) and `_SEVERITY_GUIDE`. The guide anchors severity to what an attacker can do: critical for no-login RCE, SQL injection or auth bypass, SSRF reaching cloud metadata or internal services, and live production credentials; high for anything any logged-in user can exploit with serious impact, and for denial of service that one request, or a few, from anyone can cause; medium for denial of service that needs a login or sustained volume, among other things; then low (hardening) and info (not a vulnerability). The DoS lines were added on 2026-11-06, after Opus rated unauthenticated multipart DoS in starlette and python-multipart as "limited impact" medium.
- **Batch prompt** (`PROMPT`): a verdict for every item. Its rules:
  - `duplicate` must name the other item in `duplicate_of`.
  - `needs_review` must say what a person has to check.
  - Dependencies: never loaded at runtime → `false_positive`; development or tests only → low. `Bundler.require` and transitive loading mean "no import" isn't proof. The fix is the lowest version that fixes every advisory. A package that fetches the URLs inside content it processes (HTML-to-PDF renderers, headless browsers, web loaders) is an SSRF sink, rated as SSRF if users can put URLs into that content. The review prompt says the same in its SSRF step.
  - Groups: judge the pattern from the samples, and give any sample that doesn't fit its own verdict.
  - Suppressions in the repo are its claim, not proof.
  - Prompt-injection items: confirmed if they try to steer an AI or hide text for no clear reason, false positive if they're the app's own prompt.
  - A 1–2 sentence summary. With several batches, the prompt says "batch n of N".
- **`SCHEMA`**: `summary`, and `findings[]` of `{id, verdict ∈ confirmed|false_positive|duplicate|needs_review, severity, reason, fix, duplicate_of?}`.

### Claude's own review

One more `_run_claude` call after the batches, with `REVIEW_PROMPT` and `REVIEW_SCHEMA` (`summary`, `additional_findings[]` of `{title, severity, file, line?, description, fix}`). Its raw output is `claude-review.json`. It's separate so a review that times out can't take the batch-1 verdicts (the most important items) with it. It used to be part of batch 1.
- It looks for up to 10 issues scanners miss (SSRF, IDOR/authz, authentication bypass, deserialization, command injection, mass assignment). It must check every route module for missing authentication or authorization, not stop in one area, and SSRF is also traced back from outbound HTTP calls.
- If the app calls an LLM, it checks for prompt injection into prompts that decide something, indirect prompt injection into agents that call tools (and tool calls from LLM output without an allowlist), unsanitised LLM output, client-chosen model/tokens/path or LLM proxies, missing auth or rate limits on LLM endpoints, and personal data sent to LLM providers or tracing tools.
- It looks for prompt injection planted in the repo and aimed at AI tools: instructions in comments, docs, test data and agent files (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.github/copilot-instructions.md`, `.claude/`, …), text hidden from people, and agent settings that run commands (hooks, `.mcp.json`).
- `_reported` gives it the selected scanner items Claude didn't dismiss (not dependencies) as `{id, title, location | rule, hits, samples}`, so it doesn't report them again.
- Each issue's description names its entry point and who can reach it, which Strix needs. The 3–5 sentence summary covers the scanners' findings too and ends with the parts of the app it didn't review.

### Mapping verdicts back (`_apply`)

- **Duplicates first** (`_check_duplicates`): a `duplicate` whose `duplicate_of` isn't another item (or sample) of the batch, names itself, or names an item that's also a duplicate becomes `needs_review`, with a note in its reason. Two items marked duplicates of each other, or one pointing at an item Claude can't see, would otherwise both vanish; now one of a pair stays open.
- **Single-finding items:** `f.triage = verdict`.
- **Group items:** every member gets `f.triage = verdict + {group: "D001"/"G001", scope: "package-level review of N advisories" / "rule-level review of N hits from K samples"}`. A sample with its own verdict gets that verdict alone, with no `group` or `scope`, as if it had been reviewed by itself.
- **A failed batch** (timeout, bad output, CLI error) is logged and recorded in `errors`; the other batches continue. Items Claude returned no verdict for are listed in `errors` too, and make the status `partial`.

### Result and metadata

- **Result:** `{summary, additional_findings}`. The summary is the review's, followed by "Triage batches:" with each batch's summary (just those if the review failed).
- **Metadata** (`report.json` → `triage`):
  - `status`: `done`, `partial` or `failed` (every call failed)
  - `cost_usd`: summed `total_cost_usd`. This is the API-rate figure; with a subscription token it's not billed.
  - `items`, `items_total`, `findings_covered`, `batches`, `review` (`done`, `failed` or `skipped`), `errors`
  - `budget_usd`, when `--claude-budget` was set

### The Claude budget (`Budget`)

`Budget(limit)` keeps the sum of `total_cost_usd` over a scan's Claude calls. Each call site checks `exhausted()` before starting a call and `add()`s its cost after. With the subscription token, nothing is billed, so it limits how much of the plan's allowance one scan can use. The order calls are made in is the priority: triage batches, then the general review, then deep-review batches. A skipped triage batch or review is recorded in `errors` as "skipped, the scan's Claude budget ($N at API rates) was reached", so `status` becomes `partial`. A skipped deep-review batch goes in that pass's `skipped`. A running call isn't stopped, so the total can pass the cap by one call. `fix` doesn't use it.

## Deep review (`deep_review.py`)

On by default in `vulnscan scan`, after triage. `--no-deep-review` skips it, and so does `--no-llm`; the CLI refuses `--deep-review` with `--no-llm`, and `--deep-path` when the deep review is off (exit 2). The general review reads what Claude chooses in one session, which on a monolith is a small part of the code. Here vulnscan decides coverage. It lists everything one issue class needs checked, splits it into batches, and gives Claude one batch per `_run_claude` call, with `REVIEW_SCHEMA` and the same `_RULES` and `_SEVERITY_GUIDE` as triage. Calls run one at a time.

1. **Inventory** (`_inventory`): walks the repo with the prompt-injection check's `_files`/`_read`, so it skips the same folders, binary files and files over 2 MB. It also skips paths matching `LOW_VALUE_PATH` (tests, vendored, examples, docs) and, with `--deep-path`, anything not under one of those prefixes. It reads code files by extension (`.rb`, `.py`, `.js`/`.ts` and variants, `.go`, `.java`, `.kt`, `.php`) and never runs anything.
   - **Outbound HTTP call sites** (`_HTTP_CALL`, per language): lines that call an HTTP client, such as Net::HTTP, Faraday, HTTParty, `URI.open`, requests, httpx, `urlopen`, fetch, axios, `http.Get` or RestTemplate. They also include calls to libraries that fetch the URLs inside content they render or load, which make requests with no HTTP call in the app's own code:
     - HTML-to-PDF renderers: WeasyPrint (`.write_pdf(`, `HTML(string=…)`), pdfkit, wkhtmltopdf, `render pdf:` and `WickedPdf.new`, PDFKit, Grover, xhtml2pdf, Dompdf, Flying Saucer and openhtmltopdf;
     - headless browsers: `page.goto` and `page.setContent`, Ferrum, chromedp, Selenium `webdriver`;
     - LangChain web loaders.

     The SSRF prompt has Claude trace the rendered content (can users put URLs or markup into it?) and check for restrictions such as a custom `url_fetcher`. Import, `require` and comment lines don't count, and neither do JS files under browser paths (`assets/`, `javascript/`, `public/`, `static/`, `client/`, `frontend/`, `components/`).
   - **LLM call sites** (`_LLM_CALL`, per language): lines that create an LLM client or call one (OpenAI and Azure OpenAI, Anthropic, Bedrock `invoke_model`/`converse`, Gemini `generate_content`, LiteLLM, the Vercel AI SDK, LangChain chat models and prompt templates, RubyLLM, Spring AI, Prism). They also include lines that build a prompt: system and user messages (`"role": "user"`, `SystemMessage(`), Python f-string prompts (`…prompt… = f"…"`) and `…PROMPT.format(`. Apps usually call the LLM in one wrapper, so the wrapper alone doesn't show where untrusted text goes in. The same import, comment and browser-path exclusions apply as for HTTP calls.
   - **Request-handler files** (`_HANDLER`, per language): Rails `*_controller.rb` or a class inheriting a `…Controller`, Grape and Sinatra routes, Flask/FastAPI route decorators, `APIRouter`, Django views (`def …(request`, `View`/`ViewSet` classes), Express routes, NestJS `@Controller`, Next.js route handlers, Go `HandleFunc` and router methods, Spring `@…Mapping`, Laravel controllers.
2. **SSRF pass** (`SSRF_PROMPT`): call sites in path order, up to `SITES_PER_BATCH = 25` per call, listed as `file: lines`. Claude traces each URL, host and scheme back, including through stored data and jobs. A call counts as safe only with a fixed host, an allowlist, or a resolved-IP check on every request including redirects. It skips browser code, reports verified SSRF with entry point, who can reach it and what an attacker could reach, and says in its summary which sites it couldn't trace. Raw output: `claude-deep-ssrf-<n>.json`.
3. **LLM pass** (`LLM_PROMPT`): LLM call sites batched the same way as SSRF, 25 per call. Claude follows what goes into each prompt and where the output goes, through callers, wrappers, jobs and stored data. It checks for:
   - prompt injection into outputs that decide something, with no separation and no check outside the LLM, including second-order injection through stored text and retrieval;
   - data the model can be talked into revealing (secrets, reference solutions, rubrics, other users' data);
   - tool calls made from LLM output without an allowlist;
   - output rendered as HTML or markdown for others, or passed into SQL, a shell, URLs or eval. When the output is rendered in another codebase, Claude says so;
   - client-chosen models, LLM proxies and missing limits (cost abuse);
   - personal data sent unredacted to providers or tracing tools.

   The app's own prompts and what the model might say aren't findings. The prompt adds a severity line for LLM issues: changing a score, grade, assessment or hiring decision, leaking solutions or rubrics, or driving actions is high. Personal data sent to a provider is low unless the wrong people can read it there. Raw output: `claude-deep-llm-<n>.json`.
4. **Access-control pass** (`ACCESS_PROMPT`): handler files sorted by folder, packed into batches of about `LINES_PER_BATCH = 4000` lines (a bigger file gets a batch of its own). Claude first learns the app's authentication and authorization mechanism and routes. It then checks every action for missing authentication (including skipped filters and filters that don't halt), missing authorization, IDOR (unscoped lookups by request id) and mass assignment. It reports one issue per root cause, and says in its summary which files it reviewed fully. Other kinds of issue are reported only when high or critical and not already reported. The first real run, with no scanner findings passed, drifted into injection, XSS and cookie settings for half its 24 issues. Raw output: `claude-deep-access-<n>.json`.
5. **Order:** SSRF, then LLM, then access control. Access control has by far the most batches, so it runs last, and a `--claude-budget` cut falls on it rather than on the two small passes.
6. **No repeats:** each call gets `_reported`, which is the general review's findings, the scanner findings Claude didn't dismiss in that batch's files, and the deep findings so far in those files (up to 80).
7. **Results:** each issue becomes one of Claude's own findings, with `found_in: "deep review: SSRF"`, `"deep review: LLM"` or `"deep review: access control"`. They're numbered `C…` with the rest, and validated by Strix like the rest. Strix can rarely prove an LLM finding from the code alone, because its sandbox has none of the app's LLM keys, so give it a live target with `--url`. `deep_review` in `report.json` has:
   - `paths` and `cost_usd`;
   - for `ssrf` and `llm`: `files`, `call_sites`, `batches`, `done`, `skipped`, `failed` and `summaries`;
   - for `access`: `files`, `lines` and the same batch fields.

   Batches are named by their files (SSRF and LLM) or folders (access).

SQL injection, command injection, deserialization, XSS and open redirects get no pass: the scanners find their sinks, and triage verifies them. On the largest local Rails app (2026-11-06), listing took 6 s and found 220 call sites in 94 files and 1,358 handler files (136,550 lines), which comes to 10 SSRF and 37 access-control batches. The LLM pass adds 60 call sites in 31 files there (3 batches), and 212 in 79 files on a local copy of the scaler backend (9 batches, next to 5 SSRF and 4 access-control batches).

## Validation stage (`validate.py`)

Stage 2, run with `vulnscan validate <repo>` after a scan. It re-checks the scan's **open critical and high findings**, 20 per pass (`config.VALIDATE_PASS`), with Strix (https://github.com/usestrix/strix), whose agents run inside Strix's own Docker sandbox and only report a finding with a working proof-of-concept.

1. **Find the run:** the stage-1 run folder is the latest with a `report.json` for that repo label (or `--run`). Its open findings come from `open_items`: confirmed, needs review, not triaged, plus Claude's own `C…` findings, but not false positives, duplicates or anything whose final severity is `info`.
   - **Groups are collapsed:** the members of one triage group (`G…` or `D…`) are sent as one entry, the first hit outside `LOW_VALUE_PATH`. A rule group adds `hits` and up to 5 `other_locations`; a dependency adds `other_advisories`. Before this, a confirmed 200-hit rule became 200 entries and pushed everything else past the cap.
   - **Order:** sorted by (dependency last, final severity, category secret→code→config, file, line), because Strix can rarely prove a dependency advisory.
   - **Selection:** only entries whose final severity is `critical` or `high`, minus the IDs already in an existing `validation.json`'s `coverage.sent`. So a re-run carries on where the last one stopped, and once everything is sent it logs that, leaves the files alone and exits 0.
   - **`--only`** (repeatable, case-insensitive) sends just those IDs instead, of any severity and without collapsing, so any hit of a group can be picked. An ID that isn't an open finding raises `ValidateError` before anything is cloned, and the chosen IDs are recorded as `only` in `validation.json`. With nothing to validate and no `validation.json`, reports are written saying so and Strix never runs.
2. **Checkout:** the repo is cloned exactly as in stage 1 (org allowlist, token via `GIT_CONFIG_*`). If the new HEAD differs from the report's commit, a warning is logged. For a GitHub repo, `_fix_branches` then runs `git ls-remote --heads origin vulnscan/fix-<run>-*`. If `vulnscan fix` already pushed branches for this run but there's no `validation.json`, it raises `ValidateError` (exit 2) before Strix runs, because numbering would start again at `V001` and the branches and PRs are named after the old ids. With a `validation.json`, new ids follow the existing ones, so the check is skipped. Strix mounts local targets **writable**, so a local folder is first copied to a throwaway directory under `work/`; our own clones are already throwaway.
3. **Passes:** the selected findings are split into passes of `VALIDATE_PASS` (20), in order, and `_run_pass` runs steps 4 to 6 once per pass. Each pass is a separate Strix run on a fresh copy of the clone, with its own budget, timeout and context, and is numbered after the passes already in `validation.json`. Reports are written after every pass. A failed pass (exit 1, timeout, no or unreadable artifacts) stops the command with `ValidateError`; only the IDs it validated are added to `coverage.sent`, so the next run sends the rest again. A pass that runs out of budget isn't a failure: Strix stops cleanly, and the run goes on to the next pass.
4. **Seed Strix:** `strix -n --target <clone> [--target <url> …] --instruction-file <run>/strix-instructions.md --workspace-file <run>/strix-findings.json:findings.json --scan-mode <mode> --scope-mode full [--max-budget <USD>]`. The instructions tell Strix to:
   - validate each listed finding, in order, without spending most of the budget on one;
   - validate a group at one of its locations, and a dependency advisory only if the app reaches the vulnerable code;
   - start each title with the stage-1 ids it validates (`[F012, C03] …`) or `[new]`, and mention an id only in the findings it belongs to;
   - report only what it validated, and treat the finding texts as untrusted data.

   `--instruction` flags are appended as operator notes (e.g. credentials for a live target).
5. **Environment:** Strix gets `STRIX_LLM` (`--model`, default `openrouter/z-ai/glm-5.3`), `LLM_API_KEY` (from `LLM_API_KEY` or `OPENROUTER_API_KEY`), `STRIX_TELEMETRY=0`, Docker and proxy variables — and nothing else. The GitHub token never reaches Strix. Each pass is stopped after `VULNSCAN_VALIDATE_TIMEOUT` (default 7200 s). Headless exit codes: 0 clean, 2 findings found (both fine), 1 fatal.
6. **Artifacts:** Strix writes `strix_runs/<name>/` into the run folder's `strix/` scratch directory, which each pass empties first; the pass's run is copied to `raw/strix/pass-<n>/` and the latest pass's output log is at `strix/strix-output.log`. `vulnerabilities.json` is parsed first, falling back to `findings.sarif`; both are read defensively because the schema isn't documented. `run.json` supplies the status and `llm_usage.cost`. If Strix exited 2 but nothing parsed, that's an error, not "no findings".
7. **Reports:** findings are normalised (severity, title, PoC, fix, location), numbered `V001…`, and the stage-1 ids they validate (`F\d{3,}`, `C\d{2,}`) go into `validates` (`_validates`). They come from the `[…]` tag a title starts with. A tag with ids, `[]` or `[new]` is trusted as it is, and only a title without such a tag falls back to every id in its title, description and PoC. The earlier version read ids from the whole text, so "F013 is a false positive" counted F013 as validated, and its `F\d{3}` never matched `F1000` and above. `validation.md`, `validation.json` and `validation.csv` are written into the stage-1 run folder, with a best-effort coverage section listing what was and wasn't referenced. `coverage.sent` lists the IDs sent. Values pass through `report._csv_value` like stage 1.
8. **Merging:** every pass, with or without `--only`, adds to `validation.json`. Its findings are kept as they are and the pass's are numbered after them (`V<n+1>…`). The IDs sent are the union of the earlier `coverage.sent` and the pass's. A `validation.json` written before `sent` existed falls back to the worst `items_sent` open findings, which is what that run sent. `referenced`, `not_referenced` and `items_sent` are recomputed over the union. `passes` keeps one entry per Strix run on this scan (`pass`, `sent`, `status`, `exit_code`, `cost_usd`, `duration_s`, `errors`), and `validation.md` lists them with the total cost. `strix` is the latest pass, which the dashboard reads. `validated_at`, `commit` and `only` describe the latest command.

On the instance, the repo copy Strix tests (`strix-target/`) is placed inside the run folder, not under `work/`: the run folder sits on the scans volume, mounted at the same path on the host and in the vulnscan container, so the host's Docker daemon — which Strix asks to mount the target into its sandbox — can see it. The copy is removed when the run finishes.

## Fix stage (`fix.py`)

Stage 3 is run with `vulnscan fix <repo>` after a validation. It opens one draft PR per finding in `validation.json`.

1. **Find the run:** the latest run folder for that repo that has a `validation.json`, or `--run`. A local folder is refused, because PRs need a GitHub repo. `--only` (repeatable, case-insensitive) narrows the findings to those IDs. An unknown ID raises `FixError` before anything is cloned, and the chosen IDs are recorded as `only` in `fix.json`. With no validated findings, `fix.md` says so and nothing else runs. Otherwise it checks first that `claude` is on `PATH` and that a GitHub token exists (unless `--dry-run`).
2. **Checkout:** `repo.checkout` clones as in stage 1, which enforces the org allowlist. `GET /repos/{owner}/{name}` supplies `private` and `default_branch`. A public repo is refused unless `--dry-run`. The PR base is `--ref`, or the default branch. If the HEAD differs from the validation's commit, a warning is logged.
3. **For each finding** (`_fix_one`):
   - **Skip check:** if the branch `vulnscan/fix-<run>-<V id>` already exists on GitHub (`git ls-remote`), the finding is skipped. This happens before Claude runs.
   - **Branch:** `git checkout -f -B <branch> <base sha>`, then `git clean -fdx`, so each finding starts from a clean base.
   - **Claude:** `triage._run_claude` with `tools="Read,Grep,Glob,Edit,Write"`, which adds `--permission-mode acceptEdits`, and the fix `SCHEMA` (`fixed`, `breaking`, `before_merging[]`, `title`, `summary`, `reproduce`, `review_notes`). The working directory is `<run>/fix/` and the repo comes in through `--add-dir`. The prompt has the finding (with its PoC), the stage-1 findings it `validates` (tool, rule, location, description, and the triage's reason and fix, from `validate.open_items` over `report.json`), the untrusted-data rule, and a rule against writing any part of a secret's value into any field. If the issue is no longer in the code, Claude changes nothing and says so. The prompt treats a fix that breaks the app as worse than no fix. Claude must learn how the app is configured and deployed before changing anything that depends on it, and prefer backwards-compatible changes. It must not delete endpoints, files or config, or add requirements callers may not meet, unless that's the only fix, in which case it sets `breaking`. It must make no change that rests on an unverifiable assumption about another system. For committed secrets, rotation always goes in `before_merging`. The raw response is saved as `fix/claude-<V id>.json`.
   - **No fix:** if `fixed` is false or `git status` shows no change, the status is `not fixed` and the reason comes from the review notes.
   - **Commit:** `git add -A` and a commit with the `vulnscan <vulnscan@noreply.invalid>` identity. Every git call adds `-c core.hooksPath=/dev/null -c commit.gpgsign=false`. The commit is saved as `fix/<V id>.patch`.
   - **Push and PR:** unless `--dry-run`, vulnscan pushes `HEAD:refs/heads/<branch>` with `repo.git_env` (the token through `GIT_CONFIG_*`). It then calls `POST /repos/{owner}/{name}/pulls` with `draft: true` and the title `[vulnscan] <title>`, or `[vulnscan][breaking] <title>`. The body opens with a CAUTION banner if the fix is breaking, and a "Before merging" checklist from `before_merging`. It then has the finding, the stage-1 ids, the run and commit, Claude's summary, "Steps to reproduce" (`reproduce`), the review notes, and an "untested" warning. `reproduce` is a `curl` command against `$BASE_URL`, or numbered steps, ending with the behaviour before and after the fix. Hosts, credentials and secret values are placeholders. Strix's raw `poc` is never copied into the PR. API calls use `urllib` with the token in the `Authorization` header. If the PR call fails, vulnscan deletes the branch it just pushed (`git push origin --delete`), because a re-run skips any finding whose branch exists and so would never open that PR. If the delete fails too, the error says to delete the branch by hand.
   - **Errors:** a git, Claude or API error marks that finding `failed`, and the loop continues.
4. **Reports:** `fix.json` has the metadata (`base`, `commit`, `validation_commit`, `model`, `dry_run`, `cost_usd`) of the latest fix run, and one result per finding: `status`, `branch`, `pr_url` or `error`, `detail` and `fixed_at`. `fix.md` shows the same as a table. `_merge_earlier` keeps the results already in `fix.json`:
   - It keeps them for findings this run didn't handle.
   - It keeps them over this run's `skipped`, since the branch exists and the earlier result, such as its PR link, still applies.
   - It drops an earlier result whose ID and title no longer match `validation.json`, which happens when the scan was re-validated.

   If any finding in this run failed, `FixError` is raised after the reports are written, so the exit code is 2.

The wrapper needs no special case for `fix`. It already passes `GITHUB_TOKEN` and `CLAUDE_CODE_OAUTH_TOKEN`, and the container gets no Docker socket.

## Dashboard (`dashboard.py`)

`vulnscan dashboard [--host 127.0.0.1] [--port 8080]` runs a stdlib `ThreadingHTTPServer` over `$VULNSCAN_HOME/scans`. It's GET only and has two routes:
- **`/`:** every `<label>/<run>` folder, newest first. `_summary` per run is cached by the three files' mtime and size, so unchanged runs aren't parsed again.
- **`/run/<label>/<run>`:** one run. Both names must be existing folder entries. The path is never built from the URL, so `..` and encoded slashes get a 404.

`_run_data` joins the stages:
- **Open findings:** the stage-1 findings that aren't `false_positive` or `duplicate`, plus Claude's own. Claude's are numbered `C01…` in `report.json`'s order, as everywhere else. `report.py` sorts them by severity before writing.
- **Strix status of each open finding:**
  - the `V…` ids whose `validates` include it;
  - `not validated` if it's in `coverage.not_referenced`;
  - `grouped with F…, which was sent` for another hit of a group that validation sent once, through that hit;
  - `not sent` if validation ran without it (medium or low, not reached yet, or not picked with `--only`);
  - nothing if validation hasn't run.
- **Fix status:** comes from `fix.json` results by `V…` id.
- **Missing or half-written files:** a missing `report.json` shows "unfinished", and one that doesn't parse shows "unreadable".

Safety:
- **Untrusted content:** findings quote repo content, so every value goes through `html.escape`. Links are rendered only for `https://` URLs.
- **Response headers:** `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; …`, `nosniff`, `Referrer-Policy: no-referrer` and `Cache-Control: no-store`.
- **Host check:** a request whose `Host` isn't `localhost`, `127.0.0.1` or `::1` gets a 403, so DNS rebinding can't reach it.
- **What it never shows:** Strix's `poc` text and raw files.

## Reports (`report.py`)

- **`report.json`:** the scan metadata (`repo`, `commit`, `scanned_at`, `stacks`, `tools`, `triage`, and `deep_review` when the deep review ran), plus `summary`, `findings` (each `Finding` as a dict, including `triage`) and `additional_findings`. `additional_findings` are sorted by severity before any file is written. Every file, `validate.py` and the dashboard number them `C01…` in that order, so an id always names the same finding.
- **`report.csv`:** the columns in `CSV_COLUMNS` (described in the [README](../README.md#outputs)). Claude's own findings come first as `C01…`. Every value goes through `_csv_value`, which guards against formula injection.
- **`report.md`:**
  - It starts with the scan details, tool status and summary. When the deep review ran, the details include a "Deep review" line (batches done of each pass, how much code they covered, skips, failures, cost). A "Deep review: batches not reviewed" section lists each skipped or failed batch.
  - **Confirmed:** a table, then one details section per finding. Group members share one section headed with the group ID, saying "and N more (see report.csv)".
  - Then Claude's own findings (`C01…`, each deep-review one with a "Found in" line), needs review (table with reason), not triaged (table), and dismissed (table with reason).

## Configuration (`config.py`)

- **Paths:** `HOME` (`$VULNSCAN_HOME` or `~/.vulnscan`) contains `tools/bin`, `tools/gems`, `tools/venvs`, `scans` and `work`.
- **Timeouts and batch size:** `TOOL_TIMEOUT`, `TRIAGE_TIMEOUT` and `TRIAGE_BATCH`, each from its environment variable.
- **Validation:** `VALIDATE_TIMEOUT` and `VALIDATE_BUDGET` (per pass, from their environment variables) and `VALIDATE_PASS`, the 20 findings per Strix run (a constant).
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
1. Source `/etc/vulnscan/config`. Refuse `dashboard` (exit 2) before reading any token: the dashboard has its own container.
2. Read `$SSM_PREFIX/github-token` and `claude-token` with the instance role; for the `validate` subcommand also `$SSM_PREFIX/openrouter-token` (which must not still be the placeholder).
3. Remove leftover containers labelled `vulnscan`.
4. Start the scan detached:
   ```
   docker run -d --init --label vulnscan --cap-drop ALL --security-opt no-new-privileges
              --memory 6g --pids-limit 1024
              -e GITHUB_TOKEN -e CLAUDE_CODE_OAUTH_TOKEN -e VULNSCAN_GITHUB_ORG
              -e VULNSCAN_TOOL_TIMEOUT -e VULNSCAN_TRIAGE_TIMEOUT -e VULNSCAN_VALIDATE_TIMEOUT
              -e VULNSCAN_TRIAGE_BATCH -e VULNSCAN_VALIDATE_BUDGET
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
4. Install `deploy/host/vulnscan` to `/usr/local/bin`, and pre-pull Strix's sandbox image.
5. Recreate the dashboard container on the new image:
   ```
   docker run -d --name vulnscan-dashboard --restart unless-stopped --init
              --cap-drop ALL --security-opt no-new-privileges --read-only --memory 512m --pids-limit 64
              --network vulnscan-dashboard -p 127.0.0.1:8080:8080
              -v /var/lib/vulnscan/scans:/var/lib/vulnscan/scans:ro
              vulnscan:latest dashboard --host 0.0.0.0 --port 8080
   ```
   - **No tokens:** it gets no `-e` at all, and has no AWS access (IMDS hop limit 1).
   - **Network:** `vulnscan-dashboard` is a bridge network of its own, created if missing. Docker isolates bridges from each other, so containers on the default bridge can't reach it. That includes the Strix sandboxes that run scanned code.
   - **Port:** it's published on the host's loopback only, and Session Manager port forwarding connects there.
   - **Restarts:** Docker starts at boot, and `--restart unless-stopped` brings the container back after a Spot stop.
6. Prune images and build cache.
7. Reinstall itself from `deploy/host/vulnscan-build`. It installs to a temporary name and renames it, so the running copy is untouched; the new copy runs from the next time. First boot writes the script only once, so before this step existed, changes to it never reached the instance.

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
