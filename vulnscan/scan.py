import time
from datetime import datetime, timezone

from .config import SCANS_DIR, TOOL_TIMEOUT, log, scanner_env
from .detect import detect_stacks
from .findings import rel_path, sort_key
from .installer import InstallError, ensure
from .repo import checkout, git_head
from .report import severity_counts, write_reports
from .tools import ALL_TOOLS
from .triage import triage


def _run_tools(repo, stacks, raw_dir):
    env = scanner_env()
    findings, runs = [], []
    for tool in ALL_TOOLS:
        targets = tool.targets(repo, stacks)
        if not targets:
            runs.append({"tool": tool.name, "status": "not applicable"})
            continue
        try:
            exe = ensure(tool)
        except InstallError as e:
            log(f"{tool.name}: install failed: {e}")
            runs.append({"tool": tool.name, "status": "install failed", "errors": [str(e)]})
            continue

        count, errors = 0, []
        for target in targets:
            rel = rel_path(target, repo)
            suffix = "" if target == repo else "__" + rel.replace("/", "_")
            started = time.time()
            log(f"{tool.name}: scanning {rel if target != repo else '.'}")
            try:
                found = tool.run(exe, repo, target, raw_dir / f"{tool.name}{suffix}.json", env, TOOL_TIMEOUT)
            except Exception as e:  # one broken tool must not stop the scan
                log(f"{tool.name}: failed: {e}")
                errors.append(f"{rel or '.'}: {e}")
                continue
            log(f"{tool.name}: {len(found)} findings ({time.time() - started:.0f}s)")
            findings += found
            count += len(found)
        status = "failed" if errors and len(errors) == len(targets) else "ok"
        runs.append({"tool": tool.name, "status": status, "findings": count, "errors": errors})
    return findings, runs


def scan(spec, ref=None, use_llm=True, model=None, max_triage=400, keep_clone=False):
    """Scan a repo and write reports. Returns (report_path, open severity counts)."""
    with checkout(spec, ref, keep_clone) as (repo, label):
        now = datetime.now(timezone.utc)
        run_dir = SCANS_DIR / label.replace("/", "__") / now.strftime("%Y%m%d-%H%M%S")
        raw_dir = run_dir / "raw"
        raw_dir.mkdir(parents=True)

        stacks = detect_stacks(repo)
        log(f"stacks: {', '.join(stacks) or 'none detected'}")

        findings, runs = _run_tools(repo, stacks, raw_dir)
        findings.sort(key=sort_key)
        for i, f in enumerate(findings, 1):
            f.id = f"F{i:03d}"

        result, triage_meta = None, {"status": "skipped (--no-llm)"}
        if use_llm:
            result, triage_meta = triage(
                [f for f in findings if f.severity != "info"], repo, list(stacks), run_dir, model, max_triage,
            )
            findings.sort(key=sort_key)

        meta = {
            "repo": label,
            "commit": git_head(repo),
            "scanned_at": now.isoformat(timespec="seconds"),
            "stacks": {k: [rel_path(p, repo) or "." for p in v] for k, v in stacks.items()},
            "tools": runs,
            "triage": triage_meta,
        }
        report = write_reports(run_dir, meta, findings, result)
        return report, severity_counts(findings, result)
