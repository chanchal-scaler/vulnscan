import time
from datetime import datetime, timezone

from .config import SCANS_DIR, TOOL_TIMEOUT, log, scanner_env
from .deep_review import deep_review as run_deep_review
from .detect import detect_stacks
from .findings import rel_path, sort_key
from .installer import InstallError, ensure
from .repo import checkout, git_head
from .report import severity_counts, write_reports
from .tools import ALL_TOOLS
from .triage import Budget, triage


def _run_tools(repo, stacks, raw_dir):
    env = scanner_env()
    findings, runs = [], []
    for tool in ALL_TOOLS:
        targets = tool.targets(repo, stacks)
        if not targets:
            runs.append({"tool": tool.name, "status": "not applicable"})
            continue
        try:
            exe = ensure(tool) if tool.command else None  # a built-in check has nothing to install
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


def scan(spec, ref=None, use_llm=True, model=None, max_triage=400, keep_clone=False,
         deep_review=True, deep_paths=(), claude_budget=None):
    """Scan a repo and write reports. Returns (report_path, open severity counts).

    deep_review (on by default, and only with use_llm) adds Claude's per-class review of the whole codebase (deep_review.py), limited to
    deep_paths if given. claude_budget caps the scan's Claude usage, in USD at API rates.
    """
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

        result, triage_meta, deep_meta = None, {"status": "skipped (--no-llm)"}, None
        if use_llm:
            budget = Budget(claude_budget)
            result, triage_meta = triage(
                [f for f in findings if f.severity != "info"], repo, list(stacks), run_dir, model, max_triage, budget,
            )
            if deep_review:
                found, deep_meta = run_deep_review(repo, list(stacks), findings, result["additional_findings"],
                                                   run_dir, model, budget, deep_paths)
                result["additional_findings"] += found
            findings.sort(key=sort_key)

        meta = {
            "repo": label,
            "commit": git_head(repo),
            "scanned_at": now.isoformat(timespec="seconds"),
            "stacks": {k: [rel_path(p, repo) or "." for p in v] for k, v in stacks.items()},
            "tools": runs,
            "triage": triage_meta,
        }
        if deep_meta is not None:
            meta["deep_review"] = deep_meta
        report = write_reports(run_dir, meta, findings, result)
        return report, severity_counts(findings, result)
