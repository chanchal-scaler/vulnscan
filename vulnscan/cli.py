import argparse
import os
import sys

from .config import CLAUDE_MODEL, VALIDATE_PASS, log
from .dashboard import serve
from .fix import FixError, fix
from .installer import InstallError, ensure, find
from .purge import PurgeError, purge
from .repo import RepoError
from .scan import scan
from .tools import ALL_TOOLS
from .validate import DEFAULT_MODEL, ValidateError, validate


def _cmd_scan(args):
    deep = not args.no_llm if args.deep_review is None else args.deep_review  # on by default, unless --no-llm
    problem = ("--deep-review needs Claude, so it can't be used with --no-llm" if args.deep_review and args.no_llm
               else "--deep-path only applies to the deep review, which --no-llm and --no-deep-review switch off"
               if args.deep_path and not deep
               else "--claude-budget must be more than 0" if args.claude_budget is not None and args.claude_budget <= 0
               else None)
    if problem:
        log(problem)
        return 2
    try:
        report, counts = scan(
            args.repo, ref=args.ref, use_llm=not args.no_llm, model=args.model,
            max_triage=args.max_triage, keep_clone=args.keep_clone,
            deep_review=deep, deep_paths=args.deep_path or (), claude_budget=args.claude_budget,
        )
    except RepoError as e:
        log(str(e))
        return 2
    summary = ", ".join(f"{n} {s}" for s, n in counts.items()) or "nothing found"
    print(f"\nOpen findings: {summary}")
    print(f"Report: {report}")
    print(f"Raw data: {report.parent}")
    return 0


def _cmd_validate(args):
    try:
        report, counts = validate(
            args.repo, run_dir=args.run, ref=args.ref, urls=args.url or [], model=args.model,
            scan_mode=args.scan_mode, budget=args.budget,
            instructions=args.instruction or [], only=args.only or [],
        )
    except (RepoError, ValidateError) as e:
        log(str(e))
        return 2
    summary = ", ".join(f"{n} {s}" for s, n in counts.items()) or "none validated"
    print(f"\nValidated findings: {summary}")
    print(f"Report: {report}")
    print(f"Raw data: {report.parent / 'raw' / 'strix'}")
    return 0


def _cmd_fix(args):
    try:
        report, counts = fix(args.repo, run_dir=args.run, ref=args.ref, model=args.model, dry_run=args.dry_run,
                             only=args.only or [])
    except (RepoError, FixError) as e:
        log(str(e))
        return 2
    summary = ", ".join(f"{n} {s}" for s, n in counts.items()) or "nothing to fix"
    print(f"\nFixes: {summary}")
    print(f"Report: {report}")
    return 0


def _cmd_purge(args):
    try:
        paths = purge(args.repo, args.stage, run=args.run, all_runs=args.all_runs, yes=args.yes)
    except (RepoError, PurgeError) as e:
        log(str(e))
        return 2
    if not paths:
        print(f"Nothing to purge: no {args.stage} results" + (f" in {args.run}" if args.run else ""))
        return 0
    print(("Deleted:" if args.yes else "Would delete (add --yes to delete):"), *paths, sep="\n  ")
    return 0


def _cmd_dashboard(args):
    try:
        serve(args.host, args.port)
    except OSError as e:
        log(f"dashboard: can't listen on {args.host}:{args.port}: {e}")
        return 2
    return 0


def _cmd_tools(args):
    status = 0
    for tool in ALL_TOOLS:
        exe = find(tool.command) if tool.command else "built in"
        if not exe and args.install:
            try:
                exe = ensure(tool)
            except InstallError as e:
                log(f"{tool.name}: install failed: {e}")
                status = 1
        how = ", ".join(f"{s}:{spec}" for s, spec in tool.install)
        print(f"{tool.name:<12} {exe or 'not installed (' + how + ')':<70} {tool.applies_to}")
    return status


def main(argv=None):
    os.umask(0o077)  # scan results and installed tools are readable by this user only

    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description="Scan a GitHub repo with the right security tools for its stack and triage the findings with Claude Code.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan a GitHub repo (org/repo or URL) or a local directory")
    s.add_argument("repo", help="org/repo, https://github.com/org/repo, or a local path")
    s.add_argument("--ref", help="branch or tag to scan (default: the repo's default branch)")
    s.add_argument("--no-llm", action="store_true", help="skip Claude triage and review")
    s.add_argument("--model", help=f"Claude model for triage, the review and the deep review (default: {CLAUDE_MODEL})")
    s.add_argument("--max-triage", type=int, default=400,
                   help="max items Claude reviews, most important first; a dependency or a rule with many hits "
                        "counts as one item (default: 400, in batches of 100)")
    s.add_argument("--keep-clone", action="store_true", help="keep the cloned repo after the scan")
    s.add_argument("--deep-review", action=argparse.BooleanOptionalAction,
                   help="after triage, have Claude check every outbound HTTP call for SSRF, every LLM call for prompt "
                        "injection and misuse, and every request handler for broken access control, in batches. "
                        "On by default (off with --no-llm). Slow, and uses far more Claude quota: "
                        "--no-deep-review skips it")
    s.add_argument("--deep-path", action="append", metavar="PATH",
                   help="limit the deep review to files under this path, relative to the repo root (repeatable)")
    s.add_argument("--claude-budget", type=float, metavar="USD",
                   help="start no more Claude calls once this scan's usage reaches this many dollars at API rates. "
                        "With a subscription token nothing is billed: it caps the plan allowance used (default: no cap)")
    s.set_defaults(func=_cmd_scan)

    t = sub.add_parser("tools", help="list scanners and whether they are installed")
    t.add_argument("--install", action="store_true", help="install every missing scanner")
    t.set_defaults(func=_cmd_tools)

    v = sub.add_parser("validate", help="stage 2: validate a scan's open critical and high findings with Strix "
                                        f"(GLM via OpenRouter), {VALIDATE_PASS} per pass")
    v.add_argument("repo", help="the repo that was scanned: org/repo, a GitHub URL, or a local path")
    v.add_argument("--run", help="stage-1 run folder with report.json (default: the latest for this repo)")
    v.add_argument("--ref", help="branch or tag to clone (default: the repo's default branch)")
    v.add_argument("--url", action="append", help="live target to also test, e.g. the staging deployment "
                                                  "(repeatable; only systems you are authorised to test)")
    v.add_argument("--only", action="append", metavar="ID",
                   help="validate only this open stage-1 finding, of any severity, e.g. F003 or C01 (repeatable). "
                        "Adds to the results already in validation.json")
    v.add_argument("--scan-mode", choices=["quick", "standard", "deep"], default="deep",
                   help="Strix scan depth (default: deep, where a pass can take hours)")
    v.add_argument("--budget", type=float,
                   help=f"max LLM spend in USD for each pass of {VALIDATE_PASS} findings "
                        "(default: VULNSCAN_VALIDATE_BUDGET, 25; 0 = no cap)")
    v.add_argument("--model", help=f"model id for Strix, in LiteLLM format (default: STRIX_LLM or {DEFAULT_MODEL})")
    v.add_argument("--instruction", action="append",
                   help="extra instruction for Strix, e.g. test credentials (repeatable)")
    v.set_defaults(func=_cmd_validate)

    x = sub.add_parser("fix", help="stage 3: open one draft PR per validated finding, with fixes written by Claude Code")
    x.add_argument("repo", help="the repo that was validated: org/repo or a GitHub URL")
    x.add_argument("--run", help="run folder with validation.json (default: the latest for this repo)")
    x.add_argument("--ref", help="branch to fix and open PRs against (default: the repo's default branch)")
    x.add_argument("--model", help=f"Claude model for the fixes (default: {CLAUDE_MODEL})")
    x.add_argument("--only", action="append", metavar="ID",
                   help="fix only this validated finding, e.g. V003 (repeatable; default: all of them)")
    x.add_argument("--dry-run", action="store_true",
                   help="commit the fixes in a throwaway clone and save them as patches; push nothing, open no PRs")
    x.set_defaults(func=_cmd_fix)

    p = sub.add_parser("purge", help="delete a stage's results (and the later stages'), from the repo's newest run "
                                     "that has them by default; only lists them without --yes")
    p.add_argument("stage", choices=["scan", "validate", "fix"],
                   help="scan: the whole run folder; validate: the validation results and the fix results made from "
                        "them; fix: the fix results. Fix PRs and branches on GitHub are never touched")
    p.add_argument("repo", help="the repo: org/repo, a GitHub URL, or the local path that was scanned")
    which = p.add_mutually_exclusive_group()
    which.add_argument("--run", help="this run folder (its name or path) instead of the newest")
    which.add_argument("--all", dest="all_runs", action="store_true", help="every run of the repo")
    p.add_argument("--yes", action="store_true", help="delete them (without it, only list what would be deleted)")
    p.set_defaults(func=_cmd_purge)

    d = sub.add_parser("dashboard", help="serve a read-only web page tracking every run through scan, validate and fix")
    d.add_argument("--host", default="127.0.0.1",
                   help="address to listen on (default: 127.0.0.1; the instance's container uses 0.0.0.0 behind a "
                        "port published on the host's loopback only)")
    d.add_argument("--port", type=int, default=8080, help="port to listen on (default: 8080)")
    d.set_defaults(func=_cmd_dashboard)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
