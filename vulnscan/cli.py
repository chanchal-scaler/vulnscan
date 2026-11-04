import argparse
import os
import sys

from .config import log
from .installer import InstallError, ensure, find
from .repo import RepoError
from .scan import scan
from .tools import ALL_TOOLS
from .validate import DEFAULT_MODEL, ValidateError, validate


def _cmd_scan(args):
    try:
        report, counts = scan(
            args.repo, ref=args.ref, use_llm=not args.no_llm, model=args.model,
            max_triage=args.max_triage, keep_clone=args.keep_clone,
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
            scan_mode=args.scan_mode, budget=args.budget, max_items=args.max_validate,
            instructions=args.instruction or [],
        )
    except (RepoError, ValidateError) as e:
        log(str(e))
        return 2
    summary = ", ".join(f"{n} {s}" for s, n in counts.items()) or "none validated"
    print(f"\nValidated findings: {summary}")
    print(f"Report: {report}")
    print(f"Raw data: {report.parent / 'raw' / 'strix'}")
    return 0


def _cmd_tools(args):
    status = 0
    for tool in ALL_TOOLS:
        exe = find(tool.command)
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
    s.add_argument("--model", help="Claude model for triage, e.g. opus (default: Claude Code's default)")
    s.add_argument("--max-triage", type=int, default=400,
                   help="max items Claude reviews, most important first; a dependency or a rule with many hits "
                        "counts as one item (default: 400, in batches of 100)")
    s.add_argument("--keep-clone", action="store_true", help="keep the cloned repo after the scan")
    s.set_defaults(func=_cmd_scan)

    t = sub.add_parser("tools", help="list scanners and whether they are installed")
    t.add_argument("--install", action="store_true", help="install every missing scanner")
    t.set_defaults(func=_cmd_tools)

    v = sub.add_parser("validate", help="stage 2: validate a scan's open findings with Strix (GLM via OpenRouter)")
    v.add_argument("repo", help="the repo that was scanned: org/repo, a GitHub URL, or a local path")
    v.add_argument("--run", help="stage-1 run folder with report.json (default: the latest for this repo)")
    v.add_argument("--ref", help="branch or tag to clone (default: the repo's default branch)")
    v.add_argument("--url", action="append", help="live target to also test, e.g. the staging deployment "
                                                  "(repeatable; only systems you are authorised to test)")
    v.add_argument("--max-validate", type=int, default=100,
                   help="max open findings to send, worst first (default: 100)")
    v.add_argument("--scan-mode", choices=["quick", "standard", "deep"], default="standard",
                   help="Strix scan depth (default: standard)")
    v.add_argument("--budget", type=float,
                   help="max LLM spend in USD for the whole run (default: VULNSCAN_VALIDATE_BUDGET, 25; 0 = no cap)")
    v.add_argument("--model", help=f"model id for Strix, in LiteLLM format (default: STRIX_LLM or {DEFAULT_MODEL})")
    v.add_argument("--instruction", action="append",
                   help="extra instruction for Strix, e.g. test credentials (repeatable)")
    v.set_defaults(func=_cmd_validate)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
