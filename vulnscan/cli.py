import argparse
import os
import sys

from .config import log
from .installer import InstallError, ensure, find
from .repo import RepoError
from .scan import scan
from .tools import ALL_TOOLS


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
    s.add_argument("--max-triage", type=int, default=150, help="max findings sent to Claude, highest severity first (default: 150)")
    s.add_argument("--keep-clone", action="store_true", help="keep the cloned repo after the scan")
    s.set_defaults(func=_cmd_scan)

    t = sub.add_parser("tools", help="list scanners and whether they are installed")
    t.add_argument("--install", action="store_true", help="install every missing scanner")
    t.set_defaults(func=_cmd_tools)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
