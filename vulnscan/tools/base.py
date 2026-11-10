import json
import subprocess
import time
from pathlib import Path
from typing import Dict, List

from ..config import log
from ..findings import Finding

HEARTBEAT = 60  # seconds between "still running" lines while a scanner works


class ToolError(Exception):
    pass


class Tool:
    """A scanner. Subclasses set the class attributes and implement args() and parse()."""

    name = ""
    command = ""            # executable to look for / install
    install = []            # [(strategy, spec)] tried in order; see installer.py
    applies_to = "all repos"
    ok_exit_codes = (0,)
    nothing_to_scan_codes = ()  # exit codes meaning "nothing this tool can scan here"
    stdout_is_report = False  # tool only prints its JSON report to stdout

    def targets(self, repo: Path, stacks: Dict[str, List[Path]]) -> List[Path]:
        """Directories to run on. An empty list means the tool does not apply."""
        return [repo]

    def args(self, exe: str, target: Path, report: Path) -> List[str]:
        raise NotImplementedError

    def parse(self, data, repo: Path, target: Path) -> List[Finding]:
        raise NotImplementedError

    def run(self, exe, repo, target, report, env, timeout) -> List[Finding]:
        cmd = self.args(exe, target, report)
        proc = subprocess.Popen(cmd, cwd=target, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        started = time.time()
        while True:
            try:
                stdout, stderr = proc.communicate(timeout=min(HEARTBEAT, max(1, timeout - (time.time() - started))))
                break
            except subprocess.TimeoutExpired:
                if time.time() - started >= timeout:
                    proc.kill()
                    proc.communicate()
                    raise subprocess.TimeoutExpired(cmd, timeout)
                log(f"{self.name}: still running ({(time.time() - started) / 60:.0f} min)")
        if proc.returncode in self.nothing_to_scan_codes:
            return []
        if self.stdout_is_report:
            report.write_text(stdout)
        detail = (stderr or stdout).strip()[-500:]
        if proc.returncode not in self.ok_exit_codes:
            raise ToolError(f"exit {proc.returncode}: {detail}")
        if not report.exists() or not report.read_text().strip():
            raise ToolError(
                f"produced no report (exit {proc.returncode}); is its runtime installed (e.g. Go for gosec)? {detail}".strip()
            )
        return self.parse(_load_json(report.read_text()), repo, target)


def _load_json(text):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Some tools print log lines before the JSON document.
        start = min((i for i in (text.find("{"), text.find("[")) if i >= 0), default=-1)
        if start < 0:
            raise
        return json.loads(text[start:])
