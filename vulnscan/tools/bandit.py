from ..findings import Finding, normalize_severity, rel_path
from .base import Tool

_EXCLUDE = ",".join(f"*/{d}/*" for d in ("node_modules", ".venv", "venv", "tests", "test"))


class Bandit(Tool):
    name = "bandit"
    command = "bandit"
    install = [("pip", "bandit")]
    applies_to = "Python"
    ok_exit_codes = (0, 1)  # 1 = issues found

    def targets(self, repo, stacks):
        return [repo] if "python" in stacks else []

    def args(self, exe, target, report):
        return [exe, "-r", str(target), "-f", "json", "-o", str(report), "-q", "-x", _EXCLUDE]

    def parse(self, data, repo, target):
        return [
            Finding(
                tool=self.name,
                rule_id=r.get("test_id", ""),
                title=f"{r.get('test_name')}: {r.get('issue_text')}",
                severity=normalize_severity(r.get("issue_severity")),
                category="code",
                file=rel_path(r.get("filename"), repo, target),
                line=r.get("line_number"),
                description=r.get("issue_text", ""),
                references=[r["more_info"]] if r.get("more_info") else [],
            )
            for r in data.get("results", [])
        ]
