from ..findings import Finding, normalize_severity, rel_path
from .base import Tool


def _line(value):
    # gosec reports lines as strings, sometimes as a range like "12-14".
    head = str(value or "").split("-")[0]
    return int(head) if head.isdigit() else None


class Gosec(Tool):
    name = "gosec"
    command = "gosec"
    install = [("github", "securego/gosec")]
    applies_to = "Go modules (needs the Go toolchain)"

    def targets(self, repo, stacks):
        return stacks.get("go", [])

    def args(self, exe, target, report):
        return [exe, "-fmt=json", f"-out={report}", "-no-fail", "-quiet", "./..."]

    def parse(self, data, repo, target):
        return [
            Finding(
                tool=self.name,
                rule_id=i.get("rule_id", ""),
                title=i.get("details", ""),
                severity=normalize_severity(i.get("severity")),
                category="code",
                file=rel_path(i.get("file"), repo, target),
                line=_line(i.get("line")),
                description=i.get("details", ""),
                references=[i["cwe"]["url"]] if (i.get("cwe") or {}).get("url") else [],
            )
            for i in data.get("Issues") or []
        ]
