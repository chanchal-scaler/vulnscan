from ..findings import Finding, normalize_severity, rel_path
from .base import Tool


class Semgrep(Tool):
    name = "semgrep"
    command = "semgrep"
    install = [("pip", "semgrep")]
    applies_to = "all repos (code, 30+ languages)"
    ok_exit_codes = (0, 1)

    def args(self, exe, target, report):
        return [
            exe, "scan", "--config", "p/default", "--json", "--output", str(report),
            "--metrics", "off", "--quiet", "--disable-version-check", str(target),
        ]

    def parse(self, data, repo, target):
        out = []
        for r in data.get("results", []):
            extra = r.get("extra", {})
            message = (extra.get("message") or "").strip()
            out.append(Finding(
                tool=self.name,
                rule_id=r.get("check_id", ""),
                title=(message.splitlines() or [r.get("check_id", "")])[0][:200],
                severity=normalize_severity(extra.get("severity")),
                category="code",
                file=rel_path(r.get("path"), repo, target),
                line=(r.get("start") or {}).get("line"),
                description=message,
                references=list((extra.get("metadata") or {}).get("references") or [])[:3],
            ))
        return out
