from ..findings import Finding, normalize_severity, rel_path
from .base import Tool


class Semgrep(Tool):
    name = "semgrep"
    command = "semgrep"
    install = [("pip", "semgrep")]
    applies_to = "all repos (code, 30+ languages)"
    ok_exit_codes = (0, 1)

    def args(self, exe, target, report):
        # --disable-nosem: the scanned repo's own nosemgrep comments don't hide findings; Claude judges them.
        return [
            exe, "scan", "--config", "p/default", "--json", "--output", str(report),
            "--metrics", "off", "--quiet", "--disable-version-check", "--disable-nosem", str(target),
        ]

    def parse(self, data, repo, target):
        out = []
        for r in data.get("results", []):
            extra = r.get("extra", {})
            message = (extra.get("message") or "").strip()
            rule = r.get("check_id", "")
            out.append(Finding(
                tool=self.name,
                rule_id=rule,
                title=(message.splitlines() or [rule])[0][:200],
                severity=normalize_severity(extra.get("severity")),
                category="secret" if ".secrets." in rule else "code",
                file=rel_path(r.get("path"), repo, target),
                line=(r.get("start") or {}).get("line"),
                description=message,
                references=list((extra.get("metadata") or {}).get("references") or [])[:3],
            ))
        return out
