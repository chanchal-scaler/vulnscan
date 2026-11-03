from ..findings import Finding, rel_path
from .base import Tool

# Brakeman reports confidence rather than severity; use it as the starting severity.
_CONFIDENCE = {"High": "high", "Medium": "medium", "Weak": "low"}


class Brakeman(Tool):
    name = "brakeman"
    command = "brakeman"
    install = [("gem", "brakeman")]
    applies_to = "Ruby on Rails apps"

    def targets(self, repo, stacks):
        return stacks.get("rails", [])

    def args(self, exe, target, report):
        return [
            exe, str(target), "-f", "json", "-o", str(report), "-q",
            "--no-pager", "--no-exit-on-warn", "--no-exit-on-error",
        ]

    def parse(self, data, repo, target):
        return [
            Finding(
                tool=self.name,
                rule_id=w.get("check_name") or w.get("warning_type", ""),
                title=f"{w.get('warning_type')}: {w.get('message')}",
                severity=_CONFIDENCE.get(w.get("confidence"), "medium"),
                category="code",
                file=rel_path(w.get("file"), repo, target),
                line=w.get("line"),
                description=str(w.get("message") or ""),
                references=[w["link"]] if w.get("link") else [],
            )
            for w in data.get("warnings", [])
        ]
