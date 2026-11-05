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
        # An empty config of ours replaces the app's config/brakeman.yml, which could skip checks.
        config = report.with_suffix(".yml")
        config.write_text("--- {}\n")
        return [
            exe, str(target), "-c", str(config), "-f", "json", "-o", str(report), "-q",
            "--no-pager", "--no-exit-on-warn", "--no-exit-on-error",
        ]

    def parse(self, data, repo, target):
        # Warnings the app's own config/brakeman.ignore hides are kept, marked, for Claude to judge.
        return [self._finding(w, repo, target, False) for w in data.get("warnings", [])] + [
            self._finding(w, repo, target, True) for w in data.get("ignored_warnings") or []]

    def _finding(self, w, repo, target, ignored):
        message = str(w.get("message") or "")
        return Finding(
            tool=self.name,
            rule_id=w.get("check_name") or w.get("warning_type", ""),
            title=f"{w.get('warning_type')}: {w.get('message')}",
            severity=_CONFIDENCE.get(w.get("confidence"), "medium"),
            category="code",
            file=rel_path(w.get("file"), repo, target),
            line=w.get("line"),
            description=message + (" (Marked as ignored in the app's config/brakeman.ignore.)" if ignored else ""),
            references=[w["link"]] if w.get("link") else [],
        )
