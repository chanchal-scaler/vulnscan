from ..findings import Finding, rel_path
from .base import Tool


class Gitleaks(Tool):
    name = "gitleaks"
    command = "gitleaks"
    install = [("github", "gitleaks/gitleaks")]
    applies_to = "all repos (hardcoded secrets)"

    def args(self, exe, target, report):
        # --redact keeps the secret values themselves out of the stored report.
        return [
            exe, "dir", str(target), "--report-format", "json", "--report-path", str(report),
            "--redact", "--no-banner", "--exit-code", "0", "--log-level", "error",
        ]

    def parse(self, data, repo, target):
        return [
            Finding(
                tool=self.name,
                rule_id=leak.get("RuleID", ""),
                title=f"Possible secret: {leak.get('Description') or leak.get('RuleID')}",
                severity="high",
                category="secret",
                file=rel_path(leak.get("File"), repo, target),
                line=leak.get("StartLine"),
                description="Value redacted. If real, rotate it and remove it from git history.",
            )
            for leak in data or []
        ]
