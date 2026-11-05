from ..findings import Finding, rel_path
from .base import Tool


class Gitleaks(Tool):
    name = "gitleaks"
    command = "gitleaks"
    install = [("github", "gitleaks/gitleaks")]
    applies_to = "all repos (hardcoded secrets)"

    def args(self, exe, target, report):
        # The scanned repo's own .gitleaks.toml would replace the rules, and gitleaks:allow comments would
        # hide lines, so gitleaks gets its default rules from a config of ours and ignores those comments.
        # It still reads the repo's .gitleaksignore (no flag turns that off); parse() reports that file.
        config = report.with_suffix(".toml")
        config.write_text("[extend]\nuseDefault = true\n")
        # --redact keeps the secret values themselves out of the stored report.
        return [
            exe, "dir", str(target), "--config", str(config), "--ignore-gitleaks-allow",
            "--report-format", "json", "--report-path", str(report),
            "--redact", "--no-banner", "--exit-code", "0", "--log-level", "error",
        ]

    def parse(self, data, repo, target):
        out = [
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
        ignore = target / ".gitleaksignore"
        if ignore.is_file():
            entries = [s for s in ignore.read_text(errors="replace").splitlines() if s.strip() and not s.startswith("#")]
            if entries:
                out.append(Finding(
                    tool=self.name, rule_id="gitleaksignore", severity="medium", category="secret",
                    title=f"The repo's .gitleaksignore hides {len(entries)} gitleaks finding(s) from this scan",
                    file=rel_path(ignore, repo, target), line=1,
                    description="Each entry is a fingerprint (file:rule:line). Check that every hidden value is"
                                " really not a secret.",
                ))
        return out
