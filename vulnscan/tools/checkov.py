from ..findings import Finding, normalize_severity, rel_path
from .base import Tool


class Checkov(Tool):
    name = "checkov"
    command = "checkov"
    install = [("pip", "checkov")]
    applies_to = "IaC (Terraform, Dockerfiles, GitHub Actions, Helm)"
    ok_exit_codes = (0, 1)
    stdout_is_report = True

    def targets(self, repo, stacks):
        return [repo] if "iac" in stacks else []

    def args(self, exe, target, report):
        # No --quiet: it also drops the checks the repo skips with checkov:skip comments, which parse() keeps.
        return [exe, "-d", str(target), "-o", "json", "--compact", "--soft-fail", "--skip-download"]

    def parse(self, data, repo, target):
        out = []
        for report in data if isinstance(data, list) else [data]:
            results = report.get("results") or {}
            checks = [(c, False) for c in results.get("failed_checks") or []]
            checks += [(c, True) for c in results.get("skipped_checks") or []]
            for check, skipped in checks:
                lines = check.get("file_line_range") or [None]
                check_id = check.get("check_id", "")
                description = f"Resource: {check.get('resource')}"
                if skipped:
                    reason = ((check.get("check_result") or {}).get("suppress_comment") or "").strip()
                    description += " (Skipped by a checkov:skip comment in the repo" + (f": {reason}" if reason else "") + ".)"
                out.append(Finding(
                    tool=self.name,
                    rule_id=check_id,
                    title=check.get("check_name", ""),
                    severity=normalize_severity(check.get("severity") or "medium"),
                    category="secret" if check_id.startswith("CKV_SECRET") else "config",
                    file=rel_path(check.get("file_abs_path") or (check.get("file_path") or "").lstrip("/"), repo, target),
                    line=lines[0] or None,
                    description=description,
                    references=[check["guideline"]] if check.get("guideline") else [],
                ))
        # Checkov reads the repo's own config, which can skip checks, and no flag overrides it.
        for name in (".checkov.yaml", ".checkov.yml"):
            config = target / name
            if config.is_file() and "skip" in config.read_text(errors="replace"):
                out.append(Finding(
                    tool=self.name, rule_id="checkov-config", severity="low", category="config",
                    title=f"The repo's {name} skips checkov checks or paths in this scan",
                    file=rel_path(config, repo, target), line=1,
                    description="What it skips (skip-check, skip-path, skip-framework) is never checked or reported."
                                " Check each entry.",
                ))
        return out
