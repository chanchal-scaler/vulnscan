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
        return [exe, "-d", str(target), "-o", "json", "--quiet", "--compact", "--soft-fail", "--skip-download"]

    def parse(self, data, repo, target):
        out = []
        for report in data if isinstance(data, list) else [data]:
            for check in (report.get("results") or {}).get("failed_checks") or []:
                lines = check.get("file_line_range") or [None]
                out.append(Finding(
                    tool=self.name,
                    rule_id=check.get("check_id", ""),
                    title=check.get("check_name", ""),
                    severity=normalize_severity(check.get("severity") or "medium"),
                    category="config",
                    file=rel_path(check.get("file_abs_path") or (check.get("file_path") or "").lstrip("/"), repo, target),
                    line=lines[0] or None,
                    description=f"Resource: {check.get('resource')}",
                    references=[check["guideline"]] if check.get("guideline") else [],
                ))
        return out
