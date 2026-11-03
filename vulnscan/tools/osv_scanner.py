from ..findings import Finding, normalize_severity, rel_path, severity_from_cvss
from .base import Tool


def _fixed_version(vuln, package):
    for affected in vuln.get("affected") or []:
        if (affected.get("package") or {}).get("name") != package:
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if "fixed" in event:
                    return event["fixed"]
    return None


class OsvScanner(Tool):
    name = "osv-scanner"
    command = "osv-scanner"
    install = [("github", "google/osv-scanner")]
    applies_to = "all repos (dependency lockfiles, every ecosystem)"
    ok_exit_codes = (0, 1)  # 1 = vulnerabilities found
    nothing_to_scan_codes = (128,)  # no lockfiles found

    def args(self, exe, target, report):
        return [exe, "scan", "source", "--recursive", "--format", "json", "--output-file", str(report), str(target)]

    def parse(self, data, repo, target):
        out = []
        for result in data.get("results") or []:
            source = rel_path((result.get("source") or {}).get("path"), repo, target)
            for pkg in result.get("packages") or []:
                p = pkg.get("package") or {}
                vulns = {v["id"]: v for v in pkg.get("vulnerabilities") or []}
                # A group is one issue reported under several IDs (GHSA, CVE, ...).
                for group in pkg.get("groups") or [{"ids": [i]} for i in vulns]:
                    ids = group.get("ids") or []
                    if not ids:
                        continue
                    vuln = vulns.get(ids[0], {})
                    aliases = sorted(set(ids) | set(group.get("aliases") or []))
                    primary = next((a for a in aliases if a.startswith("CVE-")), ids[0])
                    summary = next((vulns[i]["summary"] for i in ids if vulns.get(i, {}).get("summary")), primary)
                    severity = severity_from_cvss(group.get("max_severity")) or normalize_severity(
                        (vuln.get("database_specific") or {}).get("severity"))
                    out.append(Finding(
                        tool=self.name,
                        rule_id=primary,
                        title=f"{p.get('name')} {p.get('version')}: {summary}",
                        severity=severity,
                        category="dependency",
                        file=source,
                        description=(vuln.get("details") or "")[:1000],
                        package=p.get("name"),
                        version=p.get("version"),
                        fixed_version=_fixed_version(vuln, p.get("name")),
                        references=[f"https://osv.dev/vulnerability/{ids[0]}"],
                    ))
        return out
