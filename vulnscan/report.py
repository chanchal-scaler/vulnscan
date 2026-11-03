import json
from collections import Counter

from .findings import SEVERITIES


def _cell(text, limit=120):
    text = " ".join(str(text or "").split()).replace("|", "\\|")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _table(findings, extra_col=None):
    head = "| ID | Severity | Title | Location | Tool |" + (f" {extra_col[0]} |" if extra_col else "")
    rows = [head, "|" + "---|" * (6 if extra_col else 5)]
    for f in findings:
        row = f"| {f.id} | {f.final_severity} | {_cell(f.title)} | `{_cell(f.location, 80)}` | {f.tool} |"
        if extra_col:
            row += f" {_cell(extra_col[1](f), 160)} |"
        rows.append(row)
    return "\n".join(rows)


def _verdict(f):
    return (f.triage or {}).get("verdict")


def write_reports(run_dir, meta, findings, triage_result):
    """Write report.json (everything) and report.md (for people). Returns the markdown path."""
    additional = (triage_result or {}).get("additional_findings", [])
    data = dict(meta, summary=(triage_result or {}).get("summary"),
                findings=[f.to_dict() for f in findings], additional_findings=additional)
    (run_dir / "report.json").write_text(json.dumps(data, indent=2))

    confirmed = [f for f in findings if _verdict(f) == "confirmed"]
    review = [f for f in findings if _verdict(f) == "needs_review"]
    untriaged = [f for f in findings if not _verdict(f)]
    dismissed = [f for f in findings if _verdict(f) in ("false_positive", "duplicate")]

    tools = []
    for run in meta["tools"]:
        line = f"- **{run['tool']}**: {run['status']}"
        if run.get("findings") is not None:
            line += f", {run['findings']} findings"
        for err in run.get("errors", []):
            line += f"\n  - error: {_cell(err, 300)}"
        tools.append(line)

    t = meta["triage"]
    triage_line = t["status"]
    if t.get("cost_usd") is not None:
        triage_line += f" (${t['cost_usd']:.2f}, {t['triaged']} findings sent)"
    if t.get("error"):
        triage_line += f": {_cell(t['error'], 300)}"

    md = [
        f"# Security scan: {meta['repo']}",
        "",
        f"- Scanned: {meta['scanned_at']}",
        f"- Commit: `{meta['commit'] or 'n/a'}`",
        f"- Stacks: {', '.join(f'{k} ({len(v)})' for k, v in meta['stacks'].items()) or 'none detected'}",
        f"- Claude triage: {triage_line}",
        "",
        "## Tools",
        *tools,
    ]
    if data["summary"]:
        md += ["", "## Summary", data["summary"]]

    if confirmed:
        md += ["", f"## Confirmed findings ({len(confirmed)})", _table(confirmed)]
        for f in confirmed:
            md += [
                "", f"### {f.id} · {f.final_severity.upper()} · {_cell(f.title, 160)}",
                f"- Location: `{f.location}`",
                f"- Tool: {f.tool} (`{f.rule_id}`)",
                f"- Why: {f.triage.get('reason', '')}",
                f"- Fix: {f.triage.get('fix', '')}",
            ]
            if f.references:
                md.append(f"- Ref: {f.references[0]}")

    if additional:
        md += ["", f"## Additional issues found by Claude ({len(additional)})"]
        for i, a in enumerate(sorted(additional, key=lambda a: SEVERITIES.index(a["severity"])), 1):
            loc = f"{a['file']}:{a['line']}" if a.get("line") else a["file"]
            md += [
                "", f"### C{i:02d} · {a['severity'].upper()} · {_cell(a['title'], 160)}",
                f"- Location: `{loc}`",
                f"- Details: {a['description']}",
                f"- Fix: {a['fix']}",
            ]

    if review:
        md += ["", f"## Needs manual review ({len(review)})",
               _table(review, ("Reason", lambda f: f.triage.get("reason")))]
    if untriaged:
        md += ["", f"## Not triaged ({len(untriaged)})", _table(untriaged)]
    if dismissed:
        md += ["", f"## Dismissed as false positive or duplicate ({len(dismissed)})",
               _table(dismissed, ("Reason", lambda f: f.triage.get("reason")))]

    path = run_dir / "report.md"
    path.write_text("\n".join(md) + "\n")
    return path


def severity_counts(findings, triage_result):
    """Counts of what still needs attention: confirmed + needs review + untriaged + Claude's own."""
    open_findings = [f for f in findings if _verdict(f) not in ("false_positive", "duplicate")]
    counts = Counter(f.final_severity for f in open_findings)
    counts.update(a["severity"] for a in (triage_result or {}).get("additional_findings", []))
    return {s: counts[s] for s in SEVERITIES if counts[s]}
