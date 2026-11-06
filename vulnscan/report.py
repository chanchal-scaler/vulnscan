import csv
import json
from collections import Counter

from .findings import SEVERITIES

CSV_COLUMNS = [
    "id", "verdict", "severity", "scanner_severity", "tool", "rule", "category", "file", "line", "title",
    "package", "version", "fixed_version", "reviewed_as", "reason", "fix", "reference",
]


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


def _deep_line(deep):
    """One line on what the deep review covered, e.g. 'SSRF: 3 of 3 batches over 61 call sites; ...'."""
    parts = []
    for key, name, count, unit in (("ssrf", "SSRF", "call_sites", "outbound HTTP call sites"),
                                   ("llm", "LLM", "call_sites", "LLM call sites"),
                                   ("access", "access control", "files", "request-handler files")):
        m = deep[key]
        text = f"{name}: {m['done']} of {m['batches']} batch(es) over {m[count]} {unit}"
        if m["skipped"]:
            text += f", {len(m['skipped'])} skipped (Claude budget reached)"
        if m["failed"]:
            text += f", {len(m['failed'])} failed"
        parts.append(text)
    line = "; ".join(parts)
    if deep.get("paths"):
        line += f" (limited to {', '.join(deep['paths'])})"
    return line + f", ${deep['cost_usd']:.2f} at API rates"


def _verdict(f):
    return (f.triage or {}).get("verdict")


def _csv_value(value):
    # Scanner output quotes repo content, so stop spreadsheets from running it as a formula.
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def write_csv(path, findings, additional):
    """One row per finding (Claude's additional findings first), for spreadsheets."""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        out = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        out.writeheader()
        for i, a in enumerate(additional, 1):
            row = {"id": f"C{i:02d}", "verdict": "found by Claude", "severity": a["severity"], "tool": "claude",
                   "file": a["file"], "line": a.get("line"), "title": a["title"],
                   "reason": a["description"], "fix": a["fix"]}
            out.writerow({k: _csv_value(v) for k, v in row.items()})
        for f in findings:
            t = f.triage or {}
            row = {
                "id": f.id, "verdict": t.get("verdict", "not triaged"), "severity": f.final_severity,
                "scanner_severity": f.severity, "tool": f.tool, "rule": f.rule_id, "category": f.category,
                "file": f.file, "line": f.line, "title": f.title, "package": f.package, "version": f.version,
                "fixed_version": f.fixed_version, "reviewed_as": t.get("scope"), "reason": t.get("reason"),
                "fix": t.get("fix"), "reference": f.references[0] if f.references else None,
            }
            out.writerow({k: _csv_value(v) for k, v in row.items()})


def write_reports(run_dir, meta, findings, triage_result):
    """Write report.json (everything), report.csv (one row per finding) and report.md (for people).

    Returns the markdown path.
    """
    # Sorted once, so C01… name the same finding in report.json, report.csv and report.md, and in validate.py
    # and the dashboard, which number them in report.json's order.
    additional = sorted((triage_result or {}).get("additional_findings", []),
                        key=lambda a: SEVERITIES.index(a["severity"]))
    data = dict(meta, summary=(triage_result or {}).get("summary"),
                findings=[f.to_dict() for f in findings], additional_findings=additional)
    (run_dir / "report.json").write_text(json.dumps(data, indent=2))
    write_csv(run_dir / "report.csv", findings, additional)

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
    if t.get("items") is not None:
        triage_line += (f" ({t['items']} of {t['items_total']} items reviewed in {t['batches']} batch(es),"
                        f" covering {t['findings_covered']} findings")
        if t.get("model"):
            triage_line += f", {t['model']}"
        if t.get("cost_usd") is not None:
            triage_line += f", ${t['cost_usd']:.2f} at API rates"
        triage_line += ")"
    for err in t.get("errors", []):
        triage_line += f"\n  - error: {_cell(err, 300)}"
    deep = meta.get("deep_review")

    md = [
        f"# Security scan: {meta['repo']}",
        "",
        f"- Scanned: {meta['scanned_at']}",
        f"- Commit: `{meta['commit'] or 'n/a'}`",
        f"- Stacks: {', '.join(f'{k} ({len(v)})' for k, v in meta['stacks'].items()) or 'none detected'}",
        f"- Claude triage: {triage_line}",
        *([f"- Deep review: {_deep_line(deep)}"] if deep else []),
        "",
        "## Tools",
        *tools,
    ]
    missed = [(name, label) for key, name in (("ssrf", "SSRF"), ("llm", "LLM"), ("access", "access control")) if deep
              for label in deep[key]["skipped"] + deep[key]["failed"]]
    if missed:
        md += ["", f"## Deep review: batches not reviewed ({len(missed)})",
               "Skipped once the Claude budget was reached, or failed. The code they cover wasn't deep-reviewed.", ""]
        md += [f"- {name}: {_cell(label, 200)}" for name, label in missed[:50]]
        if len(missed) > 50:
            md.append(f"- and {len(missed) - 50} more (see report.json)")
    if data["summary"]:
        md += ["", "## Summary", data["summary"]]

    if confirmed:
        md += ["", f"## Confirmed findings ({len(confirmed)})", _table(confirmed)]
        per_group = Counter(f.triage.get("group") for f in confirmed)
        shown = set()
        for f in confirmed:
            group = f.triage.get("group")
            if group in shown:  # a grouped item gets one section, not one per hit
                continue
            if group:
                shown.add(group)
            md += [
                "", f"### {group or f.id} · {f.final_severity.upper()} · {_cell(f.title, 160)}",
                f"- Location: `{f.location}`" + (f" and {per_group[group] - 1} more (see report.csv)"
                                                  if group and per_group[group] > 1 else ""),
                f"- Tool: {f.tool} (`{f.rule_id}`)",
            ]
            if group:
                md.append(f"- Reviewed as: {f.triage['scope']}")
            md += [f"- Why: {f.triage.get('reason', '')}", f"- Fix: {f.triage.get('fix', '')}"]
            if f.references:
                md.append(f"- Ref: {f.references[0]}")

    if additional:
        md += ["", f"## Additional issues found by Claude ({len(additional)})"]
        for i, a in enumerate(additional, 1):
            loc = f"{a['file']}:{a['line']}" if a.get("line") else a["file"]
            md += [
                "", f"### C{i:02d} · {a['severity'].upper()} · {_cell(a['title'], 160)}",
                f"- Location: `{loc}`",
                f"- Details: {a['description']}",
                f"- Fix: {a['fix']}",
            ]
            if a.get("found_in"):
                md.append(f"- Found in: {a['found_in']}")

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
