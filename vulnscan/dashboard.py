"""A read-only web page that tracks every run's findings through the three stages.

Discovered (report.json) → validated by Strix (validation.json) → fix PR opened (fix.json).
The page is built from those three files on every request. It has no write actions,
serves no files from the run folders, and leaves out Strix's PoCs, which can carry
operator-supplied credentials or live URLs. Findings quote untrusted repo content, so
every value is escaped, the page has no JavaScript, and the Content-Security-Policy
blocks scripts and loads from anywhere else. A request whose Host isn't localhost is
refused, so a web page in the viewer's browser can't reach it by DNS rebinding.
"""
import html
import json
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, unquote, urlsplit

from .config import SCANS_DIR, log
from .findings import SEVERITIES

FILES = ("report.json", "validation.json", "fix.json")
DISMISSED = ("false_positive", "duplicate")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
HEADERS = {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
                               "form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
CSS = """
:root{color-scheme:light dark;--fg:#1f2328;--muted:#656d76;--bg:#fff;--line:#d0d7de;--head:#f6f8fa;--link:#0969da}
@media (prefers-color-scheme:dark){:root{--fg:#e6edf3;--muted:#8d96a0;--bg:#0d1117;--line:#30363d;--head:#161b22;
--link:#4493f8}}
body{font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:var(--fg);background:var(--bg);
margin:24px auto;padding:0 16px;max-width:1500px}
a{color:var(--link)}
table{border-collapse:collapse;width:100%;margin:8px 0 28px}
th,td{border-bottom:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top}
th{background:var(--head);position:sticky;top:0}
code{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
.muted{color:var(--muted)}
.sev{display:inline-block;padding:0 7px;border-radius:9px;font-size:12px;color:#fff}
.critical{background:#a40e26}.high{background:#d1242f}.medium{background:#9a6700}.low{background:#57606a}
.info{background:#8c959f}
.funnel{padding:10px 12px;border:1px solid var(--line);border-radius:6px;background:var(--head)}
"""

_summaries = {}  # run folder -> (file stamps, summary), so the index doesn't re-read unchanged runs


def _e(value):
    return html.escape("" if value is None else str(value))


def _short(text, limit=160):
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _link(url, text):
    """A link for https URLs only; anything else is shown as plain text."""
    url = str(url or "")
    if url.startswith("https://"):
        return f'<a href="{_e(url)}" rel="noreferrer">{_e(text)}</a>'
    return _e(text)


def _sev(severity):
    s = severity if severity in SEV_ORDER else "medium"
    return f'<span class="sev {s}">{s}</span>'


def _loc(x):
    return f"{x.get('file') or ''}:{x['line']}" if x.get("line") else (x.get("file") or "")


def _when(run_name):
    """20261104-114804 → 2026-11-04 11:48:04 UTC (the run folder's name)."""
    n = run_name
    if len(n) == 15 and n[8] == "-" and (n[:8] + n[9:]).isdigit():
        return f"{n[:4]}-{n[4:6]}-{n[6:8]} {n[9:11]}:{n[11:13]}:{n[13:]} UTC"
    return n


def _entries(folder):
    try:
        return sorted(p.name for p in folder.iterdir() if p.is_dir() and not p.name.startswith("."))
    except OSError:
        return []


def _run_dir(label, run):
    """The run folder, only when both names are real entries of the scans folder (never a path from the URL)."""
    if label in _entries(SCANS_DIR) and run in _entries(SCANS_DIR / label):
        return SCANS_DIR / label / run
    return None


def _load(path):
    """(data, problem): data is None when the file is missing or can't be parsed."""
    try:
        return json.loads(path.read_text()), None
    except FileNotFoundError:
        return None, None
    except (OSError, ValueError) as e:
        return None, f"{path.name} is unreadable ({e.__class__.__name__}); it may still be being written"


def _run_data(run_dir):
    """Join a run folder's three stages: every open stage-1 finding with its Strix and fix status."""
    (report, p1), (validation, p2), (fix, p3) = (_load(run_dir / name) for name in FILES)
    data = {"report": report, "validation": validation, "fix": fix, "problems": [p for p in (p1, p2, p3) if p],
            "discovered": 0, "open": [], "dismissed": Counter(),
            "v": (validation or {}).get("findings") or [],
            "fixes": {r.get("id"): r for r in (fix or {}).get("results") or []}}
    if report is None:
        return data
    additional = report.get("additional_findings") or []
    findings = report.get("findings") or []
    data["discovered"] = len(findings) + len(additional)

    validated_by = {}
    for v in data["v"]:
        for sid in v.get("validates") or []:
            validated_by.setdefault(sid, []).append(v.get("id"))
    not_referenced = set(((validation or {}).get("coverage") or {}).get("not_referenced") or [])

    # Claude's own findings are numbered in list order, as in report.csv and validate.py (whose ids Strix names).
    rows = [{"id": f"C{i:02d}", "severity": a.get("severity"), "verdict": "found by Claude", "tool": "claude",
             "title": a.get("title"), "location": _loc(a)} for i, a in enumerate(additional, 1)]
    for f in findings:
        t = f.get("triage") or {}
        verdict = t.get("verdict") or "not triaged"
        if verdict in DISMISSED:
            data["dismissed"][verdict] += 1
            continue
        rows.append({"id": f.get("id"), "severity": t.get("severity") or f.get("severity"), "verdict": verdict,
                     "tool": f.get("tool"), "title": f.get("title"), "location": _loc(f)})
    for r in rows:
        r["validated_by"] = validated_by.get(r["id"], [])
        if validation is None:
            r["strix"] = None
        elif r["validated_by"]:
            r["strix"] = "validated"
        elif r["id"] in not_referenced:
            r["strix"] = "not validated"
        else:
            r["strix"] = "not sent"  # beyond --max-validate
    rows.sort(key=lambda r: SEV_ORDER.get(r["severity"], 2))
    data["open"] = rows
    return data


def _stamp(path):
    try:
        st = path.stat()
        return st.st_mtime_ns, st.st_size
    except OSError:
        return None


def _summary(run_dir):
    stamps = tuple(_stamp(run_dir / name) for name in FILES)
    cached = _summaries.get(run_dir)
    if cached and cached[0] == stamps:
        return cached[1]
    d = _run_data(run_dir)
    report, validation = d["report"] or {}, d["validation"]
    s = {"finished": d["report"] is not None, "problems": d["problems"], "commit": report.get("commit"),
         "discovered": d["discovered"], "open": Counter(r["severity"] for r in d["open"]),
         "validated": None, "fix": None}
    if validation is not None:
        s["validated"] = {"v": len(d["v"]), "confirms": sum(1 for r in d["open"] if r["validated_by"]),
                          "sent": validation.get("items_sent"),
                          "strix": (validation.get("strix") or {}).get("status")}
    if d["fix"] is not None:
        s["fix"] = Counter(r.get("status") for r in d["fixes"].values())
    _summaries[run_dir] = (stamps, s)
    return s


def _fix_cell(vid, d):
    if d["fix"] is None:
        return '<span class="muted">—</span>'
    r = d["fixes"].get(vid)
    if not r:
        return '<span class="muted">not attempted</span>'
    status = r.get("status") or "?"
    if str(r.get("pr_url") or "").startswith("https://"):
        out = f"{_e(status)}: {_link(r['pr_url'], '#' + str(r['pr_url']).rstrip('/').rsplit('/', 1)[-1])}"
    else:
        out = _e(status)
        detail = r.get("detail") or r.get("error")
        if detail:
            out += f'<div class="muted">{_e(_short(detail, 200))}</div>'
    if r.get("breaking"):
        out += ' <span class="sev high">breaking</span>'
    return out


def _counts(counter):
    return " · ".join(f"{n} {_e(k)}" for k, n in counter.most_common()) or "none"


def _page(title, body):
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            f"<title>{_e(title)}</title><style>{CSS}</style></head><body>{body}"
            '<p class="muted">Read-only. Built from report.json, validation.json and fix.json on every request.'
            " Findings quote untrusted repo content. Strix's proofs of concept are in validation.md on the"
            " instance, not here.</p></body></html>")


def _index():
    labels = _entries(SCANS_DIR)
    parts = ["<h1>vulnscan</h1>",
             '<p class="muted">Every scan run, newest first: what was discovered, what Strix validated, and the'
             " fix PRs opened.</p>"]
    if not labels:
        parts.append(f"<p>No scans in <code>{_e(SCANS_DIR)}</code> yet.</p>")
    for label in labels:
        rows = []
        for run in reversed(_entries(SCANS_DIR / label)):
            s = _summary(SCANS_DIR / label / run)
            link = f'<a href="/run/{quote(label, safe="")}/{quote(run, safe="")}">{_e(_when(run))}</a>'
            if not s["finished"]:
                note = "; ".join(s["problems"]) or "unfinished (no report.json: still running, or interrupted)"
                rows.append(f'<tr><td>{link}</td><td colspan="5" class="muted">{_e(note)}</td></tr>')
                continue
            o = s["open"]
            open_cell = f"{sum(o.values())}" + "".join(f" · {o[k]} {k}" for k in ("critical", "high") if o[k])
            v = s["validated"]
            if v is None:
                v_cell = '<span class="muted">not run</span>'
            else:
                v_cell = (f"{v['v']} validated · confirms {v['confirms']} of {v['sent'] or 0} sent"
                          f' <span class="muted">(strix {_e(v["strix"] or "?")})</span>')
            fix_cell = '<span class="muted">not run</span>' if s["fix"] is None else _counts(s["fix"])
            rows.append(f"<tr><td>{link}</td><td><code>{_e((s['commit'] or '')[:10])}</code></td>"
                        f"<td>{s['discovered']}</td><td>{open_cell}</td><td>{v_cell}</td><td>{fix_cell}</td></tr>")
        parts += [f"<h2>{_e(label.replace('__', '/', 1))}</h2>",
                  "<table><tr><th>Run</th><th>Commit</th><th>Discovered</th><th>Open after triage</th>"
                  "<th>Validated by Strix</th><th>Fixes</th></tr>", *rows, "</table>"]
    return _page("vulnscan", "".join(parts))


def _run_page(label, run, run_dir):
    d = _run_data(run_dir)
    report, validation, fix = d["report"], d["validation"], d["fix"]
    repo = (report or {}).get("repo") or label.replace("__", "/", 1)
    parts = ['<p><a href="/">← all runs</a></p>', f"<h1>{_e(repo)}</h1>"]
    parts += [f'<p class="muted">{_e(p)}</p>' for p in d["problems"]]
    if report is None:
        parts.append("<p>This run has no report.json: the scan is still running, or was interrupted.</p>")
        return _page(repo, "".join(parts))

    triage = report.get("triage") or {}
    meta = [f"Scan {_e(_when(run))}", f"commit <code>{_e((report.get('commit') or 'n/a')[:12])}</code>",
            f"Claude triage: {_e(triage.get('status') or 'n/a')}"]
    if validation is not None:
        st = validation.get("strix") or {}
        meta.append(f"Validated {_e(validation.get('validated_at'))} ({_e(validation.get('scan_mode'))} mode,"
                    f" strix {_e(st.get('status'))})")
    if fix is not None:
        meta.append(f"Last fix run {_e(fix.get('fixed_at'))}" + (" (dry run)" if fix.get("dry_run") else ""))
    parts.append(f'<p class="muted">{" · ".join(meta)}</p>')

    prs = sum(1 for r in d["fixes"].values() if r.get("status") == "pr opened")
    sent = (validation or {}).get("items_sent")
    parts.append(
        f'<p class="funnel">Discovered <b>{d["discovered"]}</b> → open after triage <b>{len(d["open"])}</b>'
        + (" → validation not run" if validation is None else
           f" → sent to Strix <b>{sent or 0}</b> → validated <b>{len(d['v'])}</b>"
           f" (confirming {sum(1 for r in d['open'] if r['validated_by'])} open findings)"
           + (" → fix not run" if fix is None else f" → PRs opened <b>{prs}</b>"))
        + "</p>")

    if validation is not None:
        parts.append(f"<h2>Validated by Strix ({len(d['v'])})</h2>")
        if d["v"]:
            parts.append("<table><tr><th>ID</th><th>Severity</th><th>Title</th><th>Location</th>"
                         "<th>Confirms</th><th>Fix</th></tr>")
            for v in d["v"]:
                parts.append(f"<tr><td>{_e(v.get('id'))}</td><td>{_sev(v.get('severity'))}</td>"
                             f"<td>{_e(_short(v.get('title')))}</td><td><code>{_e(_loc(v))}</code></td>"
                             f"<td>{_e(', '.join(v.get('validates') or [])) or '—'}</td>"
                             f"<td>{_fix_cell(v.get('id'), d)}</td></tr>")
            parts.append("</table>")
        else:
            parts.append("<p>Strix reported no validated findings.</p>")

    parts.append(f"<h2>Open findings from the scan ({len(d['open'])})</h2>")
    if d["open"]:
        parts.append("<table><tr><th>ID</th><th>Severity</th><th>Claude</th><th>Title</th><th>Location</th>"
                     "<th>Tool</th><th>Strix</th><th>Fix</th></tr>")
        for r in d["open"]:
            if r["strix"] is None:
                strix = '<span class="muted">—</span>'
            elif r["validated_by"]:
                strix = _e(", ".join(r["validated_by"]))
            else:
                strix = f'<span class="muted">{_e(r["strix"])}</span>'
            fixes = "<br>".join(f"{_e(vid)}: {_fix_cell(vid, d)}" for vid in r["validated_by"])
            parts.append(f"<tr><td>{_e(r['id'])}</td><td>{_sev(r['severity'])}</td><td>{_e(r['verdict'])}</td>"
                         f"<td>{_e(_short(r['title']))}</td><td><code>{_e(r['location'])}</code></td>"
                         f"<td>{_e(r['tool'])}</td><td>{strix}</td>"
                         f"<td>{fixes or '<span class=muted>—</span>'}</td></tr>")
        parts.append("</table>")
    if d["dismissed"]:
        parts.append(f'<p class="muted">Dismissed by Claude: {_counts(d["dismissed"])} (listed in report.md).</p>')
    return _page(f"{repo} · {run}", "".join(parts))


class _Handler(BaseHTTPRequestHandler):
    server_version = "vulnscan"
    sys_version = ""

    def do_GET(self):
        try:
            host = urlsplit("//" + (self.headers.get("Host") or "")).hostname
        except ValueError:
            host = None
        if host not in LOCAL_HOSTS:
            return self._send(403, _page("Forbidden", "<p>Open this page through localhost.</p>"))
        parts = [unquote(p) for p in urlsplit(self.path).path.split("/") if p]
        try:
            if not parts:
                return self._send(200, _index())
            run_dir = _run_dir(parts[1], parts[2]) if len(parts) == 3 and parts[0] == "run" else None
            if run_dir:
                return self._send(200, _run_page(parts[1], parts[2], run_dir))
            return self._send(404, _page("Not found", '<p>Not found. <a href="/">All runs</a></p>'))
        except Exception as e:  # one bad run folder shouldn't take the page down
            log(f"dashboard: {self.path}: {e.__class__.__name__}: {e}")
            return self._send(500, _page("Error", "<p>Could not build this page; details are in the server log.</p>"))

    def _send(self, code, body):
        data = body.encode()
        self.send_response(code)
        for k, v in HEADERS.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        log("dashboard: " + fmt % args)


def serve(host="127.0.0.1", port=8080):
    server = ThreadingHTTPServer((host, port), _Handler)
    log(f"dashboard: serving {SCANS_DIR} read-only on http://{host}:{port}/")
    try:
        server.serve_forever()
    finally:
        server.server_close()
