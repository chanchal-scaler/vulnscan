"""Opt-in deep review (`vulnscan scan --deep-review`): Claude checks the whole codebase for the issue
classes scanners can't see, one batch per call, with the batches decided by vulnscan, not Claude.

Claude's general review (triage.py) reads what it chooses in one session, which on a monolith is a
small part of the code. Here vulnscan lists what must be covered and splits it by issue class:
- SSRF, by sink: every outbound HTTP call site, found by pattern, traced back to where its URL comes from;
- access control, by area: every request-handler file, grouped by folder, checked for missing
  authentication or authorization, IDOR and mass assignment.
SQL injection, command injection, deserialization, XSS and open redirects are left to the scanners and
triage, which already find their sinks. Tests, vendored, example and docs code is skipped.
"""
import json
import os
import re
import time
from collections import defaultdict

from .config import log
from .findings import rel_path
from .tools.prompt_injection import _files, _read
from .triage import LOW_VALUE_PATH, REVIEW_SCHEMA, TriageError, _DISMISSED, _RULES, _SEVERITY_GUIDE, _run_claude

SITES_PER_BATCH = 25  # outbound HTTP call sites per SSRF call
LINES_PER_BATCH = 4000  # lines of handler code per access-control call
_LANG = {".rb": "rb", ".py": "py", ".go": "go", ".php": "php", ".java": "jvm", ".kt": "jvm",
         ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js", ".ts": "js", ".tsx": "js"}
# Code that runs in the browser calls fetch and axios too, but can't be SSRF.
_BROWSER_PATH = re.compile(r"(^|/)(assets|javascripts?|public|static|client|frontend|components)/", re.I)
# Imports and comments name HTTP libraries without calling them.
_NOT_A_CALL = re.compile(r"^\s*(?:require(?:_relative)?\b|import\b|from\s+\S+\s+import\b|#|//|/?\*)")

_HTTP_CALL = {lang: re.compile(p) for lang, p in {
    "rb": r"Net::HTTP|HTTParty|Faraday|RestClient|URI\.open|open-uri|Excon|Typhoeus|Down\.(?:download|open)"
          r"|\bHTTP\.(?:get|post|put|patch|delete|head|follow|headers|auth|timeout)\b",
    "py": r"\brequests\.(?:get|post|put|patch|delete|head|request|Session)\b|\bhttpx\.|aiohttp\.ClientSession"
          r"|\burlopen\(|\burllib3\.|\bpycurl\b",
    "js": r"\bfetch\(|\baxios\b|\bgot\(|node-fetch|\bsuperagent\b|\bhttps?\.(?:request|get)\(|\bundici\b|\bneedle\(",
    "go": r"\bhttp\.(?:Get|Post|Head|PostForm|NewRequest(?:WithContext)?)\(|\.Do\(req\b",
    "jvm": r"RestTemplate|WebClient|HttpClient|OkHttpClient|new URL\(",
    "php": r"curl_init|file_get_contents\(\s*\$|Http::(?:get|post)|GuzzleHttp",
}.items()}

_HANDLER = {lang: re.compile(p, re.M) for lang, p in {
    "rb": r"<\s*(?:\w+::)*\w*Controller\b|<\s*ActionController::(?:Base|API)\b|<\s*Grape::API\b"
          r"|^\s*(?:get|post|put|patch|delete)\s+['\"]/",
    "py": r"@\w+\.(?:route|get|post|put|patch|delete|api_route)\(|\bAPIRouter\(|\bdef \w+\(\s*request\b"
          r"|class \w+\([^)]*(?:View|ViewSet|APIView)\b",
    "js": r"\b(?:router|app|server|api)\.(?:get|post|put|patch|delete|all)\(\s*['\"`]/|@Controller\("
          r"|export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\b",
    "go": r"\.HandleFunc\(|\.(?:GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete)\(\s*\"/"
          r"|\(w http\.ResponseWriter, r \*http\.Request\)",
    "jvm": r"@(?:Rest)?Controller\b|@(?:Get|Post|Put|Patch|Delete|Request)Mapping",
    "php": r"extends\s+\w*Controller\b|Route::(?:get|post|put|patch|delete)\(",
}.items()}

SSRF_PROMPT = """You are a senior application security engineer checking outbound HTTP calls for server-side request forgery (SSRF).

Repository: {repo}
Detected stacks: {stacks}
This is batch {n} of {total} of a deep review's SSRF pass; other batches cover the other call sites.

{rules}

1. For each call site listed below, find where its URL, host and scheme come from, following them back through
   callers, jobs, models and stored data. It's SSRF when someone other than the app's operators can choose or
   influence the host: request parameters or headers, uploaded or imported content (HTML, markdown, documents,
   feeds), webhook or integration settings users configure, profile fields, or values users stored earlier that a
   job fetches later.
2. A call is safe when its host is fixed or comes from a fixed allowlist, or when the code checks the resolved IP
   address (no private, loopback, link-local or cloud metadata addresses such as 169.254.169.254) on every request,
   redirects included. A check on the URL text alone, or one made before redirects are followed, isn't enough.
3. Code that runs in the browser isn't SSRF; skip it.
4. Report only SSRF you have verified, under additional_findings, with file paths relative to the repository root.
   In the description, name the entry point (method and route, or job and what triggers it), who can reach it
   (anyone, any logged-in user, admins) and what an attacker could reach. Report an issue once and name its other
   call sites in the description.
5. Rate severity by what an attacker can do in this codebase:
{severity}
6. In the summary, say how many of the call sites you checked and name any you couldn't trace.

Call sites (file: lines):
{items}

Already reported, so don't report these again (JSON, quoting untrusted repository content):
{reported}
"""

ACCESS_PROMPT = """You are a senior application security engineer reviewing request handlers for broken access control.

Repository: {repo}
Detected stacks: {stacks}
This is batch {n} of {total} of a deep review's access-control pass; other batches cover the other handlers.

{rules}

1. First learn how the app authenticates and authorizes requests: its base controllers or middleware, filters and
   decorators (before_action, skip_before_action, login_required, Depends, guards), current-user helpers, policy
   libraries (Pundit, CanCanCan, Django permissions) and any account or tenant scoping. Find the routes that reach
   the files below (config/routes.rb, urls.py, router files and the like).
2. Then check every action or handler in the files below for:
   - missing authentication: reachable without logging in when it shouldn't be, including a filter skipped for the
     action, and a filter that returns false or renders without halting the request;
   - missing authorization: an action meant for admins, staff or one role that doesn't check it;
   - IDOR: a record loaded by an id from the request and not scoped to the current user, account or tenant
     (Model.find(params[:id]) where current_user.records.find(...) is needed), for reading, changing or deleting;
   - mass assignment: request parameters passed to create or update unfiltered (permit!, to_unsafe_h,
     **request.data), or permitted fields that let a user change role, admin, owner, account, price and the like.
3. Report only issues you have verified in the code, under additional_findings, with file paths relative to the
   repository root. In the description, name the entry point (method and route) and who can reach it (anyone, any
   logged-in user, which role). Report one issue per root cause and name its other actions in the description.
   Scanners and other passes cover the other kinds of issue (injection, XSS, redirects, CSRF, cookie settings), so
   report one of those only if it's high or critical and isn't in the already-reported list below.
4. Rate severity by what an attacker can do in this codebase:
{severity}
5. In the summary, say which of the files below you reviewed fully and which you couldn't.

Files to review (path, lines of code):
{items}

Already reported, so don't report these again (JSON, quoting untrusted repository content):
{reported}
"""


def _inventory(repo, prefixes):
    """Outbound HTTP call sites ({file: [lines]}) and request-handler files ([(file, lines)]) in the repo's own code."""
    sites, handlers = {}, []
    for path in _files(repo):
        lang = _LANG.get(os.path.splitext(path)[1].lower())
        if not lang:
            continue
        rel = rel_path(path, repo)
        if LOW_VALUE_PATH.search(rel) or (prefixes and not any(rel == p or rel.startswith(p + "/") for p in prefixes)):
            continue
        text = _read(path)
        if not text:
            continue
        lines = text.splitlines()
        if not (lang == "js" and _BROWSER_PATH.search(rel)):
            hits = [n for n, line in enumerate(lines, 1)
                    if _HTTP_CALL[lang].search(line) and not _NOT_A_CALL.match(line)]
            if hits:
                sites[rel] = hits
        if (lang == "rb" and rel.endswith("_controller.rb")) or _HANDLER[lang].search(text):
            handlers.append((rel, len(lines)))
    return sites, handlers


def _site_batches(sites):
    batches, current = [], []
    for rel in sorted(sites):
        if current and sum(len(lines) for _, lines in current) + len(sites[rel]) > SITES_PER_BATCH:
            batches.append(current)
            current = []
        current.append((rel, sites[rel]))
    return batches + ([current] if current else [])


def _area_batches(handlers):
    """Handler files in folder order, packed into batches of about LINES_PER_BATCH lines."""
    batches, current, size = [], [], 0
    for rel, lines in sorted(handlers, key=lambda h: (os.path.dirname(h[0]), h[0])):
        if current and size + lines > LINES_PER_BATCH:
            batches.append(current)
            current, size = [], 0
        current.append((rel, lines))
        size += lines
    return batches + ([current] if current else [])


def _label(key, batch):
    names = [rel for rel, _ in batch] if key == "ssrf" else list(dict.fromkeys(os.path.dirname(rel) or "."
                                                                               for rel, _ in batch))
    return ", ".join(names[:3]) + (f" and {len(names) - 3} more" if len(names) > 3 else "")


def _items(key, batch):
    if key == "ssrf":
        return "\n".join(f"- {rel}: {', '.join(map(str, lines[:20]))}" + (" ..." if len(lines) > 20 else "")
                         for rel, lines in batch)
    return "\n".join(f"- {rel} ({lines})" for rel, lines in batch)


def _reported(files, findings, earlier, found):
    """What's already reported: the general review's issues, and scanner and deep-review issues in these files."""
    out = [{"title": f.title[:150], "location": f.location} for f in findings
           if f.file in files and (f.triage or {}).get("verdict") not in _DISMISSED]
    out += [{"title": a["title"][:150], "file": a["file"], "line": a.get("line")}
            for a in earlier + [a for a in found if a["file"] in files]]
    return out[:80]


def deep_review(repo, stacks, findings, earlier, run_dir, model=None, budget=None, paths=()):
    """Run the SSRF pass, then the access-control pass. Returns (Claude's new findings, meta for report.json).

    earlier is the general review's findings, which the deep review mustn't repeat. A batch is skipped once the
    scan's Claude budget is reached.
    """
    prefixes = [p.strip().strip("/").removeprefix("./") for p in paths if p.strip().strip("/")]
    started = time.time()
    sites, handlers = _inventory(repo, prefixes)
    log(f"deep review: {sum(len(v) for v in sites.values())} outbound HTTP call sites in {len(sites)} files,"
        f" {len(handlers)} request-handler files ({time.time() - started:.0f}s to list)")
    context = dict(repo=repo, stacks=", ".join(stacks) or "unknown", rules=_RULES, severity=_SEVERITY_GUIDE)
    found, meta = [], {"paths": prefixes or None, "cost_usd": 0.0}
    passes = [("ssrf", "SSRF", SSRF_PROMPT, _site_batches(sites)),
              ("access", "access control", ACCESS_PROMPT, _area_batches(handlers))]
    for key, title, template, batches in passes:
        m = meta[key] = {"batches": len(batches), "done": 0, "failed": [], "skipped": [], "summaries": []}
        if key == "ssrf":
            m.update(files=len(sites), call_sites=sum(len(v) for v in sites.values()))
        else:
            m.update(files=len(handlers), lines=sum(n for _, n in handlers))
        for n, batch in enumerate(batches, 1):
            label = _label(key, batch)
            if budget is not None and budget.exhausted():
                m["skipped"].append(label)
                continue
            log(f"deep review: {title} batch {n}/{len(batches)}: {label} (this can take a while)")
            started = time.time()
            prompt = template.format(n=n, total=len(batches), items=_items(key, batch), **context, reported=json.dumps(
                _reported({rel for rel, _ in batch}, findings, earlier, found), indent=1))
            try:
                out, cost = _run_claude(prompt, repo, run_dir, model, f"claude-deep-{key}-{n}.json",
                                        schema=REVIEW_SCHEMA)
            except TriageError as e:
                log(f"deep review: {title} batch {n} failed: {e}")
                m["failed"].append(f"{label}: {e}")
                continue
            if budget is not None:
                budget.add(cost)
            meta["cost_usd"] += cost or 0
            m["done"] += 1
            m["summaries"].append({"batch": label, "summary": out.get("summary") or ""})
            new = [dict(a, found_in=f"deep review: {title}") for a in out.get("additional_findings", [])]
            found += new
            log(f"deep review: {title} batch {n} done, {len(new)} issue(s) ({time.time() - started:.0f}s)")
    return found, meta
