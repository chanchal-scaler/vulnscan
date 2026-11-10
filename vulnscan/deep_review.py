"""The deep review (on by default in `vulnscan scan`; `--no-deep-review` skips it): Claude checks the whole codebase for the issue
classes scanners can't see, one batch per call, with the batches decided by vulnscan, not Claude.

Claude's general review (triage.py) reads what it chooses in one session, which on a monolith is a
small part of the code. Here vulnscan lists what must be covered and splits it by issue class:
- SSRF, by sink: every outbound HTTP call site, found by pattern, traced back to where its URL comes from;
- LLM use, by sink: every LLM API call and prompt-building line, checked for prompt injection into
  outputs that decide something, data the model can be talked into revealing, unchecked tool calls,
  unsanitised output, client-chosen models and cost abuse, and personal data sent to providers;
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

# HTTP clients, plus libraries that fetch the URLs inside content they render or load (HTML-to-PDF
# renderers, headless browsers, web loaders): those make requests with no HTTP call in the app's own code.
_HTTP_CALL = {lang: re.compile(p) for lang, p in {
    "rb": r"Net::HTTP|HTTParty|Faraday|RestClient|URI\.open|open-uri|Excon|Typhoeus|Down\.(?:download|open)"
          r"|\bHTTP\.(?:get|post|put|patch|delete|head|follow|headers|auth|timeout)\b"
          r"|WickedPdf\.new|\brender\s*\(?\s*pdf:|PDFKit\.new|Grover\.new|Ferrum::Browser",
    "py": r"\brequests\.(?:get|post|put|patch|delete|head|request|Session)\b|\bhttpx\.|aiohttp\.ClientSession"
          r"|\burlopen\(|\burlretrieve\(|\burllib3\.|\bpycurl\b"
          r"|\.write_pdf\(|\bweasyprint\.HTML\(|\bHTML\(\s*(?:string|url|filename)=|\bpdfkit\.from_|\bwkhtmltopdf\b"
          r"|\bpisa\.CreatePDF\(|\.goto\(|\bwebdriver\.\w+\(|\b(?:WebBase|UnstructuredURL|SeleniumURL|PlaywrightURL"
          r"|AsyncHtml|AsyncChromium|RecursiveUrl|Sitemap)Loader\(",
    "js": r"\bfetch\(|\baxios\b|\bgot\(|node-fetch|\bsuperagent\b|\bhttps?\.(?:request|get)\(|\bundici\b|\bneedle\("
          r"|\.goto\(|\.setContent\(|\bhtml-pdf\b|\bwkhtmltopdf\b",
    "go": r"\bhttp\.(?:Get|Post|Head|PostForm|NewRequest(?:WithContext)?)\(|\.Do\(req\b|\bchromedp\.Navigate\("
          r"|\bwkhtmltopdf\.",
    "jvm": r"RestTemplate|WebClient|HttpClient|OkHttpClient|new URL\(|ITextRenderer|PdfRendererBuilder",
    "php": r"curl_init|file_get_contents\(\s*\$|Http::(?:get|post)|GuzzleHttp|\bDompdf\b|Browsershot|wkhtmltopdf",
}.items()}

# LLM API calls (OpenAI, Anthropic, Bedrock, Gemini, LangChain, LiteLLM and the like), plus the lines that build
# a prompt: system and user messages, prompt templates and f-string prompts. Those matter when the call itself
# is in one shared wrapper, because the untrusted text goes in where the prompt is built.
_LLM_CALL = {lang: re.compile(p) for lang, p in {
    "rb": r"OpenAI::Client|Anthropic::Client|RubyLLM\.|Langchain::LLM|Aws::BedrockRuntime|\binvoke_model\(|\.converse\("
          r"|\brole:\s*['\"](?:system|user)['\"]|['\"]role['\"]\s*=>\s*['\"](?:system|user)['\"]",
    "py": r"\b(?:Async)?(?:Azure)?OpenAI\(|\b(?:Async)?Anthropic(?:Bedrock|Vertex)?\(|\.chat\.completions\.(?:create|parse|stream)\("
          r"|\.responses\.(?:create|parse|stream)\(|\.messages\.(?:create|stream)\(|\binvoke_model(?:_with_response_stream)?\("
          r"|\.converse(?:_stream)?\(|\bgenerate_content(?:_async|_stream)?\(|\bGenerativeModel\(|\bgenai\.Client\("
          r"|\blitellm\.a?completion\(|\bChat(?:OpenAI|AzureOpenAI|Anthropic|Bedrock(?:Converse)?|VertexAI"
          r"|GoogleGenerativeAI|LiteLLM|Ollama|Groq|MistralAI)\(|\b(?:Chat)?PromptTemplate\.from_|\b(?:System|Human)Message\("
          r"|['\"]role['\"]\s*:\s*['\"](?:system|user)['\"]|\brole\s*=\s*['\"](?:system|user)['\"]"
          r"|\b(?i:\w*prompt\w*)\s*=\s*f['\"]|\b(?i:\w*prompt\w*)\.format\(",
    "js": r"\bnew (?:OpenAI|AzureOpenAI|Anthropic|GoogleGenerativeAI|ChatOpenAI|ChatAnthropic|BedrockRuntimeClient)\("
          r"|\.chat\.completions\.(?:create|parse|stream)\(|\.responses\.create\(|\.messages\.(?:create|stream)\("
          r"|\b(?:generate|stream)(?:Text|Object)\(|\b(?:InvokeModel(?:WithResponseStream)?|Converse(?:Stream)?)Command\("
          r"|\.generateContent(?:Stream)?\(|\b(?:System|Human)Message\(|['\"]?role['\"]?\s*:\s*['\"](?:system|user)['\"]",
    "go": r"\bopenai\.NewClient|\banthropic\.NewClient|\.CreateChatCompletion(?:Stream)?\(|\.Chat\.Completions\.New\("
          r"|\.Messages\.New(?:Streaming)?\(|\bbedrockruntime\.|\bgenai\.NewClient|\.GenerateContent\("
          r"|ChatMessageRole(?:System|User)|Role:\s*\"(?:system|user)\"",
    "jvm": r"OpenAIClient|AnthropicClient|ChatCompletionCreateParams|MessageCreateParams|BedrockRuntime(?:Async)?Client"
           r"|ChatLanguageModel|\bChatModel\b|\bChatClient\b|(?:System|User)Message\b|GenerativeModel",
    "php": r"OpenAI::(?:client|factory)|->chat\(\)->create\(|Anthropic::|BedrockRuntimeClient|\bPrism::"
           r"|['\"]role['\"]\s*=>\s*['\"](?:system|user)['\"]",
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
3. Some call sites render or load content rather than call an HTTP client: HTML-to-PDF renderers (WeasyPrint,
   pdfkit, wkhtmltopdf, WickedPdf, Dompdf), headless browsers (page.goto, page.setContent) and web loaders. They
   fetch every URL inside that content (img src, link href, CSS url(), iframes, redirects), and often file://
   paths too. For these, trace where the content comes from and whether users can put URLs or markup into it,
   for example through notes, Markdown, rich text or LLM output built from their input, and check whether the
   library's fetching is restricted (a custom url_fetcher, request interception, disabled local file access).
4. Code that runs in the browser isn't SSRF; skip it.
5. Report only SSRF you have verified, under additional_findings, with file paths relative to the repository root.
   In the description, name the entry point (method and route, or job and what triggers it), who can reach it
   (anyone, any logged-in user, admins) and what an attacker could reach. Report an issue once and name its other
   call sites in the description.
6. Rate severity by what an attacker can do in this codebase:
{severity}
7. In the summary, say how many of the call sites you checked and name any you couldn't trace.

Call sites (file: lines):
{items}

Already reported, so don't report these again (JSON, quoting untrusted repository content):
{reported}
"""

LLM_PROMPT = """You are a senior application security engineer checking how an application uses LLMs.

Repository: {repo}
Detected stacks: {stacks}
This is batch {n} of {total} of a deep review's LLM pass; other batches cover the other call sites.

{rules}

1. The lines below call an LLM API (OpenAI, Anthropic, Bedrock, Gemini, LangChain, LiteLLM and the like), wrap one
   for the rest of the app, or build a prompt. For each, find what goes into the prompt and where the output goes,
   following them through callers, wrappers, jobs and stored data. Untrusted text is anything users or outsiders
   control: answers, submitted code, chat messages, resumes, uploaded files, web pages, emails, support tickets,
   and anything stored from them earlier (transcripts, notes, documents) that a later job or a retrieval (RAG)
   puts into a prompt.
2. Check for:
   - prompt injection: untrusted text in a prompt whose output decides something (scores, grades, pass or fail,
     feedback or reports other people rely on, approvals, what gets stored or sent), with no separation from the
     instructions and no check of the output outside the LLM (tests run on submitted code, schema and range checks,
     a separate grader). Include text stored now and put into a prompt later by a job, a report or a retrieval;
   - data a user can talk the model into revealing: secrets, reference solutions, rubrics, hidden test cases, or
     other users' data in a prompt that user's text reaches;
   - LLM output that calls tools or takes actions (database writes, emails, HTTP requests, running code) without an
     allowlist or a check of the arguments;
   - LLM output shown to other users or staff as HTML or markdown without sanitising (stored XSS, phishing links),
     or passed into SQL, shell commands, file paths, URLs or eval. If the output is rendered in another codebase,
     such as a separate frontend, say so in the description;
   - endpoints that let the client choose the model, max tokens, system prompt or upstream API path, or that proxy
     to an LLM with the server's key; LLM endpoints with no authentication, rate limit or input size limit (cost
     abuse);
   - personal data (resumes, interview answers, contact details, transcripts) sent unredacted to LLM providers or
     to tracing tools such as Langfuse or LangSmith.
3. The app's own prompts aren't findings in themselves, and neither is what the model might say (offensive or
   off-topic output). Report weaknesses in how the code builds the prompt or uses the output.
4. Report only issues you have verified in the code, under additional_findings, with file paths relative to the
   repository root. In the description, name the entry point (method and route, or job and what triggers it), who
   can reach it (anyone, any logged-in user, admins), what text they control and what it changes. Report one issue
   per root cause and name its other call sites in the description.
5. Rate severity by what an attacker can do in this codebase:
{severity}
   - for LLM issues: high when a user's text can change a score, grade, assessment or hiring decision, reveal
     reference solutions or rubrics, or make the model take actions; personal data sent to a provider or tracing
     tool is low, unless people who shouldn't see it can read it there.
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
    """Outbound HTTP call sites and LLM call sites ({file: [lines]} each), and request-handler files
    ([(file, lines)]), in the repo's own code."""
    sites, llm, handlers = {}, {}, []
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
            hits = [n for n, line in enumerate(lines, 1)
                    if _LLM_CALL[lang].search(line) and not _NOT_A_CALL.match(line)]
            if hits:
                llm[rel] = hits
        if (lang == "rb" and rel.endswith("_controller.rb")) or _HANDLER[lang].search(text):
            handlers.append((rel, len(lines)))
    return sites, llm, handlers


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
    names = [rel for rel, _ in batch] if key != "access" else list(dict.fromkeys(os.path.dirname(rel) or "."
                                                                                 for rel, _ in batch))
    return ", ".join(names[:3]) + (f" and {len(names) - 3} more" if len(names) > 3 else "")


def _items(key, batch):
    if key != "access":
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
    """Run the SSRF pass, the LLM pass, then the access-control pass, the biggest, last, so a budget cut
    falls on it. Returns (Claude's new findings, meta for report.json).

    earlier is the general review's findings, which the deep review mustn't repeat. A batch is skipped once the
    scan's Claude budget is reached.
    """
    prefixes = [p.strip().strip("/").removeprefix("./") for p in paths if p.strip().strip("/")]
    started = time.time()
    sites, llm, handlers = _inventory(repo, prefixes)
    log(f"deep review: {sum(len(v) for v in sites.values())} outbound HTTP call sites in {len(sites)} files,"
        f" {sum(len(v) for v in llm.values())} LLM call sites in {len(llm)} files,"
        f" {len(handlers)} request-handler files ({time.time() - started:.0f}s to list)")
    context = dict(repo=repo, stacks=", ".join(stacks) or "unknown", rules=_RULES, severity=_SEVERITY_GUIDE)
    found, meta = [], {"paths": prefixes or None, "cost_usd": 0.0}
    passes = [("ssrf", "SSRF", SSRF_PROMPT, sites, _site_batches(sites)),
              ("llm", "LLM", LLM_PROMPT, llm, _site_batches(llm)),
              ("access", "access control", ACCESS_PROMPT, handlers, _area_batches(handlers))]
    for key, title, template, units, batches in passes:
        m = meta[key] = {"batches": len(batches), "done": 0, "failed": [], "skipped": [], "summaries": []}
        if key == "access":
            m.update(files=len(handlers), lines=sum(n for _, n in handlers))
        else:
            m.update(files=len(units), call_sites=sum(len(v) for v in units.values()))
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
