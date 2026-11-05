"""A built-in check for prompt injection planted in the scanned repo: text written to steer AI tools
(vulnscan's own Claude and Strix, other scanners, developers' coding agents) rather than people, and
characters that hide text from people.

It runs in-process and only reads files, so there's nothing to install and no repo code runs. It flags
candidates; Claude's triage decides which are real, since an app's own LLM prompts can match too.
"""
import bisect
import json
import os
import re

from ..detect import SKIP_DIRS
from ..findings import Finding, rel_path
from .base import Tool

MAX_BYTES = 2_000_000  # bigger files are bundles, dumps and fixtures, not hand-written text
PER_FILE = 3  # hits kept per rule and file
_SKIP_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z",
    ".jar", ".war", ".class", ".pyc", ".so", ".dylib", ".dll", ".exe", ".bin", ".woff", ".woff2", ".ttf", ".otf",
    ".eot", ".mp3", ".mp4", ".mov", ".webm", ".wav", ".sqlite", ".db", ".map", ".min.js", ".min.css",
)
_TAG_RUN = re.compile("[\U000E0000-\U000E007F]+")
_INVISIBLE = re.compile("[\u202a-\u202e\u2066-\u2069\u200b-\u200d\u2060-\u2064\ufeff]")
_AI = (r"(?:AI|LLMs?|language\s+models?|(?:AI\s+)?assistants?|AI\s+(?:agents?|reviewers?|scanners?|tools?)"
       r"|coding\s+agents?|Claude|ChatGPT|GPT(?:-?\d\w*)?|Copilot|Cursor|Gemini)")

_STEER = "May be a prompt injection aimed at AI tools that read this repository."
# (rule, severity, title, why, pattern), most telling first: a line gets one finding, from the first rule it matches.
RULES = [
    ("hidden-unicode-tags", "high", "Invisible Unicode tag characters hide text",
     "People can't see these characters, but language models read them as text.", _TAG_RUN),
    ("reviewer-steering", "high", "Text telling an AI or scanner to dismiss or hide findings", _STEER, re.compile(
        r"\b(?:mark|classify|report|treat|label|consider)\s+(?:this|these|it|them|all|every|any|the\s+following)\b"
        r"[^.\n]{0,40}?\bas\s+(?:an?\s+)?(?:false[\s_-]?positives?|not\s+(?:an?\s+)?(?:vulnerab\w*|security\s+issues?"
        r"|exploitable))"
        r"|\b(?:security\s+)?(?:scanners?|reviewers?|auditors?|" + _AI + r")\s+(?:should|must|can|may)\s+"
        r"(?:safely\s+)?(?:ignore|skip|not\s+(?:report|flag))\b"
        r"|\b(?:do\s+not|don'?t|never)\s+(?:report|flag|mention)\s+(?:this|these|it|them|any)\s+(?:as\s+(?:an?\s+)?)?"
        r"(?:vulnerabilit\w*|security\s+(?:issues?|findings?|problems?)|findings?|secrets?|credentials?)\b", re.I)),
    ("bidi-control", "medium", "Bidirectional control character can reorder or hide text (Trojan Source)",
     "It can make text read differently to people than to compilers and models.",
     re.compile("[\u202a-\u202e\u2066-\u2069]")),
    ("zero-width-run", "medium", "Run of zero-width characters can hide text",
     "Invisible characters in a row can encode hidden text.", re.compile("[\u200b-\u200d\u2060-\u2064]{4,}")),
    ("instruction-override", "medium", "Text telling an AI to ignore its instructions", _STEER, re.compile(
        r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+|of\s+)*(?:previous|prior|above"
        r"|earlier|preceding|system|original|existing)\s+(?:instructions?|prompts?|rules|directions|guidelines"
        r"|messages)", re.I)),
    ("ai-addressed", "medium", "Instructions addressed to an AI tool", _STEER, re.compile(
        r"\b" + _AI + r"\s*[,:]\s*(?:please\s+)?(?:ignore|disregard|do\s+not|don'?t|never|you\s+must)\b"
        r"|\bnote\s+(?:to|for)\s+(?:the\s+|any\s+)?" + _AI + r"\b", re.I)),
    ("chat-markup", "low", "LLM chat-template tokens",
     "They can make a model read file content as a new system or user message.", re.compile(
        r"<\|(?:im_start|im_end|system|user|assistant|endoftext|begin_of_text|start_header_id)\|>", re.I)),
]
_UNICODE_RULES = {"hidden-unicode-tags", "bidi-control", "zero-width-run"}


def _files(target):
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if not name.lower().endswith(_SKIP_SUFFIXES):
                yield os.path.join(dirpath, name)


def _read(path):
    try:
        if os.path.islink(path) or os.path.getsize(path) > MAX_BYTES:
            return None
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    text = data.decode("utf-8", errors="replace")
    # Bytes that don't decode are a binary file under another name, such as a PDF test fixture.
    return None if b"\0" in data[:8192] or text.count(chr(0xFFFD)) > len(text) // 100 else text


def _visible(text):
    """The line as text a reviewer can read: hidden runs and invisible characters spelled out."""
    text = _TAG_RUN.sub("<hidden text>", text)
    return _INVISIBLE.sub(lambda m: f"<U+{ord(m.group()):04X}>", text)


def _decode_tags(run):
    return "".join(chr(ord(c) - 0xE0000) for c in run if 0x20 <= ord(c) - 0xE0000 < 0x7F)


class PromptInjection(Tool):
    name = "prompt-injection"
    command = ""  # built in: nothing to install
    applies_to = "all repos (text aimed at AI tools, hidden Unicode; built in)"

    def run(self, exe, repo, target, report, env, timeout):
        findings, hits = [], []
        for path in _files(target):
            text = _read(path)
            if not text:
                continue
            starts, lines = None, set()
            for rule, severity, title, why, pattern in RULES:
                if rule in _UNICODE_RULES and text.isascii():
                    continue
                kept = 0
                for m in pattern.finditer(text):
                    # A subdivision flag emoji (England, Scotland, Wales) is a black flag plus tag characters.
                    if rule == "hidden-unicode-tags" and m.start() and text[m.start() - 1] == "\U0001F3F4":
                        continue
                    if starts is None:
                        starts = [n.start() for n in re.finditer("\n", text)]
                    line_no = bisect.bisect_left(starts, m.start()) + 1
                    if line_no in lines:
                        continue
                    lines.add(line_no)
                    begin = starts[line_no - 2] + 1 if line_no > 1 else 0
                    end = starts[line_no - 1] if line_no <= len(starts) else len(text)
                    snippet = _visible(text[begin:end].strip())[:200]
                    detail = f"{why} Line: {snippet}"
                    if rule == "hidden-unicode-tags":
                        detail += f" Hidden text: {json.dumps(_decode_tags(m.group())[:300])}"
                    file = rel_path(path, repo, target)
                    hits.append({"rule": rule, "file": file, "line": line_no, "snippet": snippet})
                    findings.append(Finding(
                        tool=self.name, rule_id=f"prompt-injection.{rule}", title=title, severity=severity,
                        category="code", file=file, line=line_no, description=detail,
                    ))
                    kept += 1
                    if kept == PER_FILE:
                        break
        report.write_text(json.dumps(hits, indent=1))
        return findings
