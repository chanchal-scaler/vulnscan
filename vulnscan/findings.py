from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List, Optional

SEVERITIES = ["critical", "high", "medium", "low", "info"]

_ALIASES = {
    "error": "high",
    "warning": "medium",
    "warn": "medium",
    "moderate": "medium",
    "note": "low",
    "weak": "low",
    "none": "info",
}


def normalize_severity(value):
    v = str(value or "").strip().lower()
    v = _ALIASES.get(v, v)
    return v if v in SEVERITIES else "medium"


def severity_from_cvss(score):
    try:
        score = float(score)
    except (TypeError, ValueError):
        return None
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low" if score > 0 else "info"


def rel_path(path, repo: Path, base: Optional[Path] = None):
    """Return a path relative to the repo root, whatever form the tool reported it in."""
    if not path:
        return ""
    p = Path(path)
    if not p.is_absolute():
        p = (base or repo) / p
    try:
        return str(p.resolve().relative_to(repo))
    except ValueError:
        return str(path)


@dataclass
class Finding:
    tool: str
    rule_id: str
    title: str
    severity: str
    category: str  # code | dependency | secret | config
    file: str = ""
    line: Optional[int] = None
    description: str = ""
    package: Optional[str] = None
    version: Optional[str] = None
    fixed_version: Optional[str] = None
    references: List[str] = field(default_factory=list)
    id: str = ""
    triage: Optional[dict] = None

    @property
    def location(self):
        return f"{self.file}:{self.line}" if self.line else self.file

    @property
    def final_severity(self):
        return (self.triage or {}).get("severity") or self.severity

    def to_dict(self):
        return asdict(self)


def sort_key(f: Finding):
    return (SEVERITIES.index(f.final_severity), f.file, f.line or 0)
