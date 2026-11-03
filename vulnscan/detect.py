import os
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

SKIP_DIRS = {
    ".git", "node_modules", "vendor", ".venv", "venv", "env", "__pycache__",
    "dist", "build", ".bundle", "tmp", "log", "coverage", ".terraform", "target", ".next",
}

# Stack -> files that mark a project root for that stack.
ROOT_MARKERS = {
    "ruby": {"Gemfile"},
    "go": {"go.mod"},
    "javascript": {"package.json"},
    "java": {"pom.xml", "build.gradle", "build.gradle.kts"},
    "php": {"composer.json"},
    "rust": {"Cargo.toml"},
}


def _is_iac(dirpath: Path, filename: str):
    return (
        filename.endswith(".tf")
        or filename.startswith("Dockerfile")
        or filename == "Chart.yaml"
        or (dirpath.parts[-2:] == (".github", "workflows") and filename.endswith((".yml", ".yaml")))
    )


def detect_stacks(repo: Path) -> Dict[str, List[Path]]:
    """Map each detected stack to the directories it lives in."""
    stacks = defaultdict(set)
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        d = Path(dirpath)
        files = set(filenames)
        for stack, markers in ROOT_MARKERS.items():
            if files & markers:
                stacks[stack].add(d)
        if "Gemfile" in files and (d / "config" / "application.rb").exists():
            stacks["rails"].add(d)
        if any(f.endswith(".py") for f in filenames):
            stacks["python"].add(repo)
        if any(_is_iac(d, f) for f in filenames):
            stacks["iac"].add(repo)
    return {k: sorted(v) for k, v in sorted(stacks.items())}
