"""Delete one stage's results from a repo's run folders: `vulnscan purge scan|validate|fix <repo>`.

A stage's results go together with the later stages', which depend on them: a scan's run folder
holds all three, and fix results name findings by the V ids of the validation they were made from.
Only local files are deleted. Fix PRs and branches stay on GitHub.
"""
import shutil
from pathlib import Path

from .config import SCANS_DIR
from .repo import label_for

FIX = ("fix.json", "fix.md", "fix")
VALIDATE = ("validation.json", "validation.md", "validation.csv", "strix-instructions.md", "strix-findings.json",
            "strix", "strix-target", "raw/strix") + FIX


class PurgeError(Exception):
    pass


def results(run_dir, stage):
    """The paths in run_dir that hold this stage's results and the later stages'."""
    if stage == "scan":
        return [run_dir]
    return [run_dir / name for name in (VALIDATE if stage == "validate" else FIX)
            if (run_dir / name).exists() or (run_dir / name).is_symlink()]


def remove(paths):
    for p in paths:
        if p.is_dir() and not p.is_symlink():
            shutil.rmtree(p)
        else:
            p.unlink(missing_ok=True)


def _run_dirs(base, stage, run, all_runs):
    runs = sorted(d for d in base.iterdir() if d.is_dir() and not d.is_symlink()) if base.is_dir() else []
    if run:
        p = Path(run).expanduser()
        p = p if "/" in run else base / run
        if not (p.is_dir() and p.resolve().parent == base.resolve()):
            raise PurgeError(f"{run} is not a run folder under {base}")
        return [p.resolve()]
    with_results = [d for d in runs if results(d, stage)]
    return with_results if all_runs else with_results[-1:]


def purge(spec, stage, run=None, all_runs=False, yes=False):
    """Delete (or with yes=False, only list) this stage's results, and the later stages', from the repo's newest
    run that has them, the run folder `run`, or every run. Returns the paths."""
    base = SCANS_DIR / label_for(spec).replace("/", "__")
    paths = [p for d in _run_dirs(base, stage, run, all_runs) for p in results(d, stage)]
    if yes:
        remove(paths)
        if stage == "scan" and base.is_dir() and not any(base.iterdir()):
            base.rmdir()
    return paths
