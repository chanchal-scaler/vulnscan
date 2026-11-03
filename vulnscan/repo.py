import base64
import os
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .config import GITHUB_ORGS, WORK_DIR, log

_GITHUB_RE = re.compile(
    r"^(?:https://github\.com/|git@github\.com:)?(?P<owner>[\w.-]+)/(?P<name>[\w.-]+?)(?:\.git)?/?$"
)


class RepoError(Exception):
    pass


def parse_github(spec):
    m = _GITHUB_RE.match(spec.strip())
    return (m.group("owner"), m.group("name")) if m else None


def _clone(owner, name, dest, ref):
    cmd = ["git", "clone", "--depth", "1", "--quiet"]
    if ref:
        cmd += ["--branch", ref]
    cmd += [f"https://github.com/{owner}/{name}.git", str(dest)]
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1")
    # A fine-grained token only reaches one owner's repos, so a per-org token
    # (GITHUB_TOKEN_SCALER_HQ for scaler-hq) wins over the generic one.
    token = os.environ.get("GITHUB_TOKEN_" + re.sub(r"\W", "_", owner).upper()) or os.environ.get("GITHUB_TOKEN")
    if token:
        # Passed through the environment so it never lands in .git/config or the process list.
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        env.update(
            GIT_CONFIG_COUNT="1",
            GIT_CONFIG_KEY_0="http.https://github.com/.extraheader",
            GIT_CONFIG_VALUE_0=f"AUTHORIZATION: basic {basic}",
        )
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RepoError(f"git clone failed: {proc.stderr.strip()}")


def git_head(repo: Path):
    proc = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True)
    return proc.stdout.strip() if proc.returncode == 0 else None


@contextmanager
def checkout(spec, ref=None, keep=False):
    """Yield (repo_path, label) for a local directory or a GitHub repo (cloned, then removed)."""
    local = Path(spec).expanduser()
    if local.is_dir():
        yield local.resolve(), local.resolve().name
        return

    parsed = parse_github(spec)
    if not parsed:
        raise RepoError(f"'{spec}' is neither a local directory nor a GitHub repo (org/repo or URL)")
    owner, name = parsed
    if GITHUB_ORGS and owner.lower() not in [o.lower() for o in GITHUB_ORGS]:
        raise RepoError(f"{owner}/{name} is outside the allowed orgs '{', '.join(GITHUB_ORGS)}' (VULNSCAN_GITHUB_ORG)")

    WORK_DIR.mkdir(parents=True, exist_ok=True)
    dest = Path(tempfile.mkdtemp(prefix=f"{owner}__{name}__", dir=WORK_DIR))
    try:
        log(f"cloning {owner}/{name}" + (f"@{ref}" if ref else ""))
        _clone(owner, name, dest, ref)
        yield dest.resolve(), f"{owner}/{name}"
    finally:
        if keep:
            log(f"clone kept at {dest}")
        else:
            shutil.rmtree(dest, ignore_errors=True)
