"""Finds scanner executables and installs missing ones under VULNSCAN_HOME/tools.

Install strategies:
  pip     - its own virtualenv per tool, so tool dependencies never clash
  gem     - an isolated gem directory (needs Ruby)
  github  - the tool's latest GitHub release binary, checked against the release's checksums file
"""
import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

from .config import BIN_DIR, GEM_DIR, TOOLS_DIR, log


class InstallError(Exception):
    pass


def find(command):
    return shutil.which(command, path=os.pathsep.join([str(BIN_DIR), os.environ.get("PATH", "")]))


def ensure(tool):
    exe = find(tool.command)
    if exe:
        return exe
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    errors = []
    for strategy, spec in tool.install:
        log(f"{tool.name}: installing via {strategy} ({spec})")
        try:
            INSTALLERS[strategy](tool.command, spec)
        except Exception as e:  # keep trying other strategies
            errors.append(f"{strategy}: {e}")
            continue
        exe = find(tool.command)
        if exe:
            return exe
        errors.append(f"{strategy}: installed but '{tool.command}' not found")
    raise InstallError("; ".join(errors) or "no install method")


def _run(cmd):
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise InstallError((proc.stderr or proc.stdout).strip()[-500:])


def _pip(command, package):
    venv = TOOLS_DIR / "venvs" / command
    pip = venv / "bin" / "pip"
    if not pip.exists():
        _run([sys.executable, "-m", "venv", str(venv)])
        _run([str(pip), "install", "--quiet", "--upgrade", "pip"])
    _run([str(pip), "install", "--quiet", package])
    link = BIN_DIR / command
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(venv / "bin" / command)


def _gem(command, package):
    if not shutil.which("gem"):
        raise InstallError("gem not found (install Ruby)")
    _run(["gem", "install", package, "--no-document", "--install-dir", str(GEM_DIR), "--bindir", str(BIN_DIR)])


def _http_get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "vulnscan", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def _pick_asset(assets, command):
    os_names = {"Darwin": {"darwin", "macos"}, "Linux": {"linux"}}.get(platform.system(), set())
    arch_names = {
        "x86_64": {"amd64", "x64"},
        "amd64": {"amd64", "x64"},
        "arm64": {"arm64", "aarch64"},
        "aarch64": {"arm64", "aarch64"},
    }.get(platform.machine().lower(), set())
    for asset in assets:
        name = asset["name"].lower()
        # Only .tar.gz archives or bare binaries (no extension after the last "_").
        if not name.startswith(command) or not (name.endswith(".tar.gz") or "." not in name.rsplit("_", 1)[-1]):
            continue
        tokens = set(re.split(r"[_.-]", name))
        if tokens & os_names and tokens & arch_names:
            return asset
    return None


def _verify_checksum(assets, name, data):
    sums = next((a for a in assets if re.search(r"(checksums\.txt|sha256sums)$", a["name"], re.I)), None)
    if not sums:
        log(f"warning: no checksums file published for {name}; skipping verification")
        return
    for line in _http_get(sums["browser_download_url"]).decode().splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == name:
            if parts[0].lower() != hashlib.sha256(data).hexdigest():
                raise InstallError(f"checksum mismatch for {name}")
            return
    raise InstallError(f"{name} not listed in {sums['name']}")


def _github(command, repo):
    release = json.loads(_http_get(f"https://api.github.com/repos/{repo}/releases/latest"))
    assets = release.get("assets", [])
    asset = _pick_asset(assets, command)
    if not asset:
        raise InstallError(f"no {platform.system()}/{platform.machine()} binary in {repo} {release.get('tag_name')}")
    data = _http_get(asset["browser_download_url"])
    _verify_checksum(assets, asset["name"], data)
    dest = BIN_DIR / command
    if asset["name"].endswith(".tar.gz"):
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            member = next((m for m in tar.getmembers() if m.isfile() and Path(m.name).name == command), None)
            if not member:
                raise InstallError(f"'{command}' not found inside {asset['name']}")
            dest.write_bytes(tar.extractfile(member).read())
    else:
        dest.write_bytes(data)
    dest.chmod(0o700)
    log(f"{command}: installed {release.get('tag_name')}")


INSTALLERS = {"pip": _pip, "gem": _gem, "github": _github}
