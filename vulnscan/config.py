import os
import sys
from pathlib import Path

HOME = Path(os.environ.get("VULNSCAN_HOME", Path.home() / ".vulnscan")).expanduser()
TOOLS_DIR = HOME / "tools"
BIN_DIR = TOOLS_DIR / "bin"
GEM_DIR = TOOLS_DIR / "gems"
SCANS_DIR = HOME / "scans"
WORK_DIR = HOME / "work"

# When set (comma-separated), only repos owned by these GitHub orgs can be scanned.
GITHUB_ORGS = [o.strip() for o in os.environ.get("VULNSCAN_GITHUB_ORG", "").split(",") if o.strip()]

TOOL_TIMEOUT = int(os.environ.get("VULNSCAN_TOOL_TIMEOUT", "1800"))
TRIAGE_TIMEOUT = int(os.environ.get("VULNSCAN_TRIAGE_TIMEOUT", "3600"))  # per Claude batch
TRIAGE_BATCH = int(os.environ.get("VULNSCAN_TRIAGE_BATCH", "100"))  # items per Claude batch
# The model for every Claude Code call (triage, review, deep review, fix), so runs don't depend on Claude
# Code's default for the account and version. --model overrides it. Needs Claude Code 2.1.280 or newer.
CLAUDE_MODEL = "claude-opus-5-5"

# Stage 2 (validation with Strix).
VALIDATE_TIMEOUT = int(os.environ.get("VULNSCAN_VALIDATE_TIMEOUT", "7200"))  # one Strix run (one pass)
VALIDATE_BUDGET = float(os.environ.get("VULNSCAN_VALIDATE_BUDGET", "25"))  # max LLM spend in USD, per pass
VALIDATE_PASS = 20  # findings per Strix run: the critical and high ones are sent in passes of this size

# Variables scanners may see. Everything else (GITHUB_TOKEN, CLAUDE_CODE_OAUTH_TOKEN,
# AWS_* and so on) is withheld so a tool can never leak it.
SCANNER_ENV_ALLOWLIST = (
    "PATH", "HOME", "USER", "SHELL", "LANG", "LC_ALL", "TMPDIR",
    "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
    "GOPATH", "GOROOT", "GOCACHE", "GOMODCACHE", "GOPROXY", "GOFLAGS",
    "RBENV_ROOT", "RBENV_VERSION", "GEM_PATH", "PYENV_ROOT",
)


def scanner_env():
    env = {k: os.environ[k] for k in SCANNER_ENV_ALLOWLIST if k in os.environ}
    env["PATH"] = os.pathsep.join([str(BIN_DIR), env.get("PATH", "")])
    if GEM_DIR.exists():
        # A trailing separator keeps Ruby's default gem paths searchable as well.
        env["GEM_PATH"] = os.pathsep.join([str(GEM_DIR), env.get("GEM_PATH", "")])
    env["SEMGREP_SEND_METRICS"] = "off"
    env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
    return env


def log(message):
    print(f"[vulnscan] {message}", file=sys.stderr, flush=True)
