"""Scanner registry. To add a scanner, create a Tool subclass in this package and list it here."""
from .bandit import Bandit
from .brakeman import Brakeman
from .checkov import Checkov
from .gitleaks import Gitleaks
from .gosec import Gosec
from .osv_scanner import OsvScanner
from .prompt_injection import PromptInjection
from .semgrep import Semgrep

ALL_TOOLS = [
    # Every repo
    Semgrep(),
    OsvScanner(),
    Gitleaks(),
    PromptInjection(),  # built in
    # Stack-specific
    Checkov(),
    Brakeman(),
    Bandit(),
    Gosec(),
]
