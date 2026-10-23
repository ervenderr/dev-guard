"""Constants only: regexes, severities, walk limits."""
import re
from pathlib import Path

SEVERITY_HIGH = "high"
SEVERITY_MED = "med"
SEVERITY_LOW = "low"

CHECK_H1 = "H1"
CHECK_H2 = "H2"

_SHELLS = r"(?:sh|bash|zsh|dash)"

H1_PATTERNS: dict[str, re.Pattern[str]] = {
    "network_fetch": re.compile(r"\b(?:curl|wget|nc|ncat)\b"),
    "base64_decode": re.compile(r"\bbase64\s+(?:-d|-D|--decode)\b"),
    "eval": re.compile(r"\beval\b"),
    "remote_shell": re.compile(
        rf"\|\s*(?:sudo\s+)?{_SHELLS}\b"
        rf"|\b{_SHELLS}\s+-c\b.*(?:https?://|\$\(\s*(?:curl|wget)\b)"
    ),
}

SKIP_DIRS: frozenset[str] = frozenset({"node_modules", ".git"})
MAX_FILE_BYTES: int = 1024 * 1024
HOME_CONFIG_FILES: tuple[Path, ...] = (Path.home() / ".claude" / "settings.json",)
