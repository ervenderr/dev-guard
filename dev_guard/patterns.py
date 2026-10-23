"""Constants only: regexes, severities, walk limits."""
import re
from pathlib import Path

SEVERITY_HIGH = "high"
SEVERITY_MED = "med"
SEVERITY_LOW = "low"

CHECK_H1 = "H1"
CHECK_H2 = "H2"
CHECK_H3 = "H3"
CHECK_WALK = "walk"

_SHELLS = r"(?:sh|bash|zsh|dash|ksh|fish)"
_PATH = r"(?:[^\s/|]*+/)*+"  # path prefix that cannot cross | or whitespace and never backtracks
_WRAPPERS = rf"(?:{_PATH}(?:sudo|env|xargs)\s+)*+"

# Linear-time: first keyword per line/segment is locked with an atomic group, so each line is scanned once.
H1_PATTERNS: dict[str, re.Pattern[str]] = {
    "network_fetch": re.compile(
        r"\b(?:curl|wget|nc|ncat)\b|/dev/tcp/"
        r"|(?m:^)(?>.*?\bpython[0-9.]*\s+-c\b).*\b(?:urllib|requests|socket|http)"
        r"|(?m:^)(?>.*?\bnode\s+-e\b).*\b(?:fetch|https?|net)\b"
    ),
    "base64_decode": re.compile(
        r"(?:^|[|;&])(?>[^|;&]*?\bbase64\b)[^|;&]*\s(?:-(?=[a-zA-Z]*[dD])[a-zA-Z]++|--decode)\b"
    ),
    "eval": re.compile(r"\beval\b"),
    "remote_shell": re.compile(
        rf"\|\s*{_WRAPPERS}{_PATH}{_SHELLS}\b"
        rf"|(?m:^)(?>.*?\b{_SHELLS}\s+-c\b).*(?:https?://|\$\(\s*(?:curl|wget|python[0-9.]*|node|perl)\b)"
    ),
}

HOOK_ALLOWLIST: tuple[str, ...] = ("prettier", "npx prettier", "eslint", "npx eslint", "git")
SHELL_CHAIN_RE = re.compile(r"[;&|`\n<>]|\$\(")

# backslash-escaped letters, empty quote pairs, $'...' and ${...} hide tokens like curl from the regexes
OBFUSCATION_RE = re.compile(r"\\[A-Za-z]|''|\"\"|\$'|\$\{")

FOLDER_OPEN_RE = re.compile(r'"runOn"\s*:\s*"folderOpen"')

PATTERN_NOT_IN_ALLOWLIST = "not_in_allowlist"
PATTERN_MALFORMED_JSON = "malformed_json"
PATTERN_RUN_ON_FOLDER_OPEN = "run_on_folder_open"
PATTERN_SYMLINKED_CONFIG = "symlinked_config"
PATTERN_UNREADABLE_DIR = "unreadable_dir"
PATTERN_OBFUSCATED = "obfuscated_command"
PATTERN_OVERSIZE_FILE = "oversize_file"
PATTERN_UNREADABLE_FILE = "unreadable_file"
PATTERN_OVERSIZE_LINE = "oversize_line"

SKIP_DIRS: frozenset[str] = frozenset({"node_modules", ".git"})
MAX_FILE_BYTES: int = 1024 * 1024
# defence in depth: no single line/value longer than this is regex-matched
MAX_LINE_LEN: int = 4096
HOME_CONFIG_FILES: tuple[Path, ...] = (
    Path.home() / ".claude" / "settings.json",
    Path.home() / ".claude" / "settings.local.json",
)

LIFECYCLE_SCRIPTS: tuple[str, ...] = ("preinstall", "install", "postinstall")
LIFECYCLE_ALLOWLIST: tuple[str, ...] = (
    "husky", "husky install", "node-gyp rebuild", "node-gyp-build", "prebuild-install", "patch-package",
)
# shortcut: fallback matches lifecycle keys anywhere in the file, not only under "scripts"; only runs on RecursionError files
LIFECYCLE_VALUE_RE = re.compile(
    '"(?:' + "|".join(map(re.escape, LIFECYCLE_SCRIPTS)) + r')"\s*:\s*"(?P<value>(?:[^"\\]|\\.){0,%d})(?P<end>")?'
    % MAX_LINE_LEN
)

CHECK_H4 = "H4"
WORKFLOW_SUFFIXES: tuple[str, ...] = (".yml", ".yaml")
WORKFLOW_DIRS: tuple[str, ...] = (".github", "workflows")
LOCAL_ACTION_PREFIXES: tuple[str, ...] = ("./", "docker://")

OIDC_TOKEN_RE = re.compile(r"ACTIONS_ID_TOKEN_\w+")
# shortcut: nested $(...) inside the substitution is not matched, upgrade if seen in the wild
PROC_MEM_RE = re.compile(r"/proc/(?:[^/\s$()]+|\$\([^()\n]*\))/mem\b")
USES_RE = re.compile(r"""^\s*(?:-\s+)?uses\s*:\s*["']?(?P<ref>[^\s"'#]+)""")
RUN_KEY_RE = re.compile(r"^(?P<lead>\s*(?:-\s+)?)run\s*:(?P<value>.*)$")
BLOCK_SCALAR_RE = re.compile(r"^[|>][+\-0-9]*\s*(#.*)?$")
SHA_RE = re.compile(r"[0-9a-fA-F]{40}")

PATTERN_ACTIONS_ID_TOKEN = "actions_id_token"
PATTERN_PROC_MEM = "proc_mem"
PATTERN_UNPINNED_ACTION = "unpinned_action"
