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

SKIP_DIRS: frozenset[str] = frozenset({"node_modules", ".git"})
MAX_FILE_BYTES: int = 1024 * 1024
HOME_CONFIG_FILES: tuple[Path, ...] = (
    Path.home() / ".claude" / "settings.json",
    Path.home() / ".claude" / "settings.local.json",
)

LIFECYCLE_SCRIPTS: tuple[str, ...] = (
    "preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly", "prepack", "postpack",
)
LIFECYCLE_ALLOWLIST: tuple[str, ...] = (
    "husky", "husky install", "node-gyp rebuild", "node-gyp-build", "prebuild-install", "patch-package",
)
# shortcut: fallback matches lifecycle keys anywhere in the file, not only under "scripts"; only runs on RecursionError files
LIFECYCLE_VALUE_RE = re.compile(
    '"(?:' + "|".join(map(re.escape, LIFECYCLE_SCRIPTS)) + r')"\s*:\s*"(?P<value>(?:[^"\\]|\\.)*)(?P<end>")?'
)

CHECK_H4 = "H4"
WORKFLOW_SUFFIXES: tuple[str, ...] = (".yml", ".yaml")
WORKFLOW_DIRS: tuple[str, ...] = (".github", "workflows")
LOCAL_ACTION_PREFIXES: tuple[str, ...] = ("./", "docker://")

OIDC_TOKEN_RE = re.compile(r"ACTIONS_ID_TOKEN_\w+")
# shortcut: nested $(...) inside the substitution is not matched, upgrade if seen in the wild
PROC_MEM_RE = re.compile(r"/proc/(?:[^/\s()]+|\$\([^()\n]*\))/mem\b")
USES_RE = re.compile(r"""^\s*(?:-\s+)?uses\s*:\s*["']?(?P<ref>[^\s"'#]+)""")
# lead is the line start (block mapping) or a flow-mapping { or , (no continuation tracking)
RUN_KEY_RE = re.compile(r"""(?P<lead>^\s*(?:-\s+)?|[{,]\s*)["']?run["']?\s*:(?P<value>.*)$""")
SHA_RE = re.compile(r"[0-9a-fA-F]{40}")

PATTERN_ACTIONS_ID_TOKEN = "actions_id_token"
PATTERN_PROC_MEM = "proc_mem"
PATTERN_UNPINNED_ACTION = "unpinned_action"

CHECK_H5 = "H5"
IOCS_ENV = "DEV_GUARD_IOCS"  # overrides IOCS_PATH when scan() gets no iocs_path
IOCS_PATH = Path(__file__).resolve().parent.parent / "iocs.json"  # repo root; revisit for packaging
NPM_LOCK_NAMES: tuple[str, ...] = ("package-lock.json", "npm-shrinkwrap.json")
PNPM_LOCK_NAME = "pnpm-lock.yaml"
REQUIREMENTS_MARKER = "requirements"  # in the file name or the parent dir name
REQUIREMENTS_SUFFIX = ".txt"
NPM_ALIAS_PREFIX = "npm:"
NODE_MODULES_SEP = "node_modules/"

# shortcut: pnpm v5 /name/version keys, yarn.lock and poetry.lock are not parsed (yarn/poetry out of scope for H5)
PNPM_ENTRY_RE = re.compile(
    r"""^\s+['"]?/?(?P<name>(?:@[^@/\s'"]+/)?[^@/\s'"(]+)@(?P<version>[^_('":\s]+)"""
)
REQUIREMENTS_PIN_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]\n]*\])?\s*===?\s*(?P<version>[^\s;#,]+)"
)
# shortcut: an entry whose "version" comes after a nested object, or a key with backslash escapes, is missed by the fallback; only used on RecursionError files
# body is captured in a lookahead so nested keys are still visited; [^"\\]* (not (?:[^"\\]|\\.)*) keeps it linear on \"*N
LOCK_ENTRY_RE = re.compile(r'"(?P<key>[^"\\]*)"\s*:\s*\{(?=(?P<body>[^{}]*))')
LOCK_VERSION_FIELD_RE = re.compile(r'"version"\s*:\s*"(?P<v>[^"\\]*)"')
LOCK_NAME_FIELD_RE = re.compile(r'"name"\s*:\s*"(?P<v>[^"\\]*)"')
# PEP 440: v prefix and trailing .0 segments do not change the version
PYPI_VERSION_PREFIX_RE = re.compile(r"^[vV]")
PYPI_TRAILING_ZEROS_RE = re.compile(r"(?:\.0+)+$")
PYPI_NORMALIZE_RE = re.compile(r"[-_.]+")

PATTERN_IOC_MATCH = "ioc_match"
PATTERN_IOCS_MISSING = "iocs_missing"
PATTERN_IOCS_MALFORMED = "iocs_malformed"

SEVERITY_ORDER: dict[str, int] = {SEVERITY_HIGH: 0, SEVERITY_MED: 1, SEVERITY_LOW: 2}
EXIT_CLEAN = 0
EXIT_HIGH = 1
EXIT_USAGE = 2
EXIT_INTERNAL = 70  # sysexits EX_SOFTWARE
TABLE_HEADERS = ("SEV", "ID", "FILE:LINE", "PATTERN")
NO_FINDINGS_MSG = "No findings."
