"""Safe tree walk and H1 hook detection. Text is parsed, never executed."""
import json
import os
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from dev_guard.patterns import (
    CHECK_H1,
    H1_PATTERNS,
    HOME_CONFIG_FILES,
    HOOK_ALLOWLIST,
    MAX_FILE_BYTES,
    PATTERN_MALFORMED_JSON,
    PATTERN_NOT_IN_ALLOWLIST,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MED,
    SHELL_CHAIN_RE,
    SKIP_DIRS,
)


@dataclass(frozen=True)
class Finding:
    check_id: str
    severity: str
    file: str
    line: int
    pattern: str


def iter_files(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS and not os.path.islink(os.path.join(dirpath, d))
        ]
        for name in filenames:
            full = os.path.join(dirpath, name)
            if not os.path.islink(full):
                yield Path(full)


def read_text(path: Path) -> str | None:
    try:
        if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return None


def collect_commands(obj: object) -> list[str]:
    if isinstance(obj, dict):
        out: list[str] = []
        for key, value in obj.items():
            if key == "command" and isinstance(value, str):
                out.append(value)
            else:
                out.extend(collect_commands(value))
        return out
    if isinstance(obj, list):
        return [c for item in obj for c in collect_commands(item)]
    return []


def find_line(text: str, needle: str) -> int:
    # json.loads drops line info, so search the raw text for the escaped string.
    for candidate in (json.dumps(needle)[1:-1], json.dumps(needle, ensure_ascii=False)[1:-1]):
        for i, line in enumerate(text.splitlines(), 1):
            if candidate in line:
                return i
    return 1


# shortcut: prefix match trusts any args after git/npx, so git -c alias.x='!sh ...' or npx <unknown-pkg> pass as allowlisted; upgrade to argv parsing if seen in the wild
def is_allowlisted(command: str) -> bool:
    cmd = command.strip()
    if SHELL_CHAIN_RE.search(cmd):
        return False
    return any(cmd == a or cmd.startswith(a + " ") for a in HOOK_ALLOWLIST)


def check_claude_settings(path: Path, text: str) -> list[Finding]:
    try:
        data = json.loads(text)
        hooks = data.get("hooks") if isinstance(data, dict) else None
        commands = collect_commands(hooks) if isinstance(hooks, dict) else []
    except json.JSONDecodeError as err:
        return [Finding(CHECK_H1, SEVERITY_LOW, str(path), err.lineno, PATTERN_MALFORMED_JSON)]
    except (RecursionError, ValueError):
        return [Finding(CHECK_H1, SEVERITY_LOW, str(path), 1, PATTERN_MALFORMED_JSON)]
    findings: list[Finding] = []
    for cmd in commands:
        hits = [name for name, rx in H1_PATTERNS.items() if rx.search(cmd)]
        line = find_line(text, cmd)
        findings += [Finding(CHECK_H1, SEVERITY_HIGH, str(path), line, n) for n in hits]
        if not hits and not is_allowlisted(cmd):
            findings.append(Finding(CHECK_H1, SEVERITY_MED, str(path), line, PATTERN_NOT_IN_ALLOWLIST))
    return findings


TARGETS = {(".claude", "settings.json"): check_claude_settings}


def scan(root: Path, extra_files: Iterable[Path] = HOME_CONFIG_FILES) -> list[Finding]:
    seen: set[str] = set()
    findings: list[Finding] = []
    for path in [*iter_files(Path(root)), *map(Path, extra_files)]:
        real = os.path.realpath(path)
        check = TARGETS.get((path.parent.name, path.name))
        if check is None or real in seen:
            continue
        seen.add(real)
        text = read_text(path)
        if text is not None:
            findings.extend(check(path, text))
    return sorted(findings, key=lambda f: (f.file, f.line, f.check_id, f.pattern))
