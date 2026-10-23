"""Safe tree walk and H1 hook detection. Text is parsed, never executed."""
import json
import os
import stat
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from dev_guard.patterns import (
    CHECK_H1,
    CHECK_WALK,
    CHECK_H2,
    FOLDER_OPEN_RE,
    H1_PATTERNS,
    HOME_CONFIG_FILES,
    HOOK_ALLOWLIST,
    MAX_FILE_BYTES,
    OBFUSCATION_RE,
    PATTERN_OBFUSCATED,
    PATTERN_MALFORMED_JSON,
    PATTERN_NOT_IN_ALLOWLIST,
    PATTERN_OVERSIZE_FILE,
    PATTERN_RUN_ON_FOLDER_OPEN,
    PATTERN_SYMLINKED_CONFIG,
    PATTERN_UNREADABLE_DIR,
    PATTERN_UNREADABLE_FILE,
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


def iter_files(root: Path, errors: list[Finding] | None = None) -> Iterator[Path]:
    def on_error(err: OSError) -> None:
        if errors is not None:
            errors.append(Finding(CHECK_WALK, SEVERITY_LOW, str(err.filename), 1, PATTERN_UNREADABLE_DIR))

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=on_error):
        # symlinks are never followed, but are yielded so scan() can report config ones
        yield from (Path(dirpath, d) for d in dirnames if os.path.islink(os.path.join(dirpath, d)))
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS and not os.path.islink(os.path.join(dirpath, d))
        ]
        for name in filenames:
            yield Path(dirpath, name)


def read_text(path: Path) -> tuple[str | None, str | None]:
    """Return (text, problem_pattern). Both None means the file does not exist."""
    try:
        # one fd for type check and read: no swap race, never follows a link, never blocks on a FIFO
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                return None, PATTERN_UNREADABLE_FILE
            data = f.read(MAX_FILE_BYTES + 1)
    except FileNotFoundError:
        return None, None
    except OSError:
        return None, PATTERN_UNREADABLE_FILE
    if len(data) > MAX_FILE_BYTES:
        return None, PATTERN_OVERSIZE_FILE
    return data.decode("utf-8-sig", errors="replace"), None


def iter_command_dicts(obj: object) -> Iterator[dict]:
    if isinstance(obj, dict):
        if "command" in obj or "args" in obj:
            yield obj
        for value in obj.values():
            yield from iter_command_dicts(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from iter_command_dicts(item)


def _text_of(item: object) -> str | None:
    if isinstance(item, str):
        return item
    if isinstance(item, dict) and isinstance(item.get("value"), str):
        return item["value"]
    return None


def command_parts(d: dict) -> list[str]:
    args = d.get("args")
    items = [d.get("command"), *(args if isinstance(args, list) else [])]
    return [t for t in map(_text_of, items) if t is not None]


def find_line(text: str, needle: str) -> int:
    # json.loads drops line info, so search the raw text for the escaped string.
    escaped = json.dumps(needle)[1:-1]
    # json.loads counts only \n as a line break; str.splitlines() also splits on \x0c, \x85, U+2028...
    lines = text.split("\n")
    for candidate in (escaped, json.dumps(needle, ensure_ascii=False)[1:-1], escaped.replace("/", "\\/")):
        for i, line in enumerate(lines, 1):
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
        dicts = list(iter_command_dicts(hooks)) if isinstance(hooks, dict) else []
    except (json.JSONDecodeError, RecursionError, ValueError) as err:
        line = err.lineno if isinstance(err, json.JSONDecodeError) else 1
        return [Finding(CHECK_H1, SEVERITY_LOW, str(path), line, PATTERN_MALFORMED_JSON),
                *_raw_scan(CHECK_H1, path, text)]
    findings: list[Finding] = []
    for d in dicts:
        parts = command_parts(d)
        if not parts:
            continue
        hits = _high(CHECK_H1, path, text, d)
        findings += hits
        if OBFUSCATION_RE.search(" ".join(parts)):
            findings.append(Finding(CHECK_H1, SEVERITY_MED, str(path), find_line(text, parts[0]), PATTERN_OBFUSCATED))
        if not hits and not is_allowlisted(" ".join(parts)):
            line = find_line(text, parts[0])
            findings.append(Finding(CHECK_H1, SEVERITY_MED, str(path), line, PATTERN_NOT_IN_ALLOWLIST))
    return findings


def _high(check_id: str, path: Path, text: str, d: dict) -> list[Finding]:
    parts = command_parts(d)
    joined = " ".join(parts)
    out: list[Finding] = []
    for name, rx in H1_PATTERNS.items():
        if not rx.search(joined):
            continue
        part = next((p for p in parts if rx.search(p)), parts[0] if parts else None)
        line = find_line(text, part) if part is not None else 1
        out.append(Finding(check_id, SEVERITY_HIGH, str(path), line, name))
    return out


def _is_folder_open(task: object) -> bool:
    opts = task.get("runOptions") if isinstance(task, dict) else None
    return isinstance(opts, dict) and opts.get("runOn") == "folderOpen"


def _raw_scan(check_id: str, path: Path, text: str) -> list[Finding]:
    # VS Code parses JSONC leniently, so a file our strict parse rejects may still run.
    out: list[Finding] = []
    for n, line in enumerate(text.split("\n"), 1):
        out += [Finding(check_id, SEVERITY_HIGH, str(path), n, name)
                for name, rx in H1_PATTERNS.items() if rx.search(line)]
        if FOLDER_OPEN_RE.search(line):
            out.append(Finding(check_id, SEVERITY_MED, str(path), n, PATTERN_RUN_ON_FOLDER_OPEN))
    return out


def check_vscode_tasks(path: Path, text: str) -> list[Finding]:
    try:
        data = json.loads(text)
        tasks = data.get("tasks") if isinstance(data, dict) else None
        # list() inside the try: the generator raises RecursionError lazily
        groups = [(t, list(iter_command_dicts(t))) for t in tasks] if isinstance(tasks, list) else []
    except (json.JSONDecodeError, RecursionError, ValueError) as err:
        line = err.lineno if isinstance(err, json.JSONDecodeError) else 1
        return [Finding(CHECK_H2, SEVERITY_LOW, str(path), line, PATTERN_MALFORMED_JSON),
                *_raw_scan(CHECK_H2, path, text)]
    findings: list[Finding] = []
    for task, dicts in groups:
        # HOOK-04: an H1 pattern is high with or without folderOpen (task can be run by hand)
        for d in dicts:
            findings += _high(CHECK_H2, path, text, d)
        if _is_folder_open(task):
            parts = command_parts(dicts[0]) if dicts else []
            line = find_line(text, parts[0]) if parts else 1
            findings.append(Finding(CHECK_H2, SEVERITY_MED, str(path), line, PATTERN_RUN_ON_FOLDER_OPEN))
    return findings


TARGETS = {
    (".claude", "settings.json"): (CHECK_H1, check_claude_settings),
    (".claude", "settings.local.json"): (CHECK_H1, check_claude_settings),
    (".vscode", "tasks.json"): (CHECK_H2, check_vscode_tasks),
}


def _symlink_findings(path: Path) -> list[Finding]:
    name = path.name.lower()
    by_dir = {parent: cid for (parent, _), (cid, _) in TARGETS.items()}
    target = TARGETS.get((path.parent.name.lower(), name))
    check_id = target[0] if target else by_dir.get(name)
    if check_id is None:
        return []
    return [Finding(check_id, SEVERITY_MED, str(path), 1, PATTERN_SYMLINKED_CONFIG)]


def scan(root: Path, extra_files: Iterable[Path] = HOME_CONFIG_FILES) -> list[Finding]:
    seen: set[str] = set()
    findings: list[Finding] = []
    walk_errors: list[Finding] = []
    for path in [*iter_files(Path(root), walk_errors), *map(Path, extra_files)]:
        if path.is_symlink():
            findings += _symlink_findings(path)
            continue
        real = os.path.realpath(path)
        target = TARGETS.get((path.parent.name.lower(), path.name.lower()))
        if target is None or real in seen:
            continue
        seen.add(real)
        check_id, check = target
        text, problem = read_text(path)
        if problem is not None:
            findings.append(Finding(check_id, SEVERITY_LOW, str(path), 1, problem))
        elif text is not None:
            findings.extend(check(path, text))
    return sorted([*findings, *walk_errors], key=lambda f: (f.file, f.line, f.check_id, f.pattern))
