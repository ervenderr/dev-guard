"""Safe tree walk and H1 hook detection. Text is parsed, never executed."""
import functools
import json
import os
import re
import stat
from collections.abc import Callable, Collection, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from dev_guard.patterns import (
    CHECK_H1,
    CHECK_H3,
    CHECK_H4,
    CHECK_H5,
    CHECK_WALK,
    CHECK_H2,
    FOLDER_OPEN_RE,
    H1_PATTERNS,
    LIFECYCLE_ALLOWLIST,
    LIFECYCLE_SCRIPTS,
    LIFECYCLE_VALUE_RE,
    LOCAL_ACTION_PREFIXES,
    OIDC_TOKEN_RE,
    PATTERN_ACTIONS_ID_TOKEN,
    PATTERN_PROC_MEM,
    PATTERN_UNPINNED_ACTION,
    PROC_MEM_RE,
    RUN_KEY_RE,
    SHA_RE,
    USES_RE,
    WORKFLOW_DIRS,
    WORKFLOW_SUFFIXES,
    HOME_CONFIG_FILES,
    IOCS_ENV,
    IOCS_PATH,
    LOCK_ENTRY_RE,
    LOCK_NAME_FIELD_RE,
    LOCK_VERSION_FIELD_RE,
    NODE_MODULES_SEP,
    NPM_ALIAS_PREFIX,
    NPM_LOCK_NAMES,
    PATTERN_IOC_MATCH,
    PATTERN_IOCS_MALFORMED,
    PATTERN_IOCS_MISSING,
    PNPM_ENTRY_RE,
    PNPM_LOCK_NAME,
    PYPI_NORMALIZE_RE,
    PYPI_TRAILING_ZEROS_RE,
    PYPI_VERSION_PREFIX_RE,
    REQUIREMENTS_PIN_RE,
    REQUIREMENTS_MARKER,
    REQUIREMENTS_SUFFIX,
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


def iter_files(root: Path, errors: list[Finding] | None = None, exclude: Collection[str] = ()) -> Iterator[Path]:
    def on_error(err: OSError) -> None:
        if errors is not None:
            errors.append(Finding(CHECK_WALK, SEVERITY_LOW, str(err.filename), 1, PATTERN_UNREADABLE_DIR))

    # compare by device/inode, not path text: APFS is case-insensitive, realpath keeps the spelling given
    excluded = set()
    for e in exclude:
        try:
            st = os.stat(e)
        except OSError:
            continue  # nonexistent: nothing to skip (the CLI warns)
        excluded.add((st.st_dev, st.st_ino))

    def is_excluded(path: str) -> bool:
        try:
            st = os.stat(path)
        except OSError:
            return False
        return (st.st_dev, st.st_ino) in excluded

    if excluded:
        real_root = Path(os.path.realpath(root))
        if any(is_excluded(str(p)) for p in (real_root, *real_root.parents)):
            return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=on_error):
        # symlinks are never followed, but are yielded so scan() can report config ones
        yield from (Path(dirpath, d) for d in dirnames if os.path.islink(os.path.join(dirpath, d)))
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS and not os.path.islink(os.path.join(dirpath, d))
            and not (excluded and is_excluded(os.path.join(dirpath, d)))
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
def is_allowlisted(command: str, allowlist: tuple[str, ...] = HOOK_ALLOWLIST) -> bool:
    cmd = command.strip()
    if SHELL_CHAIN_RE.search(cmd):
        return False
    return any(cmd == a or cmd.startswith(a + " ") for a in allowlist)


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


def h1_findings(check_id: str, path: Path, text: str, line: int) -> list[Finding]:
    return [Finding(check_id, SEVERITY_HIGH, str(path), line, name)
            for name, rx in H1_PATTERNS.items() if rx.search(text)]


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
        out += h1_findings(check_id, path, line, n)
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


def _lifecycle_findings(path: Path, value: str, line: int) -> list[Finding]:
    hits = h1_findings(CHECK_H3, path, value, line)
    if not hits and not is_allowlisted(value, LIFECYCLE_ALLOWLIST):
        hits.append(Finding(CHECK_H3, SEVERITY_MED, str(path), line, PATTERN_NOT_IN_ALLOWLIST))
    return hits


def _deep_json_fallback(path: Path, text: str) -> list[Finding]:
    # valid JSON too deep for Python's parser: whole-text scan, line derived from match offset
    out = [Finding(CHECK_H3, SEVERITY_LOW, str(path), 1, PATTERN_MALFORMED_JSON)]
    line, prev = 1, 0
    for m in LIFECYCLE_VALUE_RE.finditer(text):
        line += text.count("\n", prev, m.start())
        prev = m.start()
        try:
            value = json.loads('"' + m["value"] + '"')
        except ValueError:
            value = m["value"]
        out += _lifecycle_findings(path, value, line)
    return out


def check_package_json(path: Path, text: str) -> list[Finding]:
    try:
        data = json.loads(text)
    except RecursionError:
        return _deep_json_fallback(path, text)
    except ValueError as err:  # includes JSONDecodeError
        line = err.lineno if isinstance(err, json.JSONDecodeError) else 1
        return [Finding(CHECK_H3, SEVERITY_LOW, str(path), line, PATTERN_MALFORMED_JSON)]
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if not isinstance(scripts, dict):
        return []
    findings: list[Finding] = []
    for key in LIFECYCLE_SCRIPTS:
        value = scripts.get(key)
        if isinstance(value, str):
            findings += _lifecycle_findings(path, value, find_line(text, value))
    return findings


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


# shortcut: line-based text scan, no YAML parser; anchors and multi-line flow mappings can hide uses:/run:, upgrade if seen in the wild
def check_workflow(path: Path, text: str) -> list[Finding]:
    out: list[Finding] = []
    run_indent: int | None = None
    for n, raw in enumerate(text.split("\n"), 1):
        line = raw.removesuffix("\r")
        if OIDC_TOKEN_RE.search(line):
            out.append(Finding(CHECK_H4, SEVERITY_HIGH, str(path), n, PATTERN_ACTIONS_ID_TOKEN))
        if PROC_MEM_RE.search(line):
            out.append(Finding(CHECK_H4, SEVERITY_HIGH, str(path), n, PATTERN_PROC_MEM))
        if line.strip() == "":
            continue
        if run_indent is not None:
            if _indent(line) > run_indent:
                out += h1_findings(CHECK_H4, path, line, n)
                continue
            run_indent = None
        run = RUN_KEY_RE.search(line)
        if run:
            out += h1_findings(CHECK_H4, path, run["value"], n)
            # deeper lines are block-scalar or multi-line plain/quoted continuation
            run_indent = len(run["lead"]) if run.start() == 0 else None
        uses = USES_RE.match(line)
        if uses and not uses["ref"].startswith(LOCAL_ACTION_PREFIXES):
            ref = uses["ref"].rpartition("@")
            if not ref[1] or not SHA_RE.fullmatch(ref[2]):
                out.append(Finding(CHECK_H4, SEVERITY_MED, str(path), n, PATTERN_UNPINNED_ACTION))
    return out

Iocs = dict[str, frozenset[str]]
EMPTY_IOCS: Iocs = {"npm": frozenset(), "pypi": frozenset()}


def _pypi_key(name: str, version: str) -> str:
    version = PYPI_TRAILING_ZEROS_RE.sub("", PYPI_VERSION_PREFIX_RE.sub("", version.strip()))
    return f"{PYPI_NORMALIZE_RE.sub('-', name.lower())}=={version}"


def load_iocs(path: Path) -> tuple[Iocs, list[Finding]]:
    """Never raises: any problem yields one low H5 finding; bad entries are skipped, good ones kept."""
    def problem(pattern: str) -> tuple[Iocs, list[Finding]]:
        return EMPTY_IOCS, [Finding(CHECK_H5, SEVERITY_LOW, str(path), 1, pattern)]

    text, bad = read_text(path)
    if bad is not None:
        return problem(bad)
    if text is None:
        return problem(PATTERN_IOCS_MISSING)
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return problem(PATTERN_IOCS_MALFORMED)
    if not isinstance(data, dict):
        return problem(PATTERN_IOCS_MALFORMED)
    out: dict[str, set[str]] = {"npm": set(), "pypi": set()}
    bad_entries = False
    for eco, sep in (("npm", "@"), ("pypi", "==")):
        entries = data.get(eco, [])
        if not isinstance(entries, list):
            bad_entries = True
            continue
        for entry in entries:
            name, found, version = entry.rpartition(sep) if isinstance(entry, str) else ("", "", "")
            name, version = name.strip(), version.strip()
            if not found or not name or not version:
                bad_entries = True
                continue
            out[eco].add(f"{name}@{version}" if eco == "npm" else _pypi_key(name, version))
    findings = [Finding(CHECK_H5, SEVERITY_LOW, str(path), 1, PATTERN_IOCS_MALFORMED)] if bad_entries else []
    return {k: frozenset(v) for k, v in out.items()}, findings


def _npm_candidates(key_name: str, entry_name: str | None, version: str) -> set[str]:
    if version.startswith(NPM_ALIAS_PREFIX):
        return {version[len(NPM_ALIAS_PREFIX):]}
    return {f"{n}@{version}" for n in (key_name, entry_name) if n}


def _ioc_finding(path: Path, line: int) -> Finding:
    return Finding(CHECK_H5, SEVERITY_HIGH, str(path), line, PATTERN_IOC_MATCH)


def _lock_entries(data: object) -> Iterator[tuple[str, str, str | None, str]]:
    """Yield (raw_key, key_name, entry_name, version) from v2/v3 packages and v1 dependencies."""
    if not isinstance(data, dict):
        return
    packages = data.get("packages")
    pairs = [(k, v) for k, v in packages.items()] if isinstance(packages, dict) else []
    stack = [data.get("dependencies")]  # explicit stack: no recursion limit on nesting
    while stack:
        deps = stack.pop()
        if not isinstance(deps, dict):
            continue
        for key, entry in deps.items():
            pairs.append((key, entry))
            if isinstance(entry, dict):
                stack.append(entry.get("dependencies"))
    for key, entry in pairs:
        key_name = key.rpartition(NODE_MODULES_SEP)[2]
        if key_name and isinstance(entry, dict) and isinstance(entry.get("version"), str):
            name = entry.get("name")
            yield key, key_name, name if isinstance(name, str) else None, entry["version"]


def _lock_json_fallback(path: Path, text: str, iocs: Iocs) -> list[Finding]:
    # valid JSON too deep for Python's parser: whole-text scan, line derived from match offset
    out = [Finding(CHECK_H5, SEVERITY_LOW, str(path), 1, PATTERN_MALFORMED_JSON)]
    line, prev = 1, 0
    for m in LOCK_ENTRY_RE.finditer(text):
        line += text.count("\n", prev, m.start())
        prev = m.start()
        key_name = m["key"].rpartition(NODE_MODULES_SEP)[2]
        ver = LOCK_VERSION_FIELD_RE.search(m["body"])
        if not key_name or ver is None:
            continue
        name = LOCK_NAME_FIELD_RE.search(m["body"])
        if _npm_candidates(key_name, name["v"] if name else None, ver["v"]) & iocs["npm"]:
            out.append(_ioc_finding(path, line))
    return out


def _check_npm_lock(path: Path, text: str, iocs: Iocs) -> list[Finding]:
    try:
        entries = list(_lock_entries(json.loads(text)))
    except RecursionError:
        return _lock_json_fallback(path, text, iocs)
    except ValueError as err:
        line = err.lineno if isinstance(err, json.JSONDecodeError) else 1
        return [Finding(CHECK_H5, SEVERITY_LOW, str(path), line, PATTERN_MALFORMED_JSON)]
    hits = [_ioc_finding(path, find_line(text, key))
            for key, key_name, name, version in entries
            if _npm_candidates(key_name, name, version) & iocs["npm"]]
    return list(dict.fromkeys(hits))  # v2 lists each package twice


def _logical_lines(text: str) -> Iterator[tuple[int, str]]:
    """Yield (first line number, text) with backslash continuations joined."""
    buf, start = "", 0
    for n, raw in enumerate(text.split("\n"), 1):
        raw = raw.removesuffix("\r")
        start = start or n
        if raw.endswith("\\"):
            buf += raw[:-1] + " "
            continue
        yield start, buf + raw
        buf, start = "", 0
    if buf:
        yield start, buf


def _line_matches(path: Path, text: str, rx, lookup: Callable[[re.Match], bool]) -> list[Finding]:
    out: list[Finding] = []
    for n, logical in _logical_lines(text):
        m = rx.match(logical)
        if m and lookup(m):
            out.append(_ioc_finding(path, n))
    return out


def check_lockfile(path: Path, text: str, iocs: Iocs) -> list[Finding]:
    name = path.name.lower()
    if name in NPM_LOCK_NAMES:
        return _check_npm_lock(path, text, iocs)
    if name == PNPM_LOCK_NAME:
        return _line_matches(path, text, PNPM_ENTRY_RE, lambda m: f"{m['name']}@{m['version']}" in iocs["npm"])
    return _line_matches(path, text, REQUIREMENTS_PIN_RE, lambda m: _pypi_key(m["name"], m["version"]) in iocs["pypi"])


TARGETS = {
    (".claude", "settings.json"): (CHECK_H1, check_claude_settings),
    (".claude", "settings.local.json"): (CHECK_H1, check_claude_settings),
    (".vscode", "tasks.json"): (CHECK_H2, check_vscode_tasks),
}


def _is_lockfile(path: Path) -> bool:
    name = path.name.lower()
    return name in (*NPM_LOCK_NAMES, PNPM_LOCK_NAME) or (
        name.endswith(REQUIREMENTS_SUFFIX)
        and (REQUIREMENTS_MARKER in re.split(r"[-_.]", name) or path.parent.name.lower() == REQUIREMENTS_MARKER))


def target_for(path: Path, lockfile_check: Callable[[Path, str], list[Finding]] | None = None
               ) -> tuple[str, Callable[[Path, str], list[Finding]] | None] | None:
    target = TARGETS.get((path.parent.name.lower(), path.name.lower()))
    if target is None and path.name.lower() == "package.json":
        return CHECK_H3, check_package_json
    if target is None and _is_lockfile(path):
        return CHECK_H5, lockfile_check
    if (target is None and path.suffix.lower() in WORKFLOW_SUFFIXES
            and (path.parent.parent.name.lower(), path.parent.name.lower()) == WORKFLOW_DIRS):
        return CHECK_H4, check_workflow
    return target


def _symlink_findings(path: Path) -> list[Finding]:
    name = path.name.lower()
    by_dir = {parent: cid for (parent, _), (cid, _) in TARGETS.items()}
    target = target_for(path)
    check_id = target[0] if target else by_dir.get(name)
    if name == WORKFLOW_DIRS[0] or (name == WORKFLOW_DIRS[1] and path.parent.name.lower() == WORKFLOW_DIRS[0]):
        check_id = CHECK_H4
    if check_id is None:
        return []
    return [Finding(check_id, SEVERITY_MED, str(path), 1, PATTERN_SYMLINKED_CONFIG)]


def scan(root: Path, extra_files: Iterable[Path] = HOME_CONFIG_FILES, iocs_path: Path | None = None,
         exclude: Collection[str] = ()) -> list[Finding]:
    seen: set[str] = set()
    iocs, findings = load_iocs(Path(iocs_path or os.environ.get(IOCS_ENV) or IOCS_PATH))
    lockfile_check = functools.partial(check_lockfile, iocs=iocs)
    walk_errors: list[Finding] = []
    for path in [*iter_files(Path(root), walk_errors, exclude), *map(Path, extra_files)]:
        if path.is_symlink():
            findings += _symlink_findings(path)
            continue
        real = os.path.realpath(path)
        target = target_for(path, lockfile_check)
        if target is None or real in seen:
            continue
        seen.add(real)
        check_id, check = target
        text, problem = read_text(path)
        if problem is not None:
            severity = SEVERITY_MED if problem == PATTERN_OVERSIZE_FILE else SEVERITY_LOW
            findings.append(Finding(check_id, severity, str(path), 1, problem))
        elif text is not None:
            findings.extend(check(path, text))
    return sorted([*findings, *walk_errors], key=lambda f: (f.file, f.line, f.check_id, f.pattern))
