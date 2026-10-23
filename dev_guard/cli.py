"""Command line entry point: table output and exit codes."""
import argparse
import dataclasses
import json
import os
import sys
from collections.abc import Iterable
from pathlib import Path

from dev_guard import __version__
from dev_guard.checks import Finding, scan
from dev_guard.patterns import (
    DEFAULT_SCAN_ROOTS,
    EXIT_CLEAN,
    EXIT_HIGH,
    EXIT_INTERNAL,
    EXIT_USAGE,
    HOME_CONFIG_FILES,
    NO_FINDINGS_MSG,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MED,
    SEVERITY_ORDER,
    TABLE_HEADERS,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dev-guard")
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--json", action="store_true", help="print findings as JSON")
    parser.add_argument("--version", action="version", version=f"dev-guard {__version__}")
    return parser


def sanitize(s: str) -> str:
    s = s.replace("\\", "\\\\")
    return "".join(c if c.isprintable() else repr(c)[1:-1] for c in s)


def run_scan(roots: list[Path], extra_files: Iterable[Path]) -> list[Finding]:
    found: set[Finding] = set()
    extras = tuple(extra_files)
    for i, root in enumerate(roots):
        found.update(scan(root, extra_files=extras if i == 0 else ()))
    return sorted(
        found,
        key=lambda f: (SEVERITY_ORDER[f.severity], f.file, f.line, f.check_id, f.pattern),
    )


def format_table(findings: list[Finding]) -> str:
    if not findings:
        return NO_FINDINGS_MSG
    rows = [TABLE_HEADERS] + [
        tuple(sanitize(c) for c in (f.severity, f.check_id, f"{f.file}:{f.line}", f.pattern))
        for f in findings
    ]
    widths = [max(len(r[i]) for r in rows) for i in range(len(TABLE_HEADERS))]
    lines = [" | ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip() for r in rows]
    s = _summary(findings)
    lines.append(f"{s['high']} high, {s['med']} med, {s['low']} low")
    return "\n".join(lines)


def _summary(findings: list[Finding]) -> dict[str, int]:
    return {
        key: sum(f.severity == sev for f in findings)
        for key, sev in (("high", SEVERITY_HIGH), ("med", SEVERITY_MED), ("low", SEVERITY_LOW))
    }


def format_json(findings: list[Finding]) -> str:
    # ensure_ascii (default) escapes control chars and surrogates, so output is safe ASCII JSON
    return json.dumps(
        {"findings": [dataclasses.asdict(f) for f in findings], "summary": _summary(findings)}
    )


def _check_roots(paths: list[str]) -> tuple[list[Path], str | None]:
    roots = []
    for p in paths:
        path = Path(p).expanduser()
        if not path.exists():
            return [], f"dev-guard: {sanitize(p)}: no such directory"
        if not path.is_dir():
            return [], f"dev-guard: {sanitize(p)}: not a directory"
        roots.append(path)
    return roots, None


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    extra_files = () if args.paths else HOME_CONFIG_FILES
    roots, err = _check_roots(args.paths or [str(p) for p in DEFAULT_SCAN_ROOTS])
    if err:
        sys.stderr.write(err + "\n")
        return EXIT_USAGE
    try:
        findings = run_scan(roots, extra_files)
        code = EXIT_HIGH if any(f.severity == SEVERITY_HIGH for f in findings) else EXIT_CLEAN
        text = format_json(findings) if args.json else format_table(findings)
    except Exception as exc:  # only the type name is printed: exc text may carry file content
        sys.stderr.write(f"dev-guard: internal error: {type(exc).__name__}\n")
        return EXIT_INTERNAL
    try:
        sys.stdout.write(text + "\n")
        sys.stdout.flush()
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    return code
