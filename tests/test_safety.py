import ast
import dataclasses
import json
from pathlib import Path

import pytest

from dev_guard.checks import Finding, scan

PKG = Path(__file__).parent.parent / "dev_guard"
MAL = Path(__file__).parent / "fixtures" / "h1" / "malicious"
SECRET = "FAKE_SECRET_TOKEN_1234567890"
BANNED_CALLS = {"eval", "exec", "compile", "__import__", "print"}
BANNED_MODULES = {"subprocess", "pty"}


def test_no_secret_in_findings():
    findings = scan(MAL, extra_files=())
    assert findings
    for f in findings:
        assert SECRET not in repr(f)
        assert SECRET not in json.dumps(dataclasses.asdict(f))


def test_finding_shape_and_frozen():
    assert {f.name for f in dataclasses.fields(Finding)} == {"check_id", "severity", "file", "line", "pattern"}
    f = Finding("H1", "high", "x", 1, "eval")
    with pytest.raises(dataclasses.FrozenInstanceError):
        f.line = 2


def violations(tree):
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] in BANNED_MODULES:
                    yield n.lineno
        elif isinstance(n, ast.ImportFrom):
            if (n.module or "").split(".")[0] in BANNED_MODULES:
                yield n.lineno
        elif isinstance(n, ast.Call):
            fn = n.func
            if isinstance(fn, ast.Name) and fn.id in BANNED_CALLS:
                yield n.lineno
            elif isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) and fn.value.id == "os":
                if fn.attr in {"system", "popen"} or fn.attr.startswith(("exec", "spawn")):
                    yield n.lineno


def test_ast_gate():
    files = list(PKG.glob("*.py"))
    assert files
    for p in files:
        assert not list(violations(ast.parse(p.read_text()))), p
