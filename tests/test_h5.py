import json
from pathlib import Path

import pytest

from dev_guard.checks import scan

FIXTURES = Path(__file__).parent / "fixtures" / "h5"
MALICIOUS = FIXTURES / "malicious"
CLEAN = FIXTURES / "clean"

LOCK_LINE = 6  # node_modules/dev-guard-ioc-placeholder in malicious/package-lock.json
PNPM_LINES = (5, 8, 11)
REQ_LINE = 2

BAD = "dev-guard-ioc-placeholder"
DEPTH = 100_000  # 5000 does not overflow json on py3.12
NEST = "[" * DEPTH + "]" * DEPTH


def got(findings, severity=None):
    return {(f.check_id, f.severity, f.pattern, f.line) for f in findings
            if severity is None or f.severity == severity}


def scan_text(tmp_path, text, name="package-lock.json"):
    (tmp_path / name).write_text(text)
    return scan(tmp_path, extra_files=())


def highs(findings):
    return got(findings, "high")


def lock_v3(entries: dict) -> str:
    return json.dumps({"lockfileVersion": 3, "packages": {"": {"name": "root"}, **entries}}, indent=2)


def line_of(text, needle):
    return next(i for i, ln in enumerate(text.split("\n"), 1) if needle in ln)


def test_malicious_fixture():
    findings = scan(MALICIOUS, extra_files=())
    assert ("H5", "high", "ioc_match", LOCK_LINE) in got(findings)
    for n in PNPM_LINES:
        assert ("H5", "high", "ioc_match", n) in got(findings)
    assert ("H5", "high", "ioc_match", REQ_LINE) in got(findings)
    assert len(findings) == 5
    assert all(f.check_id == "H5" for f in findings)


def test_clean_fixture():
    assert scan(CLEAN, extra_files=()) == []


def test_no_package_text_in_findings():
    assert BAD not in repr(scan(MALICIOUS, extra_files=()))


def test_v1_nested_dependencies(tmp_path):
    text = json.dumps({"lockfileVersion": 1, "dependencies": {
        "a": {"version": "1.0.0", "dependencies": {BAD: {"version": "0.0.1"}}}}}, indent=2)
    assert ("H5", "high", "ioc_match", line_of(text, BAD)) in highs(scan_text(tmp_path, text))


def test_different_version_not_flagged(tmp_path):
    assert highs(scan_text(tmp_path, lock_v3({f"node_modules/{BAD}": {"version": "0.0.2"}}))) == set()


def test_v3_alias_name_field(tmp_path):
    text = lock_v3({"node_modules/innocent-name": {"name": BAD, "version": "0.0.1"}})
    assert len(highs(scan_text(tmp_path, text))) == 1


def test_v1_alias_npm_prefix(tmp_path):
    text = json.dumps({"lockfileVersion": 1, "dependencies": {
        "innocent-name": {"version": f"npm:{BAD}@0.0.1"}}}, indent=2)
    assert len(highs(scan_text(tmp_path, text))) == 1


def test_malformed_lockfile(tmp_path):
    f = scan_text(tmp_path, '{"packages": {')
    assert [(x.check_id, x.severity, x.pattern) for x in f] == [("H5", "low", "malformed_json")]


@pytest.mark.parametrize("version,flagged", [("0.0.1", True), ("0.0.2", False)])
def test_deep_nesting_multiline(tmp_path, version, flagged):
    text = ('{\n"x": ' + NEST + ',\n"packages": {\n"": {"name": "root"},\n'
            f'"node_modules/{BAD}": {{\n"version": "{version}"\n}}\n}}\n}}\n')
    findings = scan_text(tmp_path, text)
    assert ("H5", "low", "malformed_json", 1) in got(findings)
    assert (("H5", "high", "ioc_match", 5) in got(findings)) is flagged
    assert (highs(findings) != set()) is flagged


def deep_min(tail: str) -> str:
    return '{"x": ' + NEST + ", " + tail + "}"


@pytest.mark.parametrize("tail,flagged", [
    (f'"packages": {{"": {{"name": "root"}}, "node_modules/a/node_modules/{BAD}": {{"version": "0.0.1"}}}}', True),
    (f'"packages": {{"node_modules/{BAD}": {{"version": "0.0.2"}}}}', False),
    (f'"dependencies": {{"innocent-name": {{"version": "npm:{BAD}@0.0.1"}}}}', True),
    (f'"dependencies": {{"innocent-name": {{"version": "npm:{BAD}@0.0.2"}}}}', False),
    (f'"packages": {{"node_modules/innocent-name": {{"name": "{BAD}", "version": "0.0.1"}}}}', True),
    (f'"packages": {{"node_modules/innocent-name": {{"name": "{BAD}", "version": "0.0.2"}}}}', False),
])
def test_deep_nesting_minified(tmp_path, tail, flagged):
    findings = scan_text(tmp_path, deep_min(tail))
    assert ("H5", "low", "malformed_json", 1) in got(findings)
    assert (("H5", "high", "ioc_match", 1) in got(findings)) is flagged


def test_iocs_missing(tmp_path):
    findings = scan(CLEAN, extra_files=(), iocs_path=tmp_path / "nope.json")
    assert [(f.check_id, f.severity, f.pattern) for f in findings] == [("H5", "low", "iocs_missing")]


def scan_iocs(tmp_path, content):
    p = tmp_path / "iocs.json"
    p.write_text(content if isinstance(content, str) else json.dumps(content))
    return scan(CLEAN, extra_files=(), iocs_path=p)


@pytest.mark.parametrize("content", [
    "{not json",
    [],
    {"npm": "x"},
    {"npm": ["a@1.0.0", 5]},
    {"npm": ["@scope/pkg"]},
    {"pypi": ["name"]},
    {"pypi": "x"},
])
def test_iocs_malformed(tmp_path, content):
    findings = scan_iocs(tmp_path, content)
    assert [(f.check_id, f.severity, f.pattern) for f in findings] == [("H5", "low", "iocs_malformed")]


def test_iocs_without_pypi_key(tmp_path):
    p = tmp_path / "iocs.json"
    p.write_text(json.dumps({"npm": [f"{BAD}@0.0.1"]}))
    assert scan(CLEAN, extra_files=(), iocs_path=p) == []
    assert len(highs(scan(MALICIOUS, extra_files=(), iocs_path=p))) == 3  # npm lock + 2 unscoped pnpm keys


@pytest.mark.parametrize("name,scanned", [
    ("REQUIREMENTS.TXT", True), ("requirements-prod.txt", True),
    ("notrequirements.txt", False), ("requirements.in", False),
])
def test_requirements_names(tmp_path, name, scanned):
    findings = scan_text(tmp_path, f"{BAD}==0.0.1\n", name)
    assert (len(highs(findings)) == 1) is scanned


def test_long_requirements_line_still_matched(tmp_path):
    text = f"{BAD}==0.0.1 # " + "a" * 5000 + "\n"
    assert ("H5", "high", "ioc_match", 1) in got(scan_text(tmp_path, text, "requirements.txt"))


def test_iocs_bad_entry_keeps_good_ones(tmp_path):
    content = {"npm": ["bad", 5, f"{BAD}@0.0.1"], "pypi": "x"}
    findings = scan_iocs_over(tmp_path, content, lock_v3({f"node_modules/{BAD}": {"version": "0.0.1"}}))
    assert [(f.severity, f.pattern) for f in findings if f.pattern == "iocs_malformed"] == [("low", "iocs_malformed")]
    assert any(f.pattern == "ioc_match" for f in findings)


def scan_iocs_over(tmp_path, iocs, lock):
    d = tmp_path / "proj"
    d.mkdir()
    (d / "package-lock.json").write_text(lock)
    p = tmp_path / "iocs.json"
    p.write_text(json.dumps(iocs))
    return scan(d, extra_files=(), iocs_path=p)


def test_iocs_path_env_override(tmp_path, monkeypatch):
    p = tmp_path / "custom.json"
    p.write_text(json.dumps({"npm": [f"{BAD}@0.0.1"]}))
    monkeypatch.setenv("DEV_GUARD_IOCS", str(p))
    (tmp_path / "proj").mkdir()
    (tmp_path / "proj" / "package-lock.json").write_text(lock_v3({f"node_modules/{BAD}": {"version": "0.0.1"}}))
    assert any(f.pattern == "ioc_match" for f in scan(tmp_path / "proj", extra_files=()))
