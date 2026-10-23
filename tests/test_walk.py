import os
from pathlib import Path

import pytest

from dev_guard.checks import scan
from dev_guard.patterns import MAX_FILE_BYTES

MAL = (Path(__file__).parent / "fixtures" / "h1" / "malicious" / ".claude" / "settings.json").read_text()


def put(path: Path, text: str = MAL) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def run(root):
    return scan(root, extra_files=())


def test_control_finds_in_plain_dir(tmp_path):
    put(tmp_path / "root" / "app" / ".claude" / "settings.json")
    assert run(tmp_path / "root")


def test_node_modules_skipped(tmp_path):
    put(tmp_path / "node_modules" / "pkg" / ".claude" / "settings.json")
    assert run(tmp_path) == []


def test_git_skipped(tmp_path):
    put(tmp_path / ".git" / ".claude" / "settings.json")
    assert run(tmp_path) == []


def test_oversize_skipped(tmp_path):
    p = put(tmp_path / "root" / ".claude" / "settings.json", MAL + " " * MAX_FILE_BYTES)
    assert p.stat().st_size > MAX_FILE_BYTES
    assert run(tmp_path / "root") == []


def test_symlinked_dir_skipped(tmp_path):
    put(tmp_path / "outside" / ".claude" / "settings.json")
    (tmp_path / "root").mkdir()
    os.symlink(tmp_path / "outside", tmp_path / "root" / "link")
    assert run(tmp_path / "root") == []


def test_symlinked_file_skipped(tmp_path):
    target = put(tmp_path / "outside" / "evil.json")
    link = tmp_path / "root" / ".claude" / "settings.json"
    link.parent.mkdir(parents=True)
    os.symlink(target, link)
    assert run(tmp_path / "root") == []


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file modes")
def test_unreadable_skipped(tmp_path):
    p = put(tmp_path / "root" / ".claude" / "settings.json")
    p.chmod(0o000)
    try:
        assert run(tmp_path / "root") == []
    finally:
        p.chmod(0o644)


@pytest.mark.parametrize(
    "payload",
    ['{"hooks": ' + "[" * 100000, '{"hooks": {"x": ' + "9" * 5000 + "}}"],
    ids=["deep_nesting", "huge_int"],
)
def test_hostile_json_does_not_raise(tmp_path, payload):
    put(tmp_path / "root" / ".claude" / "settings.json", payload)
    assert [(f.severity, f.pattern) for f in run(tmp_path / "root")] == [("low", "malformed_json")]
