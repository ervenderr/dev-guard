import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

from dev_guard.cli import main

REPO_ROOT = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / "fixtures"
CHECKS = ["h1", "h2", "h3", "h4", "h5"]
PERF_BUDGET_S = 30.0  # SPEC constraint for ~/Projects; tight bounds flake on loaded CI


def _run(*args: str) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k != "DEV_GUARD_IOCS"}
    return subprocess.run(
        [sys.executable, "-m", "dev_guard", *args],
        capture_output=True, text=True, cwd=REPO_ROOT, env=env, timeout=120,
    )


def _high_ids(proc) -> set[str]:
    return {f["check_id"] for f in json.loads(proc.stdout)["findings"] if f["severity"] == "high"}


def test_clean_exits_zero():
    p = _run(*[str(FIXTURES / h / "clean") for h in CHECKS])
    assert p.returncode == 0 and p.stdout == "No findings.\n"


def test_all_fixtures_exit_one_with_every_check():
    table = _run(str(FIXTURES))
    assert table.returncode == 1
    as_json = _run("--json", str(FIXTURES))
    assert as_json.returncode == 1
    assert {"H1", "H2", "H3", "H4", "H5"} <= _high_ids(as_json)


def _edit_json(path: Path, mutate) -> None:
    data = json.loads(path.read_text())
    mutate(data)
    path.write_text(json.dumps(data))


def _plant(tree: Path, marker: str) -> None:
    def h1(d):
        d["hooks"]["PostToolUse"][0]["hooks"][0]["command"] += f" # {marker}"

    def h2(d):
        d["tasks"][0]["command"] += f" # {marker}"

    def h3(d):
        d["scripts"]["postinstall"] += f" # {marker}"

    def h5(d):
        d["packages"][""]["name"] = marker

    _edit_json(tree / "h1" / ".claude" / "settings.json", h1)
    _edit_json(tree / "h2" / ".vscode" / "tasks.json", h2)
    _edit_json(tree / "h3" / "package.json", h3)
    wf = tree / "h4" / ".github" / "workflows" / "release.yaml"
    wf.write_text(wf.read_text().replace("FAKE_SECRET_TOKEN_H4", marker))
    _edit_json(tree / "h5" / "package-lock.json", h5)
    with open(tree / "h5" / "requirements-dev.txt", "a") as fh:
        fh.write(f"# {marker}\n")


def test_no_secret_marker_in_output(tmp_path):
    marker = "DGSECRET_" + uuid.uuid4().hex
    for h in CHECKS:
        shutil.copytree(FIXTURES / h / "malicious", tmp_path / h)
    _plant(tmp_path, marker)
    as_json = _run("--json", str(tmp_path))
    assert {"H1", "H2", "H3", "H4", "H5"} <= _high_ids(as_json)
    for proc in (as_json, _run(str(tmp_path))):
        assert marker not in proc.stdout and marker not in proc.stderr


def test_perf_5k_files(tmp_path):
    clean_pkg = (FIXTURES / "h3" / "clean" / "package.json").read_text()
    clean_cfg = (FIXTURES / "h1" / "clean" / ".claude" / "settings.json").read_text()
    for i in range(5000):
        d = tmp_path / f"a{i % 20}" / f"b{i % 50}" / f"c{i}"
        d.mkdir(parents=True)
        if i < 50:
            (d / "package.json").write_text(clean_pkg)
        elif i < 100:
            (d / ".claude").mkdir()
            (d / ".claude" / "settings.json").write_text(clean_cfg)
        else:
            (d / "f.txt" if i % 2 else d / "f.js").write_text("x = 1\n")
    start = time.perf_counter()
    assert main([str(tmp_path)]) == 0
    assert time.perf_counter() - start < PERF_BUDGET_S
