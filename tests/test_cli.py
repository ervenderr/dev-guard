import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from dev_guard import cli
from dev_guard.checks import Finding
from dev_guard.cli import format_table, main, sanitize

FIXTURES = Path(__file__).parent / "fixtures"
REPO_ROOT = Path(__file__).parent.parent
CHECKS = ["h1", "h2", "h3", "h4", "h5"]


def _dirs(kind: str) -> list[str]:
    return [str(FIXTURES / h / kind) for h in CHECKS]


def test_single_malicious_table(capsys):
    assert main([str(FIXTURES / "h1" / "malicious")]) == 1
    out = capsys.readouterr().out
    header = out.splitlines()[0]
    for col in ("SEV", "ID", "FILE:LINE", "PATTERN"):
        assert col in header
    assert any(
        "high" in ln and "H1" in ln and "settings.json:" in ln for ln in out.splitlines()
    )


def test_all_malicious_has_every_id(capsys):
    assert main(_dirs("malicious")) == 1
    out = capsys.readouterr().out
    for cid in ("H1", "H2", "H3", "H4", "H5"):
        assert cid in out


def test_all_clean(capsys):
    assert main(_dirs("clean")) == 0
    assert capsys.readouterr().out == "No findings.\n"


def test_sort_order_and_summary():
    fs = [
        Finding("H2", "low", "b", 1, "p"),
        Finding("H1", "med", "a", 1, "p"),
        Finding("H1", "high", "z", 9, "p"),
        Finding("H1", "high", "z", 2, "p"),
    ]
    from dev_guard.cli import run_scan  # noqa: F401  (sorting lives in run_scan)

    lines = format_table(sorted(fs, key=lambda f: (cli.SEVERITY_ORDER[f.severity], f.file, f.line))).splitlines()
    assert lines[-1] == "2 high, 1 med, 1 low"
    assert [ln.split(" | ")[0].strip() for ln in lines[1:-1]] == ["high", "high", "med", "low"]


def test_run_scan_sorted_and_deduped():
    d = Path(_dirs("malicious")[0])
    once = cli.run_scan([d], ())
    twice = cli.run_scan([d, d], ())
    assert once == twice and len(set(once)) == len(once)
    keys = [cli.SEVERITY_ORDER[f.severity] for f in once]
    assert keys == sorted(keys)


def test_missing_path(capsys):
    assert main(["/nonexistent/xyz"]) == 2
    cap = capsys.readouterr()
    assert cap.out == "" and "/nonexistent/xyz" in cap.err


def test_file_path(capsys):
    f = FIXTURES / "h1" / "malicious"
    f = next(p for p in f.rglob("*") if p.is_file())
    assert main([str(f)]) == 2
    assert "not a directory" in capsys.readouterr().err


def test_duplicate_path_rows_once(capsys):
    d = _dirs("malicious")[0]
    main([d])
    single = capsys.readouterr().out
    main([d, d])
    assert capsys.readouterr().out == single


def test_sanitize_control_chars():
    f = Finding("H1", "high", "a\nb\x1b[31mc\rd\te", 3, "p")
    out = format_table([f])
    assert "\x1b" not in out and "\r" not in out and "\t" not in out
    assert len(out.splitlines()) == 3  # header, row, summary


def test_sanitize_backslash_unambiguous():
    assert sanitize("a\\x1bb") == "a\\\\x1bb"
    assert sanitize("a\x1bb") == "a\\x1bb"
    assert sanitize("a\\x1bb") != sanitize("a\x1bb")


def test_explicit_path_skips_home_config(monkeypatch):
    seen = {}

    def fake_scan(root, extra_files=(), **kw):
        seen.setdefault("extras", []).append(tuple(extra_files))
        return []

    monkeypatch.setattr(cli, "scan", fake_scan)
    assert main(_dirs("clean")[:2]) == 0
    assert seen["extras"] == [(), ()]


def test_internal_error(monkeypatch, capsys):
    def boom(*a, **k):
        raise RuntimeError("DGSECRET_internal")

    monkeypatch.setattr(cli, "run_scan", boom)
    assert main([_dirs("clean")[0]]) == 70
    cap = capsys.readouterr()
    assert cap.out == ""
    assert len(cap.err.strip().splitlines()) == 1
    assert "internal error" in cap.err and "RuntimeError" in cap.err
    assert "DGSECRET_internal" not in cap.err and "Traceback" not in cap.err


def test_broken_pipe():
    proc = subprocess.Popen(
        [sys.executable, "-m", "dev_guard", str(FIXTURES)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=REPO_ROOT,
    )
    proc.stdout.close()
    err = proc.stderr.read().decode()
    proc.stderr.close()
    assert proc.wait() == 1
    assert "Traceback" not in err and "BrokenPipeError" not in err


def _json_run(capsys, argv):
    code = main(argv)
    return code, json.loads(capsys.readouterr().out)


def test_json_malicious(capsys):
    code, d = _json_run(capsys, ["--json", _dirs("malicious")[0]])
    assert code == 1 and set(d) == {"findings", "summary"}
    assert d["findings"]
    for f in d["findings"]:
        assert set(f) == {"check_id", "severity", "file", "line", "pattern"}
    for sev in ("high", "med", "low"):
        assert d["summary"][sev] == sum(f["severity"] == sev for f in d["findings"])


def test_json_clean(capsys):
    code = main(["--json", *_dirs("clean")])
    assert code == 0
    assert capsys.readouterr().out == (
        '{"findings": [], "summary": {"high": 0, "med": 0, "low": 0}}\n'
    )


def test_json_hostile_filename(tmp_path, capsys):
    d = tmp_path / 'evil"\\\n\x1b[2Jé'
    try:
        d.mkdir()
    except OSError:
        pytest.skip("filesystem rejects name")
    shutil.copy(FIXTURES / "h3" / "malicious" / "package.json", d / "package.json")
    code, data = _json_run(capsys, ["--json", str(tmp_path)])
    assert code == 1
    assert str(d / "package.json") in [f["file"] for f in data["findings"]]
    main([str(tmp_path)])
    assert "\x1b" not in capsys.readouterr().out


def test_version(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
    assert capsys.readouterr().out == "dev-guard 0.1.0\n"


def _home_cfg(tmp_path):
    cfg = tmp_path / ".claude" / "settings.json"
    cfg.parent.mkdir()
    shutil.copy(FIXTURES / "h1" / "malicious" / ".claude" / "settings.json", cfg)
    return cfg


def test_default_roots_and_home_config(tmp_path, monkeypatch, capsys):
    cfg = _home_cfg(tmp_path)
    monkeypatch.setattr(cli, "DEFAULT_SCAN_ROOTS", (FIXTURES / "h3" / "malicious",))
    monkeypatch.setattr(cli, "HOME_CONFIG_FILES", (cfg,))
    code, d = _json_run(capsys, ["--json"])
    assert code == 1
    assert any(f["check_id"] == "H1" and f["severity"] == "high" and f["file"] == str(cfg) for f in d["findings"])
    assert any(f["check_id"] == "H3" for f in d["findings"])


def test_explicit_path_ignores_home_config(tmp_path, monkeypatch, capsys):
    cfg = _home_cfg(tmp_path)
    monkeypatch.setattr(cli, "HOME_CONFIG_FILES", (cfg,))
    _, d = _json_run(capsys, ["--json", _dirs("malicious")[2]])
    assert all(f["file"] != str(cfg) for f in d["findings"])


def test_default_root_missing(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "DEFAULT_SCAN_ROOTS", (tmp_path / "nope",))
    assert main([]) == 2
    assert "nope" in capsys.readouterr().err


def test_unknown_flag():
    with pytest.raises(SystemExit) as e:
        main(["--fix"])
    assert e.value.code == 2
