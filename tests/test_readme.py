import re
from pathlib import Path

from dev_guard.cli import build_parser

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
ALLOWED_HOSTS = {"n8n.io", "docs.n8n.io", "github.com", "core.telegram.org", "t.me"}
CRON_RE = re.compile(r"^\s*(\S+\s+){5}\S*run-alert\.sh", re.M)


def text() -> str:
    assert README.exists(), "README.md missing"
    return README.read_text()


def test_required_strings():
    t = text()
    for s in ["pip install -e .", "dev-guard", "--json", "--exclude", "--version",
              "DEV_GUARD_IOCS", "DEV_GUARD_WEBHOOK_URL", "DEV_GUARD_PYTHON",
              "scripts/run-alert.sh", "n8n/dev-guard-alert.json", "Telegram", "crontab"]:
        assert s in text(), s


def test_exit_codes():
    t = text()
    for code, word in [("0", "clean|no high"), ("1", "high"), ("2", "usage|path"), ("70", "internal")]:
        assert re.search(rf"^\W*{code}\W.*({word})", t, re.M | re.I), code


def test_every_cli_flag_documented():
    t = text()
    for action in build_parser()._actions:
        for opt in action.option_strings:
            if opt not in ("-h", "--help"):
                assert opt in t, opt


def test_referenced_paths_exist():
    refs = re.findall(r"`((?:scripts|n8n)/[^`\s]+)`", text())
    assert refs
    for r in refs:
        assert (ROOT / r).exists(), r


def test_cron_sample_uses_placeholders():
    t = text()
    m = CRON_RE.search(t)
    assert m, "no cron sample line"
    line = t[m.start():t.index("\n", m.start())]
    assert "/path/to/dev-guard" in line
    assert "/Users/" not in t


def test_no_secrets():
    t = text()
    for url in re.findall(r"https?://([^/\s)>`]+)(\S*)", t):
        assert url[0] in ALLOWED_HOSTS, url
        assert "/webhook/" not in url[1]
    assert not re.search(r"\d{6,}:[A-Za-z0-9_-]{30,}", t)


def test_privacy_and_dedupe_notes():
    t = text().lower()
    assert "never file contents" in t
    assert "production" in t and "static data" in t
    assert "indefinitely" in t
    assert "typeversion" in t or "confirm" in t
