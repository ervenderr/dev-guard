import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

if not (shutil.which("bash") and shutil.which("curl")):
    pytest.skip("bash and curl required", allow_module_level=True)

REPO_ROOT = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / "fixtures" / "h1"
SCRIPT = "scripts/run-alert.sh"


class _Receiver:
    def __init__(self):
        self.requests = []
        self.status = 200
        self.token = "DGURL_" + uuid.uuid4().hex
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                outer.requests.append({
                    "path": self.path,
                    "headers": dict(self.headers),
                    "body": self.rfile.read(n),
                })
                self.send_response(outer.status)
                self.end_headers()

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/webhook/{self.token}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


@pytest.fixture
def receiver():
    r = _Receiver()
    yield r
    r.server.shutdown()
    r.server.server_close()


def _run(env_extra, *scan_args):
    env = {k: v for k, v in os.environ.items()
           if k not in ("DEV_GUARD_IOCS", "DEV_GUARD_WEBHOOK_URL")}
    env["DEV_GUARD_PYTHON"] = sys.executable
    env.update(env_extra)
    return subprocess.run(
        ["bash", SCRIPT, *map(str, scan_args)],
        capture_output=True, text=True, cwd=REPO_ROOT, env=env, timeout=60,
    )


def _copy(name, tmp_path):
    dst = tmp_path / name
    shutil.copytree(FIXTURES / name, dst)
    return dst


def _no_leak(p, url, token):
    out = p.stdout + p.stderr
    assert token not in out and url not in out


def test_happy_path_posts_findings_and_summary_only(receiver, tmp_path):
    p = _run({"DEV_GUARD_WEBHOOK_URL": receiver.url}, _copy("malicious", tmp_path))
    assert p.returncode == 0, p.stderr
    assert len(receiver.requests) == 1
    req = receiver.requests[0]
    assert req["path"].endswith(receiver.token)
    assert req["headers"]["Content-Type"] == "application/json"
    body = json.loads(req["body"])
    assert set(body) == {"findings", "summary"}
    assert body["summary"]["high"] >= 1
    _no_leak(p, receiver.url, receiver.token)


def test_clean_still_posts(receiver, tmp_path):
    p = _run({"DEV_GUARD_WEBHOOK_URL": receiver.url}, _copy("clean", tmp_path))
    assert p.returncode == 0, p.stderr
    assert len(receiver.requests) == 1
    assert json.loads(receiver.requests[0]["body"])["findings"] == []


def test_unset_variable_fails_without_post(receiver, tmp_path):
    p = _run({}, _copy("clean", tmp_path))
    assert p.returncode != 0
    assert "DEV_GUARD_WEBHOOK_URL" in p.stderr
    assert receiver.requests == []


def test_bad_scan_path_no_post(receiver, tmp_path):
    p = _run({"DEV_GUARD_WEBHOOK_URL": receiver.url}, tmp_path / "nope")
    assert p.returncode != 0
    assert receiver.requests == []
    _no_leak(p, receiver.url, receiver.token)


def test_http_500_fails(receiver, tmp_path):
    receiver.status = 500
    p = _run({"DEV_GUARD_WEBHOOK_URL": receiver.url}, _copy("clean", tmp_path))
    assert p.returncode != 0
    _no_leak(p, receiver.url, receiver.token)


def test_unreachable_fails_without_leak(tmp_path):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    token = "DGURL_" + uuid.uuid4().hex
    url = f"http://127.0.0.1:{port}/webhook/{token}"
    p = _run({"DEV_GUARD_WEBHOOK_URL": url}, _copy("clean", tmp_path))
    assert p.returncode != 0
    _no_leak(p, url, token)


def test_secret_marker_not_in_post_body(receiver, tmp_path):
    d = _copy("malicious", tmp_path)
    marker = "DGSECRET_" + uuid.uuid4().hex
    f = d / ".claude" / "settings.json"
    data = json.loads(f.read_text())
    data["hooks"]["PostToolUse"][0]["hooks"][0]["command"] += " " + marker
    f.write_text(json.dumps(data))
    p = _run({"DEV_GUARD_WEBHOOK_URL": receiver.url}, d)
    assert p.returncode == 0, p.stderr
    assert len(receiver.requests) == 1
    assert marker.encode() not in receiver.requests[0]["body"]
