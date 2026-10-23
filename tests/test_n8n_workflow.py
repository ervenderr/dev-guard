import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

WORKFLOW = Path(__file__).parent.parent / "n8n" / "dev-guard-alert.json"

HARNESS = """
const fs = require('fs');
const [code, markCode, payloadsPath] = process.argv.slice(2);
const payloads = JSON.parse(fs.readFileSync(payloadsPath, 'utf8'));
const staticData = {};
const getData = () => staticData;
const results = [];
for (const { body, commit } of payloads) {
  const $input = { first: () => ({ json: { body } }) };
  const out = new Function('$input', '$getWorkflowStaticData', code)($input, getData);
  results.push(out);
  if (commit) {  // the Telegram send succeeded: run the Mark Seen node
    const $ = () => ({ first: () => out[0] });
    new Function('$', '$input', '$getWorkflowStaticData', markCode)($, { all: () => out }, getData);
  }
}
console.log(JSON.stringify(results));
"""


@pytest.fixture(scope="module")
def wf():
    return json.loads(WORKFLOW.read_text())


def _nodes(wf):
    return {n["name"]: n for n in wf["nodes"]}


def test_top_level_and_node_types(wf):
    assert {"name", "nodes", "connections"} <= set(wf)
    nodes = _nodes(wf)
    assert nodes["Webhook"]["type"] == "n8n-nodes-base.webhook"
    assert nodes["Webhook"]["parameters"]["httpMethod"] == "POST"
    assert nodes["Webhook"]["parameters"]["path"]
    assert nodes["Filter New Highs"]["type"] == "n8n-nodes-base.code"
    assert nodes["Any New?"]["type"] == "n8n-nodes-base.if"
    assert nodes["Telegram"]["type"] == "n8n-nodes-base.telegram"
    assert nodes["Mark Seen"]["type"] == "n8n-nodes-base.code"


def test_connections(wf):
    c = wf["connections"]
    names = _nodes(wf)
    assert c["Webhook"]["main"][0][0]["node"] == "Filter New Highs"
    assert c["Filter New Highs"]["main"][0][0]["node"] == "Any New?"
    assert c["Any New?"]["main"][0][0]["node"] == "Telegram"
    assert c["Telegram"]["main"][0][0]["node"] == "Mark Seen"
    for src, v in c.items():
        assert src in names
        for branch in v["main"]:
            for dst in branch:
                assert dst["node"] in names


def test_telegram_credential_by_name_and_placeholder(wf):
    t = _nodes(wf)["Telegram"]
    cred = t["credentials"]
    assert set(cred) == {"telegramApi"}
    assert isinstance(cred["telegramApi"]["name"], str) and cred["telegramApi"]["name"]
    assert set(cred["telegramApi"]) == {"name"}
    assert t["parameters"]["chatId"] == "REPLACE_WITH_CHAT_ID"


def test_no_secrets_in_raw_text():
    raw = WORKFLOW.read_text()
    assert not re.search(r"https?://", raw)
    assert not re.search(r"\d{6,}:[A-Za-z0-9_-]{30,}", raw)
    assert not re.search(r"\b\d{8,}\b", raw)
    assert "DGSECRET" not in raw
    assert not re.search(r'"(apiKey|token)"\s*:\s*"[^"]+"', raw)


def test_code_node_content(wf):
    js = _nodes(wf)["Filter New Highs"]["parameters"]["jsCode"]
    assert "$getWorkflowStaticData" in js and "high" in js
    for field in ("check_id", "file", "line", "pattern"):
        assert field in js


def _f(sev, check, line):
    return {"check_id": check, "severity": sev, "file": f"/p/{check}.json", "line": line, "pattern": "pat" + check}


def _run_node(wf, tmp_path, payloads):
    nodes = _nodes(wf)
    (tmp_path / "h.js").write_text(HARNESS)
    (tmp_path / "p.json").write_text(json.dumps(payloads))
    proc = subprocess.run(
        ["node", str(tmp_path / "h.js"), nodes["Filter New Highs"]["parameters"]["jsCode"],
         nodes["Mark Seen"]["parameters"]["jsCode"], str(tmp_path / "p.json")],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    return [x[0]["json"] for x in json.loads(proc.stdout)]


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_dedupe_behaviour(wf, tmp_path):
    base = [_f("high", "H1", 1), _f("high", "H2", 2), _f("med", "H3", 3), _f("low", "H4", 4)]
    payloads = [
        {"body": {"findings": base, "summary": {}}, "commit": True},
        {"body": {"findings": base, "summary": {}}, "commit": True},
        {"body": {"findings": base + [_f("high", "H5", 5)], "summary": {}}, "commit": True},
        {"body": {}, "commit": True},
    ]
    r = _run_node(wf, tmp_path, payloads)
    assert r[0]["count"] == 2
    assert "H1" in r[0]["text"] and "H2" in r[0]["text"]
    assert "H3" not in r[0]["text"] and "H4" not in r[0]["text"]
    assert r[1]["count"] == 0
    assert r[2]["count"] == 1 and "H5" in r[2]["text"] and "H1" not in r[2]["text"]
    assert r[3]["count"] == 0


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_failed_send_does_not_mark_seen(wf, tmp_path):
    body = {"findings": [_f("high", "H1", 1)], "summary": {}}
    payloads = [{"body": body, "commit": False}, {"body": body, "commit": True}, {"body": body, "commit": True}]
    r = _run_node(wf, tmp_path, payloads)
    assert [x["count"] for x in r] == [1, 1, 0]


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_message_is_capped_and_overflow_stays_unseen(wf, tmp_path):
    body = {"findings": [_f("high", f"H{i:03d}", i) for i in range(50)], "summary": {}}
    r = _run_node(wf, tmp_path, [{"body": body, "commit": True}] * 4)
    assert all(len(x["text"]) <= 4000 for x in r)
    assert r[0]["count"] == 20 and r[1]["count"] == 20 and r[2]["count"] == 10 and r[3]["count"] == 0


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_finding_that_disappears_and_returns_realerts(wf, tmp_path):
    h1 = {"findings": [_f("high", "H1", 1)], "summary": {}}
    gone = {"findings": [], "summary": {}}
    r = _run_node(wf, tmp_path, [{"body": b, "commit": True} for b in (h1, h1, gone, h1)])
    assert [x["count"] for x in r] == [1, 0, 0, 1]


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_pipe_in_fields_does_not_collide(wf, tmp_path):
    a = {"check_id": "H1", "severity": "high", "file": "a|b", "line": 1, "pattern": "c"}
    b = {"check_id": "H1", "severity": "high", "file": "a", "line": "b|1", "pattern": "c"}
    r = _run_node(wf, tmp_path, [{"body": {"findings": [a], "summary": {}}, "commit": True},
                                 {"body": {"findings": [a, b], "summary": {}}, "commit": True}])
    assert [x["count"] for x in r] == [1, 1]
