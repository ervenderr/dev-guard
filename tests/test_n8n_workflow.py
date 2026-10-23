import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

WORKFLOW = Path(__file__).parent.parent / "n8n" / "dev-guard-alert.json"

HARNESS = """
const fs = require('fs');
const [code, payloadsPath] = process.argv.slice(2);
const payloads = JSON.parse(fs.readFileSync(payloadsPath, 'utf8'));
const staticData = {};
const results = [];
for (const body of payloads) {
  const $input = { first: () => ({ json: { body } }) };
  const $getWorkflowStaticData = () => staticData;
  const fn = new Function('$input', '$getWorkflowStaticData', code);
  results.push(fn($input, $getWorkflowStaticData));
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


def test_connections(wf):
    c = wf["connections"]
    names = _nodes(wf)
    assert c["Webhook"]["main"][0][0]["node"] == "Filter New Highs"
    assert c["Filter New Highs"]["main"][0][0]["node"] == "Any New?"
    assert c["Any New?"]["main"][0][0]["node"] == "Telegram"
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


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_dedupe_behaviour(wf, tmp_path):
    js = _nodes(wf)["Filter New Highs"]["parameters"]["jsCode"]
    base = [_f("high", "H1", 1), _f("high", "H2", 2), _f("med", "H3", 3), _f("low", "H4", 4)]
    payloads = [
        {"findings": base, "summary": {}},
        {"findings": base, "summary": {}},
        {"findings": base + [_f("high", "H5", 5)], "summary": {}},
        {},
    ]
    (tmp_path / "h.js").write_text(HARNESS)
    (tmp_path / "p.json").write_text(json.dumps(payloads))
    proc = subprocess.run(
        ["node", str(tmp_path / "h.js"), js, str(tmp_path / "p.json")],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    r = [x[0]["json"] for x in json.loads(proc.stdout)]
    assert r[0]["count"] == 2
    assert "H1" in r[0]["text"] and "H2" in r[0]["text"]
    assert "H3" not in r[0]["text"] and "H4" not in r[0]["text"]
    assert r[1]["count"] == 0
    assert r[2]["count"] == 1 and "H5" in r[2]["text"] and "H1" not in r[2]["text"]
    assert r[3]["count"] == 0
