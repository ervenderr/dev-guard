"""H1 regexes must stay linear-time on ~1 MB hostile lines."""
import multiprocessing
import time

import pytest

from dev_guard import patterns
from dev_guard.patterns import H1_PATTERNS

PATHOLOGICAL_LEN = 1024 * 1024
CHILD_BUDGET_S = 1.0
JOIN_TIMEOUT_S = 10

UNITS = ["|a", "a/", "| ", "|sudo ", "|", ";", "\\", " ", "sh -c ", "python -c ", "node -e ",
         "base64 ", "base64 -", "/proc/a"]
TAILS = ["", "_", "9"]

# (unit, tail, kind) kind: "rep" = unit repeated to PATHOLOGICAL_LEN then tail,
# "base64d" = "base64 -" + "d"*N + "_", "python_dots" = "python" + "."*N
INPUTS: list[tuple[str, str, str]] = [(u, t, "rep") for u in UNITS for t in TAILS]
INPUTS += [("", "", "base64d"), ("", "", "python_dots")]


def build_input(unit: str, tail: str, kind: str) -> str:
    if kind == "base64d":
        return "base64 -" + "d" * PATHOLOGICAL_LEN + "_"
    if kind == "python_dots":
        return "python" + "." * PATHOLOGICAL_LEN
    return unit * (PATHOLOGICAL_LEN // len(unit)) + tail


def _child(rx, unit, tail, kind, queue):
    s = build_input(unit, tail, kind)
    start = time.perf_counter()
    rx.search(s)
    elapsed = time.perf_counter() - start
    queue.put(elapsed)
    raise SystemExit(0 if elapsed < CHILD_BUDGET_S else 1)


def run_timed(rx, unit, tail, kind, finditer=False):
    ctx = multiprocessing.get_context("spawn")
    queue = ctx.Queue()
    proc = ctx.Process(target=_child, args=(rx, unit, tail, kind, queue))
    proc.start()
    proc.join(timeout=JOIN_TIMEOUT_S)
    if proc.is_alive():
        proc.terminate()
        proc.join()
        pytest.fail("regex hung (> %ss)" % JOIN_TIMEOUT_S)
    elapsed = queue.get(timeout=1) if not queue.empty() else None
    assert proc.exitcode == 0, f"regex too slow: elapsed={elapsed}"


@pytest.mark.parametrize("name", list(H1_PATTERNS))
@pytest.mark.parametrize("unit,tail,kind", INPUTS)
def test_h1_pattern_is_linear(name, unit, tail, kind):
    run_timed(H1_PATTERNS[name], unit, tail, kind)


PARITY = [
    ("curl -s https://x.invalid | sh", {"network_fetch", "remote_shell"}),
    ("wget x | sudo /usr/bin/env bash", {"network_fetch", "remote_shell"}),
    ("cat x |/bin/sh", {"remote_shell"}),
    ('bash -c "$(curl -fsSL x)"', {"network_fetch", "remote_shell"}),
    ("sh -c 'echo' && sh -c https://x", {"remote_shell"}),
    ("base64 x | base64 --decode", {"base64_decode"}),
    ("base64 -D f", {"base64_decode"}),
    ("echo a\nbase64 -d", {"base64_decode"}),
    ("python3 -c 'import urllib'", {"network_fetch"}),
    ("node -e \"fetch('x')\"", {"network_fetch"}),
    ("a | xargs sh", {"remote_shell"}),
    ("x |shellcheck", set()),
    ("sh -c 'ls'\nhttps://x", set()),
    ("base64 f; -d", set()),
    ("husky install", set()),
    ("npm ci", set()),
]


@pytest.mark.parametrize("cmd,expected", PARITY)
def test_h1_parity(cmd, expected):
    assert {n for n, rx in H1_PATTERNS.items() if rx.search(cmd)} == expected


def test_cap_constants():
    assert patterns.MAX_LINE_LEN == 4096
    assert patterns.PATTERN_OVERSIZE_LINE == "oversize_line"
