from pathlib import Path

import pytest

from dev_guard.checks import scan

FIXTURES = Path(__file__).parent / "fixtures"
CHECKS = [("h1", "H1"), ("h2", "H2"), ("h3", "H3"), ("h4", "H4"), ("h5", "H5")]


@pytest.mark.parametrize("directory,check_id", CHECKS)
def test_clean_fixture_has_no_findings(directory, check_id):
    assert scan(FIXTURES / directory / "clean", extra_files=()) == []


@pytest.mark.parametrize("directory,check_id", CHECKS)
def test_malicious_fixture_detected(directory, check_id):
    findings = scan(FIXTURES / directory / "malicious", extra_files=())
    assert any(f.check_id == check_id and f.severity == "high" for f in findings)


def test_every_fixture_dir_is_in_matrix():
    on_disk = {p.name for p in FIXTURES.glob("h*") if p.is_dir()}
    assert on_disk == {d for d, _ in CHECKS}
