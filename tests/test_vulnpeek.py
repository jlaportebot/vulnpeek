"""Tests for vulnpeek."""

from vulnpeek.requirements import parse_requirements
from vulnpeek.osv import _parse_vuln


def test_parse_requirements_pinned():
    reqs = parse_requirements("requests==2.28.0\nflask>=1.0\nnumpy==1.24.0")
    assert len(reqs) == 3
    assert reqs[0].name == "requests"
    assert reqs[0].version == "2.28.0"
    assert reqs[1].name == "flask"
    assert reqs[1].version is None  # >= is not pinned
    assert reqs[2].name == "numpy"
    assert reqs[2].version == "1.24.0"


def test_parse_requirements_extras():
    reqs = parse_requirements("package[extra1,extra2]==1.0.0")
    assert len(reqs) == 1
    assert reqs[0].name == "package"
    assert reqs[0].version == "1.0.0"


def test_parse_requirements_comments():
    reqs = parse_requirements("# comment\nrequests==2.0.0  # inline comment")
    assert len(reqs) == 1
    assert reqs[0].name == "requests"
    assert reqs[0].version == "2.0.0"


def test_parse_requirements_empty():
    reqs = parse_requirements("")
    assert len(reqs) == 0


def test_parse_requirements_flags():
    text = "-r base.txt\n--index-url https://example.com\nrequests==1.0.0"
    reqs = parse_requirements(text)
    assert len(reqs) == 1
    assert reqs[0].name == "requests"


def test_parse_vuln_basic():
    data = {
        "id": "GHSA-xxxx-yyyy",
        "summary": "A test vulnerability",
        "severity": [{"score": "HIGH"}],
        "affected": [],
        "aliases": ["CVE-2024-0001"],
    }
    v = _parse_vuln(data)
    assert v.id == "GHSA-xxxx-yyyy"
    assert v.summary == "A test vulnerability"
    assert v.severity == "HIGH"
    assert v.aliases == ["CVE-2024-0001"]
    assert v.url == "https://osv.dev/vulnerability/GHSA-xxxx-yyyy"


def test_parse_vuln_with_fixes():
    data = {
        "id": "OSV-2024-1",
        "summary": "Something bad",
        "affected": [
            {
                "package": {"name": "pip:requests"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "2.29.0"},
                        ],
                    }
                ],
            }
        ],
    }
    v = _parse_vuln(data)
    assert v.fixed_versions == ["2.29.0"]


def test_severity_rank():
    from vulnpeek.osv import Vulnerability

    v = Vulnerability(id="x", severity="CRITICAL")
    assert v.severity_rank == 0
    v = Vulnerability(id="x", severity="LOW")
    assert v.severity_rank == 3


def test_cvss_base_score_network_high_impact():
    from vulnpeek.osv import _cvss_base_score, _score_to_severity

    # Network, low complexity, no priv, no user interaction, high C/I/A
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    score = _cvss_base_score(vector)
    assert score is not None
    assert score >= 9.0  # Should be CRITICAL
    assert _score_to_severity(score) == "CRITICAL"


def test_cvss_base_score_local_low_impact():
    from vulnpeek.osv import _cvss_base_score, _score_to_severity

    # Physical, high complexity, high priv, required UI, low C, no I/A
    vector = "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
    score = _cvss_base_score(vector)
    assert score is not None
    assert score < 4.0  # Should be LOW
    assert _score_to_severity(score) == "LOW"


def test_cvss_base_score_medium():
    from vulnpeek.osv import _cvss_base_score, _score_to_severity

    # Adjacent, low complexity, low priv, required UI, high C, no I/A
    vector = "CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N"
    score = _cvss_base_score(vector)
    assert score is not None
    assert 4.0 <= score < 7.0  # Should be MEDIUM
    assert _score_to_severity(score) == "MEDIUM"


def test_extract_severity_from_cvss_vector():
    from vulnpeek.osv import _extract_severity

    data = {
        "id": "GHSA-test",
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        ],
        "affected": [],
    }
    assert _extract_severity(data) == "CRITICAL"


def test_extract_severity_from_numeric_score():
    from vulnpeek.osv import _extract_severity

    data = {
        "id": "TEST",
        "severity": [{"type": "CVSS_V3", "score": "7.5"}],
        "affected": [],
    }
    assert _extract_severity(data) == "HIGH"


def test_extract_severity_unknown_when_no_data():
    from vulnpeek.osv import _extract_severity

    data = {"id": "TEST", "affected": []}
    assert _extract_severity(data) == "UNKNOWN"


def test_parse_pyproject_toml_pep621():
    from vulnpeek.requirements import parse_pyproject_toml

    content = """
[project]
name = "my-project"
version = "1.0.0"
dependencies = [
    "requests==2.28.0",
    "click>=8.0,<9.0",
    "rich==13.0.0",
]
"""
    reqs = parse_pyproject_toml(content)
    assert len(reqs) == 3
    assert reqs[0].name == "requests"
    assert reqs[0].version == "2.28.0"
    assert reqs[1].name == "click"
    assert reqs[1].version is None  # not pinned
    assert reqs[2].name == "rich"
    assert reqs[2].version == "13.0.0"


def test_parse_pyproject_toml_optional_dependencies():
    from vulnpeek.requirements import parse_pyproject_toml

    content = """
[project]
name = "my-project"
dependencies = ["requests==2.28.0"]

[project.optional-dependencies]
dev = ["pytest==7.0.0", "ruff>=0.1"]
test = ["pytest-cov==4.0.0"]
"""
    reqs = parse_pyproject_toml(content, include_optional=["dev", "test"])
    assert len(reqs) == 4
    names = {r.name for r in reqs}
    assert names == {"requests", "pytest", "ruff", "pytest-cov"}
    # Check versions
    req_map = {r.name: r.version for r in reqs}
    assert req_map["requests"] == "2.28.0"
    assert req_map["pytest"] == "7.0.0"
    assert req_map["pytest-cov"] == "4.0.0"
    assert req_map["ruff"] is None


def test_parse_pyproject_toml_no_project():
    from vulnpeek.requirements import parse_pyproject_toml

    content = """
[build-system]
requires = ["setuptools>=61.0"]
"""
    reqs = parse_pyproject_toml(content)
    assert len(reqs) == 0


def test_parse_uv_lock():
    from vulnpeek.requirements import parse_uv_lock

    content = """
[[package]]
name = "requests"
version = "2.28.0"
source = "pypi"

[[package]]
name = "click"
version = "8.1.0"
source = "pypi"

[[package]]
name = "certifi"
version = "2023.01.01"
source = "registry+https://github.com/pypa/pypi"
"""
    reqs = parse_uv_lock(content)
    assert len(reqs) == 3
    assert reqs[0].name == "requests"
    assert reqs[0].version == "2.28.0"
    assert reqs[1].name == "click"
    assert reqs[1].version == "8.1.0"
    assert reqs[2].name == "certifi"
    assert reqs[2].version == "2023.01.01"
