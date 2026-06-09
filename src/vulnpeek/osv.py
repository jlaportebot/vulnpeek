"""OSV API client for querying known vulnerabilities."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import httpx

OSV_API = "https://api.osv.dev/v1"


@dataclass
class Vulnerability:
    """A single vulnerability report from OSV."""

    id: str
    summary: str = ""
    severity: str = "UNKNOWN"
    affected_versions: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    url: str = ""
    aliases: list[str] = field(default_factory=list)

    @property
    def severity_rank(self) -> int:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        return order.get(self.severity, 4)


@dataclass
class PackageResult:
    """Scan result for a single package."""

    name: str
    version: str
    vulnerabilities: list[Vulnerability] = field(default_factory=list)

    @property
    def is_vulnerable(self) -> bool:
        return len(self.vulnerabilities) > 0


def _cvss_base_score(vector: str) -> float | None:
    """Compute a rough CVSS v3.1 base score from a vector string.

    This is a simplified calculation that approximates the official
    CVSS formula. It's accurate enough for severity classification
    (CRITICAL/HIGH/MEDIUM/LOW) without pulling in a heavy dependency.
    """
    parts = {}
    for m in re.finditer(r"([A-Z]+):([A-Za-z]+)", vector):
        parts[m.group(1)] = m.group(2)

    # Attack Vector
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}.get(parts.get("AV", ""), 0.85)
    # Attack Complexity
    ac = {"L": 0.77, "H": 0.44}.get(parts.get("AC", ""), 0.44)
    # Privileges Required (depends on Scope, use Unchanged default)
    sc = parts.get("S", "U")
    pr_map = {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.50},
    }
    pr = pr_map.get(sc, pr_map["U"]).get(parts.get("PR", ""), 0.85)
    # User Interaction
    ui = {"N": 0.85, "R": 0.62}.get(parts.get("UI", ""), 0.62)
    # Scope
    scope_changed = sc == "C"

    # Impact subscores
    c_val = {"H": 0.56, "L": 0.22, "N": 0.0}.get(parts.get("C", ""), 0.0)
    i_val = {"H": 0.56, "L": 0.22, "N": 0.0}.get(parts.get("I", ""), 0.0)
    a_val = {"H": 0.56, "L": 0.22, "N": 0.0}.get(parts.get("A", ""), 0.0)

    iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))

    if scope_changed:
        impact = 7.52 * (iss - 0.027) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0

    if scope_changed:
        score = min(1.08 * (impact + exploitability), 10.0)
    else:
        score = min(impact + exploitability, 10.0)

    # Roundup to 1 decimal (CVSS spec "Roundup" function)
    score = (score * 10 + 0.5) / 10  # ceiling to 1 decimal
    return round(score, 1)


def _score_to_severity(score: float) -> str:
    """Map CVSS score to severity label."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"


def _extract_severity(vuln_data: dict[str, Any]) -> str:
    """Extract the worst severity from a vulnerability entry.

    OSV entries may provide severity as:
    - CVSS vector strings (e.g. "CVSS:3.1/AV:N/AC:L/...")
    - Numeric CVSS base scores
    - Direct severity labels
    - GitHub Advisory database_specific severity
    """
    severity_values = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    best = "UNKNOWN"
    best_rank = 4

    # Check top-level severity array
    for sv in vuln_data.get("severity", []):
        score_str = sv.get("score", "")

        # Try direct label match first
        for token in re.split(r"[;:/\s]+", score_str.upper()):
            if token in severity_values:
                rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}[token]
                if rank < best_rank:
                    best = token
                    best_rank = rank

        # Try numeric CVSS score
        try:
            cvss_score = float(score_str)
            label = _score_to_severity(cvss_score)
            rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}[label]
            if rank < best_rank:
                best = label
                best_rank = rank
        except (ValueError, TypeError):
            pass

        # Try parsing CVSS vector string
        if score_str.startswith("CVSS:"):
            computed = _cvss_base_score(score_str)
            if computed is not None:
                label = _score_to_severity(computed)
                rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}[label]
                if rank < best_rank:
                    best = label
                    best_rank = rank

    # Check database_specific for GitHub Advisory severity
    for affected in vuln_data.get("affected", []):
        db_specific = affected.get("database_specific", {})
        if isinstance(db_specific, dict):
            gh_sev = db_specific.get("severity", "")
            if gh_sev.upper() in severity_values:
                rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}[gh_sev.upper()]
                if rank < best_rank:
                    best = gh_sev.upper()
                    best_rank = rank

    return best


def _extract_versions(vuln_data: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Extract affected and fixed version strings."""
    affected_versions: list[str] = []
    fixed_versions: list[str] = []
    for affected in vuln_data.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name", "").startswith("pip:"):
            # OSV uses "pip:" prefix for PyPI packages
            pass
        for rng in affected.get("ranges", []):
            introduced = ""
            for evt in rng.get("events", []):
                if "introduced" in evt:
                    introduced = evt["introduced"]
                elif "fixed" in evt:
                    fixed_versions.append(evt["fixed"])
                elif "last_affected" in evt:
                    affected_versions.append(evt["last_affected"])
            if introduced and not fixed_versions:
                affected_versions.append(f">={introduced}")
    return affected_versions, fixed_versions


def _parse_vuln(vuln_data: dict[str, Any]) -> Vulnerability:
    """Parse raw OSV vulnerability data into a Vulnerability object."""
    vid = vuln_data.get("id", "UNKNOWN")
    summary = vuln_data.get("summary", "")
    if not summary:
        refs = vuln_data.get("references", [])
        summary = refs[0].get("url", "") if refs else "No summary available"
    severity = _extract_severity(vuln_data)
    affected_versions, fixed_versions = _extract_versions(vuln_data)
    url = f"https://osv.dev/vulnerability/{vid}"
    aliases = vuln_data.get("aliases", [])
    return Vulnerability(
        id=vid,
        summary=summary,
        severity=severity,
        affected_versions=affected_versions,
        fixed_versions=fixed_versions,
        url=url,
        aliases=aliases,
    )


async def query_package(
    name: str, version: str, *, ecosystem: str = "PyPI"
) -> PackageResult:
    """Query OSV for vulnerabilities affecting a specific package version."""
    result = PackageResult(name=name, version=version)
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(
            f"{OSV_API}/query",
            json={
                "version": version,
                "package": {"name": name, "ecosystem": ecosystem},
            },
        )
        if resp.status_code != 200:
            return result
        data = resp.json()
        for vuln_data in data.get("vulns", []):
            result.vulnerabilities.append(_parse_vuln(vuln_data))
    result.vulnerabilities.sort(key=lambda v: v.severity_rank)
    return result
