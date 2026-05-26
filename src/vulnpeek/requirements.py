"""Parse requirements files to extract package names and versions."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

# Matches: package==1.2.3, package>=1.0,<2.0, package~=1.2
# Handles extras like package[extra]==1.0
_REQ_RE = re.compile(
    r"^\s*"
    r"(?P<name>[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"(?:\[[^\]]*\])?"  # extras
    r"\s*(?P<specifier>[><=!~].+)?",
    re.MULTILINE,
)

_COMMENT_RE = re.compile(r"#.*$")


class Requirement:
    """A parsed requirement with name and pinned version (if any)."""

    __slots__ = ("name", "version", "line")

    def __init__(self, name: str, version: str | None, line: str) -> None:
        self.name = name
        self.version = version
        self.line = line

    def __repr__(self) -> str:
        if self.version:
            return f"Requirement({self.name}=={self.version})"
        return f"Requirement({self.name}, unpinned)"


def _extract_version(specifier: str | None) -> str | None:
    """Extract a pinned version from a specifier string."""
    if not specifier:
        return None
    # Look for ==1.2.3 pattern
    m = re.search(r"==\s*([^\s,;]+)", specifier)
    if m:
        return m.group(1).strip()
    # Look for ~=1.2 (compatible release)
    m = re.search(r"~=\s*([^\s,;]+)", specifier)
    if m:
        return m.group(1).strip()
    # For >= without ==, we can't pin — return None
    return None


def parse_requirements(text: str) -> list[Requirement]:
    """Parse a requirements.txt string into Requirement objects."""
    results: list[Requirement] = []
    for line in text.splitlines():
        # Strip comments
        line = _COMMENT_RE.sub("", line).strip()
        if not line or line.startswith("-") or line.startswith("."):
            continue
        # Handle line continuations (backslash) — simple approach
        m = _REQ_RE.match(line)
        if m:
            name = m.group("name").strip()
            specifier = m.group("specifier")
            version = _extract_version(specifier)
            results.append(Requirement(name=name, version=version, line=line))
    return results


def parse_requirements_file(path: Path) -> list[Requirement]:
    """Parse a requirements file by path."""
    return parse_requirements(path.read_text(encoding="utf-8"))
