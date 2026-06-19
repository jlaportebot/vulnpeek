"""Parse requirements files to extract package names and versions."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

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


def parse_pyproject_toml(
    content: str, *, include_optional: list[str] | None = None
) -> list[Requirement]:
    """Parse a pyproject.toml string (PEP 621) into Requirement objects.

    Args:
        content: The pyproject.toml file content as a string.
        include_optional: Optional list of optional dependency group names
            (e.g., ["dev", "test"]) to include in addition to main dependencies.

    Returns:
        List of Requirement objects with pinned versions extracted where possible.
    """
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError:
        return []

    project = data.get("project", {})
    if not project:
        return []

    results: list[Requirement] = []

    # Parse main dependencies
    for dep in project.get("dependencies", []):
        m = _REQ_RE.match(dep)
        if m:
            name = m.group("name").strip()
            specifier = m.group("specifier")
            version = _extract_version(specifier)
            results.append(Requirement(name=name, version=version, line=dep))

    # Parse optional dependencies
    if include_optional:
        optional_deps = project.get("optional-dependencies", {})
        for group in include_optional:
            for dep in optional_deps.get(group, []):
                m = _REQ_RE.match(dep)
                if m:
                    name = m.group("name").strip()
                    specifier = m.group("specifier")
                    version = _extract_version(specifier)
                    results.append(Requirement(name=name, version=version, line=dep))

    return results


def parse_pyproject_toml_file(
    path: Path, *, include_optional: list[str] | None = None
) -> list[Requirement]:
    """Parse a pyproject.toml file by path."""
    return parse_pyproject_toml(
        path.read_text(encoding="utf-8"), include_optional=include_optional
    )


def parse_uv_lock(content: str) -> list[Requirement]:
    """Parse a uv.lock file into Requirement objects.

    Args:
        content: The uv.lock file content as a string.

    Returns:
        List of Requirement objects with exact versions from the lock file.
    """
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError:
        return []

    results: list[Requirement] = []
    for pkg in data.get("package", []):
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        if name and version:
            results.append(
                Requirement(name=name, version=version, line=f"{name}=={version}")
            )
    return results


def parse_uv_lock_file(path: Path) -> list[Requirement]:
    """Parse a uv.lock file by path."""
    return parse_uv_lock(path.read_text(encoding="utf-8"))
