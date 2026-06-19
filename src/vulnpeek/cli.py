"""CLI entry point for vulnpeek."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import TextIO

from rich.console import Console
from rich.table import Table
from rich.text import Text

from vulnpeek import __version__
from vulnpeek.osv import PackageResult, query_package
from vulnpeek.requirements import (
    parse_requirements,
    parse_requirements_file,
    parse_pyproject_toml_file,
    parse_uv_lock_file,
)

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "UNKNOWN": "dim",
}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnpeek",
        description="🔍 Scan Python dependencies for known vulnerabilities via the OSV database",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="requirements.txt",
        help="Requirements file path (requirements.txt, pyproject.toml, uv.lock) or 'package==version'",
    )
    parser.add_argument(
        "--format",
        choices=["table", "json", "quiet"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=None,
        help="Minimum severity to report (default: show all)",
    )
    parser.add_argument(
        "--include-optional",
        action="append",
        default=[],
        help="Optional dependency groups to include for pyproject.toml (e.g., --include-optional dev --include-optional test)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"vulnpeek {__version__}",
    )
    return parser


def _severity_min(severity: str | None) -> int:
    """Return numeric rank for severity filter."""
    if severity is None:
        return 5
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}[severity]


async def scan_packages(reqs: list, *, semaphore: int = 5) -> list[PackageResult]:
    """Scan a list of (name, version) tuples concurrently."""
    sem = asyncio.Semaphore(semaphore)
    results: list[PackageResult] = []

    async def _scan(name: str, version: str | None) -> PackageResult:
        if version is None:
            return PackageResult(name=name, version="unpinned")
        async with sem:
            return await query_package(name, version)

    tasks = [_scan(r.name, r.version) for r in reqs if r.name]
    results = await asyncio.gather(*tasks)
    return list(results)


def _filter_results(
    results: list[PackageResult], min_severity: int
) -> list[PackageResult]:
    """Filter results by minimum severity."""
    filtered = []
    for r in results:
        vulns = [v for v in r.vulnerabilities if v.severity_rank <= min_severity]
        if vulns:
            filtered.append(
                PackageResult(name=r.name, version=r.version, vulnerabilities=vulns)
            )
    return filtered


def _print_table(results: list[PackageResult], console: Console) -> int:
    """Print results as a rich table. Returns count of vulnerable packages."""
    if not results:
        console.print("[green]✓ No known vulnerabilities found![/green]")
        return 0

    table = Table(
        title="🔍 Vulnerability Scan Results",
        show_lines=True,
        title_style="bold",
    )
    table.add_column("Package", style="bold")
    table.add_column("Version")
    table.add_column("Vuln ID", style="cyan")
    table.add_column("Severity")
    table.add_column("Summary", max_width=50)
    table.add_column("Fix", style="green")

    total_vulns = 0
    for r in results:
        for v in r.vulnerabilities:
            sev_style = SEVERITY_COLORS.get(v.severity, "dim")
            fix = ", ".join(v.fixed_versions) if v.fixed_versions else "—"
            table.add_row(
                r.name,
                r.version,
                v.id,
                Text(v.severity, style=sev_style),
                v.summary[:80],
                fix,
            )
            total_vulns += 1

    console.print(table)
    console.print(
        f"\n[bold]{len(results)} packages[/bold] with "
        f"[bold red]{total_vulns} vulnerabilities[/bold red] found."
    )
    return len(results)


def _print_json(results: list[PackageResult], out: TextIO) -> int:
    """Print results as JSON. Returns count of vulnerable packages."""
    data = []
    for r in results:
        pkg = {
            "name": r.name,
            "version": r.version,
            "vulnerabilities": [
                {
                    "id": v.id,
                    "severity": v.severity,
                    "summary": v.summary,
                    "fixed_versions": v.fixed_versions,
                    "url": v.url,
                    "aliases": v.aliases,
                }
                for v in r.vulnerabilities
            ],
        }
        data.append(pkg)
    json.dump(data, out, indent=2)
    print(file=out)
    return len(results)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    console = Console()

    # Determine if target is a file or a single package spec
    target = args.target
    target_path = Path(target)

    if target_path.is_file():
        suffix = target_path.suffix.lower()
        if suffix == ".toml" or target_path.name == "pyproject.toml":
            reqs = parse_pyproject_toml_file(
                target_path, include_optional=args.include_optional or None
            )
        elif suffix == ".lock" or target_path.name == "uv.lock":
            reqs = parse_uv_lock_file(target_path)
        else:
            reqs = parse_requirements_file(target_path)
    elif "==" in target or ">=" in target:
        # Single package spec like "requests==2.28.0"
        reqs = parse_requirements(target)
    else:
        # Try as file, fallback to error
        try:
            reqs = parse_requirements_file(target_path)
        except FileNotFoundError:
            console.print(f"[red]Error:[/red] File '{target}' not found")
            return 1

    if not reqs:
        console.print("[yellow]No packages found to scan.[/yellow]")
        return 0

    pinned = [r for r in reqs if r.version is not None]
    unpinned = [r for r in reqs if r.version is None]

    if unpinned:
        console.print(
            f"[yellow]⚠ {len(unpinned)} packages without pinned versions "
            f"(skipping): {', '.join(r.name for r in unpinned)}[/yellow]"
        )

    if not pinned:
        console.print("[yellow]No pinned packages to scan.[/yellow]")
        return 0

    console.print(f"🔍 Scanning [bold]{len(pinned)}[/bold] packages...\n")

    results = asyncio.run(scan_packages(pinned))

    min_sev = _severity_min(args.severity)
    results = _filter_results(results, min_sev)

    if args.format == "json":
        count = _print_json(results, sys.stdout)
    elif args.format == "quiet":
        for r in results:
            for v in r.vulnerabilities:
                fix = ", ".join(v.fixed_versions) if v.fixed_versions else "no fix"
                print(f"{r.name}=={r.version} {v.id} [{v.severity}] {fix}")
        count = len(results)
    else:
        _print_table(results, console)
        count = len(results)

    return 1 if count > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
