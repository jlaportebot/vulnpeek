# 🔍 VulnPeek

> Lightweight CLI to scan Python dependencies for known vulnerabilities via the [OSV database](https://osv.dev)

[![PyPI](https://img.shields.io/pypi/v/vulnpeek)](https://pypi.org/project/vulnpeek/)
[![Python](https://img.shields.io/pypi/pyversions/vulnpeek)](https://pypi.org/project/vulnpeek/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Why VulnPeek?

- **⚡ Fast** — concurrent API queries, no local database needed
- **🎯 Precise** — queries exact versions, not just package names
- **🎨 Beautiful** — rich terminal output with severity color-coding
- **📋 Flexible** — table, JSON, or quiet output formats
- **🔒 Private** — no account needed, uses the open OSV API
- **🪶 Lightweight** — only `httpx` and `rich` as dependencies

## Installation

```bash
pip install vulnpeek
```

## Quick Start

Scan your `requirements.txt`:

```bash
vulnpeek
```

Scan a specific file:

```bash
vulnpeek requirements-dev.txt
```

Scan a single package:

```bash
vulnpeek "requests==2.28.0"
```

## Output Formats

### Table (default)

```bash
vulnpeek requirements.txt
```

Shows a beautiful table with package, version, vulnerability ID, severity, summary, and fix version.

### JSON

```bash
vulnpeek requirements.txt --format json
```

Machine-readable JSON output, perfect for CI pipelines.

### Quiet

```bash
vulnpeek requirements.txt --format quiet
```

One line per vulnerability: `package==version VULN-ID [SEVERITY] fix_version`

## Filtering by Severity

Only show CRITICAL and HIGH:

```bash
vulnpeek --severity HIGH
```

## How It Works

1. Parses your `requirements.txt` (supports `==` and `~=` version specifiers)
2. Queries the [OSV API](https://osv.dev) for each pinned package+version
3. Displays results sorted by severity (CRITICAL → UNKNOWN)

> **Note:** Only packages with pinned versions (`==` or `~=`) are scanned. Unpinned packages are skipped with a warning.

## Example Output

```
🔍 Scanning 3 packages...

┏━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Package  ┃ Version ┃ Vuln ID         ┃ Severity ┃ Summary                          ┃ Fix      ┃
┡━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━┩
│ requests │ 2.28.0  │ GHSA-x9j5-xxxx  │ HIGH     │ Unintended leak of Proxy-Authoriz │ 2.32.0   │
│ jinja2   │ 3.0.0   │ GHSA-q2x7-xxxx  │ HIGH     │ Jinja is susceptible to an undefi │ 3.1.3    │
└──────────┴─────────┴─────────────────┴──────────┴──────────────────────────────────┴──────────┘

2 packages with 2 vulnerabilities found.
```

## Use in CI

```bash
vulnpeek --format quiet --severity HIGH
if [ $? -ne 0 ]; then
  echo "Vulnerabilities found!"
  exit 1
fi
```

Exit code `1` if vulnerabilities are found, `0` if clean.

## Development

```bash
git clone https://github.com/jlaportebot/vulnpeek.git
cd vulnpeek
pip install -e ".[dev]"
pytest
```

## License

[MIT](LICENSE)
