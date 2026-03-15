<div align="center">
  <h1>PyAegis</h1>
  <p><b>The next-generation Static Application Security Testing (SAST) engine for Python codebases.</b></p>

  <p>
    <a href="README.md">English</a> |
    <a href="README.zh-CN.md">简体中文</a> |
    <a href="README.ja.md">日本語</a>
  </p>

  <p>
    <a href="https://python.org"><img alt="Python Supported" src="https://img.shields.io/badge/Python-3.8%20|%203.9%20|%203.10%20|%203.11%20|%203.12-blue.svg?style=for-the-badge&logo=python"></a>
    <a href="https://github.com/mnbplus/PyAegis/actions"><img alt="Build Status" src="https://img.shields.io/github/actions/workflow/status/mnbplus/PyAegis/ci.yml?branch=main&style=for-the-badge&logo=github"></a>
    <a href="https://codecov.io/gh/mnbplus/PyAegis"><img alt="codecov" src="https://img.shields.io/codecov/c/github/mnbplus/PyAegis?style=for-the-badge&logo=codecov"></a>
    <a href="https://opensource.org/licenses/MIT"><img alt="License" src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge"></a>
    <a href="https://github.com/psf/black"><img alt="Code Style: Black" src="https://img.shields.io/badge/code%20style-black-000000.svg?style=for-the-badge"></a>
    <a href="http://makeapullrequest.com"><img alt="PRs Welcome" src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=for-the-badge"></a>
  </p>
</div>

> **Lightning-fast. Data-flow aware. Built for modern CI/CD.**

**PyAegis** is a static analysis vulnerability scanner designed for modern Python projects. Instead of relying on brittle regex matching, PyAegis parses your code into an AST, builds a lightweight control-flow representation, and performs taint-style data-flow checks to determine whether **untrusted sources** can reach **dangerous sinks**.

---

## Table of Contents

- [Features](#features)
- [Quick Start (5 steps)](#quick-start-5-steps)
- [Usage](#usage)
- [Architecture (in plain words)](#architecture-in-plain-words)
- [Writing custom rules](#writing-custom-rules)
- [CI/CD integration](#cicd-integration)
- [Comparison with other tools](#comparison-with-other-tools)
- [Roadmap](#roadmap)
- [Contributing](#contributing)

---

## Features

- **Multiprocessing AST parsing** for fast repo-wide scanning
- **Taint-style checks**: track data from sources (e.g., `input`, environment, request objects) into sinks (e.g., `os.system`, `subprocess.*`, `eval/exec`)
- **Rule-driven**: define sources/sinks in YAML (easy to extend)
- **Multiple output formats**: `text`, `json`, `sarif` (SARIF v2.1.0)
- **CI-ready**: fail builds on findings and upload SARIF to code scanning UIs

---

## Quick Start (5 steps)

1) **Install**
```bash
pip install pyaegis
```

2) **Scan a project directory** (uses default rules)
```bash
pyaegis .
```

3) **Scan with a custom rules file**
```bash
pyaegis . --rules ./pyaegis/rules/default.yml
# or
pyaegis . --rules ./custom_rules.yml
```

4) **Export SARIF for GitHub / code scanning**
```bash
pyaegis . --format sarif --output pyaegis-results.sarif
```

5) **Use it in CI** (example: GitHub Actions SARIF upload)

See: [docs/ci-integration.md](docs/ci-integration.md)

---

## Usage

Basic:
```bash
pyaegis <target>
```

Common options:

| Flag | Description | Default |
|------|-------------|---------|
| `target` | Target file or directory to scan | - |
| `--rules` | Path to rules YAML file | `pyaegis/rules/default.yml` |
| `--format` | Output format: `text`, `json`, `sarif` | `text` |
| `--output` | Output file path (otherwise stdout) | - |
| `--debug` | Verbose logging | off |

Example (JSON to file):
```bash
pyaegis ./my_project --format json --output results.json
```

Exit codes:
- `0`: no findings
- `1`: findings detected or fatal scan error

---

## Architecture (in plain words)

PyAegis is intentionally simple to understand and extend. A scan flows like this:

1. **Collect targets**: discover `.py` files from the provided path.
2. **Parse & model**: parse each file into an **AST** (in parallel), then build a per-function representation (CFG-like blocks).
3. **Load rules**: read YAML rules that define:
   - **inputs**: where untrusted data originates (sources)
   - **sinks**: dangerous functions/APIs that should never receive tainted data
4. **Taint tracking**:
   - mark variables assigned from a source call as tainted
   - propagate taint through the function body
   - when a tainted value reaches a sink call, emit a finding
5. **Report**: output as text/JSON/SARIF for humans and CI systems.

Key terms:
- **Sources**: entry points for untrusted data (e.g., `input()`, request parameters, environment variables)
- **Sinks**: sensitive APIs where tainted data is dangerous (e.g., `os.system`, `subprocess.call`, `eval`)

---

## Writing custom rules

Rules are YAML files with two top-level keys:

- `inputs`: a list of source names
- `sinks`: a list of sink names

Example:

```yaml
inputs:
  - input
  - os.getenv
  - request

sinks:
  - eval
  - exec
  - os.system
  - subprocess.call
  - subprocess.Popen
```

Run:
```bash
pyaegis ./src --rules custom_rules.yml
```

More details: [docs/rules.md](docs/rules.md)

---

## CI/CD integration

PyAegis is designed to work as a build step:
- fail the pipeline if findings are detected
- optionally export SARIF and upload it to your code scanning UI

See full examples for **GitHub Actions**, **GitLab CI**, and **Jenkins**:
- [docs/ci-integration.md](docs/ci-integration.md)

---

## Comparison with other tools

| Tool | Primary focus | Languages | Rule format | Data-flow / taint mode | SARIF output | Typical usage |
|------|---------------|-----------|-------------|-------------------------|--------------|---------------|
| **PyAegis** | Python SAST with source→sink checks | Python | YAML (sources/sinks) | Yes (source→sink taint-style) | Yes | Lightweight Python repo scans + CI gates |
| Bandit | Python security lints | Python | Python plugins + config | Limited (mostly pattern/AST checks) | Not native (can be integrated via converters) | Quick lint-style security checks |
| Semgrep | Multi-language SAST + patterns | Many | YAML rules | Yes (taint mode available) | Yes | Broad scanning across polyglot monorepos |

Notes:
- Bandit excels at quick, well-known Python security checks, but is typically less focused on end-to-end source→sink tracking.
- Semgrep is great for multi-language repos and has a powerful rule ecosystem; PyAegis focuses on Python-first scanning with a minimal rule surface.

---

## Roadmap

Planned improvements (in rough priority order):

- More built-in **sources/sinks** (Django/FastAPI/Flask helpers, deserialization, template injection)
- Better **inter-procedural tracking** (taint across function boundaries)
- Framework-aware modeling (request objects, ORMs, common sanitizers)
- Baselines / suppressions (ignore existing findings, focus on new regressions)
- Performance profiling and incremental scanning for large monorepos

---

## Contributing

Contributions are welcome:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [SECURITY.md](SECURITY.md)

Documentation site (MkDocs): see `docs/` and `mkdocs.yml`.
