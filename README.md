<div align="center">
  <!-- Slogan and Shield -->
  <h1>🛡️ PyAegis</h1>
  <p><b>The Next-Generation Static Application Security Testing (SAST) Engine for Python Codebases.</b></p>
  <br>
  [![Python Supported](https://img.shields.io/badge/Python-3.8%20|%203.9%20|%203.10%20|%203.11%20|%203.12-blue.svg?style=for-the-badge&logo=python)](https://python.org)
  [![Build Status](https://img.shields.io/github/actions/workflow/status/mnbplus/PyAegis/ci.yml?branch=main&style=for-the-badge&logo=github)](https://github.com/mnbplus/PyAegis/actions)
  [![codecov](https://img.shields.io/codecov/c/github/mnbplus/PyAegis?style=for-the-badge&logo=codecov)](https://codecov.io/gh/mnbplus/PyAegis)
  [![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
  [![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg?style=for-the-badge)](https://github.com/psf/black)
  [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=for-the-badge)](http://makeapullrequest.com)
  [![Security Scanned](https://img.shields.io/badge/Security-Scanned_by_PyAegis-red.svg?style=for-the-badge)](#)
</div>

<br/>

> **Lightning-fast.** **Data-flow aware.** **Built for modern CI/CD pipelines.**

**PyAegis** is an advanced static analysis vulnerability scanner designed specifically for the complexities of modern Python ecosystems. Stop relying on outdated, noisy regular expression scanners. PyAegis leverages true multiprocessing **AST (Abstract Syntax Tree) unrolling** and Control-Flow Graph (CFG) based **deep taint analysis** to track user input seamlessly across your application, massively reducing false positives while identifying critical zero-day logic flaws.

---

## ⚡ Table of Contents
- [Enterprise-Grade Features](#-enterprise-grade-features)
- [Installation](#-installation)
- [Advanced Usage](#-advanced-usage)
  - [CLI Flags](#cli-options)
  - [SARIF Integration](#github-advanced-security-integration-sarif)
- [Architecture & Data Flow](#-architecture--data-flow)
- [Writing Custom Rules](#-writing-custom-rules)
- [Continuous Integration (CI/CD)](#-continuous-integration-cicd)
- [Contributing](#-community--contributing)

---

## ✨ Enterprise-Grade Features

*   🚀 **Zero-Overhead AST Parsing**: Multi-core enabled parsing utilizing Python's native `ast` and `multiprocessing`. Scans massive monorepos in fractions of a second.
*   🕸️ **Deep Taint Tracking**: Accurately detects SQL Injections, Command Injections, and XSS by tracking untrusted variables (`sources`) all the way down into sensitive system functions (`sinks`).
*   🛠️ **Extensible Rule Engine**: YAML-based rule definitions allow your red team or AppSec engineers to write custom context-aware vulnerability signatures effortlessly.
*   🤖 **Polymorphic Exports**: Natively exports to `TEXT`, `JSON`, and the industry-standard **`SARIF v2.1.0`**.
*   🔗 **CI/CD Ready**: Drop-in GitHub Actions integration to block vulnerable pull requests before they reach your `main` branch. GitHub Advanced Security standard compliant.

## 📦 Installation

**Using pip (Recommended)**
```bash
pip install pyaegis
```

**From Source (Development Version)**
```bash
git clone https://github.com/mnbplus/PyAegis.git
cd PyAegis
pip install -e ".[dev]"
```

Verify the installation:
```bash
pyaegis --help
```

---

## 🚀 Advanced Usage

Scan your entire codebase for vulnerabilities with a single command:

```bash
pyaegis ./my_project --rules ./pyaegis/rules/default.yml
```

### CLI Options
PyAegis is designed to be highly configurable via the command line:

| Flag | Description | Default | Example |
|------|-------------|---------|---------|
| `target` | (Required) Target file or directory to scan. | - | `pyaegis ./src` |
| `--rules` | Path to custom YAML rules file. | `./pyaegis/rules/default.yml` | `--rules custom-rules.yml` |
| `--format` | Output format (`text`, `json`, `sarif`). | `text` | `--format json` |
| `--output` | Output file path. If not provided, prints to stdout. | `None` | `--output results.json` |
| `--debug` | Enable verbose debug logging. | `False` | `--debug` |

### Terminal Output Example (Human-Readable)

```text
[*] Parsing 45 Python files via AST...
[*] Performing Taint Tracking against Context Sinks...
[-] Detected 1 Potential Vulnerabilities:
    -> [CRITICAL] Untrusted user input executed by system sink. (PYA-100) | File: ./my_project/app.py:42 | Context: handle_request
```

### 🔒 GitHub Advanced Security Integration (SARIF)

Export your findings directly into GitHub's Native Code Scanning Alerts UI:

```bash
pyaegis ./my_project --format sarif --output results.sarif
```
*Upload `results.sarif` to GitHub Actions, and findings will be annotated directly on the vulnerable lines of code in your Pull Requests!*

---

## 🧠 Architecture & Data Flow

How exactly does PyAegis achieve its low false-positive rate? It mathematically models your application's execution path without actually running it.

Here is the high-level architecture of the PyAegis engine:

```mermaid
graph TD
    A[Source Code (.py)] -->|Parallel AST Parser| B(AST Nodes)
    B -->|CFG Builder| C{Control-Flow Graph}
    C -->|Taint Engine| D[Identify Sources]
    D --> E[Track Variable Propagation]
    E --> F{Reaches a Sink?}
    F -- Yes --> G[Flag Vulnerability]
    F -- No --> H[Mark as Safe]
    G --> I[Reporter Module]
    I -->|Polymorphic Export| J[SARIF / JSON / Text]
```

- **Sources**: Entry points for untrusted user data (e.g., `request.args.get()`, `os.environ`).
- **Sinks**: Dangerous execution contexts where malicious data can cause harm (e.g., `subprocess.call()`, `eval()`, SQL driver execution strings).

---

## 🛠️ Writing Custom Rules

Security is not one-size-fits-all. You can easily extend PyAegis to detect business-logic specific vulnerabilities using our unified YAML signature engine.

Create a file named `custom_rules.yml`:

```yaml
# A simple rule to detect untrusted data hitting internal microservices

inputs:
  # Define where untrusted data originates
  - request.GET.get
  - flask.request.form
  - user_input_prompt

sinks:
  # Define the dangerous functions
  - my_internal_api.send_payment
  - utils.execute_raw_query
```

Run PyAegis with your custom signature:
```bash
pyaegis ./src --rules custom_rules.yml
```

---

## ⚙️ Continuous Integration (CI/CD)

PyAegis is built to be embedded directly into modern DevOps pipelines to establish **Shift-Left Security**.

### GitHub Actions Workflow
Create a `.github/workflows/pyaegis-scan.yml` file to block insecure pull requests automatically:

```yaml
name: PyAegis SAST Scan

on:
  push:
    branches: [ "main" ]
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4

    - name: Set up Python
      uses: actions/setup-python@v5
      with:
        python-version: "3.10"

    - name: Install PyAegis
      run: pip install pyaegis

    - name: Run Scan and Export SARIF
      run: pyaegis . --format sarif --output pyaegis-results.sarif
      continue-on-error: true # Allow upload step to happen even if vulns are found

    - name: Upload SARIF file
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: pyaegis-results.sarif
```

---

## 🤝 Community & Contributing

We welcome contributions from the community! Whether you want to add new framework parsers (e.g., Django, FastAPI), improve the CFG logic, or enhance the reporting engine, we'd love your help.

Please read our guidelines before submitting a Pull Request:
- [Contributing Guidelines](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)

---
<div align="center">
  <i>A massive shout-out to all early adopters who believed in the AST approach. Let's make Python secure by default.</i> 🛡️
</div>
