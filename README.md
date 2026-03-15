<div align="center">
  <!-- Slogan and Shield -->
  <h1>🛡️ PyAegis</h1>
  <p><b>The Next-Generation Static Application Security Testing (SAST) Engine for Python Codebases.</b></p>

  [![Python Supported](https://img.shields.io/badge/Python-3.8%20|%203.9%20|%203.10%20|%203.11%20|%203.12-blue.svg?style=for-the-badge&logo=python)](https://python.org)
  [![Build Status](https://img.shields.io/github/actions/workflow/status/mnbplus/PyAegis/ci.yml?branch=main&style=for-the-badge&logo=github)](https://github.com/mnbplus/PyAegis/actions)
  [![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
  [![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg?style=for-the-badge)](https://github.com/psf/black)
  [![Security Scanned](https://img.shields.io/badge/Security-Scanned_by_PyAegis-red.svg?style=for-the-badge)](#)
</div>

<br/>

> **Lightning-fast.** **Data-flow aware.** **Built for modern CI/CD.**

**PyAegis** is an advanced static analysis vulnerability scanner designed specifically for the complexities of modern Python ecosystems. Stop relying on outdated, noisy regular expression scanners. PyAegis leverages true multiprocessing **AST (Abstract Syntax Tree) unrolling** and Control-Flow Graph (CFG) based **deep taint analysis** to track user input across your application, massively reducing false positives while identifying critical zero-day logic flaws.

---

## ✨ Enterprise-Grade Features

*   🚀 **Zero-Overhead AST Parsing**: Multi-core enabled parsing for large monorepos. Scans hundreds of thousands of lines of Python code in fractions of a second.
*   🕸️ **Deep Taint Tracking**: Accurately detects SQL Injections, Command Injections, and XSS by tracking untrusted variables (`sources`) all the way down into sensitive system functions (`sinks`).
*   🛠️ **Extensible Rule Engine**: YAML-based rule definitions allow your red team or AppSec engineers to write custom context-aware vulnerability signatures effortlessly.
*   🤖 **Polymorphic Exports**: Natively exports to `TEXT`, `JSON`, and the industry-standard **`SARIF v2.1.0`**.
*   🔗 **CI/CD Ready**: Drop-in GitHub Actions integration to block vulnerable pull requests before they reach your `main` branch. GitHub Advanced Security standard compliant.

## 📦 Installation

```bash
# Requires Python 3.8+
pip install pyaegis
```

## 🚀 Quick Start

Scan your entire codebase for vulnerabilities with a single command:

```bash
pyaegis ./my_project --rules ./pyaegis/rules/default.yml
```

### Terminal Output Example

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

## 🧠 How It Works

PyAegis builds a normalized Control-Flow Graph for every Python file it analyzes. By mathematically simulating execution paths without actually running the malicious code, it maps data flow. When an `input()` or `request.args.get()` (a **Source**) reaches an execution context like `eval()` or `subprocess.call()` (a **Sink**) without proper sanitization, PyAegis flags it.

## 🤝 Why Support PyAegis? (The Roadmap)

PyAegis currently acts as the last line of defense for open-source pipelines. In our upcoming major release, we intend to introduce **AI Auto-Remediation**.
When PyAegis finds a vulnerability, it will automatically generate a secure, contextually-correct patch (e.g., parameterized SQL queries, sanitized shell executions) directly in the developer's PR using large language models.

---
<div align="center">
  <i>A massive shout-out to all early adopters who believed in the AST approach. Let's make Python secure by default.</i> 🛡️
</div>
