# PyAegis GitHub Action

Run PyAegis SAST directly in your CI/CD pipeline with the official GitHub Action.

## Overview

The `mnbplus/pyaegis` action installs PyAegis and scans your Python codebase on every push or pull request. It outputs results in SARIF format by default, enabling seamless integration with **GitHub Advanced Security** and the Security tab.

## Prerequisites

- Python available in the runner environment (standard on `ubuntu-latest`)
- For SARIF upload: GitHub Advanced Security enabled on your repository (free for public repos)

---

## Example 1 — Basic Usage

Run a scan and print results to the log in text format.

```yaml
name: PyAegis Basic Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run PyAegis
        uses: mnbplus/pyaegis@v1
        with:
          target: .
          format: text
```

---

## Example 2 — Upload SARIF to GitHub Security Tab

Generate a SARIF report and upload it so findings appear under **Security → Code scanning alerts**.

```yaml
name: PyAegis SARIF Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Run PyAegis
        id: pyaegis
        uses: mnbplus/pyaegis@v1
        with:
          target: .
          format: sarif
          output: pyaegis.sarif
          severity: MEDIUM

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.pyaegis.outputs.sarif_file }}
```

---

## Example 3 — Custom Rules

Apply your own YAML rule file on top of the built-in ruleset.

```yaml
name: PyAegis Custom Rules Scan

on: [push]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run PyAegis with custom rules
        uses: mnbplus/pyaegis@v1
        with:
          target: src/
          format: sarif
          output: pyaegis.sarif
          rules: .github/pyaegis-rules.yml
          severity: HIGH
          fail_on_findings: 'true'
```

See the [Rule Format](../README.md#rule-format) section in the main README for how to write custom rules.

---

## Full Workflow — GitHub Advanced Security Integration

This is the recommended production workflow. It scans on every push and PR, uploads results to the Security tab, and blocks merges when `fail_on_findings` is set.

```yaml
name: Security — PyAegis SAST

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]
  schedule:
    # Nightly scan at 02:00 UTC
    - cron: '0 2 * * *'

jobs:
  sast:
    name: PyAegis SAST
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
      actions: read

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Run PyAegis SAST
        id: pyaegis
        uses: mnbplus/pyaegis@v1
        with:
          target: .
          format: sarif
          output: pyaegis.sarif
          severity: MEDIUM
          fail_on_findings: 'false'   # Set 'true' to block PRs on findings

      - name: Upload SARIF to GitHub Advanced Security
        if: always()   # Upload even if scan step fails
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.pyaegis.outputs.sarif_file }}
          category: pyaegis

      - name: Archive SARIF artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: pyaegis-sarif-${{ github.sha }}
          path: pyaegis.sarif
          retention-days: 30
```

### What you get

| Feature | Details |
|---|---|
| Inline PR annotations | Findings shown as review comments on changed lines |
| Security tab alerts | Persistent tracking of open/closed/dismissed findings |
| Trend graphs | GitHub tracks finding counts over time |
| Nightly scheduled scan | Catch supply-chain issues between commits |
| SARIF artifact | Downloadable report retained for 30 days |

---

## Action Inputs Reference

| Input | Required | Default | Description |
|---|---|---|---|
| `target` | No | `.` | Path to scan |
| `format` | No | `sarif` | Output format: `text`, `json`, `sarif` |
| `output` | No | `pyaegis.sarif` | Output file path |
| `severity` | No | *(all)* | Minimum severity: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `rules` | No | *(built-in)* | Custom rules YAML file path |
| `fail_on_findings` | No | `false` | Exit non-zero if findings detected |

## Action Outputs Reference

| Output | Description |
|---|---|
| `sarif_file` | Path to the generated SARIF file |

---

## Why PyAegis over Bandit?

> "Bandit flagged 87 warnings on our codebase. PyAegis found 3 — all real." — Early adopter feedback

Bandit uses pattern matching. PyAegis uses **taint analysis** — it tracks whether untrusted data actually reaches a dangerous sink, through your real control flow. Fewer alerts. Higher signal. Less time triaging noise.
