# PyAegis Documentation

PyAegis is a Python-first **Static Application Security Testing (SAST)** tool focused on **source → sink** security checks.

Unlike regex-based scanners, PyAegis parses code into an **AST**, builds a lightweight per-function model, and performs taint-style analysis to answer a practical question:

> Can **untrusted input** reach a **dangerous API**?

## Who is this for?

- Application Security / DevSecOps teams who want a CI gate for Python repositories
- Developers who want quick, explainable findings (with file/line/context)
- Contributors who want a small codebase that’s easy to extend

## What PyAegis detects (today)

PyAegis ships with a simple default ruleset (YAML) that models:

- **Sources** (`inputs`): `input`, `request`, `os.getenv`, `sys.argv`, ...
- **Sinks** (`sinks`): `eval`, `exec`, `os.system`, `subprocess.*`, ...

This enables detection of common injection-style issues where tainted data is passed into an execution sink.

## Get started

- [Quickstart](quickstart.md) — install + scan in 5 minutes
- [Rules](rules.md) — define sources/sinks and create custom rules
- [CI integration](ci-integration.md) — GitHub Actions / GitLab CI / Jenkins examples
- [Comparison](comparison.md) — how PyAegis compares to Bandit and Semgrep
- [FAQ](faq.md)

## Core concepts

- **Source**: an entry point of untrusted data (user input, request params, env vars, CLI args)
- **Sink**: a sensitive operation where tainted data is dangerous (command execution, dynamic eval, deserialization, SQL execution)
- **Finding**: a reported issue with rule id, location, severity, and context

## Output formats

PyAegis supports:

- `text` — human-readable terminal output
- `json` — easy to consume by scripts
- `sarif` — integrates with code scanning platforms (e.g., GitHub Advanced Security)

---

Tip: If you’re new, start with **Quickstart**, then read **Rules** and **CI integration**.
