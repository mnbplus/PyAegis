# Comparison

PyAegis is a Python-first SAST tool with a minimal rules surface (sources/sinks), designed for fast scans and CI integration.

This page compares PyAegis with two widely used security scanning tools:

- **Bandit** (Python security linter)
- **Semgrep** (multi-language pattern/taint scanning)

## Feature comparison

| Feature | PyAegis | Bandit | Semgrep |
|---|---:|---:|---:|
| Primary focus | Python source→sink checks | Python security lints | Multi-language SAST patterns + taint |
| Supported languages | Python | Python | Many |
| Rules | YAML (`inputs` / `sinks`) | Python plugins + config | YAML rules (large ecosystem) |
| Data-flow / taint analysis | Yes (source→sink) | Limited | Yes (taint mode) |
| SARIF output | Yes | Not native | Yes |
| CI integration | Yes | Yes | Yes |
| Typical adoption | Lightweight, Python-only repos | Quick security lint in Python projects | Broad monorepos, org-wide rule sets |

## When to choose which

### Choose PyAegis if you want:

- Python-only scanning with a small, readable codebase
- minimal rule authoring (sources/sinks) and quick iteration
- SARIF export and a CI gate with strong “untrusted input → sink” framing

### Choose Bandit if you want:

- a mature set of Python security lint rules with low setup cost
- standard checks for common pitfalls (e.g., `subprocess` usage, `pickle`, weak crypto patterns)

### Choose Semgrep if you want:

- one scanner for many languages
- a large rule ecosystem (community + enterprise)
- advanced pattern matching and taint tracking across many frameworks

## Limitations (current)

PyAegis currently prioritizes simplicity, which implies some trade-offs:

- limited modeling of sanitizers/validators
- limited cross-function (inter-procedural) tracking
- dynamic imports and aliases may reduce precision

These are common roadmap items for SAST engines.
