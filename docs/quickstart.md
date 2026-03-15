# Quickstart (5 minutes)

This guide gets you from install → first scan → CI-friendly output.

## 1) Install

```bash
pip install pyaegis
```

## 2) Scan a directory

```bash
pyaegis .
```

PyAegis exits with:

- `0` when no findings were reported
- `1` when findings were detected (useful as a CI gate)

## 3) Use the default rules explicitly (optional)

```bash
pyaegis . --rules ./pyaegis/rules/default.yml
```

## 4) Create a custom rules file

Create `custom_rules.yml`:

```yaml
inputs:
  - input
  - os.getenv
  - request
  - sys.argv

sinks:
  - eval
  - exec
  - os.system
  - os.popen
  - subprocess.call
  - subprocess.Popen
```

Run:

```bash
pyaegis . --rules ./custom_rules.yml
```

## 5) Export SARIF for code scanning

```bash
pyaegis . --format sarif --output pyaegis-results.sarif
```

If you are using GitHub Actions, you can upload this SARIF so findings appear as code scanning alerts.

Next: [CI integration](ci-integration.md)
