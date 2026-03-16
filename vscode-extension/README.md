# PyAegis — VS Code Extension

Lightweight Python security scanner powered by [PyAegis](https://github.com/mnbplus/PyAegis).

## Features

- **Auto-scan on save** — findings appear as inline diagnostics (red/yellow underlines)
- **Workspace scan** — scan all Python files in the project at once
- **Technical debt analysis** — Git churn + cyclomatic complexity hotspot report
- **Zero config** — works out of the box with the Python extension's interpreter

## Requirements

```bash
pip install pyaegis
# For debt analysis:
pip install pyaegis[debt]
```

## Commands

| Command | Description |
|---------|-------------|
| `PyAegis: Scan Current File` | Scan the active Python file |
| `PyAegis: Scan Workspace` | Scan all Python files in the workspace |
| `PyAegis: Technical Debt Analysis` | Show debt hotspots in the Output panel |
| `PyAegis: Show Output Panel` | Open the PyAegis output channel |

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `pyaegis.scanOnSave` | `true` | Auto-scan on file save |
| `pyaegis.severity` | `[CRITICAL, HIGH, MEDIUM]` | Severity levels to report |
| `pyaegis.pythonPath` | `` | Python executable path |
| `pyaegis.rulesPath` | `` | Custom rules YAML path |
| `pyaegis.debtMinChurn` | `2` | Min commit count for debt analysis |

## License

MIT
