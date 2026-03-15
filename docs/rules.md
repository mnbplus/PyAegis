# Writing rules

PyAegis rules are intentionally minimal: a rule file defines **sources** and **sinks**.

- **Sources** are where untrusted data can enter your program.
- **Sinks** are sensitive APIs where tainted data can cause security impact.

PyAegis reports a finding when a variable assigned from a **source call** is later passed into a **sink call**.

## Rule file structure

A rules file is YAML with two top-level keys:

```yaml
inputs:
  - <source-name>
  - ...

sinks:
  - <sink-name>
  - ...
```

### `inputs` (sources)

Examples:

- `input` (built-in)
- `os.getenv`
- `sys.argv` (CLI arguments as a conceptual source)
- `request` (framework request objects; you can model your own conventions)

Tip: Keep source names consistent with how they appear in the AST call names.

### `sinks`

Examples:

- `eval`, `exec`
- `os.system`, `os.popen`
- `subprocess.call`, `subprocess.Popen`
- `sqlite3.connect().execute` (if your modeling supports it)

## Matching semantics (important)

PyAegis uses a simple function name representation (e.g., `os.system`, `subprocess.call`).

Current matching behavior (high-level):

- It detects sources when code does an assignment from a call whose **root object** matches an entry in `inputs`.
  - Example: if `inputs` contains `request`, then `request.args.get(...)` can be treated as a source.
- It detects sinks when a `Call` expression resolves to a full name present in `sinks`.
  - Example: `subprocess.call(...)` resolves to `subprocess.call`.

Because this is static analysis, the model is conservative and may not resolve dynamic imports/aliases.

## Recommended rule conventions

- Prefer **fully-qualified names** for sinks: `subprocess.Popen`, `os.system`, ...
- Keep rules small and composable; maintain separate files per product/team if needed.
- Start with high-signal sinks (code execution, command execution, deserialization) and expand gradually.

## Example ruleset

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
  - pickle.loads
  - yaml.load
```

## Testing your rules

1. Create a small sample file with a known flow:

```python
import os

def f():
    x = input()
    os.system(x)
```

2. Run:

```bash
pyaegis ./sample.py --rules ./custom_rules.yml --debug
```

3. Confirm a finding is reported with the expected sink and line number.
