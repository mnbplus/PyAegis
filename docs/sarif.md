# SARIF Output Format

PyAegis supports native **SARIF v2.1.0** output, the industry-standard format for static analysis results. SARIF integrates directly with GitHub Advanced Security, Azure DevOps, and many other code scanning platforms.

---

## Generating SARIF Output

```bash
pyaegis . --format sarif --output results.sarif
```

Or to stdout:

```bash
pyaegis . --format sarif
```

---

## SARIF Schema

PyAegis emits SARIF v2.1.0 conforming to the [official schema](https://json.schemastore.org/sarif-2.1.0.json).

### Top-level structure

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": { ... },
      "results": [ ... ]
    }
  ]
}
```

### Tool descriptor

```json
"tool": {
  "driver": {
    "name": "PyAegis",
    "informationUri": "https://github.com/PyAegis/PyAegis",
    "rules": []
  }
}
```

### Result object

Each finding maps to one SARIF `result` object:

```json
{
  "ruleId": "PYA-TAINT",
  "level": "error",
  "message": {
    "text": "Tainted data reaches sink: os.system"
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {
          "uri": "app/views.py"
        },
        "region": {
          "startLine": 42,
          "snippet": {
            "text": "run_command"
          }
        }
      }
    }
  ]
}
```

### Severity mapping

| PyAegis severity | SARIF level |
|-----------------|-------------|
| `CRITICAL` | `error` |
| `HIGH` | `warning` |
| `MEDIUM` | `warning` |
| `LOW` | `note` |

---

## Full Example

Given a scan of `vuln_app.py` with two findings:

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "PyAegis",
          "informationUri": "https://github.com/PyAegis/PyAegis",
          "rules": []
        }
      },
      "results": [
        {
          "ruleId": "PYA-TAINT",
          "level": "error",
          "message": {
            "text": "Tainted data reaches sink: os.system"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "vuln_app.py"
                },
                "region": {
                  "startLine": 12,
                  "snippet": {
                    "text": "run_command"
                  }
                }
              }
            }
          ]
        },
        {
          "ruleId": "PYA-TAINT",
          "level": "error",
          "message": {
            "text": "Tainted data reaches sink: pickle.loads"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "vuln_app.py"
                },
                "region": {
                  "startLine": 19,
                  "snippet": {
                    "text": "deserialize_data"
                  }
                }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

---

## GitHub Advanced Security Integration

Upload SARIF results to GitHub Code Scanning for inline PR annotations and a security dashboard:

```yaml
# .github/workflows/pyaegis.yml
name: PyAegis SAST

on: [push, pull_request]

jobs:
  sast:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install PyAegis
        run: pip install pyaegis

      - name: Run PyAegis
        run: pyaegis . --format sarif --output pyaegis.sarif
        continue-on-error: true  # upload results even if findings exist

      - name: Upload SARIF to GitHub Advanced Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: pyaegis.sarif
          category: pyaegis
```

After upload, findings appear in the **Security → Code scanning** tab of your repository with file, line, and description annotations.

---

## Azure DevOps Integration

```yaml
- task: PythonScript@0
  displayName: "Run PyAegis SAST"
  inputs:
    scriptSource: inline
    script: |
      pip install pyaegis
      pyaegis . --format sarif --output $(Build.ArtifactStagingDirectory)/pyaegis.sarif

- task: PublishBuildArtifacts@1
  inputs:
    PathtoPublish: "$(Build.ArtifactStagingDirectory)"
    ArtifactName: "sast-results"
```

---

## Consuming SARIF Programmatically

Python example to parse PyAegis SARIF output:

```python
import json

with open("results.sarif") as f:
    sarif = json.load(f)

for run in sarif["runs"]:
    for result in run["results"]:
        rule_id = result["ruleId"]
        level = result["level"]
        message = result["message"]["text"]
        loc = result["locations"][0]["physicalLocation"]
        uri = loc["artifactLocation"]["uri"]
        line = loc["region"]["startLine"]
        print(f"[{level.upper()}] {rule_id}: {message}")
        print(f"  → {uri}:{line}")
```

---

## SARIF Validation

Validate your SARIF output against the schema:

```bash
# Using sarif-tools
pip install sarif-tools
sarif summary pyaegis.sarif
sarif ls pyaegis.sarif

# Or validate schema online:
# https://sarifweb.azurewebsites.net/Validation
```

---

## Known Limitations

- Rule descriptors under `runs[].tool.driver.rules` are included for built-in rule IDs. For unknown rule IDs, PyAegis falls back to a generic descriptor.
- `artifactLocation.uri` uses the path as provided to the scanner; relative paths are recommended for portability.
- `region.snippet` is emitted when the source file is available; otherwise it is omitted.
