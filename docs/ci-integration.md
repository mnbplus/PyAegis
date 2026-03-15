# CI/CD integration

PyAegis is designed to run as a pipeline step:

- run scans on pushes / merge requests
- **fail the build** when findings are detected (exit code `1`)
- optionally export **SARIF** and upload it to your code scanning UI

## GitHub Actions

### Option A: CI gate (text output)

```yaml
name: PyAegis scan

on:
  pull_request:
  push:
    branches: ["main"]

jobs:
  pyaegis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install
        run: pip install pyaegis
      - name: Scan
        run: pyaegis .
```

### Option B: Upload SARIF to Code Scanning

```yaml
name: PyAegis SARIF

on:
  pull_request:
  push:
    branches: ["main"]

jobs:
  pyaegis-sarif:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install
        run: pip install pyaegis

      - name: Run scan (generate SARIF)
        run: pyaegis . --format sarif --output pyaegis-results.sarif
        continue-on-error: true

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: pyaegis-results.sarif
```

## GitLab CI

Add `.gitlab-ci.yml`:

```yaml
stages:
  - security

pyaegis:
  stage: security
  image: python:3.11
  script:
    - pip install pyaegis
    - pyaegis . --format json --output pyaegis-results.json
  artifacts:
    when: always
    paths:
      - pyaegis-results.json
```

If you want to fail the job on findings, remove `when: always` and rely on the exit code.

## Jenkins

In a `Jenkinsfile`:

```groovy
pipeline {
  agent any
  stages {
    stage('Install') {
      steps {
        sh 'python -m pip install --upgrade pip'
        sh 'pip install pyaegis'
      }
    }
    stage('Scan') {
      steps {
        sh 'pyaegis . --format sarif --output pyaegis-results.sarif'
      }
      post {
        always {
          archiveArtifacts artifacts: 'pyaegis-results.sarif', fingerprint: true
        }
      }
    }
  }
}
```

Note: Jenkins doesn't natively ingest SARIF unless you add a plugin or export into a format your security platform understands.

---

See also: [Quickstart](quickstart.md)
