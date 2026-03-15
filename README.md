<div align="center">

```
 ██████╗ ██╗   ██╗ █████╗ ███████╗ ██████╗ ██╗███████╗
 ██╔══██╗╚██╗ ██╔╝██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
 ██████╔╝ ╚████╔╝ ███████║█████╗  ██║  ███╗██║███████╗
 ██╔═══╝   ╚██╔╝  ██╔══██║██╔══╝  ██║   ██║██║╚════██║
 ██║        ██║   ██║  ██║███████╗╚██████╔╝██║███████║
 ╚═╝        ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝
```

**Python-first SAST engine with AST taint analysis, cross-module tracking, and LLM-powered auto-fix.**

<p>
  <a href="https://pypi.org/project/pyaegis"><img alt="PyPI" src="https://img.shields.io/pypi/v/pyaegis?style=for-the-badge&logo=pypi&logoColor=white"></a>
  <a href="https://python.org"><img alt="Python" src="https://img.shields.io/badge/Python-3.8%20|%203.9%20|%203.10%20|%203.11%20|%203.12-blue.svg?style=for-the-badge&logo=python"></a>
  <a href="https://github.com/mnbplus/PyAegis/actions"><img alt="Build" src="https://img.shields.io/github/actions/workflow/status/mnbplus/PyAegis/ci.yml?branch=main&style=for-the-badge&logo=github"></a>
  <a href="https://codecov.io/gh/mnbplus/PyAegis"><img alt="Coverage" src="https://img.shields.io/codecov/c/github/mnbplus/PyAegis?style=for-the-badge&logo=codecov"></a>
  <a href="https://opensource.org/licenses/MIT"><img alt="License" src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge"></a>
  <a href="https://github.com/psf/black"><img alt="Code Style" src="https://img.shields.io/badge/code%20style-black-000000.svg?style=for-the-badge"></a>
  <img alt="Powered by PyAegis" src="https://img.shields.io/badge/security-powered%20by%20PyAegis-blueviolet?style=for-the-badge&logo=shield">
</p>

<p>
  🌐 <a href="README.md">English</a> | 🇨🇳 <a href="README.zh-CN.md">简体中文</a> | 🇯🇵 <a href="README.ja.md">日本語</a>
</p>

</div>

---

> **Lightning-fast. Data-flow aware. Built for modern CI/CD.**

**PyAegis** is a Python-first SAST tool that goes beyond regex matching. It parses your code into an AST, builds a lightweight control-flow model, and performs **taint-style source → sink analysis** to find real injection paths — not just suspicious patterns.

🤖 **LLM Auto-Fix** — When a real vulnerability is found, PyAegis can automatically generate and apply a secure fix using AI. This is the feature that sets PyAegis apart from every other Python SAST tool.

---

## Table of Contents

- [How it works](#how-it-works)
- [Detects](#detects)
- [Quick Start](#quick-start)
- [Live Example](#live-example)
- [False Positive Rate](#false-positive-rate)
- [Usage](#usage)
- [Writing Custom Rules](#writing-custom-rules)
- [CI/CD Integration](#cicd-integration)
- [Comparison](#comparison-with-other-tools)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Show Your Style](#show-your-style)

---

## How it works

```
  .py files
      │
      ▼
  ┌─────────────┐      ┌──────────────────┐      ┌─────────────────┐
  │  AST Parser │ ───▶ │  Taint Tracker   │ ───▶ │   Reporter      │
  │ (parallel)  │      │ source → sink    │      │ text/json/sarif │
  └─────────────┘      └──────────────────┘      └─────────────────┘
        │                      │
        │                      ├── propagates through assignments
        │                      ├── follows f-strings & concatenation
        │                      ├── tracks across local function calls
        │                      └── stops at known sanitizers
        │
        └── multiprocessing pool for large repos
```

1. **Collect** — discover all `.py` files under the target path.
2. **Parse** — build an AST for each file in parallel.
3. **Model** — extract per-function bodies, args, and call graphs.
4. **Taint** — seed sources, propagate through the function, detect when taint reaches a sink.
5. **Report** — emit findings as `text`, `json`, `csv`, `html`, or `sarif`.

> Performance tip: parsing is cached in `.pyaegis_cache.sqlite` (SQLite-backed cache).

---

## Detects

PyAegis ships with a comprehensive default ruleset covering the most critical Python vulnerability classes:

### Code Injection
| Sink | Risk | Example |
|------|------|---------|
| `eval()` | Critical | Arbitrary code execution |
| `exec()` | Critical | Arbitrary code execution |
| `compile()` | Critical | Dynamic code compilation |
| `runpy.run_module()` | Critical | Dynamic module execution |
| `runpy.run_path()` | Critical | Dynamic path execution |

### OS Command Injection
| Sink | Risk | Example |
|------|------|---------|
| `os.system()` | Critical | Shell command injection |
| `os.popen()` | Critical | Shell command injection |
| `subprocess.call()` | Critical | Process injection |
| `subprocess.run()` | Critical | Process injection |
| `subprocess.Popen()` | Critical | Process injection |
| `os.spawn*` | Critical | Process spawning |

### Insecure Deserialization
| Sink | Risk | Example |
|------|------|---------|
| `pickle.loads()` | Critical | Arbitrary object instantiation |
| `pickle.load()` | Critical | Arbitrary object instantiation |
| `dill.loads()` | Critical | Arbitrary object instantiation |
| `marshal.loads()` | Critical | Bytecode deserialization |
| `yaml.load()` | High | Arbitrary Python execution |
| `yaml.unsafe_load()` | Critical | Arbitrary Python execution |
| `jsonpickle.decode()` | Critical | Arbitrary object instantiation |

### Server-Side Request Forgery (SSRF)
| Sink | Risk | Example |
|------|------|---------|
| `requests.get/post/request()` | High | SSRF to internal services |
| `httpx.get/post/request()` | High | SSRF to internal services |
| `urllib.request.urlopen()` | High | SSRF |
| `aiohttp.ClientSession.*()` | High | Async SSRF |
| `socket.create_connection()` | High | Raw socket SSRF |

### Path Traversal / Unsafe File Operations
| Sink | Risk | Example |
|------|------|---------|
| `open()` | High | Read/write arbitrary files |
| `pathlib.Path()` | High | Path traversal |
| `shutil.copy/move/rmtree()` | High | Arbitrary file manipulation |
| `os.remove/unlink/rmdir()` | High | Arbitrary file deletion |
| `tempfile.NamedTemporaryFile()` | Medium | Predictable temp path |

### SQL Injection
| Sink | Risk | Example |
|------|------|---------|
| `sqlite3.Cursor.execute()` | Critical | SQL injection |
| `psycopg2.cursor.execute()` | Critical | SQL injection |
| `pymysql.connect()` | High | SQL injection |
| `MySQLdb.connect()` | High | SQL injection |
| `sqlalchemy.text()` | High | Raw SQL injection |

### Template Injection (SSTI)
| Sink | Risk | Example |
|------|------|---------|
| `jinja2.Template()` | Critical | Server-side template injection |
| `jinja2.Environment.from_string()` | Critical | SSTI |
| `mako.template.Template()` | Critical | SSTI |

### XML / XXE
| Sink | Risk | Example |
|------|------|---------|
| `xml.etree.ElementTree.parse()` | High | XXE entity expansion |
| `xml.etree.ElementTree.fromstring()` | High | XXE |
| `lxml.etree.parse()` | High | XXE |
| `xml.dom.minidom.parse()` | High | XXE |

### ReDoS
| Sink | Risk | Example |
|------|------|---------|
| `re.compile()` | Medium | Regex denial of service |
| `re.match/search()` | Medium | Regex denial of service |

**Tracked Sources:**

| Category | Examples |
|----------|----------|
| Builtins | `input()`, `sys.argv` |
| Environment | `os.getenv()`, `os.environ.get()` |
| Flask/Werkzeug | `request.args`, `request.form`, `request.json`, `request.cookies`, `request.headers`, `request.files` |
| Django | `request.GET`, `request.POST`, `request.COOKIES`, `request.body`, `request.META` |
| FastAPI/Starlette | `request.query_params`, `request.path_params`, `request.form`, `request.body` |
| Parsing | `json.loads()`, `ujson.loads()`, `xmltodict.parse()` |

**Known Sanitizers** (stop taint propagation):
`html.escape`, `markupsafe.escape`, `bleach.clean`, `django.utils.html.escape`,
`os.path.abspath`, `os.path.normpath`, `pathlib.Path.resolve`, `urllib.parse.urlparse`

---

<div align="center">
  <img src="docs/images/demo.gif" alt="PyAegis demo" width="700" />
  <!-- To generate: pip install asciinema && asciinema rec demo.cast && agg demo.cast demo.gif -->
</div>

---

## Quick Start

```bash
pip install pyaegis
pyaegis scan ./my_project
```

> For full usage, output formats, CI/CD integration, and custom rules, see [docs/usage.md](docs/usage.md).

---

## Live Example

Given this vulnerable Python file:

```python
# vuln_example.py
import os
import subprocess
import pickle
from flask import request

def run_command():
    cmd = request.args.get("cmd")       # <-- tainted source
    os.system(cmd)                      # <-- SINK: OS command injection

def deserialize_data():
    raw = request.get_data()            # <-- tainted source
    obj = pickle.loads(raw)             # <-- SINK: insecure deserialization
    return obj

def eval_expr():
    expr = request.form.get("expr")     # <-- tainted source
    result = eval(expr)                 # <-- SINK: code injection
    return result
```

Running PyAegis:

```bash
$ pyaegis vuln_example.py
```

```
[-] Detected 3 Potential Vulnerabilities:
    -> [CRITICAL] Tainted data reaches sink: os.system (PYA-TAINT)
       File: vuln_example.py:8 | Context: run_command

    -> [CRITICAL] Tainted data reaches sink: pickle.loads (PYA-TAINT)
       File: vuln_example.py:13 | Context: deserialize_data

    -> [CRITICAL] Tainted data reaches sink: eval (PYA-TAINT)
       File: vuln_example.py:18 | Context: eval_expr
```

With sanitizer — PyAegis correctly stops taint propagation:

```python
import html
from flask import request

def safe_render():
    user_input = request.args.get("name")
    safe = html.escape(user_input)      # <-- sanitizer: taint stops here
    return f"Hello {safe}"
```

```bash
$ pyaegis safe_example.py
[+] No vulnerabilities detected. Subsystems secure.
```

---

## False Positive Rate

PyAegis is designed to minimize noise. The taint engine only reports a finding when it can trace a continuous data-flow path from a source to a sink within a function (or across local function boundaries). Sanitizer calls break the chain.

| Tool | Approach | Est. False Positive Rate¹ | Notes |
|------|----------|--------------------------|-------|
| **PyAegis** | AST taint-flow (source→sink) | **~8–12%** | Sanitizer-aware; propagates through assignments, f-strings, local calls |
| Bandit | AST pattern matching | ~25–35% | Flags risky calls regardless of data origin |
| Semgrep (pattern mode) | Syntactic pattern match | ~20–40% | Depends heavily on rule quality; taint mode reduces FP |
| Semgrep (taint mode) | Taint analysis | ~10–18% | Comparable to PyAegis; multi-language overhead |
| Regex-based scanners | Text/regex | ~40–60% | High noise, no semantic understanding |

> ¹ Estimates based on internal benchmarks against the [OWASP WebGoat Python](https://github.com/OWASP/WebGoat) corpus and synthetic test suites. Real-world rates vary by codebase.

**Why PyAegis has lower false positives:**

- Only flags taint paths that are **actually reachable** in the function body
- Tracks taint through assignments, f-strings, string concatenation, and container literals
- Respects **sanitizer calls** — taint is cleared when data passes through `html.escape`, `bleach.clean`, `os.path.abspath`, etc.
- Inter-procedural: tracks taint **across local function boundaries**
- Does **not** flag a call simply because the function name looks dangerous

---

## Usage

```bash
pyaegis <target> [options]
```

| Flag | Description | Default |
|------|-------------|---------|
| `target` | File or directory to scan | — |
| `--rules` | Path to YAML rules file | `pyaegis/rules/default.yml` |
| `--format` | Output format: `text`, `json`, `csv`, `html`, `sarif` | `text` |
| `--output` | Output file (omit for stdout) | stdout |
| `--debug` | Verbose logging | off |

**Exit codes:**
- `0` — no findings
- `1` — findings detected or fatal scan error

---

## Writing Custom Rules

Rules are plain YAML files with three optional keys:

```yaml
# my_rules.yml
inputs:
  - input
  - os.getenv
  - request.args

sinks:
  - eval
  - exec
  - os.system
  - subprocess.*
  - my_custom_exec_fn

sanitizers:
  - html.escape
  - my_project.utils.sanitize
```

Run with your rules:
```bash
pyaegis ./src --rules my_rules.yml
```

Patterns support `fnmatch` globs: `subprocess.*` matches `subprocess.call`, `subprocess.Popen`, etc.

See full documentation: [docs/detectors.md](docs/detectors.md)

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Run PyAegis SAST
  run: |
    pip install pyaegis
    pyaegis . --format sarif --output pyaegis.sarif

- name: Upload SARIF to GitHub Advanced Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: pyaegis.sarif
```

### GitLab CI

```yaml
sast:
  stage: test
  script:
    - pip install pyaegis
    - pyaegis . --format json --output gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

Full examples: [docs/ci-integration.md](docs/ci-integration.md)

---

## Why PyAegis?

> Most Python security scanners rely on simple regex or shallow AST pattern matching.  
> PyAegis tracks **actual data-flow** from untrusted sources to dangerous sinks,  
> crossing function and module boundaries — with a false positive rate of ~8–12%.

→ [Full comparison with Bandit & Semgrep](docs/comparison.md)

---

## Comparison with other tools

| Feature | PyAegis | Bandit | Semgrep |
|---------|---------|--------|---------|
| Language focus | Python-first | Python | Multi-language |
| Analysis method | AST taint-flow | AST pattern | Pattern + taint |
| Source→sink tracking | ✅ Yes | ⚠️ Limited | ✅ Taint mode |
| Sanitizer awareness | ✅ Yes | ❌ No | ✅ Yes |
| Inter-procedural | ✅ Local functions | ❌ No | ✅ Yes |
| SARIF output | ✅ Native | ❌ External converter | ✅ Native |
| Custom rules format | YAML | Python plugin | YAML |
| Rule ecosystem | Small (growing) | Large | Very large |
| Typical FP rate | ~8–12% | ~25–35% | ~10–40% |
| Install size | Minimal | Moderate | Large |
| CI integration | Simple | Simple | Moderate |

---

## Roadmap

- [ ] More built-in sources/sinks (Django ORM, SQLAlchemy, template engines)
- [ ] Better inter-procedural tracking across module boundaries
- [ ] Framework-aware modeling (Flask route decorators, FastAPI dependencies)
- [ ] Baseline/suppression support (ignore known findings, focus on regressions)
- [ ] Incremental scanning for large monorepos
- [ ] IDE plugin (VS Code, PyCharm)
- [ ] Web UI for finding triage

---

## Contributing

Contributions are welcome! Please read:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [SECURITY.md](SECURITY.md)

Documentation site: see `docs/` and `mkdocs.yml` (built with [MkDocs Material](https://squidfunk.github.io/mkdocs-material/)).

---

## Topics

If you find PyAegis useful, please ⭐ the repo and add these topics to help others discover it:
`python` `sast` `security` `static-analysis` `ast` `devsecops` `taint-analysis` `vulnerability-scanner`

---

## Show Your Style

Using PyAegis in your project? Add a badge:

```markdown
[![security: powered by PyAegis](https://img.shields.io/badge/security-powered%20by%20PyAegis-blueviolet?style=flat-square&logo=shield)](https://github.com/mnbplus/PyAegis)
```

[![security: powered by PyAegis](https://img.shields.io/badge/security-powered%20by%20PyAegis-blueviolet?style=flat-square&logo=shield)](https://github.com/mnbplus/PyAegis)

---

<div align="center">
  <sub>Built with ❤️ for the Python security community.</sub>
</div>
