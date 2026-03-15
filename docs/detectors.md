# Detector Catalog

This page documents all vulnerability classes that PyAegis detects, the sources and sinks involved, and concrete code examples.

All detectors are driven by the [default rule set](https://github.com/mnbplus/PyAegis/blob/main/pyaegis/rules/default.yml). You can override or extend any of them with a custom YAML file.

---

## Rule ID: PYA-TAINT

PyAegis currently uses a single unified rule ID (`PYA-TAINT`) for all taint-flow findings. The **description** field specifies the exact sink reached. Granular rule IDs per vulnerability class are planned for a future release.

---

## Sources (Untrusted Input Origins)

A **source** is any expression or call that introduces untrusted, externally-controlled data into the program.

### Built-in / CLI / Environment

| Source | Description |
|--------|-------------|
| `input()` | Interactive user input |
| `sys.argv` | Command-line arguments |
| `os.getenv()` | Environment variable lookup |
| `os.environ.get()` | Environment variable lookup |
| `environ.get()` | Environment variable lookup |

### Flask / Werkzeug

| Source | Description |
|--------|-------------|
| `request` | Entire Flask request object |
| `request.args` | URL query parameters |
| `request.form` | POST form data |
| `request.values` | Combined GET + POST values |
| `request.data` | Raw request body bytes |
| `request.json` | Parsed JSON body |
| `request.get_json()` | Parsed JSON body (method) |
| `request.headers` | HTTP request headers |
| `request.cookies` | HTTP cookies |
| `request.files` | Uploaded files |
| `request.view_args` | URL route parameters |
| `request.get_data()` | Raw body (method) |

### Django

| Source | Description |
|--------|-------------|
| `request.GET` | URL query parameters |
| `request.POST` | POST form data |
| `request.COOKIES` | HTTP cookies |
| `request.FILES` | Uploaded files |
| `request.headers` | HTTP headers |
| `request.body` | Raw body bytes |
| `request.META` | Server and request metadata |

### FastAPI / Starlette

| Source | Description |
|--------|-------------|
| `request.query_params` | URL query parameters |
| `request.path_params` | URL path parameters |
| `request.headers` | HTTP headers |
| `request.cookies` | HTTP cookies |
| `request.state` | Custom request state |
| `request.json()` | JSON body |
| `request.form()` | Form data |
| `request.body()` | Raw body |

### Parsing Libraries

| Source | Description |
|--------|-------------|
| `json.loads()` | Parsed JSON (user-controlled string) |
| `ujson.loads()` | Fast JSON parser |
| `orjson.loads()` | Fast JSON parser |
| `xmltodict.parse()` | XML-to-dict parser |
| `cgi.FieldStorage` | Legacy CGI form input |
| `web.input()` | web.py input |

---

## Sanitizers (Taint Stoppers)

A **sanitizer** is a call that cleans or validates untrusted data. When tainted data passes through a sanitizer, PyAegis considers the output clean and will **not** report a finding downstream.

| Sanitizer | What it protects against |
|-----------|-------------------------|
| `html.escape()` | XSS / HTML injection |
| `markupsafe.escape()` | XSS / HTML injection |
| `bleach.clean()` | XSS / HTML injection |
| `django.utils.html.escape()` | XSS / HTML injection |
| `flask.escape()` | XSS / HTML injection |
| `xml.sax.saxutils.escape()` | XML injection |
| `os.path.abspath()` | Path traversal (partial) |
| `os.path.normpath()` | Path traversal (partial) |
| `pathlib.Path.resolve()` | Path traversal (partial) |
| `urllib.parse.urlparse()` | SSRF (partial) |
| `validators.url()` | SSRF / URL validation |

!!! note
    Sanitizer detection is heuristic. PyAegis recognizes these specific call patterns. Custom sanitizer functions can be added to the `sanitizers` list in your rules YAML.

---

## Vulnerability Classes

### 1. Code Injection

**Severity:** CRITICAL

Occurs when untrusted input is passed to a Python code execution function.

**Sinks:** `eval`, `exec`, `compile`, `builtins.eval`, `builtins.exec`, `runpy.run_module`, `runpy.run_path`

```python
# VULNERABLE
from flask import request

def dangerous():
    expr = request.args.get("expr")  # source
    result = eval(expr)              # sink: code injection
    return str(result)
```

```python
# SAFE — sanitizer breaks taint (note: eval on safe data still bad practice)
from flask import request

def process():
    raw = request.args.get("n")
    n = int(raw)       # type conversion — taint is broken heuristically
    return n * 2
```

---

### 2. OS Command Injection

**Severity:** CRITICAL

Occurs when untrusted input is interpolated into a shell command or passed as a command argument.

**Sinks:** `os.system`, `os.popen`, `os.spawn*`, `subprocess.call`, `subprocess.run`, `subprocess.Popen`, `subprocess.*`, `commands.getoutput`

```python
# VULNERABLE
import subprocess
from flask import request

def ping():
    host = request.args.get("host")           # source
    subprocess.call(["ping", "-c", "1", host]) # sink: command injection
```

```python
# VULNERABLE (string interpolation)
import os
from flask import request

def run():
    cmd = request.form.get("cmd")  # source
    os.system(f"run_tool {cmd}")   # sink: injection via f-string
```

---

### 3. Insecure Deserialization

**Severity:** CRITICAL

Deserializing attacker-controlled data with `pickle`, `dill`, `marshal`, or unsafe YAML loaders can lead to arbitrary code execution.

**Sinks:** `pickle.loads`, `pickle.load`, `cPickle.loads`, `dill.loads`, `marshal.loads`, `yaml.load`, `yaml.unsafe_load`, `ruamel.yaml.load`, `jsonpickle.decode`

```python
# VULNERABLE
import pickle
from flask import request

def load_session():
    data = request.cookies.get("session")  # source
    obj = pickle.loads(data.encode())      # sink: insecure deserialization
    return obj
```

!!! warning
    `yaml.load()` without an explicit `Loader=yaml.SafeLoader` is dangerous and will be flagged. Use `yaml.safe_load()` instead.

---

### 4. Server-Side Request Forgery (SSRF)

**Severity:** HIGH

Occurs when user-controlled input determines the URL of an outbound HTTP request, allowing attackers to probe internal services.

**Sinks:** `requests.get`, `requests.post`, `requests.request`, `httpx.get`, `httpx.post`, `httpx.request`, `urllib.request.urlopen`, `urllib3.PoolManager.request`, `urllib3.request`, `aiohttp.ClientSession.get`, `aiohttp.ClientSession.post`, `aiohttp.ClientSession.request`, `socket.create_connection`

```python
# VULNERABLE
import requests
from flask import request

def fetch():
    url = request.args.get("url")  # source
    resp = requests.get(url)       # sink: SSRF
    return resp.text
```

---

### 5. Path Traversal / Unsafe File Operations

**Severity:** HIGH

Occurs when user input controls a file path, allowing traversal outside the intended directory (`../../etc/passwd`).

**Sinks:** `open`, `builtins.open`, `os.open`, `os.remove`, `os.unlink`, `os.rmdir`, `os.rename`, `os.replace`, `os.mkdir`, `os.makedirs`, `shutil.copy`, `shutil.copyfile`, `shutil.copytree`, `shutil.move`, `shutil.rmtree`, `pathlib.Path`, `pathlib.Path.open`, `pathlib.Path.write_text`,
`pathlib.Path.write_bytes`, `tempfile.NamedTemporaryFile`

```python
# VULNERABLE
from flask import request

def read_file():
    filename = request.args.get("file")      # source
    with open(f"/var/data/{filename}") as f: # sink: path traversal
        return f.read()
```

```python
# SAFE — os.path.normpath + abspath act as sanitizers
import os
from flask import request

def read_file_safe():
    filename = request.args.get("file")
    safe_path = os.path.abspath(os.path.normpath(filename))  # sanitizer
    with open(safe_path) as f:
        return f.read()
```

---

### 6. SQL Injection

**Severity:** CRITICAL

Occurs when user-controlled strings are concatenated into SQL queries without parameterization.

**Sinks:** `sqlite3.connect`, `sqlite3.Connection.execute`, `sqlite3.Cursor.execute`, `sqlite3.Cursor.executemany`, `psycopg2.connect`, `psycopg2.cursor.execute`, `MySQLdb.connect`, `pymysql.connect`, `sqlalchemy.text`

```python
# VULNERABLE
import sqlite3
from flask import request

def search():
    name = request.args.get("name")                        # source
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name='{name}'")  # sink: SQL injection
    return cur.fetchall()
```

```python
# SAFE — use parameterized queries
cur.execute("SELECT * FROM users WHERE name=?", (name,))
```

---

### 7. Server-Side Template Injection (SSTI)

**Severity:** CRITICAL

Occurs when user input is rendered as a template string, allowing attackers to execute arbitrary expressions in the template engine.

**Sinks:** `jinja2.Template`, `jinja2.Environment.from_string`, `mako.template.Template`

```python
# VULNERABLE
from jinja2 import Template
from flask import request

def render():
    tmpl = request.args.get("tmpl")   # source
    t = Template(tmpl)                # sink: SSTI
    return t.render()
```

!!! danger
    SSTI in Jinja2 can escalate to full RCE. Always render with a fixed template and pass user data as context variables, never as the template string itself.

---

### 8. XML External Entity (XXE)

**Severity:** HIGH

Occurs when user-supplied XML is parsed with an XML library that expands external entities, potentially reading local files or triggering SSRF.

**Sinks:** `xml.etree.ElementTree.parse`, `xml.etree.ElementTree.fromstring`, `lxml.etree.parse`, `lxml.etree.fromstring`, `xml.dom.minidom.parse`, `xml.dom.minidom.parseString`

```python
# VULNERABLE
from xml.etree import ElementTree as ET
from flask import request

def parse_xml():
    data = request.get_data()      # source
    tree = ET.fromstring(data)     # sink: XXE
    return tree.find("name").text
```

---

### 9. ReDoS (Regex Denial of Service)

**Severity:** MEDIUM

Occurs when user-controlled input is compiled as a regex pattern or matched against a complex pattern, potentially causing catastrophic backtracking.

**Sinks:** `re.compile`, `re.match`, `re.search`

```python
# VULNERABLE
import re
from flask import request

def validate():
    pattern = request.args.get("pattern")  # source
    if re.match(pattern, "test"):          # sink: ReDoS
        return "match"
```

---

## Taint Propagation Rules

PyAegis propagates taint through the following expression types:

| Expression | Behaviour |
|------------|----------|
| `x = source()` | `x` becomes tainted |
| `y = x` | `y` becomes tainted if `x` is tainted |
| `z = f"{x} literal"` | `z` becomes tainted (f-string) |
| `z = x + " suffix"` | `z` becomes tainted (string concat) |
| `z = x % fmt` | `z` becomes tainted (%-format) |
| `z = [x, y]` | `z` becomes tainted if any element is tainted |
| `z = {"k": x}` | `z` becomes tainted if any value is tainted |
| `z = x.attr` | `z` becomes tainted if `x` is tainted |
| `z = x[key]` | `z` becomes tainted if `x` is tainted |
| `z += x` | `z` becomes tainted if `x` is tainted |
| `z = sanitizer(x)` | `z` is **clean** regardless of `x` |
| `z = local_fn(x)` | inter-procedural: `z` tainted if `local_fn` returns tainted given `x` |

---

## Adding Custom Detectors

To detect a custom sink or add a framework-specific source:

```yaml
# custom_rules.yml
inputs:
  - my_framework.get_user_input
  - my_framework.Request.body

sinks:
  - my_dangerous_exec
  - my_framework.shell_run
  - legacy_lib.*

sanitizers:
  - my_project.utils.clean_html
  - my_project.validators.validate_path
```

```bash
pyaegis ./src --rules custom_rules.yml
```

Glob patterns (`*`, `?`, `[seq]`) follow Python's `fnmatch` module semantics.
