"""Synthetic vulnerability corpus for PyAegis benchmark testing.

Structure of each sample:
    code              : Python source code string
    expected_findings : int  -- number of HIGH/CRITICAL findings expected
    label             : short description
    category          : vulnerability class or 'safe' for FP traps
"""

# ---------------------------------------------------------------------------
# TRUE POSITIVE samples -- real vulnerabilities, must be detected
# ---------------------------------------------------------------------------

VULN_SAMPLES = [
    {
        "label": "os.system direct injection",
        "category": "command_injection",
        "expected_findings": 1,
        "code": (
            "import os\n"
            "from flask import request\n"
            "def run_cmd():\n"
            "    cmd = request.args.get('cmd')\n"
            "    os.system(cmd)\n"
        ),
    },
    {
        "label": "subprocess.run shell=True string",
        "category": "command_injection",
        "expected_findings": 1,
        "code": (
            "import subprocess\n"
            "from flask import request\n"
            "def run():\n"
            "    user = request.args.get('name')\n"
            "    subprocess.run('echo ' + user, shell=True)\n"
        ),
    },
    {
        "label": "eval user input",
        "category": "code_execution",
        "expected_findings": 1,
        "code": (
            "from flask import request\n"
            "def calc():\n"
            "    expr = request.args.get('expr')\n"
            "    result = eval(expr)\n"
            "    return str(result)\n"
        ),
    },
    {
        "label": "exec user input",
        "category": "code_execution",
        "expected_findings": 1,
        "code": (
            "from flask import request\n"
            "def run_code():\n"
            "    code = request.form.get('code')\n"
            "    exec(code)\n"
        ),
    },
    {
        "label": "sqlite3 raw SQL injection",
        "category": "sql_injection",
        "expected_findings": 1,
        "code": (
            "import sqlite3\n"
            "from flask import request\n"
            "def query():\n"
            "    username = request.args.get('user')\n"
            "    conn = sqlite3.connect('db.sqlite3')\n"
            "    conn.execute(\"SELECT * FROM users WHERE name='\" + username + \"'\")\n"
        ),
    },
    {
        "label": "open path traversal",
        "category": "path_traversal",
        "expected_findings": 1,
        "code": (
            "from flask import request\n"
            "def read_file():\n"
            "    filename = request.args.get('file')\n"
            "    with open(filename, 'r') as f:\n"
            "        return f.read()\n"
        ),
    },
    {
        "label": "SSRF requests.get",
        "category": "ssrf",
        "expected_findings": 1,
        "code": (
            "import requests\n"
            "from flask import request\n"
            "def proxy():\n"
            "    url = request.args.get('url')\n"
            "    return requests.get(url).text\n"
        ),
    },
    {
        "label": "SSRF urllib urlopen",
        "category": "ssrf",
        "expected_findings": 1,
        "code": (
            "import urllib.request\n"
            "from flask import request\n"
            "def fetch():\n"
            "    url = request.args.get('target')\n"
            "    urllib.request.urlopen(url)\n"
        ),
    },
    {
        "label": "pickle.loads deserialization",
        "category": "deserialization",
        "expected_findings": 1,
        "code": (
            "import pickle\n"
            "from flask import request\n"
            "def load_data():\n"
            "    blob = request.data\n"
            "    obj = pickle.loads(blob)\n"
            "    return str(obj)\n"
        ),
    },
    {
        "label": "yaml.load unsafe",
        "category": "deserialization",
        "expected_findings": 1,
        "code": (
            "import yaml\n"
            "from flask import request\n"
            "def parse_config():\n"
            "    data = request.data\n"
            "    return yaml.load(data)\n"
        ),
    },
    {
        "label": "XXE xml.etree.ElementTree.fromstring",
        "category": "xxe",
        "expected_findings": 1,
        "code": (
            "import xml.etree.ElementTree as ET\n"
            "from flask import request\n"
            "def parse_xml():\n"
            "    xml_data = request.data\n"
            "    root = ET.fromstring(xml_data)\n"
            "    return root.tag\n"
        ),
    },
    {
        "label": "jinja2.Template SSTI",
        "category": "template_injection",
        "expected_findings": 1,
        "code": (
            "from jinja2 import Template\n"
            "from flask import request\n"
            "def render():\n"
            "    tmpl = request.args.get('template')\n"
            "    return Template(tmpl).render()\n"
        ),
    },
    {
        "label": "os.popen injection",
        "category": "command_injection",
        "expected_findings": 1,
        "code": (
            "import os\n"
            "from flask import request\n"
            "def run():\n"
            "    q = request.args.get('q')\n"
            "    result = os.popen('grep ' + q + ' /var/log/app.log').read()\n"
            "    return result\n"
        ),
    },
    {
        "label": "subprocess.Popen shell=True",
        "category": "command_injection",
        "expected_findings": 1,
        "code": (
            "import subprocess\n"
            "from flask import request\n"
            "def run():\n"
            "    cmd = request.form.get('cmd')\n"
            "    proc = subprocess.Popen(cmd, shell=True)\n"
            "    proc.wait()\n"
        ),
    },
    {
        "label": "SSRF requests.post",
        "category": "ssrf",
        "expected_findings": 1,
        "code": (
            "import requests\n"
            "from flask import request\n"
            "def webhook():\n"
            "    url = request.json.get('webhook_url')\n"
            "    requests.post(url, json={'status': 'ok'})\n"
        ),
    },
    {
        "label": "pathlib.Path traversal",
        "category": "path_traversal",
        "expected_findings": 1,
        "code": (
            "from pathlib import Path\n"
            "from flask import request\n"
            "def read():\n"
            "    name = request.args.get('name')\n"
            "    return Path(name).read_text()\n"
        ),
    },
    {
        "label": "Django ORM .raw() injection",
        "category": "sql_injection",
        "expected_findings": 1,
        "code": (
            "from django.http import HttpRequest\n"
            "def search(request):\n"
            "    q = request.GET.get('q')\n"
            "    results = MyModel.objects.raw('SELECT * FROM app WHERE name=' + q)\n"
            "    return list(results)\n"
        ),
    },
    {
        "label": "f-string command injection",
        "category": "command_injection",
        "expected_findings": 1,
        "code": (
            "import os\n"
            "from flask import request\n"
            "def ping():\n"
            "    host = request.args.get('host')\n"
            "    os.system(f'ping -c 1 {host}')\n"
        ),
    },
    {
        "label": "sys.argv into eval",
        "category": "code_execution",
        "expected_findings": 1,
        "code": (
            "import sys\n"
            "def main():\n"
            "    expr = sys.argv[1]\n"
            "    result = eval(expr)\n"
            "    print(result)\n"
        ),
    },
    {
        "label": "input() into exec",
        "category": "code_execution",
        "expected_findings": 1,
        "code": (
            "def run():\n"
            "    code = input('Enter code: ')\n"
            "    exec(code)\n"
        ),
    },
    {
        "label": "shutil.rmtree path traversal",
        "category": "path_traversal",
        "expected_findings": 1,
        "code": (
            "import shutil\n"
            "from flask import request\n"
            "def cleanup():\n"
            "    path = request.args.get('path')\n"
            "    shutil.rmtree(path)\n"
        ),
    },
    {
        "label": "jsonpickle.decode deserialization",
        "category": "deserialization",
        "expected_findings": 1,
        "code": (
            "import jsonpickle\n"
            "from flask import request\n"
            "def load():\n"
            "    data = request.data\n"
            "    obj = jsonpickle.decode(data)\n"
            "    return str(obj)\n"
        ),
    },
    {
        "label": "SSRF httpx.get",
        "category": "ssrf",
        "expected_findings": 1,
        "code": (
            "import httpx\n"
            "from flask import request\n"
            "def fetch():\n"
            "    url = request.args.get('url')\n"
            "    return httpx.get(url).text\n"
        ),
    },
]

# ---------------------------------------------------------------------------
# FALSE POSITIVE TRAP samples -- safe code, must NOT be flagged HIGH/CRITICAL
# ---------------------------------------------------------------------------

SAFE_SAMPLES = [
    {
        "label": "subprocess.run list no shell -- safe",
        "category": "safe",
        "expected_findings": 0,
        "code": (
            "import subprocess\n"
            "from flask import request\n"
            "def run():\n"
            "    user = request.args.get('name')\n"
            "    subprocess.run(['ls', '-la', '/tmp'], shell=False)\n"
        ),
    },
    {
        "label": "html.escape sanitizer blocks sink -- safe",
        "category": "safe",
        "expected_findings": 0,
        "code": (
            "import os\n"
            "import html\n"
            "from flask import request\n"
            "def run():\n"
            "    user = request.args.get('cmd')\n"
            "    safe = html.escape(user)\n"
            "    os.system(safe)\n"
        ),
    },
    {
        "label": "os.path.abspath sanitizes open -- safe",
        "category": "safe",
        "expected_findings": 0,
        "code": (
            "import os\n"
            "from flask import request\n"
            "def read():\n"
            "    raw = request.args.get('file')\n"
            "    safe_path = os.path.abspath(raw)\n"
            "    with open(safe_path, 'r') as f:\n"
            "        return f.read()\n"
        ),
    },
    {
        "label": "eval with constant string -- safe",
        "category": "safe",
        "expected_findings": 0,
        "code": (
            "def compute():\n"
            "    result = eval('1 + 2 + 3')\n"
            "    return result\n"
        ),
    },
    {
        "label": "subprocess.run static list shell=True -- safe",
        "category": "safe",
        "expected_findings": 0,
        "code": (
            "import subprocess\n"
            "def deploy():\n"
            "    subprocess.run(['git', 'pull', '--rebase'], shell=True)\n"
        ),
    },
    {
        "label": "yaml.safe_load -- safe",
        "category": "safe",
        "expected_findings": 0,
        "code": (
            "import yaml\n"
            "from flask import request\n"
            "def parse():\n"
            "    data = request.data\n"
            "    return yaml.safe_load(data)\n"
        ),
    },
    {
        "label": "requests.get with constant URL -- safe",
        "category": "safe",
        "expected_findings": 0,
        "code": (
            "import requests\n"
            "def health_check():\n"
            "    return requests.get('https://api.internal/health').json()\n"
        ),
    },
    {
        "label": "open with constant path -- safe",
        "category": "safe",
        "expected_findings": 0,
        "code": (
            "def read_config():\n"
            "    with open('/etc/app/config.json', 'r') as f:\n"
            "        return f.read()\n"
        ),
    },
    {
        "label": "sqlite3 parameterized query -- safe",
        "category": "safe",
        "expected_findings": 0,
        "code": (
            "import sqlite3\n"
            "from flask import request\n"
            "def query():\n"
            "    username = request.args.get('user')\n"
            "    conn = sqlite3.connect('db.sqlite3')\n"
            "    conn.execute('SELECT * FROM users WHERE name=?', (username,))\n"
        ),
    },
    {
        "label": "no user input no taint -- safe",
        "category": "safe",
        "expected_findings": 0,
        "code": (
            "import os\n"
            "def cleanup():\n"
            "    os.system('rm -f /tmp/cache.lock')\n"
        ),
    },
    {
        "label": "re.compile with constant pattern -- safe",
        "category": "safe",
        "expected_findings": 0,
        "code": (
            "import re\n"
            "from flask import request\n"
            "def validate():\n"
            "    value = request.args.get('email')\n"
            "    pattern = re.compile(r'^[\\w.+-]+@[\\w-]+\\.[\\w.]+$')\n"
            "    return bool(pattern.match(value))\n"
        ),
    },
    {
        "label": "pathlib.Path.resolve sanitizes traversal -- safe",
        "category": "safe",
        "expected_findings": 0,
        "code": (
            "from pathlib import Path\n"
            "from flask import request\n"
            "def read():\n"
            "    name = request.args.get('name')\n"
            "    safe = Path(name).resolve()\n"
            "    return safe.read_text()\n"
        ),
    },
]

# ---------------------------------------------------------------------------
# Combined corpus exposed to benchmark tests
# ---------------------------------------------------------------------------

CORPUS = VULN_SAMPLES + SAFE_SAMPLES

# Sanity assertions (fail fast on import if corpus is malformed)
assert len(VULN_SAMPLES) >= 20, f"Need >= 20 vuln samples, got {len(VULN_SAMPLES)}"
assert len(SAFE_SAMPLES) >= 10, f"Need >= 10 safe samples, got {len(SAFE_SAMPLES)}"
assert all("expected_findings" in s for s in CORPUS), "Every sample needs expected_findings"
assert all("code" in s for s in CORPUS), "Every sample needs code"
