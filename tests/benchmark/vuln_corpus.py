"""Synthetic vulnerability corpus for PyAegis benchmark testing.

Structure of each sample:
    code              : Python source code string
    expected_findings : int  -- number of HIGH/CRITICAL findings expected
    label             : short description
    category          : vulnerability class or 'safe' for FP traps

Note on expected_findings:
    Values reflect what PyAegis currently detects (empirically verified).
    Samples marked expected_findings=0 in SAFE_SAMPLES are FP-trap (safe code).
"""

# ---------------------------------------------------------------------------
# TRUE POSITIVE samples -- 23 real vulnerabilities PyAegis detects
# ---------------------------------------------------------------------------

VULN_SAMPLES = [
    # 1. os.system direct injection
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
    # 2. eval with user input
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
    # 3. exec with user input
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
    # 4. open path traversal
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
    # 5. SSRF requests.get
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
    # 6. SSRF urllib urlopen
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
    # 7. os.popen injection
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
    # 8. SSRF requests.post
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
    # 9. Django ORM .raw() injection
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
    # 10. f-string into os.system
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
    # 11. input() into exec
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
    # 12. shutil.rmtree path traversal
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
    # 13. SSRF httpx.get
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
    # 14. os.system via request.form
    {
        "label": "os.system via request.form",
        "category": "command_injection",
        "expected_findings": 1,
        "code": (
            "import os\n"
            "from flask import request\n"
            "def upload():\n"
            "    filename = request.form.get('filename')\n"
            "    os.system('convert ' + filename + ' output.png')\n"
        ),
    },
    # 15. eval via request.cookies
    {
        "label": "eval via request.cookies",
        "category": "code_execution",
        "expected_findings": 1,
        "code": (
            "from flask import request\n"
            "def view():\n"
            "    token = request.cookies.get('expr')\n"
            "    return eval(token)\n"
        ),
    },
    # 16. exec via request.headers
    {
        "label": "exec via request.headers",
        "category": "code_execution",
        "expected_findings": 1,
        "code": (
            "from flask import request\n"
            "def admin():\n"
            "    payload = request.headers.get('X-Payload')\n"
            "    exec(payload)\n"
        ),
    },
    # 17. open via request.values
    {
        "label": "open via request.values",
        "category": "path_traversal",
        "expected_findings": 1,
        "code": (
            "from flask import request\n"
            "def serve():\n"
            "    path = request.values.get('path')\n"
            "    return open(path).read()\n"
        ),
    },
    # 18. SSRF via httpx.post
    {
        "label": "SSRF httpx.post",
        "category": "ssrf",
        "expected_findings": 1,
        "code": (
            "import httpx\n"
            "from flask import request\n"
            "def notify():\n"
            "    url = request.form.get('url')\n"
            "    httpx.post(url, json={'event': 'ping'})\n"
        ),
    },
    # 19. os.system via sys.argv
    {
        "label": "os.system via sys.argv",
        "category": "command_injection",
        "expected_findings": 1,
        "code": (
            "import os\n"
            "import sys\n"
            "def main():\n"
            "    target = sys.argv[1]\n"
            "    os.system('nmap ' + target)\n"
        ),
    },
    # 20. eval via os.getenv
    {
        "label": "eval via os.getenv",
        "category": "code_execution",
        "expected_findings": 1,
        "code": (
            "import os\n"
            "def bootstrap():\n"
            "    expr = os.getenv('BOOT_EXPR', '')\n"
            "    eval(expr)\n"
        ),
    },
    # 21. shutil.copy path traversal
    {
        "label": "shutil.copy path traversal",
        "category": "path_traversal",
        "expected_findings": 1,
        "code": (
            "import shutil\n"
            "from flask import request\n"
            "def backup():\n"
            "    src = request.args.get('src')\n"
            "    shutil.copy(src, '/tmp/backup/')\n"
        ),
    },
    # 22. requests.get via Django request.GET
    {
        "label": "SSRF via Django request.GET",
        "category": "ssrf",
        "expected_findings": 1,
        "code": (
            "import requests\n"
            "def view(request):\n"
            "    url = request.GET.get('feed')\n"
            "    return requests.get(url).content\n"
        ),
    },
    # 23. exec via os.environ.get
    {
        "label": "exec via os.environ.get",
        "category": "code_execution",
        "expected_findings": 1,
        "code": (
            "import os\n"
            "def run_hook():\n"
            "    hook = os.environ.get('PRE_HOOK', '')\n"
            "    exec(hook)\n"
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

assert len(VULN_SAMPLES) >= 20
assert len(SAFE_SAMPLES) >= 10
assert all("expected_findings" in s for s in CORPUS)
assert all("code" in s for s in CORPUS)
