"""Synthetic vulnerability corpus for PyAegis benchmark testing.

Structure of each sample:
    code              : Python source code string
    expected_findings : int — number of HIGH/CRITICAL findings expected
    label             : short description
    category          : vulnerability class or 'safe' for FP traps
"""

# ---------------------------------------------------------------------------
# TRUE POSITIVE samples — real vulnerabilities, must be detected
# ---------------------------------------------------------------------------

VULN_SAMPLES = [
    # ── 1. OS command injection via os.system ─────────────────────────────
    {
        "label": "os.system direct injection",
        "category": "command_injection",
        "expected_findings": 1,
        "code": """
import os
from flask import request

def run_cmd():
    cmd = request.args.get('cmd')
    os.system(cmd)
""",
    },
    # ── 2. subprocess.run with shell=True (string arg) ────────────────────
    {
        "label": "subprocess.run shell=True string",
        "category": "command_injection",
        "expected_findings": 1,
        "code": """
import subprocess
from flask import request

def run():
    user = request.args.get('name')
    subprocess.run('echo ' + user, shell=True)
""",
    },
    # ── 3. eval with user input ───────────────────────────────────────────
    {
        "label": "eval user input",
        "category": "code_execution",
        "expected_findings": 1,
        "code": """
from flask import request

def calc():
    expr = request.args.get('expr')
    result = eval(expr)
    return str(result)
""",
    },
    # ── 4. exec with user input ───────────────────────────────────────────
    {
        "label": "exec user input",
        "category": "code_execution",
        "expected_findings": 1,
        "code": """
from flask import request

def run_code():
    code = request.form.get('code')
    exec(code)
""",
    },
    # ── 5. SQL injection via sqlite3 raw execute ──────────────────────────
    {
        "label": "sqlite3 raw SQL injection",
        "category": "sql_injection",
        "expected_findings": 1,
        "code": """
import sqlite3
from flask import request

def query():
    username = request.args.get('user')
    conn = sqlite3.connect('db.sqlite3')
    conn.execute("SELECT * FROM users WHERE name='" + username + "'")
""",
    },
    # ── 6. Path traversal via open() ─────────────────────────────────────
    {
        "label": "open path traversal",
        "category": "path_traversal",
        "expected_findings": 1,
        "code": """
from flask import request

def read_file():
    filename = request.args.get('file')
    with open(filename, 'r') as f:
        return f.read()
""",
    },
    # ── 7. SSRF via requests.get ──────────────────────────────────────────
    {
        "label": "SSRF requests.get",
        "category": "ssrf",
        "expected_findings": 1,
        "code": """
import requests
from flask import request

def proxy():
    url = request.args.get('url')
    return requests.get(url).text
""",
    },
    # ── 8. SSRF via urllib.request.urlopen ────────────────────────────────
    {
        "label": "SSRF urllib urlopen",
        "category": "ssrf",
        "expected_findings": 1,
        "code": """
import urllib.request
from flask import request

def fetch():
    url = request.args.get('target')
    urllib.request.urlopen(url)
""",
    },
    # ── 9. Pickle deserialization ─────────────────────────────────────────
    {
        "label": "pickle.loads deserialization",
        "category": "deserialization",
        "expected_findings": 1,
        "code": """
import pickle
from flask import request

def load_data():
    blob = request.data
    obj = pickle.loads(blob)
    return str(obj)
""",
    },
    # ── 10. yaml.load unsafe ──────────────────────────────────────────────
    {
        "label": "yaml.load unsafe",
        "category": "deserialization",
        "expected_findings": 1,
        "code": """
import yaml
from flask import request

def parse_config():
    data = request.data
    return yaml.load(data)
""",
    },
    # ── 11. XXE via xml.etree.ElementTree ────────────────────────────────
    {
        "label": "XXE xml.etree.ElementTree.fromstring",
        "category": "xxe",
        "expected_findings": 1,
        "code": """
import xml.etree.ElementTree as ET
from flask import request

def parse_xml():
    xml_data = request.data
    root = ET.fromstring(xml_data)
    return root.tag
""",
    },
    # ── 12. Jinja2 template injection ────────────────────────────────────
    {
        "label": "jinja2.Template SSTI",
        "category": "template_injection",
        "expected_findings": 1,
        "code": """
from jinja2 import Template
from flask import request

def render():
    tmpl = request.args.get('template')
    return Template(tmpl).render()
""",
    },
    # ── 13. os.popen command injection ───────────────────────────────────
    {
        "label": "os.popen injection",
        "category": "command_injection",
        "expected_findings": 1,
        "code": """
import os
from flask import request

def run():
    q = request.args.get('q')
    result = os.popen('grep ' + q + ' /var/log/app.log').read()
    return result
""",
    },
    # ── 14. subprocess.Popen shell=True ──────────────────────────────────
    {
        "label": "subprocess.Popen shell=True",
        "category": "command_injection",
        "expected_findings": 1,
        "code": """
import subprocess
from flask import request

def run():
    cmd = request.form.get('cmd')
    proc = subprocess.Popen(cmd, shell=True)
    proc.wait()
""",
    },
    # ── 15. requests.post SSRF ────────────────────────────────────────────
    {
        "label": "SSRF requests.post",
        "category": "ssrf",
        "expected_findings": 1,
        "code": """
import requests
from flask import request

def webhook():
    url = request.json.get('webhook_url')
    requests.post(url, json={'status': 'ok'})
""",
    },
    # ── 16. pathlib.Path traversal ────────────────────────────────────────
    {
        "label": "pathlib.Path traversal",
        "category": "path_traversal",
        "expected_findings": 1,
        "code": """
from pathlib import Path
from flask import request

def read():
    name = request.args.get('name')
    return Path(name).read_text()
""",
    },
    # ── 17. Django ORM raw() SQL injection ───────────────────────────────
    {
        "label": "Django ORM .raw() injection",
        "category": "sql_injection",
        "expected_findings": 1,
        "code": """
from django.http import HttpRequest

def search(request):
    q = request.GET.get('q')
    results = MyModel.objects.raw('SELECT * FROM app_mymodel WHERE name=' + q)
    return list(results)
""",
    },
    # ── 18. f-string into os.system ──────────────────────────────────────
    {
        "label": "f-string command injection",
        "category": "command_injection",
        "expected_findings": 1,
        "code": """
import os
from flask import request

def ping():
    host = request.args.get('host')
    os.system(f'ping -c 1 {host}')
""",
    },
    # ── 19. sys.argv into eval ────────────────────────────────────────────
    {
        "label": "sys.argv into eval",
        "category": "code_execution",
        "expected_findings": 1,
        "code": """
import sys

def main():
    expr = sys.argv[1]
    result = eval(expr)
    print(result)
""",
    },
    # ── 20. input() into exec ─────────────────────────────────────────────
    {
        "label": "input() into exec",
        "category": "code_execution",
        "expected_findings": 1,
        "code": """
def run():
    code = input('Enter code: ')
    exec(code)
""",
    },
    # ── 21. shutil.rmtree path traversal ─────────────────────────────────
    {
        "label": "shutil.rmtree path traversal",
        "category": "path_traversal",
        "expected_findings": 1,
        "code": """
import shutil
from flask import request

def cleanup():
    path = request.args.get('path')
    shutil.rmtree(path)
""",
    },
    # ── 22. jsonpickle.decode deserialization ─────────────────────────────
    {
        "label": "jsonpickle.decode deserialization",
        "category": "deserialization",
        "expected_findings": 1,
        "code": """
import jsonpickle
from flask import request

def load():
    data = request.data
    obj = jsonpickle.decode(data)
    return str(obj)
""",
    },
    # ── 23. httpx.get SSRF ────────────────────────────────────────────────
    {
        "label": "SSRF httpx.get",
        "category": "ssrf",
        "expected_findings": 1,
        "code": """
import httpx
from flask import request

def fetch():
    url = request.args.get('url')
    return httpx.get(url).text
""",
    },
]

# ---------------------------------------------------------------------------
# FALSE POSITIVE TRAP samples — safe code, must NOT be flagged HIGH/CRITICAL
# ---------------------------------------------------------------------------

SAFE_SAMPLES = [
    # ── FP-1. subprocess.run with safe list arg (no shell=True) ──────────
    {
        "label": "subprocess.run list no shell — safe",
        "category": "safe",
        "expected_findings": 0,
        "code": """
import subprocess
from flask import request

def run():
    user = request.args.get('name')
    subprocess.run(['ls', '-la', '/tmp'], shell=False)
""",
    },
    # ── FP-2. html.escape sanitizer blocks os.system ─────────────────────
    {
        "label": "html.escape sanitizer blocks sink — safe",
        "category": "safe",
        "expected_findings": 0,
        "code": """
import os
import html
from flask import request

def run():
    user = request.args.get('cmd')
    safe = html.escape(user)
    os.system(safe)
""",
    },
    # ── FP-3. os.path.abspath sanitizes path traversal ───────────────────
    {
        "label": "os.path.abspath sanitizes open — safe",
        "category": "safe",
        "expected_findings": 0,
        "code": """
import os
from flask import request

def read():
    raw = request.args.get('file')
    safe_path = os.path.abspath(raw)
    with open(safe_path, 'r') as f:
        return f.read()
""",
    },
    # ── FP-4. Constant string passed to eval ─────────────────────────────
    {
        "label": "eval with constant string — safe",
        "category": "safe",
        "expected_findings": 0,
        "code": """
def compute():
    result = eval('1 + 2 + 3')
    return result
""",
    },
    # ── FP-5. subprocess.run list with shell=True — list arg, no string taint
    {
        "label": "subprocess.run static list shell=True — safe",
        "category": "safe",
        "expected_findings": 0,
        "code": """
import subprocess

def deploy():
    subprocess.run(['git', 'pull', '--rebase'], shell=True)
""",
    },
    # ── FP-6. yaml.safe_load (not yaml.load) ─────────────────────────────
    {
        "label": "yaml.safe_load — safe",
        "category": "safe",
        "expected_findings": 0,
        "code": """
import yaml
from flask import request

def parse():
    data = request.data
    return yaml.safe_load(data)
""",
    },
    # ── FP-7. Hard-coded URL for requests.get ────────────────────────────
    {
        "label": "requests.get with constant URL — safe",
        "category": "safe",
        "expected_findings": 0,
        "code": """
import requests

def health_check():
    return requests.get('https://api.internal/health').json()
""",
    },
    # ── FP-8. open() with hard-coded path ────────────────────────────────
    {
        "label": "open with constant path — safe",
        "category": "safe",
        "expected_findings": 0,
        "code": """
def read_config():
    with open('/etc/app/config.json', 'r') as f:
        return f.read()
""",
    },
    # ── FP-9. sqlite3 with parameterized query ────────────────────────────
    {
        "label": "sqlite3 parameterized query — safe",
        "category": "safe",
        "expected_findings": 0,
        "code": """
import sqlite3
from flask import request

def query():
    username = request.args.get('user')
    conn = sqlite3.connect('db.sqlite3')
    conn.execute('SELECT * FROM users WHERE name=?', (username,))
""",
    },
    # ── FP-10. No user input reaches sink at all ──────────────────────────
    {
        "label": "no user input, no taint — safe",
        "category": "safe",
        "expected_findings": 0,
        "code": """
import os

def cleanup():
    os.system('rm -f /tmp/cache.lock')
""",
    },
    # ── FP-11. re.compile with constant pattern ───────────────────────────
    {
        "label": "re.compile with