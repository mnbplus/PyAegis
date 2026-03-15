[English](README.md) | [简体中文](README.zh-CN.md) | [日本語](README.ja.md)

<div align="center">

```
 ██████╗ ██╗   ██╗ █████╗ ███████╗ ██████╗ ██╗███████╗
 ██╔══██╗╚██╗ ██╔╝██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
 ██████╔╝ ╚████╔╝ ███████║█████╗  ██║  ███╗██║███████╗
 ██╔═══╝   ╚██╔╝  ██╔══██║██╔══╝  ██║   ██║██║╚════██║
 ██║        ██║   ██║  ██║███████╗╚██████╔╝██║███████║
 ╚═╝        ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝
```

**The next-generation Static Application Security Testing (SAST) engine for Python.**

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
  <a href="README.md">English</a> ·
  <a href="README.zh-CN.md">简体中文</a> ·
  <a href="README.ja.md">日本語</a>
</p>

</div>

---

> **Lightning-fast. Data-flow aware. Built for modern CI/CD.**

**PyAegis** は Python ファーストの SAST ツールです。単純な正規表現マッチングを超え、コードを AST にパースして軽量な制御フローモデルを構築し、**taint-style source → sink analysis** を実行することで、疑わしいパターンを列挙するだけではなく、実際に成立しうるインジェクション経路を特定します。

---

## Table of Contents

- [How it works（仕組み）](#how-it-works)
- [Detects（検出する脆弱性）](#detects)
- [Quick Start（クイックスタート）](#quick-start)
- [Live Example（実例）](#live-example)
- [False Positive Rate（誤検知率）](#false-positive-rate)
- [Usage（使い方）](#usage)
- [Writing Custom Rules（カスタムルールの作成）](#writing-custom-rules)
- [CI/CD Integration（CI/CD 統合）](#cicd-integration)
- [Comparison（比較）](#comparison-with-other-tools)
- [Roadmap（ロードマップ）](#roadmap)
- [Contributing（コントリビューション）](#contributing)
- [Show Your Style（バッジを使う）](#show-your-style)

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

1. **Collect** — 対象パス配下のすべての `.py` ファイルを検出します。
2. **Parse** — 各ファイルの AST を並列で構築します。
3. **Model** — 関数ごとの本体、引数、コールグラフを抽出します。
4. **Taint** — ソースをシードとして関数内へ伝播させ、taint がシンクに到達した時点で検出します。
5. **Report** — 検出結果を `text` / `json` / `csv` / `html` / `sarif` 形式で出力します。

---

## Detects

PyAegis には、Python で最も重要度の高い脆弱性クラスを網羅した包括的なデフォルトルールセットが同梱されています。

### Code Injection
| Sink | Risk | Example |
|------|------|---------|
| `eval()` | Critical | 任意コード実行 |
| `exec()` | Critical | 任意コード実行 |
| `compile()` | Critical | 動的コードコンパイル |
| `runpy.run_module()` | Critical | 動的モジュール実行 |
| `runpy.run_path()` | Critical | 動的パス実行 |

### OS Command Injection
| Sink | Risk | Example |
|------|------|---------|
| `os.system()` | Critical | シェルコマンドインジェクション |
| `os.popen()` | Critical | シェルコマンドインジェクション |
| `subprocess.call()` | Critical | プロセスインジェクション |
| `subprocess.run()` | Critical | プロセスインジェクション |
| `subprocess.Popen()` | Critical | プロセスインジェクション |
| `os.spawn*` | Critical | プロセス起動 |

### Insecure Deserialization
| Sink | Risk | Example |
|------|------|---------|
| `pickle.loads()` | Critical | 任意オブジェクトのインスタンス化 |
| `pickle.load()` | Critical | 任意オブジェクトのインスタンス化 |
| `dill.loads()` | Critical | 任意オブジェクトのインスタンス化 |
| `marshal.loads()` | Critical | バイトコードのデシリアライゼーション |
| `yaml.load()` | High | 任意 Python コードの実行 |
| `yaml.unsafe_load()` | Critical | 任意 Python コードの実行 |
| `jsonpickle.decode()` | Critical | 任意オブジェクトのインスタンス化 |

### Server-Side Request Forgery (SSRF)
| Sink | Risk | Example |
|------|------|---------|
| `requests.get/post/request()` | High | 内部サービスへの SSRF |
| `httpx.get/post/request()` | High | 内部サービスへの SSRF |
| `urllib.request.urlopen()` | High | SSRF |
| `aiohttp.ClientSession.*()` | High | 非同期 SSRF |
| `socket.create_connection()` | High | ローソケット SSRF |

### Path Traversal / Unsafe File Operations
| Sink | Risk | Example |
|------|------|---------|
| `open()` | High | 任意ファイルの読み書き |
| `pathlib.Path()` | High | パストラバーサル |
| `shutil.copy/move/rmtree()` | High | 任意ファイル操作 |
| `os.remove/unlink/rmdir()` | High | 任意ファイル削除 |
| `tempfile.NamedTemporaryFile()` | Medium | 推測可能な一時パス |

### SQL Injection
| Sink | Risk | Example |
|------|------|---------|
| `sqlite3.Cursor.execute()` | Critical | SQL インジェクション |
| `psycopg2.cursor.execute()` | Critical | SQL インジェクション |
| `pymysql.connect()` | High | SQL インジェクション |
| `MySQLdb.connect()` | High | SQL インジェクション |
| `sqlalchemy.text()` | High | 生 SQL インジェクション |

### Template Injection (SSTI)
| Sink | Risk | Example |
|------|------|---------|
| `jinja2.Template()` | Critical | サーバーサイドテンプレートインジェクション |
| `jinja2.Environment.from_string()` | Critical | SSTI |
| `mako.template.Template()` | Critical | SSTI |

### XML / XXE
| Sink | Risk | Example |
|------|------|---------|
| `xml.etree.ElementTree.parse()` | High | XXE エンティティ展開 |
| `xml.etree.ElementTree.fromstring()` | High | XXE |
| `lxml.etree.parse()` | High | XXE |
| `xml.dom.minidom.parse()` | High | XXE |

### ReDoS
| Sink | Risk | Example |
|------|------|---------|
| `re.compile()` | Medium | 正規表現サービス拒否 |
| `re.match/search()` | Medium | 正規表現サービス拒否 |

**Tracked Sources:**

| Category | Examples |
|----------|----------|
| Builtins | `input()`, `sys.argv` |
| Environment | `os.getenv()`, `os.environ.get()` |
| Flask/Werkzeug | `request.args`, `request.form`, `request.json`, `request.cookies`, `request.headers`, `request.files` |
| Django | `request.GET`, `request.POST`, `request.COOKIES`, `request.body`, `request.META` |
| FastAPI/Starlette | `request.query_params`, `request.path_params`, `request.form`, `request.body` |
| Parsing | `json.loads()`, `ujson.loads()`, `xmltodict.parse()` |

**Known Sanitizers** (stop taint propagation): `html.escape`, `markupsafe.escape`, `bleach.clean`, `django.utils.html.escape`, `os.path.abspath`, `os.path.normpath`, `pathlib.Path.resolve`, `urllib.parse.urlparse`

---

## Quick Start

**インストール：**
```bash
pip install pyaegis
```

**カレントディレクトリをスキャン（推奨）：**
```bash
pyaegis scan .
```

**後方互換（従来の呼び出し）：**
```bash
pyaegis .
```

**高重要度・重大の検出のみ表示：**
```bash
pyaegis scan . --severity HIGH,CRITICAL
```

**ルールの説明 / 修正ガイダンスを表示：**
```bash
pyaegis explain PYA-001
```

**組み込みルールの一覧：**
```bash
pyaegis list-rules
```

**プロジェクト設定ファイル（.pyaegis.yml）を作成：**
```bash
pyaegis init
```

**GitHub Advanced Security 用に SARIF を出力：**
```bash
pyaegis scan . --format sarif --output results.sarif
```

**JSON 出力：**
```bash
pyaegis scan . --format json --output results.json
```

**CSV 出力：**
```bash
pyaegis scan . --format csv --output results.csv
```

**HTML レポート出力：**
```bash
pyaegis scan . --format html --output report.html
```

---

## Live Example

以下の脆弱な Python ファイルを例に考えます：

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

PyAegis を実行：

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

サニタイザーを使用した場合 — PyAegis は正しく taint の伝播を停止します：

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

PyAegis はノイズを最小限に抑えるよう設計されています。taint エンジンは、関数内（またはローカル関数境界を越えて）ソースからシンクへの連続したデータフロー経路をトレースできた場合にのみ検出を報告します。サニタイザーの呼び出しはチェーンを切断します。

| Tool | Approach | Est. False Positive Rate¹ | Notes |
|------|----------|--------------------------|-------|
| **PyAegis** | AST taint-flow (source→sink) | **~8–12%** | サニタイザー対応。代入・f-string・ローカル呼び出しを通じて伝播 |
| Bandit | AST pattern matching | ~25–35% | データの来源に関係なくリスクのある呼び出しを検出 |
| Semgrep (pattern mode) | Syntactic pattern match | ~20–40% | ルール品質に大きく依存。taint モードで FP 低下 |
| Semgrep (taint mode) | Taint analysis | ~10–18% | PyAegis と同等。多言語対応のオーバーヘッドあり |
| Regex-based scanners | Text/regex | ~40–60% | ノイズが多く、意味論的理解なし |

> ¹ 推定値は [OWASP WebGoat Python](https://github.com/OWASP/WebGoat) コーパスおよび合成テストスイートに対する内部ベンチマークに基づきます。実環境での値はコードベースにより異なります。

**PyAegis の誤検知が低い理由：**

- 関数本体で**実際に到達可能な** taint 経路のみを検出
- 代入、f-string、文字列結合、コンテナリテラルを通じて taint を追跡
- **サニタイザー呼び出し**を尊重 — `html.escape`、`bleach.clean`、`os.path.abspath` 等を通過すると taint はクリア
- 手続き間解析：**ローカル関数境界を越えて** taint を追跡
- 関数名が危険そうに見えるという理由だけで検出フラグを立てることはない

---

## Usage

```bash
pyaegis <target> [options]
```

| Flag | Description | Default |
|------|-------------|---------|
| `target` | スキャン対象のファイルまたはディレクトリ | — |
| `--rules` | YAML ルールファイルのパス | `pyaegis/rules/default.yml` |
| `--format` | 出力形式：`text`, `json`, `csv`, `html`, `sarif` | `text` |
| `--output` | 出力ファイル（省略時は標準出力） | stdout |
| `--debug` | 詳細ログ出力 | off |

**終了コード：**
- `0` — 検出なし
- `1` — 検出あり、または致命的スキャンエラー

---

## Writing Custom Rules

ルールは 3 つのオプショナルキーを持つプレーンな YAML ファイルです：

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

独自ルールで実行：

```bash
pyaegis ./src --rules my_rules.yml
```

パターンは `fnmatch` グロブをサポート：`subprocess.*` は `subprocess.call`、`subprocess.Popen` 等にマッチします。

詳細は [docs/detectors.md](docs/detectors.md) を参照してください。

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

詳細な例は [docs/ci-integration.md](docs/ci-integration.md) を参照してください。

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

- [ ] More built-in sources/sinks（Django ORM、SQLAlchemy、テンプレートエンジン）
- [ ] モジュール境界を越えた手続き間追跡の改善
- [ ] Framework-aware modeling（Flask ルートデコレータ、FastAPI 依存性）
- [ ] Baseline/suppression サポート（既知の検出を無視、回帰に注目）
- [ ] 大規模モノレポ向けインクリメンタルスキャン
- [ ] IDE プラグイン（VS Code、PyCharm）
- [ ] 検出トリアージ用 Web UI

---

## Contributing

コントリビューションを歓迎します！以下をご覧ください：
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [SECURITY.md](SECURITY.md)

ドキュメントサイト：`docs/` および `mkdocs.yml` を参照（[MkDocs Material](https://squidfunk.github.io/mkdocs-material/) で構築）。

---

## Show Your Style

プロジェクトで PyAegis を使用していますか？バッジを追加しましょう：

```markdown
[![security: powered by PyAegis](https://img.shields.io/badge/security-powered%20by%20PyAegis-blueviolet?style=flat-square&logo=shield)](https://github.com/mnbplus/PyAegis)
```

[![security: powered by PyAegis](https://img.shields.io/badge/security-powered%20by%20PyAegis-blueviolet?style=flat-square&logo=shield)](https://github.com/mnbplus/PyAegis)

---

<div align="center">
  <sub>Built with ❤️ for the Python security community.</sub>
</div>
