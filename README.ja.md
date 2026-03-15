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

**Pythonのための次世代 静的アプリケーションセキュリティテスト（SAST）エンジン。**

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

> **超高速。データフロー対応。モダンな CI/CD のために設計。**

**PyAegis** は Python ファーストの SAST ツールで、単なる正規表現マッチングを超えています。コードを AST に解析し、軽量な制御フローモデルを構築し、**テイント式 source → sink 分析**を実行して、疑わしいパターンではなく実際のインジェクション経路を見つけます。

---

## 目次

- [仕組み](#how-it-works)
- [検出対象](#detects)
- [クイックスタート](#quick-start)
- [実例](#live-example)
- [誤検知率](#false-positive-rate)
- [使い方](#usage)
- [カスタムルールの作成](#writing-custom-rules)
- [CI/CD 連携](#cicd-integration)
- [他ツールとの比較](#comparison-with-other-tools)
- [ロードマップ](#roadmap)
- [コントリビューション](#contributing)
- [スタイルを示す](#show-your-style)

---

<a id="how-it-works"></a>

## 仕組み

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

1. **収集** — ターゲットパス配下のすべての `.py` ファイルを発見。
2. **解析** — 各ファイルの AST を並列で構築。
3. **モデリング** — 関数ごとのボディ、引数、コールグラフを抽出。
4. **テイント** — sources をシードし、関数内に伝播させ、テイントが sinks に到達したときに検出。
5. **レポート** — 結果を `text`、`json`、`csv`、`html`、または `sarif` として出力。

> パフォーマンスのヒント：解析は `.pyaegis_cache.sqlite`（SQLite バックエンドキャッシュ）にキャッシュされます。

---

<a id="detects"></a>

## 検出対象

PyAegis には、最も重要な Python 脆弱性クラスをカバーする包括的なデフォルトルールセットが付属しています：

### コードインジェクション
| Sink | リスク | 例 |
|------|------|---------|
| `eval()` | Critical | 任意コード実行 |
| `exec()` | Critical | 任意コード実行 |
| `compile()` | Critical | 動的コードコンパイル |
| `runpy.run_module()` | Critical | 動的モジュール実行 |
| `runpy.run_path()` | Critical | 動的パス実行 |

### OS コマンドインジェクション
| Sink | リスク | 例 |
|------|------|---------|
| `os.system()` | Critical | シェルコマンドインジェクション |
| `os.popen()` | Critical | シェルコマンドインジェクション |
| `subprocess.call()` | Critical | プロセスインジェクション |
| `subprocess.run()` | Critical | プロセスインジェクション |
| `subprocess.Popen()` | Critical | プロセスインジェクション |
| `os.spawn*` | Critical | プロセス生成 |

### 安全でないデシリアライズ
| Sink | リスク | 例 |
|------|------|---------|
| `pickle.loads()` | Critical | 任意オブジェクトのインスタンス化 |
| `pickle.load()` | Critical | 任意オブジェクトのインスタンス化 |
| `dill.loads()` | Critical | 任意オブジェクトのインスタンス化 |
| `marshal.loads()` | Critical | バイトコードデシリアライズ |
| `yaml.load()` | High | 任意 Python 実行 |
| `yaml.unsafe_load()` | Critical | 任意 Python 実行 |
| `jsonpickle.decode()` | Critical | 任意オブジェクトのインスタンス化 |

### サーバーサイドリクエストフォージェリ（SSRF）
| Sink | リスク | 例 |
|------|------|---------|
| `requests.get/post/request()` | High | 内部サービスへの SSRF |
| `httpx.get/post/request()` | High | 内部サービスへの SSRF |
| `urllib.request.urlopen()` | High | SSRF |
| `aiohttp.ClientSession.*()` | High | 非同期 SSRF |
| `socket.create_connection()` | High | 生ソケット SSRF |

### パストラバーサル / 安全でないファイル操作
| Sink | リスク | 例 |
|------|------|---------|
| `open()` | High | 任意ファイルの読み書き |
| `pathlib.Path()` | High | パストラバーサル |
| `shutil.copy/move/rmtree()` | High | 任意ファイル操作 |
| `os.remove/unlink/rmdir()` | High | 任意ファイル削除 |
| `tempfile.NamedTemporaryFile()` | Medium | 予測可能な一時パス |

### SQL インジェクション
| Sink | リスク | 例 |
|------|------|---------|
| `sqlite3.Cursor.execute()` | Critical | SQL インジェクション |
| `psycopg2.cursor.execute()` | Critical | SQL インジェクション |
| `pymysql.connect()` | High | SQL インジェクション |
| `MySQLdb.connect()` | High | SQL インジェクション |
| `sqlalchemy.text()` | High | Raw SQL インジェクション |

### テンプレートインジェクション（SSTI）
| Sink | リスク | 例 |
|------|------|---------|
| `jinja2.Template()` | Critical | サーバーサイドテンプレートインジェクション |
| `jinja2.Environment.from_string()` | Critical | SSTI |
| `mako.template.Template()` | Critical | SSTI |

### XML / XXE
| Sink | リスク | 例 |
|------|------|---------|
| `xml.etree.ElementTree.parse()` | High | XXE エンティティ展開 |
| `xml.etree.ElementTree.fromstring()` | High | XXE |
| `lxml.etree.parse()` | High | XXE |
| `xml.dom.minidom.parse()` | High | XXE |

### ReDoS
| Sink | リスク | 例 |
|------|------|---------|
| `re.compile()` | Medium | 正規表現 DoS |
| `re.match/search()` | Medium | 正規表現 DoS |

**Tracked Sources：**

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

<a id="quick-start"></a>

## クイックスタート

**インストール：**
```bash
pip install pyaegis
```

**カレントディレクトリをスキャン（推奨）：**
```bash
pyaegis scan .
```

**後方互換（こちらも利用可能）：**
```bash
pyaegis .
```

**HIGH/CRITICAL のみ表示：**
```bash
pyaegis scan . --severity HIGH,CRITICAL
```

**ルールの説明 / 修正ガイダンス：**
```bash
pyaegis explain PYA-001
```

**組み込みルール一覧：**
```bash
pyaegis list-rules
```

**プロジェクト設定ファイル（.pyaegis.yml）を作成：**
```bash
pyaegis init
```

**GitHub Advanced Security 向け SARIF を出力：**
```bash
pyaegis scan . --format sarif --output results.sarif
```

**JSON を出力：**
```bash
pyaegis scan . --format json --output results.json
```

**CSV を出力：**
```bash
pyaegis scan . --format csv --output results.csv
```

**HTML レポートを出力：**
```bash
pyaegis scan . --format html --output report.html
```

---

<a id="live-example"></a>

## 実例

次の脆弱な Python ファイルを例にします：

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

サニタイザを通すと、PyAegis は正しくテイント伝播を停止します：

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

<a id="false-positive-rate"></a>

## 誤検知率

PyAegis はノイズを最小化するよう設計されています。テイントエンジンは、関数内（またはローカル関数境界を跨いで）source から sink まで連続したデータフロー経路をトレースできる場合のみ、検出を報告します。サニタイザ呼び出しはチェーンを断ち切ります。

| Tool | Approach | Est. False Positive Rate¹ | Notes |
|------|----------|--------------------------|-------|
| **PyAegis** | AST taint-flow (source→sink) | **~8–12%** | Sanitizer-aware; propagates through assignments, f-strings, local calls |
| Bandit | AST pattern matching | ~25–35% | Flags risky calls regardless of data origin |
| Semgrep (pattern mode) | Syntactic pattern match | ~20–40% | Depends heavily on rule quality; taint mode reduces FP |
| Semgrep (taint mode) | Taint analysis | ~10–18% | Comparable to PyAegis; multi-language overhead |
| Regex-based scanners | Text/regex | ~40–60% | High noise, no semantic understanding |

> ¹ Estimates based on internal benchmarks against the [OWASP WebGoat Python](https://github.com/OWASP/WebGoat) corpus and synthetic test suites. Real-world rates vary by codebase.

**なぜ PyAegis は誤検知が少ないのか：**

- 関数ボディ内で**実際に到達可能**なテイント経路のみを報告
- 代入、f-string、文字列連結、コンテナリテラルを通じてテイントを追跡
- **サニタイザ呼び出し**を尊重 — データが `html.escape`、`bleach.clean`、`os.path.abspath` などを通るとテイントをクリア
- 手続き間：ローカル関数境界を跨いでテイントを追跡
- 関数名が危険そうというだけではフラグを立てない

<a id="usage"></a>

## 使い方

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

**終了コード：**
- `0` — 検出なし
- `1` — 検出あり、または致命的なスキャンエラー

---

<a id="writing-custom-rules"></a>

## カスタムルールの作成

ルールは 3 つの任意キーを持つプレーンな YAML ファイルです：

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

自作ルールで実行：
```bash
pyaegis ./src --rules my_rules.yml
```

パターンは `fnmatch` グロブに対応：`subprocess.*` は `subprocess.call`、`subprocess.Popen` などにマッチします。

詳しくは： [docs/detectors.md](docs/detectors.md)

---

<a id="cicd-integration"></a>

## CI/CD 連携

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

完全な例： [docs/ci-integration.md](docs/ci-integration.md)

---

<a id="comparison-with-other-tools"></a>

## 他ツールとの比較

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

<a id="roadmap"></a>

## ロードマップ

- [ ] More built-in sources/sinks (Django ORM, SQLAlchemy, template engines)
- [ ] Better inter-procedural tracking across module boundaries
- [ ] Framework-aware modeling (Flask route decorators, FastAPI dependencies)
- [ ] Baseline/suppression support (ignore known findings, focus on regressions)
- [ ] Incremental scanning for large monorepos
- [ ] IDE plugin (VS Code, PyCharm)
- [ ] Web UI for finding triage

---

<a id="contributing"></a>

## コントリビューション

貢献は歓迎です！以下を参照してください：

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [SECURITY.md](SECURITY.md)

ドキュメントサイト： `docs/` と `mkdocs.yml` を参照（[MkDocs Material](https://squidfunk.github.io/mkdocs-material/) で構築）。

---

<a id="show-your-style"></a>

## スタイルを示す

プロジェクトで PyAegis を使っていますか？バッジを追加しましょう：

```markdown
[![security: powered by PyAegis](https://img.shields.io/badge/security-powered%20by%20PyAegis-blueviolet?style=flat-square&logo=shield)](https://github.com/mnbplus/PyAegis)
```

[![security: powered by PyAegis](https://img.shields.io/badge/security-powered%20by%20PyAegis-blueviolet?style=flat-square&logo=shield)](https://github.com/mnbplus/PyAegis)

---

<div align="center">
  <sub>Built with ❤️ for the Python security community.</sub>
</div>
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

**Python向けの次世代静的アプリケーションセキュリティテスト（SAST）エンジン。**

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

> **超高速。データフロー対応。モダンなCI/CDのために設計。**

**PyAegis** は Python ファーストの SAST ツールです。正規表現マッチングを超え、コードを AST に解析し、軽量な制御フローモデルを構築して、**テイント方式の source → sink 解析**によって本物のインジェクション経路を検出します。単なる怪しいパターン検出にとどまりません。

---

## 目次

- [仕組み](#仕組み)
- [検出する脆弱性](#検出する脆弱性)
- [クイックスタート](#クイックスタート)
- [実行例](#実行例)
- [誤検知率](#誤検知率)
- [使い方](#使い方)
- [カスタムルールの作成](#カスタムルールの作成)
- [CI/CD統合](#cicd統合)
- [他ツールとの比較](#他ツールとの比較)
- [ロードマップ](#ロードマップ)
- [コントリビューション](#コントリビューション)
- [スタイルを見せよう](#スタイルを見せよう)

---

## 仕組み

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

1. **収集** — 対象パス配下の `.py` ファイルをすべて発見。
2. **解析** — 各ファイルの AST を並列に構築。
3. **モデル化** — 関数ごとの本体・引数・コールグラフを抽出。
4. **テイント** — source を播種し、関数内で伝播させ、汚染が sink に到達したら検出。
5. **レポート** — `text`、`json`、`csv`、`html`、`sarif` で結果を出力。

> パフォーマンスのヒント: 解析結果は `.pyaegis_cache.sqlite` にキャッシュされます（SQLite バックエンド）。

---
## 検出する脆弱性

PyAegis には Python の重要な脆弱性クラスを網羅したデフォルトルールセットが同梱されています。

### コードインジェクション
| Sink | リスク | 例 |
|------|------|---------|
| `eval()` | Critical | 任意のコード実行 |
| `exec()` | Critical | 任意のコード実行 |
| `compile()` | Critical | 動的コードのコンパイル |
| `runpy.run_module()` | Critical | 動的モジュール実行 |
| `runpy.run_path()` | Critical | 動的パス実行 |

### OS コマンドインジェクション
| Sink | リスク | 例 |
|------|------|---------|
| `os.system()` | Critical | シェルコマンドインジェクション |
| `os.popen()` | Critical | シェルコマンドインジェクション |
| `subprocess.call()` | Critical | プロセスインジェクション |
| `subprocess.run()` | Critical | プロセスインジェクション |
| `subprocess.Popen()` | Critical | プロセスインジェクション |
| `os.spawn*` | Critical | プロセス生成 |

### 不安全なデシリアライゼーション
| Sink | リスク | 例 |
|------|------|---------|
| `pickle.loads()` | Critical | 任意のオブジェクト生成 |
| `pickle.load()` | Critical | 任意のオブジェクト生成 |
| `dill.loads()` | Critical | 任意のオブジェクト生成 |
| `marshal.loads()` | Critical | バイトコードのデシリアライズ |
| `yaml.load()` | High | 任意の Python 実行 |
| `yaml.unsafe_load()` | Critical | 任意の Python 実行 |
| `jsonpickle.decode()` | Critical | 任意のオブジェクト生成 |

### サーバーサイドリクエストフォージェリ（SSRF）
| Sink | リスク | 例 |
|------|------|---------|
| `requests.get/post/request()` | High | 内部サービスへの SSRF |
| `httpx.get/post/request()` | High | 内部サービスへの SSRF |
| `urllib.request.urlopen()` | High | SSRF |
| `aiohttp.ClientSession.*()` | High | 非同期 SSRF |
| `socket.create_connection()` | High | 生ソケット SSRF |

### パストラバーサル / 不安全なファイル操作
| Sink | リスク | 例 |
|------|------|---------|
| `open()` | High | 任意ファイルの読み書き |
| `pathlib.Path()` | High | パストラバーサル |
| `shutil.copy/move/rmtree()` | High | 任意ファイル操作 |
| `os.remove/unlink/rmdir()` | High | 任意ファイル削除 |
| `tempfile.NamedTemporaryFile()` | Medium | 予測可能な一時パス |

### SQL インジェクション
| Sink | リスク | 例 |
|------|------|---------|
| `sqlite3.Cursor.execute()` | Critical | SQL インジェクション |
| `psycopg2.cursor.execute()` | Critical | SQL インジェクション |
| `pymysql.connect()` | High | SQL インジェクション |
| `MySQLdb.connect()` | High | SQL インジェクション |
| `sqlalchemy.text()` | High | 生 SQL インジェクション |

### テンプレートインジェクション（SSTI）
| Sink | リスク | 例 |
|------|------|---------|
| `jinja2.Template()` | Critical | サーバーサイドテンプレートインジェクション |
| `jinja2.Environment.from_string()` | Critical | SSTI |
| `mako.template.Template()` | Critical | SSTI |

### XML / XXE
| Sink | リスク | 例 |
|------|------|---------|
| `xml.etree.ElementTree.parse()` | High | XXE エンティティ展開 |
| `xml.etree.ElementTree.fromstring()` | High | XXE |
| `lxml.etree.parse()` | High | XXE |
| `xml.dom.minidom.parse()` | High | XXE |

### ReDoS
| Sink | リスク | 例 |
|------|------|---------|
| `re.compile()` | Medium | 正規表現 DoS |
| `re.match/search()` | Medium | 正規表現 DoS |

**追跡対象のソース:**

| カテゴリ | 例 |
|----------|----------|
| Builtins | `input()`, `sys.argv` |
| Environment | `os.getenv()`, `os.environ.get()` |
| Flask/Werkzeug | `request.args`, `request.form`, `request.json`, `request.cookies`, `request.headers`, `request.files` |
| Django | `request.GET`, `request.POST`, `request.COOKIES`, `request.body`, `request.META` |
| FastAPI/Starlette | `request.query_params`, `request.path_params`, `request.form`, `request.body` |
| Parsing | `json.loads()`, `ujson.loads()`, `xmltodict.parse()` |

**既知のサニタイザー**（テイント伝播を停止）:
`html.escape`, `markupsafe.escape`, `bleach.clean`, `django.utils.html.escape`,
`os.path.abspath`, `os.path.normpath`, `pathlib.Path.resolve`, `urllib.parse.urlparse`

---

## クイックスタート

**インストール:**
```bash
pip install pyaegis
```

**カレントディレクトリをスキャン（推奨）:**
```bash
pyaegis scan .
```

**後方互換（従来コマンドも利用可能）:**
```bash
pyaegis .
```

**高/重大のみ表示:**
```bash
pyaegis scan . --severity HIGH,CRITICAL
```

**ルールの説明 / 修正ガイダンス:**
```bash
pyaegis explain PYA-001
```

**内蔵ルール一覧:**
```bash
pyaegis list-rules
```

**プロジェクト設定ファイルを作成（.pyaegis.yml）:**
```bash
pyaegis init
```

**GitHub Advanced Security 向けに SARIF を出力:**
```bash
pyaegis scan . --format sarif --output results.sarif
```

**JSON を出力:**
```bash
pyaegis scan . --format json --output results.json
```

**CSV を出力:**
```bash
pyaegis scan . --format csv --output results.csv
```

**HTML レポートを出力:**
```bash
pyaegis scan . --format html --output report.html
```

---

## 実行例

次のような脆弱な Python ファイルがあるとします:

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

PyAegis の実行結果:

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

サニタイザーを使うと、PyAegis は正しくテイント伝播を停止します:

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

## 誤検知率

PyAegis はノイズを最小限に抑えるよう設計されています。テイントエンジンは、関数内（またはローカル関数間）で source から sink までの連続したデータフロー経路を追跡できた場合にのみ検出を報告します。サニタイザー呼び出しはチェーンを切断します。

| ツール | アプローチ | 推定誤検知率¹ | 備考 |
|------|----------|--------------------------|-------|
| **PyAegis** | AST テイントフロー（source→sink） | **~8–12%** | サニタイザー対応、代入・f文字列・ローカル呼び出しを伝播 |
| Bandit | AST パターンマッチング | ~25–35% | データ起点に関係なく危険呼び出しを検出 |
| Semgrep（パターンモード） | 構文パターン | ~20–40% | ルール品質に依存、テイントで FP 減少 |
| Semgrep（テイントモード） | テイント解析 | ~10–18% | PyAegis と同程度；多言語のオーバーヘッド |
| 正規表現ベース | テキスト/正規表現 | ~40–60% | ノイズが多い、意味理解なし |

> ¹ 見積りは [OWASP WebGoat Python](https://github.com/OWASP/WebGoat) コーパスと合成テストの内部ベンチマークに基づきます。実際の率はコードベースにより変わります。

**PyAegis の誤検知が少ない理由:**

- 関数本体内で **実際に到達可能** なテイント経路のみを検出
- 代入、f文字列、文字列連結、コンテナリテラル経由の汚染を追跡
- **サニタイザー呼び出し** を尊重し、`html.escape`、`bleach.clean`、`os.path.abspath` などで汚染をクリア
- プロシージャ間：ローカル関数境界をまたいだテイント追跡
- 関数名が危険そうに見えるだけでは検出しない

---
## 使い方

```bash
pyaegis <target> [options]
```

| フラグ | 説明 | デフォルト |
|------|-------------|---------|
| `target` | スキャン対象のファイル/ディレクトリ | — |
| `--rules` | YAML ルールファイルへのパス | `pyaegis/rules/default.yml` |
| `--format` | 出力形式: `text`, `json`, `csv`, `html`, `sarif` | `text` |
| `--output` | 出力ファイル（省略時は stdout） | stdout |
| `--debug` | 詳細ログ | off |

**終了コード:**
- `0` — 検出なし
- `1` — 検出あり、または致命的なスキャンエラー

---

## カスタムルールの作成

ルールは YAML で記述し、3 つの任意キーを持ちます:

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

ルールを指定して実行:
```bash
pyaegis ./src --rules my_rules.yml
```

パターンは `fnmatch` 形式のグロブをサポートします。`subprocess.*` は `subprocess.call` や `subprocess.Popen` などに一致します。

詳細: [docs/detectors.md](docs/detectors.md)

---

## CI/CD統合

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

完全なサンプル: [docs/ci-integration.md](docs/ci-integration.md)

---

## 他ツールとの比較

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

## ロードマップ

- [ ] Django ORM、SQLAlchemy、テンプレートエンジン向けソース/シンク拡充
- [ ] モジュール境界をまたいだ過程間追跡の強化
- [ ] Flask ルートデコレーター、FastAPI 依存性注入のフレームワーク対応
- [ ] ベースライン/抑制機能（既知の問題を無視、回帰に集中）
- [ ] 大規模モノリポジトリ向けの増分スキャン
- [ ] IDE プラグイン（VS Code、PyCharm）
- [ ] 検知結果トリアージ向け Web UI

---

## コントリビューション

コントリビューション歓迎です。以下をご確認ください:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [SECURITY.md](SECURITY.md)

ドキュメントサイト: `docs/` と `mkdocs.yml`（[MkDocs Material](https://squidfunk.github.io/mkdocs-material/) で構築）。

---

## スタイルを見せよう

PyAegis をあなたのプロジェクトで使っていますか？次のバッジを追加してください:

```markdown
[![security: powered by PyAegis](https://img.shields.io/badge/security-powered%20by%20PyAegis-blueviolet?style=flat-square&logo=shield)](https://github.com/mnbplus/PyAegis)
```

[![security: powered by PyAegis](https://img.shields.io/badge/security-powered%20by%20PyAegis-blueviolet?style=flat-square&logo=shield)](https://github.com/mnbplus/PyAegis)

---

<div align="center">
  <sub>Python セキュリティコミュニティのために ❤️ を込めて。</sub>
</div>
