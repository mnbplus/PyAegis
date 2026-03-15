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

**Python向け次世代静的アプリケーションセキュリティテスト（SAST）エンジン。**

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

> **高速。データフロー対応。モダンなCI/CDのために設計。**

**PyAegis** は Python ファーストの SAST ツールです。正規表現マッチングを超え、コードを AST に解析し、軽量な制御フローモデルを構築して、**テイント方式の source → sink 解析**によって本物のインジェクションパスを検出します。

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
- [バッジ](#バッジ)

---

## 仕組み

1. **収集** — `.py` ファイルを探索
2. **解析** — AST を並列ビルド
3. **モデル化** — 関数ごとに解析
4. **テイント分析** — source から sink への汚染を追跡
5. **レポート** — `text`/`json`/`csv`/`html`/`sarif` で出力

---

## 検出する脆弱性

| カテゴリ | シンク例 | リスク |
|----------|---------|--------|
| コードインジェクション | `eval`、`exec`、`compile` | Critical |
| OSコマンドインジェクション | `os.system`、`subprocess.run`、`subprocess.Popen` | Critical |
| 安全でないデシリアライゼーション | `pickle.loads`、`yaml.load`、`jsonpickle.decode` | Critical/High |
| SSRF | `requests.get`、`urllib.request.urlopen` | High |
| パストラバーサル | `open`、`shutil.*`、`pathlib.Path*` | High |
| SQLインジェクション | `sqlite3.Cursor.execute`、`sqlalchemy.text` | Critical/High |
| テンプレートインジェクション（SSTI） | `jinja2.Template`、`mako.template.Template` | Critical |
| XML / XXE | `xml.etree.ElementTree.parse`、`lxml.etree.parse` | High |
| ReDoS | `re.compile`、`re.match/search` | Medium |

**追跡されるソース:** `input()`、`sys.argv`、`os.getenv()`、Flask/Django/FastAPI リクエストオブジェクト、`json.loads()` 等

**既知のサニタイザー:** `html.escape`、`markupsafe.escape`、`bleach.clean`、`os.path.abspath`、`pathlib.Path.resolve` 等

---

## クイックスタート

```bash
pip install pyaegis
pyaegis scan .
pyaegis scan . --severity HIGH,CRITICAL
pyaegis scan . --format sarif --output results.sarif
pyaegis explain PYA-001
pyaegis list-rules
```

---

## 実行例

```bash
$ pyaegis vuln_example.py
[-] 3件の潜在的な脆弱性を検出:
    -> [CRITICAL] テイントデータがシンクに到達: os.system (PYA-TAINT)
       ファイル: vuln_example.py:8 | コンテキスト: run_command

$ pyaegis safe_example.py
[+] 脆弱性は検出されませんでした。サブシステムは安全です。
```

---

## 誤検知率

| ツール | アプローチ | 誤検知率（推定） |
|--------|-----------|------------------|
| **PyAegis** | AST テイントフロー（source→sink） | **~8–12%** |
| Bandit | AST パターンマッチング | ~25–35% |
| Semgrep（パターンモード） | 構文パターンマッチ | ~20–40% |
| Semgrep（テイントモード） | テイント解析 | ~10–18% |
| 正規表現ベース | テキスト/正規表現 | ~40–60% |

---

## 使い方

| フラグ | 説明 | デフォルト |
|--------|------|------------|
| `target` | スキャン対象 | — |
| `--rules` | YAML ルールファイル | `pyaegis/rules/default.yml` |
| `--format` | 出力形式 | `text` |
| `--output` | 出力ファイル | stdout |
| `--debug` | 詳細ログ | オフ |

終了コード: `0` = 発見なし、`1` = 検出あり

---

## カスタムルールの作成

```yaml
inputs:
  - input
  - request.args
sinks:
  - eval
  - os.system
  - subprocess.*
sanitizers:
  - html.escape
```

```bash
pyaegis ./src --rules my_rules.yml
```

詳細: [docs/detectors.md](docs/detectors.md)

---

## CI/CD統合

### GitHub Actions

```yaml
- name: PyAegis SAST スキャン
  run: |
    pip install pyaegis
    pyaegis . --format sarif --output pyaegis.sarif
- name: SARIF アップロード
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

詳細: [docs/ci-integration.md](docs/ci-integration.md)

---

## 他ツールとの比較

| 機能 | PyAegis | Bandit | Semgrep |
|------|---------|--------|---------|
| 言語フォーカス | Python ファースト | Python | 多言語 |
| 解析手法 | AST テイントフロー | AST パターン | パターン + テイント |
| Source→Sink 追跡 | あり | 限定的 | テイントモードあり |
| サニタイザー対応 | あり | なし | あり |
| 過程間解析 | ローカル + クロスモジュール | なし | あり |
| SARIF ネイティブ | あり | なし | あり |
| カスタムルール | YAML | Python プラグイン | YAML |
| 誤検知率 | ~8–12% | ~25–35% | ~10–40% |
| インストールサイズ | 最小 | 中程度 | 大 |

---

## ロードマップ

- [ ] Django ORM、SQLAlchemy、テンプレートエンジン向けソース/シンク拡充
- [ ] モジュール境界をまたいだ過程間追跡の強化
- [ ] Flask ルートデコレーター、FastAPI 依存性注入のフレームワーク対応
- [ ] ベースライン/抑制機能（既知の問題を無視）
- [ ] 大規模モノリポジトリの増分スキャン
- [ ] IDE プラグイン（VS Code、PyCharm）
- [ ] 検知結果トリアージ向け Web UI

---

## コントリビューション

コントリビューション歓迎！以下をご一読ください:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [SECURITY.md](SECURITY.md)

ドキュメントサイト: `docs/` および `mkdocs.yml`（[MkDocs Material](https://squidfunk.github.io/mkdocs-material/) を使用）

---

## バッジ

プロジェクトで PyAegis を使用していますか？バッジを追加してください:

```markdown
[![security: powered by PyAegis](https://img.shields.io/badge/security-powered%20by%20PyAegis-blueviolet?style=flat-square&logo=shield)](https://github.com/mnbplus/PyAegis)
```

[![security: powered by PyAegis](https://img.shields.io/badge/security-powered%20by%20PyAegis-blueviolet?style=flat-square&logo=shield)](https://github.com/mnbplus/PyAegis)

---

<div align="center">
