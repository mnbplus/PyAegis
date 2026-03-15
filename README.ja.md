<div align="center">

```
 ██████╗ ██╗   ██╗ █████╗ ███████╗ ██████╗ ██╗███████╗
 ██╔══██╗╚██╗ ██╔╝██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
 ██████╔╝ ╚████╔╝ ███████║█████╗  ██║  ███╗██║███████╗
 ██╔═══╝   ╚██╔╝  ██╔══██║██╔══╝  ██║   ██║██║╚════██║
 ██║        ██║   ██║  ██║███████╗╚██████╔╝██║███████║
 ╚═╝        ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝
```

**Python向け次世代静的アプリケーションセキュリティテスト（SAST）エンジン**

<p>
  <a href="https://pypi.org/project/pyaegis"><img alt="PyPI" src="https://img.shields.io/pypi/v/pyaegis?style=for-the-badge&logo=pypi&logoColor=white"></a>
  <a href="https://python.org"><img alt="Python" src="https://img.shields.io/badge/Python-3.8%20|%203.9%20|%203.10%20|%203.11%20|%203.12-blue.svg?style=for-the-badge&logo=python"></a>
  <a href="https://github.com/mnbplus/PyAegis/actions"><img alt="Build" src="https://img.shields.io/github/actions/workflow/status/mnbplus/PyAegis/ci.yml?branch=main&style=for-the-badge&logo=github"></a>
  <a href="https://codecov.io/gh/mnbplus/PyAegis"><img alt="Coverage" src="https://img.shields.io/codecov/c/github/mnbplus/PyAegis?style=for-the-badge&logo=codecov"></a>
  <a href="https://opensource.org/licenses/MIT"><img alt="License" src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge"></a>
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

**PyAegis** は Python ファーストの SAST ツールです。正規表現マッチングを超え、コードを AST に解析し、軽量な制御フローモデルを構築し、**テイント方式の source → sink 解析**によって本物のインジェクションパスを発見します。

---

## 目次

- [仕組み](#仕組み)
- [検出する脆弱性](#検出する脆弱性)
- [クイックスタート](#クイックスタート)
- [誤検知率](#誤検知率)
- [使い方](#使い方)
- [カスタムルールの作成](#カスタムルールの作成)
- [CI/CD統合](#cicd統合)
- [他ツールとの比較](#他ツールとの比較)
- [ロードマップ](#ロードマップ)
- [コントリビューション](#コントリビューション)

---

## 仕組み

1. **収集** — 対象パス以下のすべての `.py` ファイルを探索。
2. **解析** — 各ファイルの AST を並列でビルド。
3. **モデル化** — 関数ごとのボディ、引数、呼び出しグラフを抽出。
4. **テイント分析** — ソースを起点に伝播させ、テイントがシンクに到達したら検知。
5. **レポート** — text、json、csv、html、sarif で出力。

---

## 検出する脆弱性

### コードインジェクション
| シンク | リスク |
|--------|--------|
| eval() | Critical |
| exec() | Critical |
| compile() | Critical |

### OSコマンドインジェクション
| シンク | リスク |
|--------|--------|
| os.system() | Critical |
| subprocess.run() | Critical |
| subprocess.Popen() | Critical |

### 安全でないデシリアライゼーション
| シンク | リスク |
|--------|--------|
| pickle.loads() | Critical |
| yaml.load() | High |
| marshal.loads() | Critical |

### SSRF
| シンク | リスク |
|--------|--------|
| requests.get/post() | High |
| urllib.request.urlopen() | High |

### SQLインジェクション
| シンク | リスク |
|--------|--------|
| sqlite3.Cursor.execute() | Critical |
| sqlalchemy.text() | High |

### テンプレートインジェクション（SSTI）
| シンク | リスク |
|--------|--------|
| jinja2.Template() | Critical |

**追跡されるソース（Source）:**

| カテゴリ | 例 |
|----------|----|
| ビルトイン | input()、sys.argv |
| 環境変数 | os.getenv()、os.environ.get() |
| Flask/Werkzeug | request.args、request.form、request.json |
| Django | request.GET、request.POST、request.body |
| FastAPI | request.query_params、request.path_params |

**既知のサニタイザー**: html.escape、markupsafe.escape、bleach.clean、os.path.abspath、pathlib.Path.resolve

---

## クイックスタート

インストール:
```bash
pip install pyaegis
```

現在のディレクトリをスキャン:
```bash
pyaegis scan .
```

高・重大リスクのみ表示:
```bash
pyaegis scan . --severity HIGH,CRITICAL
```

SARIF形式でエクスポート:
```bash
pyaegis scan . --format sarif --output results.sarif
```

ルールの説明:
```bash
pyaegis explain PYA-001
```

---

## 誤検知率

| ツール | アプローチ | 誤検知率（推定） |
|--------|-----------|------------------|
| **PyAegis** | AST テイントフロー | **~8–12%** |
| Bandit | AST パターンマッチ | ~25–35% |
| Semgrep（テイントモード） | テイント解析 | ~10–18% |
| 正規表現ベース | テキスト/正規表現 | ~40–60% |

---

## 使い方

```bash
pyaegis <target> [options]
```

| フラグ | 説明 | デフォルト |
|--------|------|------------|
| target | スキャン対象 | — |
| --rules | YAMLルールファイル | pyaegis/rules/default.yml |
| --format | 出力形式: text/json/csv/html/sarif | text |
| --output | 出力ファイル | stdout |
| --debug | 詳細ログ | オフ |

終了コード: 0=発見なし、1=脆弱性検出

---

## カスタムルールの作成

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

sanitizers:
  - html.escape
```

実行:
```bash
pyaegis ./src --rules my_rules.yml
```

---

## CI/CD統合

### GitHub Actions

```yaml
- name: PyAegis SASTスキャン
  run: |
    pip install pyaegis
    pyaegis . --format sarif --output pyaegis.sarif

- name: SARIFをGitHub Advanced Securityへアップロード
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
| 言語対応 | Python特化 | Python | 多言語 |
| 解析手法 | AST テイントフロー | AST パターン | パターン+テイント |
| Source→Sink追跡 | あり | 限定的 | テイントモードあり |
| サニタイザー対応 | あり | なし | あり |
| SARIFネイティブ出力 | あり | なし | あり |
| 誤検知率 | ~8–12% | ~25–35% | ~10–40% |

---

## ロードマップ

- [ ] Django ORM、SQLAlchemy、テンプレートエンジン向けソース/シンク拡充
- [ ] モジュール境界をまたいだ過程間追跡の強化
- [ ] Flaskルートデコレーター、FastAPI依存性注入のフレームワーク対応
- [ ] ベースライン/抑制機能
- [ ] 大規模モノリポジトリの増分スキャン
- [ ] IDEプラグイン（VS Code、PyCharm）
- [ ] 検知結果トリアージ向けWeb UI

---

## コントリビューション

コントリビューション歓迎！以下をご一読ください:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [SECURITY.md](SECURITY.md)

---

<div align="center">
  <sub>Pythonセキュリティコミュニティへの愛を込めて ❤️</sub>
</div>
