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

