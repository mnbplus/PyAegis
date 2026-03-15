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

