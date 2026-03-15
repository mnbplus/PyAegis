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

**面向 Python 的下一代静态应用安全测试（SAST）引擎。**

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

> **极速。感知数据流。为现代 CI/CD 而生。**

**PyAegis** 是一款以 Python 为核心的 SAST 工具，远超普通正则匹配。它将代码解析为 AST，构建轻量级控制流模型，并执行**污点式 source → sink 分析**，找出真正的注入路径——而非仅仅标记可疑模式。

---

## 目录

- [工作原理](#工作原理)
- [检测能力](#检测能力)
- [快速开始](#快速开始)
- [实时示例](#实时示例)
- [误报率](#误报率)
- [用法](#用法)
- [编写自定义规则](#编写自定义规则)
- [CI/CD 集成](#cicd-集成)
- [工具对比](#与其他工具对比)
- [路线图](#路线图)
- [贡献](#贡献)
- [展示你的风格](#展示你的风格)

---

## 工作原理

```
  .py 文件
      │
      ▼
  ┌─────────────┐      ┌──────────────────┐      ┌─────────────────┐
  │  AST 解析器 │ ───▶ │   污点追踪器     │ ───▶ │    报告器       │
  │  （并行）   │      │ source → sink    │      │ text/json/sarif │
  └─────────────┘      └──────────────────┘      └─────────────────┘
        │                      │
        │                      ├── 通过赋值传播
        │                      ├── 跟踪 f-string 和字符串拼接
        │                      ├── 跨本地函数调用追踪
        │                      └── 在已知净化函数处停止
        │
        └── 多进程池处理大型仓库
```

1. **收集** — 发现目标路径下所有 `.py` 文件。
2. **解析** — 并行为每个文件构建 AST。
3. **建模** — 提取每个函数体、参数及调用图。
4. **污点分析** — 播种 source，在函数内传播，检测污点到达 sink 的情况。
5. **报告** — 以 `text`、`json`、`csv`、`html` 或 `sarif` 格式输出结果。

> 性能提示：解析结果缓存于 `.pyaegis_cache.sqlite`（SQLite 后端缓存）。

---

## 检测能力

PyAegis 内置了涵盖最关键 Python 漏洞类别的综合默认规则集：

### 代码注入
| Sink | 风险 | 示例 |
|------|------|------|
| `eval()` | 严重 | 任意代码执行 |
| `exec()` | 严重 | 任意代码执行 |
| `compile()` | 严重 | 动态代码编译 |
| `runpy.run_module()` | 严重 | 动态模块执行 |
| `runpy.run_path()` | 严重 | 动态路径执行 |

### 操作系统命令注入
| Sink | 风险 | 示例 |
|------|------|------|
| `os.system()` | 严重 | Shell 命令注入 |
| `os.popen()` | 严重 | Shell 命令注入 |
| `subprocess.call()` | 严重 | 进程注入 |
| `subprocess.run()` | 严重 | 进程注入 |
| `subprocess.Popen()` | 严重 | 进程注入 |
| `os.spawn*` | 严重 | 进程生成 |

### 不安全的反序列化
| Sink | 风险 | 示例 |
|------|------|------|
| `pickle.loads()` | 严重 | 任意对象实例化 |
| `pickle.load()` | 严重 | 任意对象实例化 |
| `dill.loads()` | 严重 | 任意对象实例化 |
| `marshal.loads()` | 严重 | 字节码反序列化 |
| `yaml.load()` | 高危 | 任意 Python 执行 |
| `yaml.unsafe_load()` | 严重 | 任意 Python 执行 |
| `jsonpickle.decode()` | 严重 | 任意对象实例化 |

### 服务端请求伪造（SSRF）
| Sink | 风险 | 示例 |
|------|------|------|
| `requests.get/post/request()` | 高危 | SSRF 攻击内部服务 |
| `httpx.get/post/request()` | 高危 | SSRF 攻击内部服务 |
| `urllib.request.urlopen()` | 高危 | SSRF |
| `aiohttp.ClientSession.*()` | 高危 | 异步 SSRF |
| `socket.create_connection()` | 高危 | 原始套接字 SSRF |

### 路径遍历 / 不安全文件操作
| Sink | 风险 | 示例 |
|------|------|------|
| `open()` | 高危 | 读写任意文件 |
| `pathlib.Path()` | 高危 | 路径遍历 |
| `shutil.copy/move/rmtree()` | 高危 | 任意文件操作 |
| `os.remove/unlink/rmdir()` | 高危 | 任意文件删除 |
| `tempfile.NamedTemporaryFile()` | 中危 | 可预测的临时路径 |

### SQL 注入
| Sink | 风险 | 示例 |
|------|------|------|
| `sqlite3.Cursor.execute()` | 严重 | SQL 注入 |
| `psycopg2.cursor.execute()` | 严重 | SQL 注入 |
| `pymysql.connect()` | 高危 | SQL 注入 |
| `MySQLdb.connect()` | 高危 | SQL 注入 |
| `sqlalchemy.text()` | 高危 | 原始 SQL 注入 |

### 模板注入（SSTI）
| Sink | 风险 | 示例 |
|------|------|------|
| `jinja2.Template()` | 严重 | 服务端模板注入 |
| `jinja2.Environment.from_string()` | 严重 | SSTI |
| `mako.template.Template()` | 严重 | SSTI |

### XML / XXE
| Sink | 风险 | 示例 |
|------|------|------|
| `xml.etree.ElementTree.parse()` | 高危 | XXE 实体扩展 |
| `xml.etree.ElementTree.fromstring()` | 高危 | XXE |
| `lxml.etree.parse()` | 高危 | XXE |
| `xml.dom.minidom.parse()` | 高危 | XXE |

### ReDoS
| Sink | 风险 | 示例 |
|------|------|------|
| `re.compile()` | 中危 | 正则拒绝服务 |
| `re.match/search()` | 中危 | 正则拒绝服务 |

**已追踪的 Source：**

| 类别 | 示例 |
|------|------|
| 内置函数 | `input()`、`sys.argv` |
| 环境变量 | `os.getenv()`、`os.environ.get()` |
| Flask/Werkzeug | `request.args`、`request.form`、`request.json`、`request.cookies`、`request.headers`、`request.files` |
| Django | `request.GET`、`request.POST`、`request.COOKIES`、`request.body`、`request.META` |
| FastAPI/Starlette | `request.query_params`、`request.path_params`、`request.form`、`request.body` |
| 解析函数 | `json.loads()`、`ujson.loads()`、`xmltodict.parse()` |

**已知净化函数**（终止污点传播）：
`html.escape`、`markupsafe.escape`、`bleach.clean`、`django.utils.html.escape`、
`os.path.abspath`、`os.path.normpath`、`pathlib.Path.resolve`、`urllib.parse.urlparse`

---

## 快速开始

**安装：**
```bash
pip install pyaegis
```

**扫描当前目录（推荐）：**
```bash
pyaegis scan .
```

**向后兼容（仍可用）：**
```bash
pyaegis .
```

**仅显示高危/严重级别的发现：**
```bash
pyaegis scan . --severity HIGH,CRITICAL
```

**解释某条规则 / 获取修复建议：**
```bash
pyaegis explain PYA-001
```

**列出内置规则：**
```bash
pyaegis list-rules
```

**创建项目配置文件（.pyaegis.yml）：**
```bash
pyaegis init
```

**导出 SARIF 供 GitHub Advanced Security 使用：**
```bash
pyaegis scan . --format sarif --output results.sarif
```

**导出 JSON：**
```bash
pyaegis scan . --format json --output results.json
```

**导出 CSV：**
```bash
pyaegis scan . --format csv --output results.csv
```

**导出 HTML 报告：**
```bash
pyaegis scan . --format html --output report.html
```

---

## 实时示例

给定如下存在漏洞的 Python 文件：

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

运行 PyAegis：

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

有了净化函数，PyAegis 会正确停止污点传播：

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

## 误报率

PyAegis 旨在最小化噪声。污点引擎仅在函数内（或跨本地函数边界）能追踪到从 source 到 sink 的连续数据流路径时报告发现。净化函数会断开传播链条。

| 工具 | 方法 | 估计误报率¹ | 备注 |
|------|----------|--------------------------|-------|
| **PyAegis** | AST 污点流（source→sink） | **~8–12%** | 识别净化函数；在赋值、f-string、本地调用中传播 |
| Bandit | AST 模式匹配 | ~25–35% | 无视数据来源直接标记危险调用 |
| Semgrep（模式） | 语法模式匹配 | ~20–40% | 依赖规则质量；污点模式更低 |
| Semgrep（污点） | 污点分析 | ~10–18% | 与 PyAegis 接近；多语言开销 |
| 正则扫描器 | 文本/正则 | ~40–60% | 噪声大，无语义理解 |

> ¹ 估计基于 [OWASP WebGoat Python](https://github.com/OWASP/WebGoat) 语料库与合成测试套件的内部基准。实际数值因代码库而异。

**为什么 PyAegis 误报更低：**

- 仅标记函数体内 **实际可达** 的污点路径
- 追踪赋值、f-string、字符串拼接和容器字面量
- 识别 **净化函数** —— `html.escape`、`bleach.clean`、`os.path.abspath` 等会清除污点
- 过程间：跨本地函数边界追踪污点
- 不会仅因函数名看起来危险就报警

---

## 用法

```bash
pyaegis <target> [options]
```

| Flag | Description | Default |
|------|-------------|---------|
| `target` | 扫描目标文件或目录 | — |
| `--rules` | YAML 规则文件路径 | `pyaegis/rules/default.yml` |
| `--format` | 输出格式：`text`、`json`、`csv`、`html`、`sarif` | `text` |
| `--output` | 输出文件（省略则 stdout） | stdout |
| `--debug` | 详细日志 | off |

**退出码：**
- `0` — 无发现
- `1` — 有发现或致命扫描错误

---

## 编写自定义规则

规则文件是普通的 YAML，包含三个可选键：

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

使用自定义规则运行：
```bash
pyaegis ./src --rules my_rules.yml
```

模式支持 `fnmatch` 通配符：`subprocess.*` 可匹配 `subprocess.call`、`subprocess.Popen` 等。

详见：[docs/detectors.md](docs/detectors.md)

---

## CI/CD 集成

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

完整示例：[docs/ci-integration.md](docs/ci-integration.md)

---

## 与其他工具对比

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

## 路线图

- [ ] 更多内置 source/sink（Django ORM、SQLAlchemy、模板引擎）
- [ ] 跨模块的更强过程间追踪
- [ ] 框架感知建模（Flask 路由装饰器、FastAPI 依赖注入）
- [ ] 基线/抑制支持（忽略已知发现，关注回归）
- [ ] 大型 monorepo 增量扫描
- [ ] IDE 插件（VS Code、PyCharm）
- [ ] 用于发现分流的 Web UI

---

## 贡献

欢迎贡献！请阅读：

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [SECURITY.md](SECURITY.md)

文档站点：`docs/` 与 `mkdocs.yml`（由 [MkDocs Material](https://squidfunk.github.io/mkdocs-material/) 构建）。

---

## 展示你的风格

在项目中使用 PyAegis？添加如下徽章：

```markdown
[![security: powered by PyAegis](https://img.shields.io/badge/security-powered%20by%20PyAegis-blueviolet?style=flat-square&logo=shield)](https://github.com/mnbplus/PyAegis)
```

[![security: powered by PyAegis](https://img.shields.io/badge/security-powered%20by%20PyAegis-blueviolet?style=flat-square&logo=shield)](https://github.com/mnbplus/PyAegis)

---

<div align="center">
  <sub>Built with ❤️ for the Python security community.</sub>
</div>
