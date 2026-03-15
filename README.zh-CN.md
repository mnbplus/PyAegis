# PyAegis

**面向现代 Python 代码库的下一代静态应用安全测试（SAST）引擎。**

[English](README.md) | [简体中文](README.zh-CN.md) | [日本語](README.ja.md)

---

## PyAegis 是什么？

PyAegis 是一个针对 Python 生态设计的静态分析漏洞扫描器。它不依赖脆弱的正则匹配，而是：

- 将代码解析为 **AST（抽象语法树）**（支持多进程加速）
- 构建轻量的控制流/函数体结构
- 基于规则文件执行 **source → sink** 的污点式数据流检查

最终判断：**不可信输入（source）是否可能流入危险 API（sink）**，从而在尽量降低误报的同时，发现真实可利用的风险。

---

## 特性

- **多进程 AST 解析**：加速扫描大仓库
- **污点式 source→sink 检测**：识别从不可信输入到危险执行点的路径
- **YAML 规则驱动**：用最小表面（sources/sinks）快速自定义
- **多种输出格式**：`text` / `json` / `sarif`（SARIF v2.1.0）
- **CI/CD 友好**：可作为流水线门禁；支持 SARIF 上传到代码扫描 UI

---

## 快速开始（5 步）

1）安装
```bash
pip install pyaegis
```

2）扫描当前项目（默认规则）
```bash
pyaegis .
```

3）使用自定义规则文件
```bash
pyaegis . --rules ./custom_rules.yml
```

4）导出 SARIF（用于 GitHub Code Scanning / 安全平台）
```bash
pyaegis . --format sarif --output pyaegis-results.sarif
```

5）接入 CI（GitHub Actions / GitLab CI / Jenkins 示例）

参见：[`docs/ci-integration.md`](docs/ci-integration.md)

---

## 用法

```bash
pyaegis <target>
```

常用参数：

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `target` | 扫描目标（文件或目录） | - |
| `--rules` | 规则 YAML 路径 | `pyaegis/rules/default.yml` |
| `--format` | 输出格式：`text` / `json` / `sarif` | `text` |
| `--output` | 输出到文件（否则 stdout） | - |
| `--debug` | 开启调试日志 | 关闭 |

退出码：
- `0`：未发现问题
- `1`：发现问题（或扫描过程出现致命错误）

---

## 架构（文字版）

一次扫描大致按以下步骤运行：

1. **收集目标文件**：从路径中递归查找 `.py` 文件。
2. **解析与建模**：并行解析每个文件的 AST，并生成按函数划分的结构（CFG-like）。
3. **加载规则**：读取 YAML 规则：
   - `inputs`：不可信数据的来源（sources）
   - `sinks`：危险的敏感 API（sinks）
4. **污点跟踪**：
   - 若变量由 source 调用赋值，则标记为 tainted
   - 在函数体内传播 taint
   - 若 tainted 数据进入 sink 调用，输出一条 Finding
5. **报告输出**：按 text / JSON / SARIF 输出，便于人读或 CI 消费。

术语解释：
- **Source（来源）**：不可信输入入口（如 `input()`、环境变量、请求参数等）
- **Sink（汇聚点）**：危险执行点（如 `os.system`、`subprocess.*`、`eval/exec` 等）

---

## 规则编写

规则文件是一个包含两个顶层键的 YAML：

- `inputs`: source 名称列表
- `sinks`: sink 名称列表

示例：

```yaml
inputs:
  - input
  - os.getenv
  - request

sinks:
  - eval
  - exec
  - os.system
  - subprocess.call
  - subprocess.Popen
```

运行：
```bash
pyaegis ./src --rules custom_rules.yml
```

详见：[`docs/rules.md`](docs/rules.md)

---

## 与同类工具对比（概览）

| 工具 | 主要定位 | 语言 | 规则形式 | 是否支持污点/数据流 | SARIF | 常见使用场景 |
|------|----------|------|----------|----------------------|------|--------------|
| **PyAegis** | Python SAST 的 source→sink 检测 | Python | YAML（sources/sinks） | 是（source→sink） | 是 | Python 工程扫描、CI 门禁 |
| Bandit | Python 安全 lint / 规则检查 | Python | Python 插件 + 配置 | 有限（多为模式/AST 检查） | 原生不提供 | 快速发现常见 Python 误用 |
| Semgrep | 多语言 SAST + 模式匹配（含 taint mode） | 多语言 | YAML 规则 | 是（支持 taint mode） | 是 | 多语言仓库统一扫描 |

---

## Roadmap

- 内置更多 sources/sinks（Django/FastAPI/Flask、反序列化、模板注入等）
- 更强的跨函数/跨文件追踪（inter-procedural）
- 常见 sanitizer（过滤/转义）建模，进一步降低误报
- Baseline / 抑制机制（只关注新增问题）
- 大仓库增量扫描与性能剖析

---

## 文档

- 文档站点：`docs/`
- 首页：[`docs/index.md`](docs/index.md)
- 5 分钟上手：[`docs/quickstart.md`](docs/quickstart.md)
- 规则指南：[`docs/rules.md`](docs/rules.md)
- CI/CD 集成：[`docs/ci-integration.md`](docs/ci-integration.md)
- FAQ：[`docs/faq.md`](docs/faq.md)
- 对比：[`docs/comparison.md`](docs/comparison.md)

---

## 贡献

欢迎贡献：

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [SECURITY.md](SECURITY.md)
