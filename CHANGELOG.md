# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-03-15

### 🚀 Added
- **精准的漏洞追踪 (Source Variable Tracking)**: 新增了对污染源的追根溯源能力 (`source_var` field)。不仅仅是找到汇聚点 (Sink)，我们现在能通过报告精确告诉安全工程师：漏洞到底是由哪个被污染的变量触发的。
- **动态严重度与特征 ID分级 (Sink-Aware Rule IDs)**: 根据进入的敏感操作不同（如 `eval`, `exec`, `os.system` 等），现在系统会自动区分对应更明确的安全事件 ID (`PYA-101`至`PYA-108`) 和特定描述。
- **新增高危框架识别 (Framework Expansions)**: 扩充了默认安全监测规则库，全新覆盖 Flask (`flask.request.*`)、Django (`django.http.QueryDict`) 等常见框架入口点，以及 `pickle.loads` 和 `yaml.load` 等高危反序列化组件。
- **现代化 CLI 体验**: 支持了 `--version` 命令标志获取工具版本。

### 🛠️ Infrastructure & Testing
- 补全了单元测试与端到端集成测试，对文本、JSON结构以及 SARIF 语法层格式均进行了100%全覆盖断言测试。
- 大幅改进了模块化的 `__init__.py` 输出规范。



## [0.1.0] - 2026-03-15

### 🎉 Added (Highlights)
- **AST 解析引擎 (Parser)**: 正式上线的杀手级特性！完全扬弃了传统正则表达式分析方案，现在我们通过原生的抽象语法树解析 (Abstract Syntax Tree unrolling) 拆解所有 Python 源代码，分析速度拉满。
- **并行分析架构 (Multiprocessing Pipeline)**: 实现了一个支持多进程资源池的并行提取架构，处理几万行的项目基本上是秒出结果。
- **污点路径追踪 (CFG Taint Tracking)**: 业界标杆级别的污点分析原型来袭，精准嗅探如 `request.GET` 等不安全源头，一路追踪到 `os.system` 等执行槽 (Sinks)，从而防止假阳性报警。
- **GitHub 行级安全挂挂载点 (SARIF Output)**: 加入了官方安全规范支持。配合 JSON、TEXT 多态导出格式，现在你可以带着它无缝对接 GitHub Advanced Security 操作大盘。

### 🛠️ Infrastructure & DevEx
- 引入了**强制强类型声明**(`@dataclass`) 以及完整的数据建模（Model abstractions），彻底抛弃到处乱飞的字典了，这应该对后期的扩展（尤其是我们要接入 OpenAI 的 AI-healing 的时候）相当关键。
- 重写了打包文件，迁移到现代化的 `pyproject.toml` 标准并且提供了 `tox.ini` 极深测试矩阵保证向后兼容性 (py38 - py312)。
- 加入了完整的格式化防线 (`black`, `flake8`) 作为 Git pre-commit hook，大家一起撸代码再也不用对着空格数量吵架了。

### 📝 Documentation
- 这次直接从0拉起了一整套 MkDocs-Material 风格的主文档系统。
- 增加了安全漏洞报告规则 `SECURITY.md` （负责任披露原则，白帽子狂喜）。
- 增加了完整大厂级开源代码协定 `CONTRIBUTING.md` / `CODE_OF_CONDUCT.md` / 下拉模板 (PR Templates & Issue forms)。大家只要提了 PR 就乖乖按清单检查测试吧。

### 🤔 Thoughts / Notes
首个大版本放出！我们知道 `AST` 对 Python这种动态语言非常难做，我们当前的 `CFG` 还只能做偏静态的分支预测。但有了这套极速核心，下一步对接 **Codex API** 实现基于大语言模型的全自动代码漏洞修复 (Auto-Remediation) 的地基就已经彻底完工了。敬请期待。

---

*A massive shout-out to all early adopters who believed in the AST approach. Let's make Python secure by default.* 🛡️
