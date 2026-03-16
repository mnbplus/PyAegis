# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-03-16

### 🚀 Added
- **跨模块调用图 (P0 - Inter-procedural Call Graph)**: 实现 `GlobalSymbolTable` 与跨文件调用图，支持跨模块污点追踪，彻底消除跨文件假阴性。
- **框架感知 Source 自动发现 (P1 - Framework-aware Sources)**: 新增 `FlaskModeler`、`FastAPIModeler`、`DjangoModeler`，自动识别路由函数并精确注入污点参数，支持 FBV/CBV/DRF `@api_view` 等 20+ 种装饰器模式。
- **条件约束规则引擎 (P2 - Conditional Sink Rules)**: `conditional_sinks` 配置项支持参数级约束（如 `subprocess.run(shell=False)` 不报警），大幅降低误报率。
- **LLM Auto-Remediation (P3)**: `LLMRemediationEngine` 通过 DeepSeek/OpenAI 兼容接口为每个漏洞生成 unified-diff 补丁，`pyaegis fix` / `pyaegis remediate --llm --apply` 可直接写回源文件。
- **增量分析缓存 (P4 - Incremental Scan)**: `pyaegis scan --incremental` 结合 `get_changed_files` + `get_affected_files`，仅重新分析 git diff 涉及的文件及其依赖，大型项目 CI 速度大幅提升。
- **Django CBV `self.request` 跨方法污染追踪**: 进入 CBV HTTP 方法时预种 `self.request`，并新增接收者污点传播规则，正确处理 `self.request.GET.get(...)` 链式调用。
- **`GlobalSymbolTable` 类方法索引**: 支持 `module.ClassName.method_name` qualname 格式，`get_by_name()` 对类方法跨模块查找正常工作。
- **技术债务分析 (`pyaegis debt`)**: 结合 Git churn 与圈复杂度，输出高风险热点文件列表，支持 JSON 输出与 LLM prompt 导出。
- **VS Code 扩展接口**: 新增 VS Code extension 骨架与 intel sample store 集成。

### 🛠️ Infrastructure & Testing
- 测试套件从 ~100 增长至 **275 个测试**，覆盖跨模块、框架感知、CBV、精确污点注入、增量扫描等全部新特性，零回归。
- 清理项目根目录 11 个遗留调试/临时脚本（约 947 行无效代码）。
- `GlobalSymbolTable` 支持 `by-name` 与 `by-file` 双索引，类方法与顶层函数统一注册路径。
- pre-commit hooks（black + flake8）在所有新提交中严格执行，无格式化债务。

### 🔧 Changed
- `TaintTracker.analyze_cfg`：路由函数分支改为优先调用框架 `get_tainted_params()` 精确污染，无结果时回退到全量非 self 参数。
- `FrameworkRegistry.get_tainted_params()`：合并所有匹配 modeler 结果（解决 Flask/FastAPI 路由模式重叠时 source_params 丢失问题）。
- 版本号升至 `0.3.0`。

---

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
