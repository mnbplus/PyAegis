<!-- 此文件由 PyAegis 自动维护，记录每轮进度 -->

## 2026-03-16 00:12 (Asia/Shanghai)

### 完成内容
- **feat(sarif): expand rule metadata for detectors** (`edce49f`) — reporter 规则元数据改为从 `rules_catalog.RULES` 动态构建；rules_catalog 扩充 detector 规则：PYA-007(Weak crypto/CWE-327)、PYA-008(Insecure randomness/CWE-338)、PYA-010(Hardcoded secret/CWE-798)；更新 `docs/sarif.md` Known Limitations，修正文档中“rules 为空”的过期描述

### 测试
- `pytest -q`：全绿（4 skipped 维持）

### 遇到问题
- 首次 `git commit` 被 pre-commit 的 black hook 自动格式化 `pyaegis/reporters.py` 拦截；重新 `git add` 后再次 commit 通过

## 2026-03-15 23:55 (Asia/Shanghai)

### 完成内容
- **feat(p1): taint FastAPI Depends params** (`34ff1b4`) — parser.py 增加 Depends 参数识别（含 import alias），taint.py 将 source_params 作为 taint 入口；新增测试 `tests/test_fastapi_depends_sources.py`，pytest 全绿（4 skipped 维持）
- **docs: complete Japanese README** (`2f2e395`) — README.ja.md 完整重写，全章节与英文版对齐
- **docs: polish homepage** (`e83747e`) — 英文 README 优化：emoji flags、pitch 精炼、Why PyAegis 章节、demo 占位、Topics 引导；+28/-54 行
- **docs: complete ja and zh-CN README sync** (`6e6d2e0`) — README.ja.md (36KB) 与 README.zh-CN.md (15KB) 完整同步，临时 parts/ 目录已删除

### 遇到问题
- `aegis-readme-sync-full` 两个实例（ce98e90、a6a24fa1）均为空输出，疑似 model 分配问题（qwen3.5-397b-a17b-thinking），未产生实质工作；后续由 aegis-next 补齐
- `ja-readme` agent 截断在 2041 bytes，需后续 agent 重新生成完整版（已由 aegis-next 修复）

### 下一步
- 继续推进 P2 项：SARIF 输出完善（CWE 映射扩充）
- 补充 `docs/usage.md` 和 `docs/comparison.md`（当前为占位链接）
- `docs/images/demo.gif` 尚为占位，考虑用 asciinema + agg 生成真实录屏
- 关注仓库中未跟踪文件（check2.py、demo/ 等），评估是否纳入版本控制

## 2026-03-16 00:00 (Asia/Shanghai)

### 完成内容
- 6e6d2e0 docs: complete ja and zh-CN README sync with English version (15:45 UTC)
- e83747e docs: polish homepage - emoji flags, pitch, why section, demo placeholder, topics (15:41 UTC)
- 2f2e395 docs: complete Japanese README - all sections included (15:36 UTC)
- 34ff1b4 feat(p1): taint FastAPI Depends params, pytest 全绿 (15:25 UTC)
- 573643f docs: update zh-CN README, cleanup temp scripts (15:14 UTC)
- FastAPI Depends 参数自动识别为 taint source，含 import alias 解析、kw-only 参数处理
- 跨模块 call graph (GlobalSymbolTable + InterproceduralTaintTracker) 已实现并测试通过

### 当前状态
- aegis-next agent (hajimicodex) 活跃中，正在读取 path_traversal.yml，疑似在优化规则集
- 主会话正在清理临时脚本并准备新 commit

### 遇到问题
- aegis-readme-sync-full 实例因 qwen3.5-plus 模型 429 冷却报错退出 (totalTokens=0)
- ja-readme agent 曾截断输出，已由后续 agent 修复

### 下一步
- aegis-next 当前处理 path_traversal 规则优化
- 待完善：docs/usage.md 内容、demo.gif 录屏、SARIF 输出
- 临时脚本清理 commit 待 push

## 2026-03-16 00:05 — 五分钟进度报告

### 完成内容
- aegis-readme-sync-full: 完整重写 README.ja.md（36824B）和 README.zh-CN.md（15611B），与英文版全量同步，commit 6e6d2e0 已推送
- aegis-homepage-polish: README.md 主页六项优化（emoji flags、pitch 精炼、Why PyAegis 章节、Topics 导航、demo 占位、Quickstart 精简），commit e83747e
- aegis-next(af04bf9): FastAPI Depends 参数污点追踪实现（parser.py + taint.py），新增 tests/test_fastapi_depends_sources.py，commit 34ff1b4，全绿
- 主会话 qqbot direct: CI #40 运行中，发现 Dogfood SARIF 上传失败根因为 GitHub Code Scanning 未启用，指引用户去 settings/security_analysis 手动开启

### 当前活跃 Agent
- aegis-next(57b942d6) [gpt-5.2-codex-high] 正在运行：规划 SARIF 输出改进（补全 PYA-007/008/010 规则元数据、添加 snippet context、修正 docs/sarif.md），刚开始读 PROGRESS_LOG.md

### 遇到问题
- GitHub Code Scanning（Dogfood workflow SARIF 上传）需在仓库设置手动启用，否则报权限错误
- aegis-readme-sync-full(a6a24fa1) 本轮 totalTokens=0，疑似 spawn 后未实际执行（前一轮已由 1654f7d9 完成）

### 下一步
- aegis-next(57b942d6) 完成 SARIF 元数据补全后 push
- 待补充：docs/usage.md 内容、demo.gif 录屏
- 用户需手动启用 GitHub Code Scanning 以解除 Dogfood CI 错误

## 2026-03-16 00:10 — 五分钟定时报告

### 完成内容
- aegis-next(1654f7d9) ✅ 完成日文/简中 README 完整同步（commit 6e6d2e0），两份文件章节与英文版对齐
- aegis-homepage-polish ✅ README 主页优化（commit e83747e）：旗帜 emoji、Why PyAegis 章节、demo 占位、Topics 引导
- aegis-next(af04bf9b) ✅ FastAPI Depends taint 污点标记 + 测试（commit 34ff1b4），pytest 全绿
- aegis-readme-sync-full(a6a24fa1) ⚠️ spawn 后 totalTokens=0，疑似未实际执行，任务已由上一轮 agent 完成
- chore commit 28f02f7：添加 demo 文件、清理临时脚本、更新进度日志

### 遇到问题
- GitHub Code Scanning (Dogfood SARIF 上传) 需在仓库 Settings > Security Analysis 手动启用，否则 CI 报权限错误
- aegis-next(881abf4b) abortedLastRun=true，异常中止，未留最终消息
- aegis-readme-sync-full 出现 spawn 成功但 agent 零 token 的空跑问题

### 下一步
- spawn aegis-next 继续优化最紧迫功能（读 PRODUCT_RESEARCH.md 后决定方向）
- 用户需手动启用 GitHub Code Scanning 解除 Dogfood CI 错误
- 待补充：docs/usage.md 实质内容、demo.gif 真实录屏（asciinema + agg）

## 2026-03-16 00:30 — 五分钟定时报告

### 完成内容
- aegis-refactor(9c4d5006) ✅ 框架感知逻辑解耦到 pyaegis/frameworks/ 插件系统（Flask/FastAPI modeler + registry），openai 移为可选依赖 pip install pyaegis[ai]（commit d93683a）
- aegis-next(cd7c6ead) ✅ 修复 cli.py 中 remediate --apply 崩溃：实现 _apply_diff_to_file() unified diff 应用器，补全 --ruleset 解析与 --list-rulesets 输出（commit d2c0622）
- GitHub 最新 HEAD：29f602a feat: add SARIF snippets in results

### 遇到问题
- 无新增阻塞问题
- GitHub Code Scanning (Dogfood CI) 仍需用户手动在仓库 Settings 启用

## 2026-03-16 00:45 (Asia/Shanghai)

### 完成内容
- **feat(cli): add ruleset selection + listing** — scan/remediate/fix 支持 `--ruleset` 并新增 `--list-rulesets`，当 ruleset 不存在时给出可用列表提示
- **docs: ruleset usage** — docs/rules.md 补充 ruleset 使用与列出命令说明

### 测试
- `pytest tests/test_cli.py -q`

### 下一步
- 可补充 CLI 测试覆盖 ruleset 分支（含未知 ruleset 错误提示）

## 2026-03-16 00:35 — 五分钟定时报告

### 完成内容
- aegis-next(2af0e238) ✅ CLI --ruleset/--list-rulesets 支持完整落地（commit ff15847），scan/remediate/fix 三命令均支持，未知 ruleset 给出可用列表提示；docs/rules.md 补充 ruleset 使用说明
- aegis-gtm(724436d3) ✅ GTM 全部完成：README 定位重写（新 pitch + LLM Auto-Fix 首位 + 早期用户引用）、action.yml 创建（6 inputs/1 output/composite run）、docs/github-action.md 完整文档（3 示例 + 生产 workflow + Inputs/Outputs 表），commit 250829c
- aegis-refactor(9c4d5006) ✅ 框架插件系统完整落地（d93683a）

### GitHub 最新 HEAD
- 29f602a feat: add SARIF snippets in results（API 缓存，本地有更多提交）

### 当前活跃 Agent
- aegis-next(1ef0f749) [hajimicodex] 活跃中：正在检查 sourceVar API 兼容性，计划取消跳过的测试
- aegis-api(4f988e99) [claude-sonnet-4-6] 活跃中：正在读取 cli.py 核心扫描命令实现

### 遇到问题
- 无新增阻塞问题
- GitHub Code Scanning (Dogfood CI) 仍需用户手动在仓库 Settings > Security Analysis 启用
- 主 QQ 会话收到深度技术建议（Visitor 模式重构、类型推导、增量扫描、Benchmark CI），已转递给后续 agent 作为方向参考

### 下一步
- aegis-next 完成 sourceVar API 兼容性修复后 push
- 待实施深度优化方向：TaintTracker Visitor 模式重构、Type Hints 类型推导、增量扫描（git diff）、Benchmark CI（靶场 + Precision/Recall）
- 待补充：docs/usage.md 实质内容、demo.gif 真实录屏


## 2026-03-16 00:41

### 完成内容
- aegis-incremental: git-diff 增量扫描 (pyaegis/core/incremental.py)，--incremental/--base-ref CLI 参数，11测试全通过，commit 1cd29f2（本地已提交，待push）
- aegis-next (2af0e238): --ruleset/--list-rulesets CLI 支持，commit ff15847 已push
- aegis-gtm (724436d3): README 产品定位重写 + action.yml + docs/github-action.md，commit 250829c 已push
- aegis-refactor (9c4d5006): 框架感知解耦为 pyaegis/frameworks/ 插件包，commit d93683a 已push
- aegis-homepage-polish (afa9bdc0): README 6项优化，commit e83747e 已push
- 历史积累: SARIF CWE映射扩充、interprocedural call graph、Python headless API

### 进行中
- aegis-api (4f988e99): Python headless API + LangChain tool，11/11测试通过，正在执行最终commit
- aegis-benchmark (e2761cbb): label存在但messages为空，疑似未实际启动

### 遇到的问题
- aegis-incremental commit 1cd29f2 本地完成但未push，远端不含此提交
- aegis-benchmark session 无消息记录，可能空spawn
- pre-commit black 多次拦截commit，各agent均需 git add 后重试

### 下一步
- 等 aegis-api 完成后确认所有本地commit已push
- 补充 docs/usage.md 内容
- demo.gif 真实录屏（asciinema + agg）
- Benchmark CI：靶场 submodule + Precision/Recall 自动输出
