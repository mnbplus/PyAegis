# PyAegis Progress Log

<!-- 自动追加，勿手动排序 -->

---

## 2026-03-15 20:35 (Asia/Shanghai)

### 完成内容
- `aegis-next`（d9d5f5b6）已完成本轮任务：新增4个规则文件（xxe.yml/ssrf.yml/deserialization.yml/path_traversal.yml），全量测试 50 passed，commit 并 push 到 main
- `aegis-next`（de214bf3）完成了本轮更早的任务：修复 TaintTracker 中 `_call_arg_tainted_params` 缺失导致的崩溃，补齐过程间传播路径，全绿后 push
- GitHub 最新5次提交（截至 20:29 UTC+8）：
  1. `c6e1f9e` fix: tuple unpacking taint, class instance attr tracking, variable reassignment sensitivity（19:29）
  2. `2ef1aea` fix: tuple unpacking taint propagation, class instance attribute tracking（19:27）
  3. `876b350` ux: scan subcommand, list-rules, version, severity filter, colored output（19:14）
  4. `2a2cdb1` ux: scan/explain/list-rules commands, colored output, code context, severity filter（19:11）
  5. `3f166d7` perf: multiprocessing scan, file cache, progress bar, --workers flag（18:35）

### 当前进行中
- `aegis-publisher`（d928a96f，label=aegis-publisher，model=gpt-5.2-codex-high）— 正在 poll process，监控 CI/push 流程，仍活跃
- `aegis-dev-b`（84e4b236，label=aegis-dev-b，model=gpt-5.2-codex-high）— 正在读取 fixers.py，处理修复/补全任务，仍活跃
- `aegis-detectors2`（94fad81f）— 已收到任务（硬编码密钥/弱加密/反序列化/不安全随机检测器），状态进行中

### 遇到的问题
- 部分 aegis-next 会话（de214bf3）发现 `taint.py` 中 inter-procedural 分支调用了未实现的方法，导致核心测试失败，已修复
- 多个 aegis-next 实例（2e8b2c12、f5979455）产生了空输出后退出（0 token output），疑似模型切换到 qwen3.5 thinking 导致超时或无输出；后续应固定 codex 模型
- aegis-publisher（e82bed5d）仅输出占位文字 "I understand the request" 后即停止，未实际执行任何工具调用；后续 publisher 由新实例（d928a96f）接替，改用 codex 模型后恢复正常

### 下一步
- aegis-dev-b 完成 fixers.py 修复后，publisher 应自动审核并 push
- aegis-detectors2 完成4个检测器（硬编码密钥/弱加密/反序列化/不安全随机）后，测试数量预计从50增至60+
- 后续优化方向：跨文件 inter-procedural taint、`--ruleset` 快捷入口、conditional_sinks 扩展