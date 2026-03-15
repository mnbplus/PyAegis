# PyAegis Technical Roadmap

> 外部技术评审输入，2026-03-15

## 当前状态评价

**优势：**
- 工程化满分：pyproject.toml/tox/pre-commit/CI/SARIF 全齐
- 性能取舍极佳：多进程 AST + 函数级污点，适合 CI 强阻断
- 规则引擎薄且易扩展：YAML Source/Sink/Sanitizer
- 污点传播覆盖 f-string/字符串拼接/容器，秒杀正则 Linter

**核心瓶颈：**
1. **过程间分析极弱** — 跨文件/跨类方法污点链断裂 → 大量漏报
2. **缺乏 SSA/别名分析** — 变量反复赋值/解包赋值丢失追踪
3. **框架语义缺失** — FastAPI 依赖注入参数无法识别为 Source
4. **规则无条件约束** — `subprocess.run(cmd, shell=False)` 误报

## v1.x 演进方向（优先级排序）

### 🥇 P0：跨模块调用图（Inter-procedural Taint）
- 构建全局函数符号表
- 解析 import，追踪跨模块污点传播
- 有限深度调用栈追踪

### 🥈 P1：框架感知 Source 自动发现
- FastAPI：`@app.get` 装饰器下所有入参自动标记为 Source
- Django ORM：`raw()` vs `filter()` 语义区分
- Flask：`request.*` 更完整的属性覆盖

### 🥉 P2：强化规则引擎
```yaml
sinks:
  - name: subprocess.run
    severity: CRITICAL
    conditions:
      - has_kwarg: {shell: True}
      - arg_type: string
```

### P3：大模型自动修复（AI Auto-Remediation）
- `pyaegis fix` 子命令
- 漏洞上下文 + Prompt → LLM → Patch
- 可对接 Codex API

### P4：增量分析缓存
- 文件变更 → 仅重新分析变更文件及其依赖方

## 紧急修复
- 确保 `pip install -e .[dev]` 在 CI 中正确更新 models.py
- `Finding.source_var` 兼容性：老测试用 `**kwargs` 实例化需更新
