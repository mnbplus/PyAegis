# PyAegis 进度日志

---

## 2026-03-16 07:35 (Asia/Shanghai)

**完成内容：**
- 扩充跨模块 sanitizer 截断链路测试，在 `tests/test_cross_module.py` 新增 3 个场景：
  1. sanitizer → wrapper → sink：clean 值经包装仍保持 clean（不误报）
  2. callee 内部先 sanitize 再 sink：应不报
  3. 补齐已有跨模块 sanitizer 截断场景，修复 lint
- 所有测试通过（pytest exit code 0）
- commit `1b93e033` 已 push 到 main

**遇到问题：**
- 尝试为 call graph 添加类方法/装饰器支持，但会破坏 interprocedural/cross_module 现有测试（symbol table key 索引方式变化），已回退，避免引入回归

**下一步：**
- 重新设计类方法/装饰器支持方案，确保不破坏现有测试
- 推进 PRODUCT_RESEARCH.md 的产品调研文档（当前不存在）
- 继续扩展污点分析核心能力

## 2026-03-16 08:30 (Asia/Shanghai)

**完成内容：**
- 重新设计并实现 GlobalSymbolTable 类方法索引支持
- 新增 _register_function() 辅助方法，统一处理顶层函数和类方法注册
- 新增 _register_class_methods()，遍历 ast.ClassDef 体，注册全部方法
- qualname 格式：module.ClassName.method_name（顶层函数格式不变，零回归）
- by-name 索引和 by-file 索引同步更新，get_by_name() 对类方法正常工作
- 新增 4 个测试：qualname 查找、args 含 self、get_by_name、跨模块 dao 场景
- 全套 234 个测试通过，commit 5f1a3d1

**遇到问题：**
- 第一次 edit 工具调用未生效（oldText 有隐形字符差异），第二次精准替换成功
- 测试里误留了未使用的 import，pre-commit flake8 拦截，已清理

**下一步：**
- 利用新的类方法索引，在 TaintTracker 中支持实例方法调用追踪（self.method() 形式）
- 推进 ROADMAP P1：框架感知 Source 自动发现（FastAPI/Django 完整覆盖）
- 可选：创建 PRODUCT_RESEARCH.md 产品调研文档
