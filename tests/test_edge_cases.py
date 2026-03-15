"""
tests/test_edge_cases.py

Edge case taint propagation tests:
- f-string interpolation
- Ternary / conditional expressions
- Function return value propagation
- List comprehensions
- Augmented assignment
- Nested attribute chains
"""
import textwrap

import pytest

from pyaegis.core.taint import TaintTracker
from pyaegis.core.parser import PyASTParser


def _write_tmp(tmp_path, name: str, code: str):
    p = tmp_path / name
    p.write_text(textwrap.dedent(code).lstrip("\n"), encoding="utf-8")
    return p


def make_tracker(**kwargs):
    defaults = dict(
        sources=["request", "request.args", "request.GET",
                 "request.form", "request.json", "input"],
        sinks=["os.system", "subprocess.*", "eval", "exec",
               "open", "sqlite3.Connection.execute"],
        sanitizers=["html.escape"],
    )
    defaults.update(kwargs)
    return TaintTracker(**defaults)


# ---------------------------------------------------------------------------
# f-string taint propagation
# ---------------------------------------------------------------------------

class TestFStringTaint:
    """f-string 中内插污点变量后整体应视为 tainted。"""

    def test_fstring_sql_injection(self, tmp_path):
        """f"SELECT {user_input}" 应被视为 tainted，传入 execute 应报警。"""
        p = _write_tmp(tmp_path, "fstr_sql.py", """
            import sqlite3

            def query_db(request):
                user_input = request.GET.get('id')
                sql = f"SELECT * FROM users WHERE id = {user_input}"
                conn = sqlite3.connect('db.sqlite3')
                conn.execute(sql)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_tracker(
            sinks=["sqlite3.Connection.execute", "sqlite3.Cursor.execute",
                   "os.system", "eval", "exec"]
        )
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) >= 1, "f-string SQL 注入应产生 finding"

    def test_fstring_command_injection(self, tmp_path):
        """f-string 构造命令字符串，传入 os.system 应报警。"""
        p = _write_tmp(tmp_path, "fstr_cmd.py", """
            import os

            def f(request):
                user_input = request.args.get('x')
                cmd = f'echo {user_input}'
                os.system(cmd)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) >= 1, "f-string 命令注入应产生 finding"

    def test_fstring_with_clean_var_no_taint(self, tmp_path):
        """f-string 仅内插已净化的变量，不应报警。"""
        p = _write_tmp(tmp_path, "fstr_clean.py", """
            import os
            import html

            def f(request):
                raw = request.args.get('x')
                safe = html.escape(raw)
                cmd = f'echo {safe}'
                os.system(cmd)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) == 0, "f-string 中仅有净化后变量不应报警"

    def test_fstring_mixed_taint_propagates(self, tmp_path):
        """f-string 同时内插净化和未净化变量，整体仍应视为 tainted。"""
        p = _write_tmp(tmp_path, "fstr_mixed.py", """
            import os
            import html

            def f(request):
                raw = request.args.get('x')
                safe = html.escape(raw)
                extra = request.args.get('y')
                cmd = f'echo {safe} {extra}'
                os.system(cmd)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) >= 1, "f-string 含未净化变量应报警"


# ---------------------------------------------------------------------------
# Ternary / conditional expression
# ---------------------------------------------------------------------------

class TestTernaryTaint:
    """三元表达式中若任一分支为 tainted，结果应视为 tainted。"""

    def test_ternary_tainted_true_branch(self, tmp_path):
        """x = tainted if cond else 'safe' — tainted 分支应传播污点。"""
        p = _write_tmp(tmp_path, "ternary_true.py", """
            import os

            def f(request):
                user_input = request.args.get('cmd')
                cmd = user_input if user_input else 'default'
                os.system(cmd)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) >= 1, "三元表达式 tainted 分支应传播污点"

    def test_ternary_tainted_false_branch(self, tmp_path):
        """x = 'safe' if cond else tainted — false 分支污点应传播。"""
        p = _write_tmp(tmp_path, "ternary_false.py", """
            import os

            def f(request):
                user_input = request.args.get('cmd')
                cmd = 'default' if not user_input else user_input
                os.system(cmd)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) >= 1, "三元表达式 false 分支污点应传播"

    def test_ternary_both_clean_no_finding(self, tmp_path):
        """x = 'a' if cond else 'b' — 两个分支均为常量，不应报警。"""
        p = _write_tmp(tmp_path, "ternary_clean.py", """
            import os

            def f(request):
                flag = request.args.get('flag')
                cmd = 'ls' if flag else 'pwd'
                os.system(cmd)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        # 两个分支均为常量，cmd 本身不含污点数据
        assert len(findings) == 0, "三元表达式两侧均为常量不应报警"


# ---------------------------------------------------------------------------
# Function return value propagation
# ---------------------------------------------------------------------------

class TestFunctionReturnTaint:
    """函数返回值污点传播：若函数返回 tainted 值，调用结果也应视为 tainted。"""

    def test_function_returns_request_get(self, tmp_path):
        """def get(): return request.GET.get('q') 调用结果应为 tainted。"""
        p = _write_tmp(tmp_path, "ret_taint.py", """
            import os

            def get_query(request):
                return request.GET.get('q')

            def endpoint(request):
                q = get_query(request)
                os.system(q)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) >= 1, "函数返回 tainted 值，调用处应传播污点"

    def test_function_returns_constant_no_taint(self, tmp_path):
        """函数只返回常量，调用结果不应视为 tainted。"""
        p = _write_tmp(tmp_path, "ret_clean.py", """
            import os

            def get_default():
                return 'ls -la'

            def endpoint(request):
                cmd = get_default()
                os.system(cmd)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) == 0, "函数返回常量不应产生 finding"

    def test_nested_function_return_taint(self, tmp_path):
        """多层函数嵌套返回污点值，最终应产生 finding。"""
        p = _write_tmp(tmp_path, "ret_nested.py", """
            import os

            def inner(request):
                return request.args.get('cmd')

            def outer(request):
                return inner(request)

            def endpoint(request):
                cmd = outer(request)
                os.system(cmd)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) >= 1, "多层函数嵌套返回污点值应产生 finding"


# ---------------------------------------------------------------------------
# List comprehension taint
# ---------------------------------------------------------------------------

class TestListComprehensionTaint:
    """列表推导式中对 tainted 元素调用 sink 应报警。"""

    def test_list_comp_sink_call(self, tmp_path):
        """[os.system(x) for x in tainted_list] 应产生 finding。"""
        p = _write_tmp(tmp_path, "listcomp.py", """
            import os

            def f(request):
                cmds = request.json
                results = [os.system(x) for x in cmds]
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) >= 1, "列表推导中对 tainted 元素调用 sink 应报警"

    def test_list_comp_eval_tainted_elements(self, tmp_path):
        """列表推导中对 tainted 字符串调用 eval 应报警。"""
        p = _write_tmp(tmp_path, "listcomp_eval.py", """
            def f(request):
                exprs = request.json
                results = [eval(e) for e in exprs]
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) >= 1, "列表推导中 eval(tainted) 应报警"

    def test_list_comp_clean_source_no_finding(self, tmp_path):
        """列表推导中元素来自常量列表，不应报警。"""
        p = _write_tmp(tmp_path, "listcomp_clean.py", """
            import os

            def f():
                safe_cmds = ['ls', 'pwd', 'echo hello']
                results = [os.system(c) for c in safe_cmds]
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) == 0, "常量列表推导不应报警"


# ---------------------------------------------------------------------------
# Augmented assignment taint propagation
# ---------------------------------------------------------------------------

class TestAugAssignTaint:
    """+= 等增量赋值应传播污点。"""

    def test_augassign_concat_taint(self, tmp_path):
        """cmd += tainted 后 cmd 应视为 tainted。"""
        p = _write_tmp(tmp_path, "augassign.py", """
            import os

            def f(request):
                user_input = request.args.get('extra')
                cmd = 'ls '
                cmd += user_input
                os.system(cmd)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) >= 1, "+= 拼接 tainted 值后应传播污点"


# ---------------------------------------------------------------------------
# Tuple unpacking taint propagation
# ---------------------------------------------------------------------------

class TestTupleUnpackTaint:
    """元组解包时污点应传播至所有目标变量。"""

    def test_tuple_unpack_both_tainted(self, tmp_path):
        """a, b = tainted_expr — 两个变量均应视为 tainted。"""
        p = _write_tmp(tmp_path, "unpack.py", """
            import os

            def f(request):
                a, b = request.args.get('x'), request.args.get('y')
                os.system(b)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) >= 1, "元组解包中 tainted 值应传播至目标变量"
