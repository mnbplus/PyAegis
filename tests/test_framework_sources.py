"""
tests/test_framework_sources.py

Tests for framework-aware source detection and sanitizer behavior.
Covers Flask route parameter tainting and sanitizer clearing taint.
"""
import ast
import textwrap
import os
import tempfile

import pytest

from pyaegis.core.taint import TaintTracker
from pyaegis.core.parser import PyASTParser


def _write_tmp(tmp_path, name: str, code: str):
    p = tmp_path / name
    p.write_text(textwrap.dedent(code).lstrip("\n"), encoding="utf-8")
    return p


def make_tracker(**kwargs):
    defaults = dict(
        sources=["request", "request.args", "request.GET", "request.form",
                 "request.json", "request.data", "input"],
        sinks=["os.system", "subprocess.*", "eval", "exec", "open"],
        sanitizers=["html.escape", "bleach.clean"],
    )
    defaults.update(kwargs)
    return TaintTracker(**defaults)


# ---------------------------------------------------------------------------
# Flask route parameter tainting
# ---------------------------------------------------------------------------

class TestFlaskRouteParams:
    """Flask 路由函数参数应自动被标记为 source。"""

    def test_flask_route_params_are_tainted(self, tmp_path):
        """Flask @app.route 装饰的函数，其参数应自动视为 source，
        传入 os.system 时应报告命令注入。"""
        p = _write_tmp(tmp_path, "flask_app.py", """
            import flask
            import os
            app = flask.Flask(__name__)

            @app.route('/search')
            def search(query):
                os.system(query)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) >= 1, (
            "@app.route 装饰的函数中，路由参数 query 应被视为 source，"
            "传入 os.system 应产生 finding"
        )
        assert findings[0].sink_context == "search"

    def test_flask_multiple_route_params_tainted(self, tmp_path):
        """多个路由参数均应被标记为 tainted。"""
        p = _write_tmp(tmp_path, "flask_multi.py", """
            import flask
            import os
            app = flask.Flask(__name__)

            @app.route('/exec/<cmd>/<arg>')
            def run_cmd(cmd, arg):
                combined = cmd + ' ' + arg
                os.system(combined)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) >= 1, "多个路由参数通过字符串拼接传入 sink 应产生 finding"

    def test_flask_get_method_decorator(self, tmp_path):
        """@app.get 装饰器同样应使参数视为 source。"""
        p = _write_tmp(tmp_path, "flask_get.py", """
            from flask import Flask
            import os
            app = Flask(__name__)

            @app.get('/items')
            def get_items(item_id):
                os.system(item_id)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) >= 1

    def test_fastapi_route_params_are_tainted(self, tmp_path):
        """FastAPI @app.get 装饰的函数参数应视为 source。"""
        p = _write_tmp(tmp_path, "fastapi_app.py", """
            from fastapi import FastAPI
            import os
            app = FastAPI()

            @app.get('/run')
            def run_command(cmd: str):
                os.system(cmd)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) >= 1, "FastAPI 路由参数传入 os.system 应产生 finding"

    def test_non_route_function_params_not_auto_tainted(self, tmp_path):
        """普通（非路由）函数的参数不应自动视为 source，传入 sink 不应误报。"""
        p = _write_tmp(tmp_path, "plain_func.py", """
            import os

            def helper(cmd):
                os.system(cmd)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        # 无 source，普通参数不应视为 tainted
        tracker = TaintTracker(
            sources=["request"],
            sinks=["os.system"],
        )
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) == 0, "普通函数参数不应误报为 tainted"


# ---------------------------------------------------------------------------
# Sanitizer clearing taint
# ---------------------------------------------------------------------------

class TestSanitizerClearsTaint:
    """净化函数应清除污点，净化后的值传入 sink 不应报警。"""

    def test_html_escape_clears_taint(self, tmp_path):
        """html.escape 净化后不应报警。"""
        p = _write_tmp(tmp_path, "sanitize_html.py", """
            import html
            import os

            def f(request):
                user_input = request.args.get('x')
                safe = html.escape(user_input)
                os.system(safe)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) == 0, "html.escape 净化后 os.system 不应报警"

    def test_html_escape_input_builtin(self, tmp_path):
        """内置 input() 经 html.escape 净化后不应报警。"""
        p = _write_tmp(tmp_path, "sanitize_input.py", """
            import html
            import os

            def main():
                user_input = input()
                safe = html.escape(user_input)
                os.system(safe)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) == 0, "input() 经 html.escape 净化后不应报警"

    def test_unsanitized_input_builtin_reports(self, tmp_path):
        """内置 input() 未经净化直接传入 sink 应报警。"""
        p = _write_tmp(tmp_path, "unsanitized_input.py", """
            import os

            def main():
                user_input = input()
                os.system(user_input)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) >= 1, "input() 未净化传入 os.system 应报警"

    def test_partial_sanitize_still_tainted(self, tmp_path):
        """只对部分值净化，另一部分未净化时拼接后仍应报警。"""
        p = _write_tmp(tmp_path, "partial_sanitize.py", """
            import html
            import os

            def f(request):
                a = request.args.get('a')
                b = request.args.get('b')
                safe_a = html.escape(a)
                cmd = safe_a + b   # b 未净化，拼接后仍 tainted
                os.system(cmd)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) >= 1, "部分净化后拼接未净化值应报警"

    def test_bleach_clean_clears_taint(self, tmp_path):
        """bleach.clean 净化后不应报警。"""
        p = _write_tmp(tmp_path, "sanitize_bleach.py", """
            import bleach
            import os

            def f(request):
                user_input = request.args.get('x')
                safe = bleach.clean(user_input)
                os.system(safe)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) == 0, "bleach.clean 净化后不应报警"
