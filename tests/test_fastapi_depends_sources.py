"""
Tests for FastAPI Depends injection source detection.
"""
import textwrap

from pyaegis.core.parser import PyASTParser
from pyaegis.core.taint import TaintTracker


def _write_tmp(tmp_path, name: str, code: str):
    p = tmp_path / name
    p.write_text(textwrap.dedent(code).lstrip("\n"), encoding="utf-8")
    return p


def make_tracker(**kwargs):
    defaults = dict(
        sources=["request", "request.args", "request.GET", "request.form", "input"],
        sinks=["os.system", "subprocess.*", "eval", "exec", "open"],
        sanitizers=["html.escape", "bleach.clean"],
    )
    defaults.update(kwargs)
    return TaintTracker(**defaults)


class TestFastAPIDependsSources:
    def test_simple_depends_param_is_tainted(self, tmp_path):
        p = _write_tmp(
            tmp_path,
            "fastapi_depends.py",
            """
            import os
            from fastapi import FastAPI, Depends

            app = FastAPI()

            def get_query(q: str) -> str:
                return q

            @app.get("/search")
            def search(query: str = Depends(get_query)):
                os.system(query)
            """,
        )
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) >= 1, "Depends 注入参数应视为 tainted source"
        assert findings[0].sink_context == "search"

    def test_chained_depends_param_is_tainted(self, tmp_path):
        p = _write_tmp(
            tmp_path,
            "fastapi_depends_chain.py",
            """
            import os
            from fastapi import FastAPI, Depends

            app = FastAPI()

            def get_token(token: str) -> str:
                return token

            def get_user(token: str = Depends(get_token)) -> str:
                return token

            @app.get("/run")
            def run(cmd: str = Depends(get_user)):
                os.system(cmd)
            """,
        )
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) >= 1, "链式 Depends 注入应标为 tainted source"
        assert findings[0].sink_context == "run"

    def test_depends_param_sanitized_no_finding(self, tmp_path):
        p = _write_tmp(
            tmp_path,
            "fastapi_depends_sanitized.py",
            """
            import os
            import html
            from fastapi import FastAPI, Depends

            app = FastAPI()

            def get_query(q: str) -> str:
                return q

            @app.get("/search")
            def search(query: str = Depends(get_query)):
                safe = html.escape(query)
                os.system(safe)
            """,
        )
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) == 0, "Depends 注入参数经 sanitizer 后不应报警"
