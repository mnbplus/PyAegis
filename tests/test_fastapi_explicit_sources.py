"""
test_fastapi_explicit_sources.py

Tests for FastAPI explicit source annotations:
  Query(), Body(), Header(), Path(), Form(), Cookie(), File(), UploadFile

These are all user-controlled inputs and must be treated as taint sources.
"""
import textwrap

from pyaegis.core.parser import PyASTParser
from pyaegis.core.taint import TaintTracker


def _write(tmp_path, name: str, code: str):
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


# ---------------------------------------------------------------------------
# Query()
# ---------------------------------------------------------------------------


class TestQuerySource:
    def test_query_param_tainted(self, tmp_path):
        p = _write(
            tmp_path,
            "fastapi_query.py",
            """
            import os
            from fastapi import FastAPI, Query

            app = FastAPI()

            @app.get("/search")
            def search(q: str = Query(...)):
                os.system(q)
            """,
        )
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()
        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()
        assert len(findings) >= 1, "Query() param should be tainted"
        assert findings[0].sink_context == "search"

    def test_query_param_sanitized_no_finding(self, tmp_path):
        p = _write(
            tmp_path,
            "fastapi_query_safe.py",
            """
            import os
            import html
            from fastapi import FastAPI, Query

            app = FastAPI()

            @app.get("/search")
            def search(q: str = Query(...)):
                safe = html.escape(q)
                os.system(safe)
            """,
        )
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()
        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()
        assert len(findings) == 0, "Sanitized Query() param should not trigger finding"


# ---------------------------------------------------------------------------
# Body()
# ---------------------------------------------------------------------------


class TestBodySource:
    def test_body_param_tainted(self, tmp_path):
        p = _write(
            tmp_path,
            "fastapi_body.py",
            """
            import os
            from fastapi import FastAPI, Body

            app = FastAPI()

            @app.post("/run")
            def run(cmd: str = Body(...)):
                os.system(cmd)
            """,
        )
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()
        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()
        assert len(findings) >= 1, "Body() param should be tainted"


# ---------------------------------------------------------------------------
# Header()
# ---------------------------------------------------------------------------


class TestHeaderSource:
    def test_header_param_tainted(self, tmp_path):
        p = _write(
            tmp_path,
            "fastapi_header.py",
            """
            import os
            from fastapi import FastAPI, Header

            app = FastAPI()

            @app.get("/info")
            def info(x_forwarded_for: str = Header(None)):
                os.system(x_forwarded_for)
            """,
        )
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()
        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()
        assert len(findings) >= 1, "Header() param should be tainted"


# ---------------------------------------------------------------------------
# Path()
# ---------------------------------------------------------------------------


class TestPathSource:
    def test_path_param_tainted(self, tmp_path):
        p = _write(
            tmp_path,
            "fastapi_path.py",
            """
            import os
            from fastapi import FastAPI, Path

            app = FastAPI()

            @app.get("/items/{item_id}")
            def get_item(item_id: str = Path(...)):
                os.system(item_id)
            """,
        )
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()
        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()
        assert len(findings) >= 1, "Path() param should be tainted"


# ---------------------------------------------------------------------------
# Form()
# ---------------------------------------------------------------------------


class TestFormSource:
    def test_form_param_tainted(self, tmp_path):
        p = _write(
            tmp_path,
            "fastapi_form.py",
            """
            import os
            from fastapi import FastAPI, Form

            app = FastAPI()

            @app.post("/login")
            def login(username: str = Form(...)):
                os.system(username)
            """,
        )
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()
        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()
        assert len(findings) >= 1, "Form() param should be tainted"


# ---------------------------------------------------------------------------
# Cookie()
# ---------------------------------------------------------------------------


class TestCookieSource:
    def test_cookie_param_tainted(self, tmp_path):
        p = _write(
            tmp_path,
            "fastapi_cookie.py",
            """
            import os
            from fastapi import FastAPI, Cookie

            app = FastAPI()

            @app.get("/profile")
            def profile(session_id: str = Cookie(None)):
                os.system(session_id)
            """,
        )
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()
        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()
        assert len(findings) >= 1, "Cookie() param should be tainted"


# ---------------------------------------------------------------------------
# File() / UploadFile
# ---------------------------------------------------------------------------


class TestFileSource:
    def test_file_param_tainted(self, tmp_path):
        p = _write(
            tmp_path,
            "fastapi_file.py",
            """
            import os
            from fastapi import FastAPI, File

            app = FastAPI()

            @app.post("/upload")
            def upload(filename: str = File(...)):
                os.system(filename)
            """,
        )
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()
        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()
        assert len(findings) >= 1, "File() param should be tainted"


# ---------------------------------------------------------------------------
# Alias import: from fastapi import Query as Q
# ---------------------------------------------------------------------------


class TestAliasedImport:
    def test_aliased_query_tainted(self, tmp_path):
        p = _write(
            tmp_path,
            "fastapi_alias.py",
            """
            import os
            from fastapi import FastAPI, Query as Q

            app = FastAPI()

            @app.get("/search")
            def search(term: str = Q(...)):
                os.system(term)
            """,
        )
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()
        tracker = make_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()
        assert len(findings) >= 1, "Aliased Query() param should be tainted"


# ---------------------------------------------------------------------------
# Mixed: Query + Depends in same endpoint
# ---------------------------------------------------------------------------


class TestMixedSourcesEndpoint:
    def test_mixed_query_and_depends(self, tmp_path):
        p = _write(
            tmp_path,
            "fastapi_mixed.py",
            """
            import os
            from fastapi import FastAPI, Query, Depends

            app = FastAPI()

            def get_user(token: str) -> str:
                return token

            @app.get("/action")
            def action(
                cmd: str = Query(...),
                user: str = Depends(get_user),
            ):
                os.system(cmd)
                os.system(user)
            """,
        )
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()
        # Verify parser extracts both params as source_params
        action_meta = cfg.get("action", {})
        source_params = action_meta.get("source_params", [])
        assert "cmd" in source_params, "Query() param 'cmd' should be in source_params"
        assert (
            "user" in source_params
        ), "Depends() param 'user' should be in source_params"
