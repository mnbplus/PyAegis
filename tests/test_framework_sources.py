"""Tests for framework-aware taint source detection.

Covers:
- Flask route decorator params auto-marked as source
- FastAPI route params
- Django view params
- Sanitizer clears taint
"""
import textwrap
from pyaegis.core.taint import TaintTracker
from pyaegis.core.parser import PyASTParser


def _parse_and_track(tmp_path, name, code, sources, sinks, sanitizers=None):
    p = tmp_path / name
    p.write_text(textwrap.dedent(code).lstrip("\n"), encoding="utf-8")
    parser = PyASTParser(str(p))
    parser.parse()
    cfg = parser.extract_cfg()
    tracker = TaintTracker(
        sources=sources,
        sinks=sinks,
        sanitizers=sanitizers or [],
    )
    tracker.analyze_cfg(cfg, filepath=str(p))
    return tracker.get_findings()


# ---------------------------------------------------------------------------
# Flask
# ---------------------------------------------------------------------------

def test_flask_route_param_tainted_to_os_system(tmp_path):
    """Flask route function param should be treated as tainted source."""
    code = """
    import os
    from flask import Flask
    app = Flask(__name__)

    @app.route('/run/<cmd>')
    def run_cmd(cmd):
        os.system(cmd)
    """
    findings = _parse_and_track(
        tmp_path, "flask_param.py", code,
        sources=["request"],
        sinks=["os.system"],
    )
    assert len(findings) >= 1, "Flask route param should be tainted"


def test_flask_route_param_sanitized_no_finding(tmp_path):
    """Sanitized Flask route param should NOT trigger a finding."""
    code = """
    import os
    import html
    from flask import Flask
    app = Flask(__name__)

    @app.route('/run/<cmd>')
    def run_safe(cmd):
        safe_cmd = html.escape(cmd)
        os.system(safe_cmd)
    """
    findings = _parse_and_track(
        tmp_path, "flask_safe.py", code,
        sources=["request"],
        sinks=["os.system"],
        sanitizers=["html.escape"],
    )
    assert len(findings) == 0, "Sanitized value should clear taint"


def test_flask_route_multiple_params_tainted(tmp_path):
    """All Flask route params should be tainted, not just the first."""
    code = """
    import subprocess
    from flask import Flask
    app = Flask(__name__)

    @app.route('/run/<host>/<port>')
    def connect(host, port):
        subprocess.run(f"{host}:{port}", shell=True)
    """
    findings = _parse_and_track(
        tmp_path, "flask_multi_params.py", code,
        sources=["request"],
        sinks=["subprocess.run", "subprocess.*"],
    )
    assert len(findings) >= 1


def test_flask_post_route_tainted(tmp_path):
    """Flask POST route decorator also marks params as tainted."""
    code = """
    import os
    from flask import Flask
    app = Flask(__name__)

    @app.post('/exec')
    def exec_cmd(cmd):
        os.system(cmd)
    """
    findings = _parse_and_track(
        tmp_path, "flask_post.py", code,
        sources=["request"],
        sinks=["os.system"],
    )
    assert len(findings) >= 1


# ---------------------------------------------------------------------------
# FastAPI
# ---------------------------------------------------------------------------

def test_fastapi_get_route_param_tainted(tmp_path):
    """FastAPI @app.get route param should be treated as tainted."""
    code = """
    import os
    from fastapi import FastAPI
    app = FastAPI()

    @app.get('/run')
    def run_cmd(cmd: str):
        os.system(cmd)
    """
    findings = _parse_and_track(
        tmp_path, "fastapi_param.py", code,
        sources=["request"],
        sinks=["os.system"],
    )
    assert len(findings) >= 1, "FastAPI route param should be tainted"


def test_fastapi_post_route_param_tainted(tmp_path):
    """FastAPI @app.post route param propagates to sink."""
    code = """
    import subprocess
    from fastapi import FastAPI
    app = FastAPI()

    @app.post('/items')
    def create_item(name: str):
        subprocess.run(name, shell=True)
    """
    findings = _parse_and_track(
        tmp_path, "fastapi_post.py", code,
        sources=["request"],
        sinks=["subprocess.*"],
    )
    assert len(findings) >= 1


def test_fastapi_sanitizer_blocks(tmp_path):
    """FastAPI route param sanitized by html.escape should not trigger."""
    code = """
    import os
    import html
    from fastapi import FastAPI
    app = FastAPI()

    @app.get('/safe')
    def safe_route(q: str):
        safe = html.escape(q)
        os.system(safe)
    """
    findings = _parse_and_track(
        tmp_path, "fastapi_sanitized.py", code,
        sources=["request"],
        sinks=["os.system"],
        sanitizers=["html.escape"],
    )
    assert len(findings) == 0


# ---------------------------------------------------------------------------
# Django
# ---------------------------------------------------------------------------

def test_django_view_request_param_tainted(tmp_path):
    """Django view: request.GET data flowing to sink should be detected."""
    code = """
    import os

    def my_view(request):
        cmd = request.GET.get('cmd')
        os.system(cmd)
    """
    findings = _parse_and_track(
        tmp_path, "django_view.py", code,
        sources=["request", "request.GET"],
        sinks=["os.system"],
    )
    assert len(findings) >= 1


def test_django_class_based_view(tmp_path):
    """Django class-based view: POST data to subprocess sink."""
    code = """
    import subprocess

    class MyView:
        def post(self, request):
            data = request.POST.get('cmd')
            subprocess.run(data, shell=True)
    """
    findings = _parse_and_track(
        tmp_path, "django_cbv.py", code,
        sources=["request", "request.POST"],
        sinks=["subprocess.*"],
    )
    assert len(findings) >= 1


def test_django_sanitizer_clears_taint(tmp_path):
    """Django view: bleach.clean sanitizer should clear taint."""
    code = """
    import os
    import bleach

    def safe_view(request):
        raw = request.GET.get('q')
        clean = bleach.clean(raw)
        os.system(clean)
    """
    findings = _parse_and_track(
        tmp_path, "django_bleach.py", code,
        sources=["request", "request.GET"],
        sinks=["os.system"],
        sanitizers=["bleach.clean"],
    )
    assert len(findings) == 0
