"""
Tests for Django framework-aware source detection via DjangoModeler.

Covers:
- FBV with ``request`` as first arg -> tainted
- FBV with ``@login_required`` decorator -> tainted
- FBV with ``@csrf_exempt`` decorator -> tainted
- CBV HTTP method (get/post) -> tainted
- DRF ``@api_view`` decorator -> tainted
- Non-view function (no request arg, no decorator) -> NOT tainted
- Sanitized FBV -> no finding
"""
import textwrap

from pyaegis.frameworks.django_modeler import DjangoModeler
from pyaegis.core.taint import TaintTracker
from pyaegis.core.parser import PyASTParser


# ---------------------------------------------------------------------------
# Unit tests: DjangoModeler.is_route_function
# ---------------------------------------------------------------------------


def _modeler():
    return DjangoModeler()


def test_fbv_request_arg_detected():
    """FBV whose first arg is 'request' is a route function."""
    meta = {"name": "my_view", "args": ["request"], "decorators": [], "routes": []}
    assert _modeler().is_route_function(meta) is True


def test_fbv_req_alias_detected():
    """FBV whose first arg is 'req' is a route function."""
    meta = {"name": "my_view", "args": ["req"], "decorators": [], "routes": []}
    assert _modeler().is_route_function(meta) is True


def test_fbv_login_required_decorator():
    """FBV with @login_required is a route function even without 'request' name."""
    meta = {
        "name": "dashboard",
        "args": ["rq"],
        "decorators": ["login_required"],
        "routes": [],
    }
    assert _modeler().is_route_function(meta) is True


def test_fbv_csrf_exempt_decorator():
    meta = {
        "name": "webhook",
        "args": ["r"],
        "decorators": ["csrf_exempt"],
        "routes": [],
    }
    assert _modeler().is_route_function(meta) is True


def test_fbv_qualified_decorator():
    """Qualified decorator like 'decorators.login_required' should match."""
    meta = {
        "name": "view",
        "args": ["request"],
        "decorators": ["decorators.login_required"],
        "routes": [],
    }
    assert _modeler().is_route_function(meta) is True


def test_cbv_get_method():
    """CBV get() with self + request args is a route function."""
    meta = {"name": "get", "args": ["self", "request"], "decorators": [], "routes": []}
    assert _modeler().is_route_function(meta) is True


def test_cbv_post_method():
    meta = {"name": "post", "args": ["self", "request"], "decorators": [], "routes": []}
    assert _modeler().is_route_function(meta) is True


def test_cbv_delete_method():
    meta = {
        "name": "delete",
        "args": ["self", "request", "pk"],
        "decorators": [],
        "routes": [],
    }
    assert _modeler().is_route_function(meta) is True


def test_drf_api_view_decorator():
    """DRF @api_view decorator marks the function as a route."""
    meta = {
        "name": "user_list",
        "args": ["request"],
        "decorators": ["api_view"],
        "routes": [],
    }
    assert _modeler().is_route_function(meta) is True


def test_explicit_route_metadata():
    """Explicit routes key (from URL conf scanner) marks as route."""
    meta = {"name": "home", "args": ["r"], "decorators": [], "routes": ["/"]}
    assert _modeler().is_route_function(meta) is True


def test_non_view_not_detected():
    """Regular helper function should NOT be detected as a route."""
    meta = {
        "name": "compute_hash",
        "args": ["data", "salt"],
        "decorators": [],
        "routes": [],
    }
    assert _modeler().is_route_function(meta) is False


def test_get_tainted_params_fbv():
    """get_tainted_params returns all non-self args."""
    meta = {
        "name": "my_view",
        "args": ["request", "pk"],
        "decorators": [],
        "routes": [],
    }
    params = _modeler().get_tainted_params(meta)
    assert "request" in params
    assert "pk" in params
    assert "self" not in params


def test_get_tainted_params_cbv():
    meta = {
        "name": "get",
        "args": ["self", "request", "pk"],
        "decorators": [],
        "routes": [],
    }
    params = _modeler().get_tainted_params(meta)
    assert "request" in params
    assert "pk" in params
    assert "self" not in params


# ---------------------------------------------------------------------------
# Integration tests: taint flows from Django view through sink
# ---------------------------------------------------------------------------


def _write(tmp_path, name, src):
    p = tmp_path / name
    p.write_text(textwrap.dedent(src), encoding="utf-8")
    return str(p)


def _analyze(tmp_path, name, src):
    fpath = _write(tmp_path, name, src)
    parser = PyASTParser(fpath)
    parser.parse()
    cfg = parser.extract_cfg()
    tracker = TaintTracker(
        sources=["request"],
        sinks=["os.system", "subprocess.*", "eval", "exec"],
        sanitizers=["shlex.quote"],
    )
    tracker.analyze_cfg(cfg, fpath)
    return tracker.get_findings()


def test_django_fbv_request_to_sink(tmp_path):
    """Django FBV: request.GET['cmd'] flows to os.system -> finding."""
    src = """\
        import os
        from django.http import HttpResponse

        def run_view(request):
            cmd = request.GET.get('cmd', '')
            os.system(cmd)
            return HttpResponse('ok')
        """
    findings = _analyze(tmp_path, "run_view.py", src)
    assert len(findings) >= 1, f"Expected finding, got: {findings}"
    assert any(f.sink_name == "os.system" for f in findings)


def test_django_fbv_sanitized_no_finding(tmp_path):
    """Django FBV: shlex.quote sanitizes before os.system -> no finding."""
    src = """\
        import os
        import shlex
        from django.http import HttpResponse

        def run_view(request):
            cmd = shlex.quote(request.GET.get('cmd', ''))
            os.system(cmd)
            return HttpResponse('ok')
        """
    findings = _analyze(tmp_path, "run_view_safe.py", src)
    assert len(findings) == 0, f"Expected no findings, got: {findings}"


def test_django_fbv_eval_sink(tmp_path):
    """Django FBV: user input passed to eval -> finding."""
    src = """\
        def eval_view(request):
            code = request.POST.get('code', '')
            eval(code)
        """
    findings = _analyze(tmp_path, "eval_view.py", src)
    assert len(findings) >= 1, f"Expected finding, got: {findings}"
    assert any(f.sink_name == "eval" for f in findings)
