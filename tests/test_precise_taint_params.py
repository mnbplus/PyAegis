"""Tests for framework-precise taint param seeding via get_tainted_params().

Verifies that TaintTracker seeds exactly the params each framework modeler
returns, rather than blindly tainting all non-self arguments.
"""
import ast

from pyaegis.core.taint import TaintTracker
from pyaegis.frameworks.django_modeler import DjangoModeler
from pyaegis.frameworks.fastapi_modeler import FastAPIModeler
from pyaegis.frameworks.flask_modeler import FlaskModeler
from pyaegis.frameworks.registry import get_tainted_params


# ---------------------------------------------------------------------------
# Registry: get_tainted_params()
# ---------------------------------------------------------------------------


class TestRegistryGetTaintedParams:
    def test_django_fbv_returns_all_non_self(self):
        meta = {"args": ["request", "pk"], "decorators": [], "routes": []}
        # DjangoModeler recognises via request param heuristic
        result = get_tainted_params(meta)
        assert result == ["request", "pk"]

    def test_flask_route_returns_url_kwargs(self):
        meta = {"args": ["user_id"], "decorators": ["app.route"], "routes": []}
        result = get_tainted_params(meta)
        assert "user_id" in result

    def test_fastapi_route_returns_args(self):
        meta = {
            "args": ["item_id", "q"],
            "decorators": ["app.get"],
            "routes": [],
            "source_params": [],
        }
        result = get_tainted_params(meta)
        assert "item_id" in result
        assert "q" in result

    def test_non_route_returns_empty(self):
        meta = {"args": ["x", "y"], "decorators": [], "routes": []}
        result = get_tainted_params(meta)
        assert result == []

    def test_fastapi_includes_source_params(self):
        meta = {
            "args": ["item_id"],
            "decorators": ["app.post"],
            "routes": [],
            "source_params": ["body"],
        }
        result = get_tainted_params(meta)
        assert "item_id" in result
        assert "body" in result


# ---------------------------------------------------------------------------
# Individual modeler: get_tainted_params()
# ---------------------------------------------------------------------------


class TestFlaskModelerTaintedParams:
    def setup_method(self):
        self.m = FlaskModeler()

    def test_returns_all_non_self_args(self):
        meta = {"args": ["name", "age"], "decorators": ["app.route"]}
        assert self.m.get_tainted_params(meta) == ["name", "age"]

    def test_excludes_self(self):
        meta = {"args": ["self", "pk"], "decorators": ["app.get"]}
        assert self.m.get_tainted_params(meta) == ["pk"]

    def test_empty_args(self):
        meta = {"args": [], "decorators": ["app.route"]}
        assert self.m.get_tainted_params(meta) == []


class TestFastAPIModelerTaintedParams:
    def setup_method(self):
        self.m = FastAPIModeler()

    def test_returns_all_non_self_args(self):
        meta = {
            "args": ["item_id", "q"],
            "decorators": ["app.get"],
            "source_params": [],
        }
        result = self.m.get_tainted_params(meta)
        assert set(result) == {"item_id", "q"}

    def test_merges_source_params(self):
        meta = {
            "args": ["item_id"],
            "decorators": ["app.post"],
            "source_params": ["payload"],
        }
        result = self.m.get_tainted_params(meta)
        assert "item_id" in result
        assert "payload" in result

    def test_no_duplicate_from_source_params(self):
        meta = {
            "args": ["item_id"],
            "decorators": ["app.post"],
            "source_params": ["item_id"],
        }
        result = self.m.get_tainted_params(meta)
        assert result.count("item_id") == 1

    def test_excludes_self(self):
        meta = {
            "args": ["self", "pk"],
            "decorators": ["router.get"],
            "source_params": [],
        }
        result = self.m.get_tainted_params(meta)
        assert "self" not in result
        assert "pk" in result


class TestDjangoModelerTaintedParams:
    def setup_method(self):
        self.m = DjangoModeler()

    def test_fbv_request_and_pk(self):
        meta = {"args": ["request", "pk"], "decorators": [], "routes": []}
        assert self.m.get_tainted_params(meta) == ["request", "pk"]

    def test_cbv_excludes_self(self):
        meta = {"args": ["self", "request"], "decorators": [], "routes": []}
        assert self.m.get_tainted_params(meta) == ["request"]

    def test_only_self_returns_empty(self):
        meta = {"args": ["self"], "decorators": [], "routes": []}
        assert self.m.get_tainted_params(meta) == []

    def test_multiple_url_kwargs(self):
        meta = {
            "args": ["request", "org_id", "repo_id"],
            "decorators": [],
            "routes": [],
        }
        result = self.m.get_tainted_params(meta)
        assert result == ["request", "org_id", "repo_id"]


# ---------------------------------------------------------------------------
# Integration: TaintTracker seeds precise params from framework modeler
# ---------------------------------------------------------------------------


def _make_cfg_sink_in_arg(arg_name: str, sink: str, decorator: str):
    """Build a minimal CFG where `arg_name` flows directly into `sink`."""
    src = f"""
def view({arg_name}):
    {sink}({arg_name})
"""
    tree = ast.parse(src)
    fn = tree.body[0]
    body_stmts = fn.body
    return {
        "view": {
            "body": body_stmts,
            "args": [arg_name],
            "decorators": [decorator],
            "routes": [],
            "source_params": [],
        }
    }


class TestTaintTrackerPreciseSeeding:
    def test_flask_route_arg_reaches_sink(self):
        cfg = _make_cfg_sink_in_arg("user_id", "os.system", "app.route")
        tracker = TaintTracker(
            sources=["request", "request.args", "request.form"],
            sinks=["os.system", "subprocess.*"],
        )
        tracker.analyze_cfg(cfg, "views.py")
        assert len(tracker.vulnerabilities) == 1

    def test_django_request_arg_reaches_sink(self):
        cfg = _make_cfg_sink_in_arg("request", "os.system", "login_required")
        tracker = TaintTracker(
            sources=["request", "request.GET"],
            sinks=["os.system", "subprocess.*"],
        )
        tracker.analyze_cfg(cfg, "views.py")
        assert len(tracker.vulnerabilities) == 1

    def test_non_route_arg_not_tainted(self):
        """A plain function with no route decorator should not auto-taint args."""
        src = "def helper(x):\n    os_system(x)\n"
        tree = ast.parse(src)
        fn = tree.body[0]
        cfg = {
            "helper": {
                "body": fn.body,
                "args": ["x"],
                "decorators": [],
                "routes": [],
                "source_params": [],
            }
        }
        tracker = TaintTracker(
            sources=["request"],
            sinks=["os_system"],
        )
        tracker.analyze_cfg(cfg, "utils.py")
        assert len(tracker.vulnerabilities) == 0
