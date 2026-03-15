from pyaegis.core.taint import TaintTracker
from pyaegis.core.parser import PyASTParser
import os
import textwrap


def _write_tmp(tmp_path, name: str, code: str):
    p = tmp_path / name
    p.write_text(textwrap.dedent(code).lstrip("\n"), encoding="utf-8")
    return p


def test_ast_parser_valid_file(tmp_path):
    p = _write_tmp(
        tmp_path,
        "test_file.py",
        """
    def hello():
        return 'Hello World'
    """,
    )

    parser = PyASTParser(str(p))
    tree = parser.parse()
    assert tree is not None

    cfg = parser.extract_cfg()
    assert "hello" in cfg


def test_parser_detects_route_decorator_flask(tmp_path):
    p = _write_tmp(
        tmp_path,
        "flask_app.py",
        """
    from flask import Flask, request
    app = Flask(__name__)

    @app.route('/run', methods=['GET'])
    def run():
        return 'ok'
    """,
    )

    parser = PyASTParser(str(p))
    parser.parse()
    cfg = parser.extract_cfg()
    assert cfg["run"]["routes"][0]["path"] == "/run"
    assert "GET" in cfg["run"]["routes"][0]["methods"]


def test_parser_detects_route_decorator_fastapi(tmp_path):
    p = _write_tmp(
        tmp_path,
        "fastapi_app.py",
        """
    from fastapi import FastAPI
    app = FastAPI()

    @app.get('/items')
    def items():
        return {'ok': True}
    """,
    )

    parser = PyASTParser(str(p))
    parser.parse()
    cfg = parser.extract_cfg()
    assert cfg["items"]["routes"][0]["path"] == "/items"
    assert "GET" in cfg["items"]["routes"][0]["methods"]


def test_taint_tracker_detects_sink_simple_source():
    code_body = """
    import os
    def insecure_endpoint(request):
        user_input = request.GET.get('cmd')
        os.system(user_input)
    """
    tmp_path = "dummy_test_file.py"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(textwrap.dedent(code_body).lstrip("\n"))

    parser = PyASTParser(tmp_path)
    parser.parse()
    cfg = parser.extract_cfg()

    tracker = TaintTracker(sources=["request", "request.GET"], sinks=["os.system"])
    tracker.analyze_cfg(cfg, filepath=tmp_path)

    findings = tracker.get_findings()
    assert len(findings) == 1
    assert findings[0].sink_context == "insecure_endpoint"

    os.remove(tmp_path)


def test_taint_propagates_string_concat(tmp_path):
    p = _write_tmp(
        tmp_path,
        "concat.py",
        """
    import os
    def f(request):
        a = request.args.get('x')
        cmd = 'ls ' + a
        os.system(cmd)
    """,
    )

    parser = PyASTParser(str(p))
    parser.parse()
    cfg = parser.extract_cfg()

    tracker = TaintTracker(sources=["request", "request.args"], sinks=["os.system"])
    tracker.analyze_cfg(cfg, filepath=str(p))
    assert len(tracker.get_findings()) == 1


def test_taint_propagates_fstring(tmp_path):
    p = _write_tmp(
        tmp_path,
        "fstring.py",
        """
    import os
    def f(request):
        a = request.args.get('x')
        cmd = f'echo {a}'
        os.system(cmd)
    """,
    )

    parser = PyASTParser(str(p))
    parser.parse()
    cfg = parser.extract_cfg()

    tracker = TaintTracker(sources=["request", "request.args"], sinks=["os.system"])
    tracker.analyze_cfg(cfg, filepath=str(p))
    assert len(tracker.get_findings()) == 1


def test_sanitizer_blocks_taint(tmp_path):
    p = _write_tmp(
        tmp_path,
        "sanitize.py",
        """
    import os
    import html

    def f(request):
        a = request.args.get('x')
        safe = html.escape(a)
        os.system(safe)
    """,
    )

    parser = PyASTParser(str(p))
    parser.parse()
    cfg = parser.extract_cfg()

    tracker = TaintTracker(
        sources=["request", "request.args"],
        sinks=["os.system"],
        sanitizers=["html.escape"],
    )
    tracker.analyze_cfg(cfg, filepath=str(p))
    assert len(tracker.get_findings()) == 0


def test_flask_sources_request_json_to_eval(tmp_path):
    p = _write_tmp(
        tmp_path,
        "flask_json.py",
        """
    def f(request):
        x = request.json
        eval(x)
    """,
    )

    parser = PyASTParser(str(p))
    parser.parse()
    cfg = parser.extract_cfg()

    tracker = TaintTracker(sources=["request", "request.json"], sinks=["eval"])
    tracker.analyze_cfg(cfg, filepath=str(p))
    assert len(tracker.get_findings()) == 1


def test_django_sources_request_post_to_open(tmp_path):
    p = _write_tmp(
        tmp_path,
        "django_post.py",
        """
    def f(request):
        fn = request.POST.get('p')
        open(fn, 'w').write('x')
    """,
    )

    parser = PyASTParser(str(p))
    parser.parse()
    cfg = parser.extract_cfg()

    tracker = TaintTracker(sources=["request", "request.POST"], sinks=["open"])
    tracker.analyze_cfg(cfg, filepath=str(p))
    assert len(tracker.get_findings()) == 1


def test_interprocedural_taint_flow(tmp_path):
    p = _write_tmp(
        tmp_path,
        "interproc.py",
        """
    import os

    def get_cmd(request):
        return request.args.get('cmd')

    def endpoint(request):
        cmd = get_cmd(request)
        os.system(cmd)
    """,
    )

    parser = PyASTParser(str(p))
    parser.parse()
    cfg = parser.extract_cfg()

    tracker = TaintTracker(sources=["request", "request.args"], sinks=["os.system"])
    tracker.analyze_cfg(cfg, filepath=str(p))
    assert len(tracker.get_findings()) == 1


def test_interprocedural_taint_through_wrapper(tmp_path):
    p = _write_tmp(
        tmp_path,
        "wrapper.py",
        """
    import subprocess

    def wrap(x):
        return x

    def endpoint(request):
        u = request.args.get('u')
        subprocess.run(wrap(u), shell=True)
    """,
    )

    parser = PyASTParser(str(p))
    parser.parse()
    cfg = parser.extract_cfg()

    tracker = TaintTracker(sources=["request", "request.args"], sinks=["subprocess.*"])
    tracker.analyze_cfg(cfg, filepath=str(p))
    assert len(tracker.get_findings()) == 1


def test_deserialization_pickle_loads(tmp_path):
    p = _write_tmp(
        tmp_path,
        "pickle.py",
        """
    import pickle

    def f(request):
        blob = request.data
        pickle.loads(blob)
    """,
    )

    parser = PyASTParser(str(p))
    parser.parse()
    cfg = parser.extract_cfg()

    tracker = TaintTracker(sources=["request", "request.data"], sinks=["pickle.loads"])
    tracker.analyze_cfg(cfg, filepath=str(p))
    assert len(tracker.get_findings()) == 1


def test_ssrf_requests_get(tmp_path):
    p = _write_tmp(
        tmp_path,
        "ssrf.py",
        """
    import requests

    def f(request):
        url = request.args.get('url')
        requests.get(url)
    """,
    )

    parser = PyASTParser(str(p))
    parser.parse()
    cfg = parser.extract_cfg()

    tracker = TaintTracker(sources=["request", "request.args"], sinks=["requests.get"])
    tracker.analyze_cfg(cfg, filepath=str(p))
    assert len(tracker.get_findings()) == 1


def test_taint_tuple_unpacking(tmp_path):
    """Taint should propagate to all variables in a tuple unpacking assignment."""
    p = _write_tmp(
        tmp_path,
        "unpack.py",
        """
    import os

    def get_user_input():
        return 'a', 'b'

    def f(request):
        a, b = request.args.get('x'), request.args.get('y')
        os.system(b)
    """,
    )

    parser = PyASTParser(str(p))
    parser.parse()
    cfg = parser.extract_cfg()

    tracker = TaintTracker(sources=["request", "request.args"], sinks=["os.system"])
    tracker.analyze_cfg(cfg, filepath=str(p))
    assert len(tracker.get_findings()) >= 1


def test_taint_instance_attribute_cross_method(tmp_path):
    """Taint set on self.attr in one method must be detected at sink in another method."""
    p = _write_tmp(
        tmp_path,
        "instance_attr.py",
        """
    import os

    class Handler:
        def setup(self, request):
            self.data = request.GET.get('q')

        def process(self):
            os.system(self.data)
    """,
    )

    parser = PyASTParser(str(p))
    parser.parse()
    cfg = parser.extract_cfg()

    tracker = TaintTracker(sources=["request", "request.GET"], sinks=["os.system"])
    tracker.analyze_cfg(cfg, filepath=str(p))
    assert len(tracker.get_findings()) >= 1
