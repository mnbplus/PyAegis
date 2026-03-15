"""
tests/test_conditional_sinks.py

Conditional sink tests for subprocess.*:
- subprocess.run(['ls', '-la'])       -> no finding (static list, no taint)
- subprocess.run(cmd, shell=True)     -> finding (shell=True + tainted)
- subprocess.run(user_input)          -> finding (tainted string arg)
- subprocess.Popen(cmd, shell=True)   -> finding
- subprocess.call(cmd, shell=True)    -> finding
"""
import textwrap
import pytest
from pyaegis.core.taint import TaintTracker
from pyaegis.core.parser import PyASTParser


def _write_tmp(tmp_path, name, code):
    p = tmp_path / name
    p.write_text(textwrap.dedent(code).lstrip("\n"), encoding="utf-8")
    return p


# Conditional sink config: subprocess.run/Popen/call only flagged when shell=True
SUBPROCESS_COND_SINKS = [
    {
        "name": "subprocess.run",
        "severity": "CRITICAL",
        "rule_id": "PYA-001",
        "conditions": [{"has_kwarg": {"shell": True}}],
    },
    {
        "name": "subprocess.Popen",
        "severity": "CRITICAL",
        "rule_id": "PYA-001",
        "conditions": [{"has_kwarg": {"shell": True}}],
    },
    {
        "name": "subprocess.call",
        "severity": "CRITICAL",
        "rule_id": "PYA-001",
        "conditions": [{"has_kwarg": {"shell": True}}],
    },
]


def make_cond_tracker(**kwargs):
    """Tracker with conditional subprocess sinks."""
    defaults = dict(
        sources=["request", "request.args", "request.GET",
                 "request.form", "request.json", "input"],
        sinks=["subprocess.run", "subprocess.Popen",
               "subprocess.call", "os.system", "eval"],
        sanitizers=["html.escape"],
        conditional_sinks=SUBPROCESS_COND_SINKS,
    )
    defaults.update(kwargs)
    return TaintTracker(**defaults)


def make_plain_tracker(**kwargs):
    """Tracker without conditional sinks — subprocess.* always a sink."""
    defaults = dict(
        sources=["request", "request.args", "request.GET",
                 "request.form", "request.json", "input"],
        sinks=["subprocess.*", "os.system", "eval"],
        sanitizers=["html.escape"],
    )
    defaults.update(kwargs)
    return TaintTracker(**defaults)


# ---------------------------------------------------------------------------
# Static list — should NOT fire regardless of tracker type
# ---------------------------------------------------------------------------

class TestSubprocessStaticList:
    """subprocess.run(['ls', '-la']) 无污点数据，不应报警。"""

    def test_static_list_no_shell_no_finding_plain(self, tmp_path):
        """静态列表参数、无 taint 来源，plain tracker 不应报警。"""
        p = _write_tmp(tmp_path, "static_list.py", """
            import subprocess

            def f():
                subprocess.run(['ls', '-la'])
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_plain_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        assert len(tracker.get_findings()) == 0, (
            "subprocess.run(['ls','-la']) 无污点，不应报警"
        )

    def test_static_list_no_shell_no_finding_cond(self, tmp_path):
        """静态列表参数、无 taint 来源，conditional tracker 不应报警。"""
        p = _write_tmp(tmp_path, "static_list_cond.py", """
            import subprocess

            def f():
                subprocess.run(['ls', '-la'])
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_cond_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        assert len(tracker.get_findings()) == 0, (
            "subprocess.run(['ls','-la']) conditional tracker 不应报警"
        )

    def test_tainted_list_no_shell_plain_tracker(self, tmp_path):
        """列表含 tainted 元素但无 shell=True，plain tracker 会报警（因 taint 传播进 arg）。"""
        p = _write_tmp(tmp_path, "tainted_list_no_shell.py", """
            import subprocess

            def f(request):
                arg = request.args.get('x')
                subprocess.run(['ls', arg])
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_plain_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        # plain tracker: subprocess.* is unconditional sink, tainted arg triggers finding
        assert len(tracker.get_findings()) >= 1, (
            "列表含 tainted 元素，plain tracker 应报警"
        )


# ---------------------------------------------------------------------------
# subprocess.run(cmd, shell=True) — should fire
# ---------------------------------------------------------------------------

class TestSubprocessShellTrue:
    """shell=True 时 tainted 命令应报警。"""

    def test_run_shell_true_tainted_cmd(self, tmp_path):
        """subprocess.run(cmd, shell=True) — cmd 来自用户输入，应报警。"""
        p = _write_tmp(tmp_path, "shell_true.py", """
            import subprocess

            def f(request):
                cmd = request.args.get('cmd')
                subprocess.run(cmd, shell=True)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_cond_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()
        assert len(findings) >= 1, (
            "subprocess.run(tainted, shell=True) 应产生 finding"
        )
        assert any(f.rule_id == "PYA-001" for f in findings)

    def test_run_shell_true_fstring_cmd(self, tmp_path):
        """shell=True 且命令用 f-string 构造，应报警。"""
        p = _write_tmp(tmp_path, "shell_fstr.py", """
            import subprocess

            def f(request):
                arg = request.args.get('arg')
                cmd = f'ls {arg}'
                subprocess.run(cmd, shell=True)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_cond_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        assert len(tracker.get_findings()) >= 1, (
            "f-string 构造命令 + shell=True 应报警"
        )

    def test_run_shell_true_clean_cmd_no_finding(self, tmp_path):
        """shell=True 但命令为常量字符串，无 taint，不应报警。"""
        p = _write_tmp(tmp_path, "shell_true_clean.py", """
            import subprocess

            def f():
                subprocess.run('ls -la', shell=True)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_cond_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        assert len(tracker.get_findings()) == 0, (
            "常量命令 shell=True 无 taint 不应报警"
        )

    def test_run_no_shell_kwarg_suppressed(self, tmp_path):
        """有 tainted arg 但无 shell=True，conditional tracker 应抑制报警。"""
        p = _write_tmp(tmp_path, "no_shell_kwarg.py", """
            import subprocess

            def f(request):
                cmd = request.args.get('cmd')
                subprocess.run(cmd)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_cond_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        # conditional_sinks entry for subprocess.run requires shell=True → suppressed
        assert len(tracker.get_findings()) == 0, (
            "无 shell=True 时 conditional tracker 应抑制 subprocess.run 报警"
        )


# ---------------------------------------------------------------------------
# subprocess.run(user_input) — plain tracker should fire
# ---------------------------------------------------------------------------

class TestSubprocessTaintedString:
    """tainted 字符串直接传入 subprocess，plain tracker 应报警。"""

    def test_plain_tracker_tainted_string_fires(self, tmp_path):
        """subprocess.run(user_input) — plain tracker 检测 tainted 字符串输入。"""
        p = _write_tmp(tmp_path, "tainted_str.py", """
            import subprocess

            def f(request):
                user_input = request.args.get('cmd')
                subprocess.run(user_input)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_plain_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        assert len(tracker.get_findings()) >= 1, (
            "subprocess.run(tainted_string) plain tracker 应报警"
        )

    def test_input_builtin_tainted_string(self, tmp_path):
        """input() 直接传入 subprocess.run，plain tracker 应报警。"""
        p = _write_tmp(tmp_path, "input_tainted.py", """
            import subprocess

            def f():
                user_input = input()
                subprocess.run(user_input)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_plain_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        assert len(tracker.get_findings()) >= 1, (
            "input() 传入 subprocess.run 应报警"
        )


# ---------------------------------------------------------------------------
# subprocess.Popen with shell=True
# ---------------------------------------------------------------------------

class TestSubprocessPopen:
    """subprocess.Popen 的条件 sink 检测。"""

    def test_popen_shell_true_tainted(self, tmp_path):
        """subprocess.Popen(cmd, shell=True) tainted 命令应报警。"""
        p = _write_tmp(tmp_path, "popen_shell.py", """
            import subprocess

            def f(request):
                cmd = request.args.get('cmd')
                subprocess.Popen(cmd, shell=True)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_cond_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        assert len(tracker.get_findings()) >= 1, (
            "subprocess.Popen(tainted, shell=True) 应报警"
        )

    def test_popen_no_shell_suppressed(self, tmp_path):
        """subprocess.Popen(cmd) 无 shell=True，conditional tracker 应抑制。"""
        p = _write_tmp(tmp_path, "popen_no_shell.py", """
            import subprocess

            def f(request):
                cmd = request.args.get('cmd')
                subprocess.Popen(cmd)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_cond_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        assert len(tracker.get_findings()) == 0, (
            "subprocess.Popen 无 shell=True，conditional tracker 应抑制"
        )


# ---------------------------------------------------------------------------
# subprocess.call with shell=True
# ---------------------------------------------------------------------------

class TestSubprocessCall:
    """subprocess.call 的条件 sink 检测。"""

    def test_call_shell_true_tainted(self, tmp_path):
        """subprocess.call(cmd, shell=True) tainted 命令应报警。"""
        p = _write_tmp(tmp_path, "call_shell.py", """
            import subprocess

            def f(request):
                cmd = request.args.get('cmd')
                subprocess.call(cmd, shell=True)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_cond_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        assert len(tracker.get_findings()) >= 1, (
            "subprocess.call(tainted, shell=True) 应报警"
        )

    def test_call_no_shell_suppressed(self, tmp_path):
        """subprocess.call(cmd) 无 shell=True，conditional tracker 应抑制。"""
        p = _write_tmp(tmp_path, "call_no_shell.py", """
            import subprocess

            def f(request):
                cmd = request.args.get('cmd')
                subprocess.call(cmd)
        """)
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = make_cond_tracker()
        tracker.analyze_cfg(cfg, filepath=str(p))
        assert len(tracker.get_findings()) == 0, (
            "subprocess.call 无 shell=True，conditional tracker 应抑制"
        )
