"""tests/test_django_raw_sink.py

Adds coverage for ROADMAP P1 item:
- Django ORM: raw() vs filter() semantics

Expectation:
- .raw(...) executes raw SQL -> treat as SQL injection sink if tainted input flows into query.
- .filter(...) uses ORM parameterization (heuristic) -> should not be flagged by default.

These tests are intentionally lightweight: they validate sink matching and taint flow,
not full ORM semantics.
"""

import textwrap

from pyaegis.core.parser import PyASTParser
from pyaegis.core.taint import TaintTracker


def _write_tmp(tmp_path, name: str, code: str):
    p = tmp_path / name
    p.write_text(textwrap.dedent(code).lstrip("\n"), encoding="utf-8")
    return p


class TestDjangoOrmRawVsFilter:
    def test_queryset_raw_is_sink(self, tmp_path):
        p = _write_tmp(
            tmp_path,
            "django_raw.py",
            """
            class User:
                objects = None

            def f(request):
                q = request.GET.get('q')
                # Typical raw() usage
                User.objects.raw(q)
            """,
        )
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = TaintTracker(
            sources=["request", "request.GET"],
            sinks=["*.objects.raw", "*.raw"],
        )
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) == 1
        # sink_name should include the full dotted name when possible
        assert findings[0].sink_name.endswith(".raw")
        assert findings[0].rule_id == "PYA-002"  # SQL injection group

    def test_queryset_filter_not_sink(self, tmp_path):
        p = _write_tmp(
            tmp_path,
            "django_filter.py",
            """
            class User:
                objects = None

            def f(request):
                q = request.GET.get('q')
                # ORM filter is parameterized; should not be treated as a sink.
                User.objects.filter(name=q)
            """,
        )
        parser = PyASTParser(str(p))
        parser.parse()
        cfg = parser.extract_cfg()

        tracker = TaintTracker(
            sources=["request", "request.GET"],
            sinks=["*.objects.raw", "*.raw"],
        )
        tracker.analyze_cfg(cfg, filepath=str(p))
        findings = tracker.get_findings()

        assert len(findings) == 0
