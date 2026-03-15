import textwrap

from pyaegis.core.parser import ParallelProjectParser
from pyaegis.core.taint import TaintTracker


def test_interprocedural_propagates_internal_source_return(tmp_path):
    """If a resolved callee returns a source expression (e.g. input()),
    the call result should be treated as tainted even when the call has no args.

    This exercises the inter-procedural return-taint computation across modules.
    """

    a = tmp_path / "mod_a.py"
    b = tmp_path / "mod_b.py"

    a.write_text(
        textwrap.dedent(
            """
            def get_cmd():
                return input()
            """
        ).lstrip("\n"),
        encoding="utf-8",
    )

    b.write_text(
        textwrap.dedent(
            """
            import os
            from mod_a import get_cmd

            def endpoint():
                cmd = get_cmd()
                os.system(cmd)
            """
        ).lstrip("\n"),
        encoding="utf-8",
    )

    parser = ParallelProjectParser(pool_size=1)
    cfgs = parser.parse_all([str(a), str(b)], show_progress=False)

    assert (
        parser.symbol_table is not None
    ), "symbol_table should be built for inter-procedural taint"

    tracker = TaintTracker(
        sources=["input"],
        sinks=["os.system"],
        symbol_table=parser.symbol_table,
        max_call_depth=5,
    )

    for fp, cfg in cfgs.items():
        tracker.analyze_cfg(cfg, filepath=fp)

    findings = tracker.get_findings()
    assert any(f.sink_name == "os.system" for f in findings)
