"""pyaegis.langchain_tool — LangChain integration for PyAegis.

Provides a ``PyAegisTool`` that AI agents can call to validate Python code
before execution.

Installation::

    pip install pyaegis langchain

Usage::

    from pyaegis.langchain_tool import PyAegisTool

    tools = [PyAegisTool()]
    # Pass to your LangChain agent as usual.
"""
from __future__ import annotations

try:
    from langchain.tools import BaseTool
    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False


if HAS_LANGCHAIN:
    from typing import Optional, Type

    class PyAegisTool(BaseTool):  # type: ignore[misc]
        """LangChain tool that scans Python code for security vulnerabilities.

        This tool wraps :func:`pyaegis.api.scan_code_string` and is intended
        to be called by AI agents *before* executing any AI-generated Python
        code.

        Example::

            from pyaegis.langchain_tool import PyAegisTool
            from langchain.agents import initialize_agent, AgentType
            from langchain.chat_models import ChatOpenAI

            llm = ChatOpenAI(model="gpt-4")
            tools = [PyAegisTool()]
            agent = initialize_agent(
                tools, llm,
                agent=AgentType.OPENAI_FUNCTIONS,
                verbose=True,
            )
        """

        name: str = "pyaegis_security_scanner"
        description: str = (
            "Validates Python code for security vulnerabilities using static "
            "taint analysis. "
            "MUST be called before executing any AI-generated Python code. "
            "Input should be the Python source code as a string. "
            "Returns a list of security findings with line numbers and fix "
            "suggestions, or a success message if no issues are detected."
        )

        def _run(self, code: str) -> str:  # type: ignore[override]
            """Run security scan on *code* and return a human-readable result."""
            from pyaegis.api import scan_code_string

            findings = scan_code_string(code, return_format="dict")
            if not findings:
                return "Security check passed: no vulnerabilities detected."
            summary = (
                f"{len(findings)} security issue(s) found:\n"
                + "\n".join(
                    f"  [{i+1}] {f['severity']} | {f['rule_id']} | "
                    f"line {f['line']} | sink: {f['sink_name']} | "
                    f"source: {f['source_var']} — {f['message']}"
                    for i, f in enumerate(findings)
                )
            )
            return summary

        async def _arun(self, code: str) -> str:  # type: ignore[override]
            """Async variant — delegates to the synchronous implementation."""
            return self._run(code)

else:
    # Provide a helpful stub so imports don't hard-fail when langchain is absent.
    class PyAegisTool:  # type: ignore[no-redef]
        """Stub: langchain is not installed.

        Install it with:  pip install langchain
        """

        def __init__(self, *args, **kwargs):
            raise ImportError(
                "langchain is required to use PyAegisTool. "
                "Install it with: pip install langchain"
            )
