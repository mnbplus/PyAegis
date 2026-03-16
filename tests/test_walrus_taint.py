"""Regression tests for walrus (NamedExpr) taint propagation."""

from __future__ import annotations

from pyaegis.api import scan_code_string


def test_walrus_taint_propagates_to_bound_name():
    code = """
from flask import request
import os

def view():
    if cmd := request.args.get("cmd"):
        os.system(cmd)
"""
    findings = scan_code_string(code)
    assert any(f.get("sink_name") == "os.system" for f in findings)


def test_walrus_sanitizer_cleans_bound_name():
    code = """
import os, html
from flask import request

def view():
    if cmd := html.escape(request.args.get("cmd")):
        os.system(cmd)
"""
    findings = scan_code_string(code)
    assert findings == []
