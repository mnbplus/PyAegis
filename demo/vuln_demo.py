"""PyAegis Demo - Vulnerable Python file for recording demo GIF.

Run: pyaegis scan demo/vuln_demo.py
"""
import os
import subprocess
import pickle
from flask import request


# Vulnerability 1: OS Command Injection
def search_files(request):
    query = request.args.get('q')          # <- tainted source
    os.system(f'grep -r {query} /var/log') # <- SINK: command injection


# Vulnerability 2: Insecure Deserialization
def load_session(request):
    raw = request.get_data()               # <- tainted source
    obj = pickle.loads(raw)                # <- SINK: arbitrary code execution
    return obj


# Vulnerability 3: SQL Injection (cross-module demo)
def get_user(request):
    username = request.form.get('user')    # <- tainted source
    import sqlite3
    conn = sqlite3.connect('app.db')
    # String concatenation -> SQL injection
    conn.execute(f"SELECT * FROM users WHERE name='{username}'")


# Safe example - sanitizer stops taint
def safe_echo(request):
    import html
    user_input = request.args.get('msg')   # <- tainted source
    safe = html.escape(user_input)         # <- SANITIZER: taint cleared
    return f'<p>{safe}</p>'               # <- safe, no finding
