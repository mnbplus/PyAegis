# -*- coding: utf-8 -*-
import pathlib

base = pathlib.Path('D:/Github项目/PyAegis')
path = base / 'tests' / 'benchmark' / 'vuln_corpus.py'
print('Target:', path)

content = path.read_text(encoding='utf-8')
print('Current length:', len(content))

trunc_marker = '            "    return'
idx = content.rfind(trunc_marker)
print(f'Truncation point at index: {idx}')
if idx == -1:
    print('ERROR: marker not found')
    raise SystemExit(1)

tail = (
    '            "    return bool(pattern.match(value))\\n"\n'
    '        ),\n'
    '    },\n'
    '    {\n'
    '        "label": "pathlib.Path.resolve sanitizes traversal -- safe",\n'
    '        "category": "safe",\n'
    '        "expected_findings": 0,\n'
    '        "code": (\n'
    '            "from pathlib import Path\\n"\n'
    '            "from flask import request\\n"\n'
    '            "def read():\\n"\n'
    '            "    name = request.args.get(\'name\')\\n"\n'
    '            "    safe = Path(name).resolve()\\n"\n'
    '            "    return safe.read_text()\\n"\n'
    '        ),\n'
    '    },\n'
    ']\n'
    '\n'
    '# ---------------------------------------------------------------------------\n'
    '# Combined corpus exposed to benchmark tests\n'
    '# ---------------------------------------------------------------------------\n'
    '\n'
    'CORPUS = VULN_SAMPLES + SAFE_SAMPLES\n'
    '\n'
    'assert len(VULN_SAMPLES) >= 20\n'
    'assert len(SAFE_SAMPLES) >= 10\n'
    'assert all("expected_findings" in s for s in CORPUS)\n'
    'assert all("code" in s for s in CORPUS)\n'
)

fixed = content[:idx] + tail
path.write_text(fixed, encoding='utf-8')
print(f'Written {len(fixed)} bytes')

# Quick syntax check
import ast
try:
    ast.parse(fixed)
    print('Syntax OK')
except SyntaxError as e:
    print(f'Syntax ERROR: {e}')
    raise SystemExit(1)
