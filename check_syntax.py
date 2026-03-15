import ast, sys
try:
    src = open('pyaegis/core/taint.py', encoding='utf-8').read()
    ast.parse(src)
    print('taint.py syntax OK, lines:', src.count('\n'))
except SyntaxError as e:
    print('SYNTAX ERROR:', e)
    sys.exit(1)

try:
    from pyaegis.core.taint import TaintTracker
    print('TaintTracker import OK')
except Exception as e:
    print('IMPORT ERROR:', e)
    sys.exit(1)

try:
    from pyaegis.models import Finding
    f = Finding(rule_id='X', description='d', file_path='f.py', line_number=1,
                sink_context='fn', source_var='v', sink_name='s')
    print('Finding with source_var OK')
except Exception as e:
    print('Finding ERROR:', e)
    sys.exit(1)

print('All checks passed.')
