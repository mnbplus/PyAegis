import ast, sys
try:
    src = open('pyaegis/api.py', encoding='utf-8').read()
    ast.parse(src)
    print('OK')
except SyntaxError as e:
    print(f'SyntaxError at line {e.lineno}: {e.msg}')
    lines = src.splitlines()
    for i in range(max(0, e.lineno-3), min(len(lines), e.lineno+2)):
        print(f'  {i+1:4d}: {lines[i]}')
