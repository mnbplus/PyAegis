lines = open('pyaegis/core/taint.py', encoding='utf-8').readlines()
print(f'Total lines: {len(lines)}')
print('--- LAST 20 ---')
for i, l in enumerate(lines[-20:], start=len(lines)-19):
    print(f'{i:4d}: {l}', end='')
