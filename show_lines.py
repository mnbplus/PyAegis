lines = open('pyaegis/core/taint.py', encoding='utf-8').readlines()
print(f'Total lines: {len(lines)}')
for i, l in enumerate(lines[320:380], start=321):
    print(f'{i:4d}: {l}', end='')
