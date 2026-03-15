path = r'D:\Github项目\PyAegis\pyaegis\cli.py'
with open(path, 'rb') as f:
    content = f.read()

# Find the target area
idx = content.find(b'keys=["rules", "format"')
print('Index:', idx)

# Get 150 bytes
area = content[idx:idx+150]
print('Area:')
print(area)
print()
print('Area repr:')
print(repr(area))
print()
print('Length:', len(area))
print()

# Check each byte
for i, b in enumerate(area[:80]):
    print(f'{i}: {b:02x} ({chr(b) if 32 <= b < 127 else "?"})')
