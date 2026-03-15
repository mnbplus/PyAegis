path = r'D:\Github项目\PyAegis\pyaegis\cli.py'
with open(path, 'rb') as f:
    content = f.read()

# Find and print the exact bytes around the target
idx = content.find(b'keys=["rules", "format"')
if idx == -1:
    print('NOT FOUND')
else:
    # Print the next 200 bytes in hex to understand the format
    print('Raw bytes:')
    print(content[idx:idx+200])
    print()
    print('As repr:')
    print(repr(content[idx:idx+200]))
