import os

target_dir = os.path.dirname(os.path.abspath(__file__))
parts = ['_ja_part1.md', '_ja_part2.md', '_ja_part3.md', '_ja_part4.md', '_ja_part5.md']

content = []
for part in parts:
    with open(os.path.join(target_dir, part), 'r', encoding='utf-8') as f:
        content.append(f.read())

output_path = os.path.join(target_dir, 'README.ja.md')
with open(output_path, 'w', encoding='utf-8', newline='\n') as f:
    f.write('\n'.join(content))
    f.write('\n')

print(f'File size: {os.path.getsize(output_path)} bytes')