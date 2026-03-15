from pyaegis.models import Finding
import dataclasses
print(dataclasses.fields(Finding))
f = Finding(rule_id='X', description='d', file_path='f', line_number=1, sink_context='s')
try:
    f.file_path = 'new'
    print('mutable:', f.file_path)
except Exception as e:
    print('frozen:', e)
