import ast
src = open('pyaegis/core/taint.py', encoding='utf-8').read()
tree = ast.parse(src)

# Check all methods in TaintTracker
for node in ast.walk(tree):
    if isinstance(node, ast.ClassDef) and node.name == 'TaintTracker':
        methods = [n.name for n in ast.walk(node) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        print('TaintTracker methods:', methods)

# Check module-level functions
mod_funcs = [n.name for n in tree.body if isinstance(n, ast.FunctionDef)]
print('Module-level functions:', mod_funcs)

# Check _find_tainted_arg exists as method
print('Has _find_tainted_arg in source:', '_find_tainted_arg' in src)
print('Has for kw loop:', 'for kw in call.keywords' in src)
print('Syntax OK, lines:', src.count(chr(10)))
