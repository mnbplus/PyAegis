from typing import List, Dict, Any
import ast

class TaintTracker:
    def __init__(self, sources: List[str], sinks: List[str]):
        """
        sources: Functions/inputs that are considered untrusted (e.g., request.GET)
        sinks: Sensitive functions (e.g., os.system, exec)
        """
        self.sources = set(sources)
        self.sinks = set(sinks)
        self.vulnerabilities = []

    def analyze_cfg(self, cfg: Dict[str, list], filepath: str):
        """Perform basic taint tracking across control flow graph blocks."""
        for func_name, body in cfg.items():
            tainted_vars = set()
            for node in ast.walk(ast.Module(body=body)):
                # Detect assignment from Source
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            # Very basic source detection mock
                            if self._is_source(node.value):
                                tainted_vars.add(target.id)
                
                # Detect Sink execution with tainted variable
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in self.sinks:
                        for arg in node.args:
                            if isinstance(arg, ast.Name) and arg.id in tainted_vars:
                                self.vulnerabilities.append({
                                    "type": "Tainted Sink Execution",
                                    "file": filepath,
                                    "function": func_name,
                                    "sink": node.func.id,
                                    "line": node.lineno
                                })

    def _is_source(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in self.sources:
                return True
        return False

    def get_findings(self) -> List[Dict[str, Any]]:
        return self.vulnerabilities
