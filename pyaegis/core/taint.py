import ast
from typing import List, Set, Dict
from pyaegis.models import Finding


class TaintTracker:
    def __init__(self, sources: List[str], sinks: List[str]):
        """
        sources: Functions/inputs that are considered untrusted (e.g., request.GET)
        sinks: Sensitive functions (e.g., os.system, exec)
        """
        self.sources: Set[str] = set(sources)
        self.sinks: Set[str] = set(sinks)
        self.vulnerabilities: List[Finding] = []

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
                    sink_name = self._get_full_name(node.func)
                    if sink_name in self.sinks:
                        for arg in node.args:
                            if isinstance(arg, ast.Name) and arg.id in tainted_vars:
                                finding = Finding(
                                    rule_id="PYA-100",
                                    description=(
                                        "Untrusted user input executed by system sink."
                                    ),
                                    file_path=filepath,
                                    line_number=node.lineno,
                                    sink_context=func_name,
                                    severity="CRITICAL",
                                )
                                self.vulnerabilities.append(finding)

    def _get_full_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            base = self._get_full_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return ""

    def _is_source(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            root_var = node.func
            while isinstance(root_var, ast.Attribute):
                root_var = root_var.value
            if isinstance(root_var, ast.Name) and root_var.id in self.sources:
                return True
        return False

    def get_findings(self) -> List[Finding]:
        return self.vulnerabilities
