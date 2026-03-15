import ast
import multiprocessing
from typing import List, Dict, Any

class PyASTParser:
    """High-performance AST unroller and CFG (Control Flow Graph) generator."""
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.tree = None
        
    def parse(self) -> ast.Module:
        with open(self.filepath, "r", encoding="utf-8") as f:
            code = f.read()
            self.tree = ast.parse(code, filename=self.filepath)
        return self.tree

    def extract_cfg(self) -> Dict[str, Any]:
        """Extracts rough control flow graph blocks for taint analysis."""
        blocks = {}
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef):
                blocks[node.name] = node.body
        return blocks

def _worker_parse(filepath: str) -> Dict[str, Any]:
    parser = PyASTParser(filepath)
    parser.parse()
    return parser.extract_cfg()

class ParallelProjectParser:
    def __init__(self, pool_size: int = 4):
        self.pool_size = pool_size

    def parse_all(self, filepaths: List[str]) -> Dict[str, Any]:
        results = {}
        with multiprocessing.Pool(self.pool_size) as pool:
            cfgs = pool.map(_worker_parse, filepaths)
            for path, cfg in zip(filepaths, cfgs):
                results[path] = cfg
        return results
