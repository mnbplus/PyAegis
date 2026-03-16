import fnmatch
from typing import Any, Dict, List

from .base import FrameworkModeler


class FastAPIModeler(FrameworkModeler):
    """Framework modeler for FastAPI route detection."""

    ROUTE_PATTERNS = [
        "app.get",
        "app.post",
        "app.put",
        "app.delete",
        "app.patch",
        "app.head",
        "app.options",
        "app.route",
        "router.get",
        "router.post",
        "router.put",
        "router.delete",
        "router.patch",
        "router.head",
        "router.options",
        "router.route",
    ]

    def get_name(self) -> str:
        return "fastapi"

    def is_route_function(self, func_meta: Dict[str, Any]) -> bool:
        decorators = func_meta.get("decorators", []) or []
        routes = func_meta.get("routes", []) or []
        if routes:
            return True
        for dec in decorators:
            for pat in self.ROUTE_PATTERNS:
                if fnmatch.fnmatch(str(dec), pat) or str(dec) == pat:
                    return True
        return False

    def get_tainted_params(self, func_meta: Dict[str, Any]) -> List[str]:
        """Return tainted params for a FastAPI route handler.

        FastAPI injects path/query params and Depends() results as function
        arguments.  All non-self parameters (including those surfaced via
        ``source_params`` by the parser) are considered tainted.
        """
        args: List[str] = func_meta.get("args", []) or []
        source_params: List[str] = func_meta.get("source_params", []) or []
        tainted = {a for a in args if a != "self"}
        tainted.update(source_params)
        return list(tainted)
