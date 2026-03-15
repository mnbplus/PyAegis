import fnmatch
from typing import Any, Dict

from .base import FrameworkModeler


class FlaskModeler(FrameworkModeler):
    """Framework modeler for Flask route detection."""

    ROUTE_PATTERNS = [
        "app.route",
        "app.get",
        "app.post",
        "app.put",
        "app.delete",
        "app.patch",
        "bp.route",
        "bp.get",
        "bp.post",
        "blueprint.route",
    ]

    def get_name(self) -> str:
        return "flask"

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
