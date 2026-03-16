import fnmatch
from typing import Any, Dict, List

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

    def get_tainted_params(self, func_meta: Dict[str, Any]) -> List[str]:
        """Return tainted params for a Flask route handler.

        Flask injects URL path variables as keyword arguments; the implicit
        ``flask.request`` global is *not* a parameter, so all explicit
        non-self parameters are URL kwargs and should be tainted.
        """
        args: List[str] = func_meta.get("args", []) or []
        return [a for a in args if a != "self"]
