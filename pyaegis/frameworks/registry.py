from typing import Any, Dict, List

from .base import FrameworkModeler
from .flask_modeler import FlaskModeler
from .fastapi_modeler import FastAPIModeler
from .django_modeler import DjangoModeler

_registry: Dict[str, FrameworkModeler] = {}


def register(modeler: FrameworkModeler) -> None:
    """Register a framework modeler by name."""
    _registry[modeler.get_name()] = modeler


def is_route_function(func_meta: Dict[str, Any], extra_patterns=None) -> bool:
    """Return True if any registered modeler recognises this function as a route handler.

    Args:
        func_meta: Function metadata dict (keys: decorators, routes, args, ...).
        extra_patterns: Unused placeholder kept for API compatibility; reserved
            for future per-call overrides.
    """
    for modeler in _registry.values():
        if modeler.is_route_function(func_meta):
            return True
    return False


def get_tainted_params(func_meta: Dict[str, Any]) -> List[str]:
    """Return the tainted parameter names for a route function.

    Queries *all* registered modelers that recognise the function and merges
    their results.  This ensures that e.g. FastAPI's ``source_params`` are
    included even when a modeler with overlapping route patterns (Flask) also
    matches.

    Returns an empty list when no modeler recognises the function, signalling
    the caller to fall back to tainting all non-self arguments.

    Args:
        func_meta: Function metadata dict passed to framework modelers.

    Returns:
        Deduplicated list of parameter names to taint, or ``[]`` for "taint all".
    """
    seen: Dict[str, None] = {}  # ordered set via insertion-order dict
    matched = False
    for modeler in _registry.values():
        if modeler.is_route_function(func_meta):
            matched = True
            for p in modeler.get_tainted_params(func_meta):
                seen[p] = None
    if not matched:
        return []
    return list(seen)


# Auto-register built-in framework modelers.
register(FlaskModeler())
register(FastAPIModeler())
register(DjangoModeler())
