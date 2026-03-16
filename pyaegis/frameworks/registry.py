from typing import Any, Dict

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


# Auto-register built-in framework modelers.
register(FlaskModeler())
register(FastAPIModeler())
register(DjangoModeler())
