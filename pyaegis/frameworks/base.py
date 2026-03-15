from abc import ABC, abstractmethod
from typing import Any, Dict, List


class FrameworkModeler(ABC):
    """Base class for framework-specific source/sink modeling."""

    @abstractmethod
    def get_name(self) -> str:
        """Framework name (e.g. 'flask', 'fastapi')."""

    @abstractmethod
    def is_route_function(self, func_meta: Dict[str, Any]) -> bool:
        """Return True if the function is a web route handler."""

    def get_tainted_params(self, func_meta: Dict[str, Any]) -> List[str]:
        """Return list of param names that should be tainted.

        Default implementation returns empty list, meaning the caller
        should taint all non-self parameters.
        """
        return []
