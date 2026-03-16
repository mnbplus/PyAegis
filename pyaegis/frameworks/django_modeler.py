import fnmatch
from typing import Any, Dict, List

from .base import FrameworkModeler


class DjangoModeler(FrameworkModeler):
    """Framework modeler for Django view detection.

    Covers:
    - Function-based views (FBVs): recognised by parameter name ``request``
      as the first argument, or by ``@login_required`` / ``@permission_required``
      / ``@csrf_exempt`` / ``@require_http_methods`` / ``@require_GET`` /
      ``@require_POST`` decorator patterns.
    - Class-based views (CBVs): methods named ``get``, ``post``, ``put``,
      ``patch``, ``delete``, ``head``, ``options``, ``trace`` on classes that
      appear to extend a Django view (detected via ``as_view`` usage or
      class name heuristic).
    - Django REST Framework (DRF): ``@api_view`` decorator and ``APIView``
      subclass methods.
    - URL-conf ``path()`` / ``re_path()`` / ``url()`` route metadata set by
      the parser (``routes`` key in func_meta).
    """

    # Decorator patterns that mark a function as a Django view entry-point.
    ROUTE_DECORATOR_PATTERNS = [
        # Django built-ins
        "login_required",
        "permission_required",
        "csrf_exempt",
        "csrf_protect",
        "require_http_methods",
        "require_GET",
        "require_POST",
        "require_safe",
        "never_cache",
        "cache_page",
        "cache_control",
        # DRF
        "api_view",
        "api_view(*)",
        "authentication_classes",
        "permission_classes",
        "throttle_classes",
        "renderer_classes",
        # Common third-party
        "login_required_ajax",
        "staff_member_required",
        "superuser_required",
        "user_passes_test",
    ]

    # CBV HTTP-method handler names (Django dispatches to these).
    CBV_HTTP_METHODS = {
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "trace",
    }

    # Parameter names treated as tainted HTTP-request objects.
    REQUEST_PARAM_NAMES = {"request", "req", "http_request", "self_request"}

    def get_name(self) -> str:
        return "django"

    def is_route_function(self, func_meta: Dict[str, Any]) -> bool:
        """Return True if this function looks like a Django view handler."""
        # 1. Explicit route metadata from URL conf scanner
        if func_meta.get("routes"):
            return True

        func_name: str = func_meta.get("name", "") or ""
        args: List[str] = func_meta.get("args", []) or []
        decorators: List[str] = func_meta.get("decorators", []) or []

        # 2. Decorator-based detection
        for dec in decorators:
            dec_str = str(dec)
            for pat in self.ROUTE_DECORATOR_PATTERNS:
                if dec_str == pat or fnmatch.fnmatch(dec_str, pat):
                    return True
            # Qualified decorator: e.g. ``decorators.login_required``
            bare = dec_str.split(".")[-1]
            for pat in self.ROUTE_DECORATOR_PATTERNS:
                if bare == pat or fnmatch.fnmatch(bare, pat):
                    return True

        # 3. FBV heuristic: first non-self arg is named ``request`` (or variant)
        non_self_args = [a for a in args if a != "self"]
        if non_self_args and non_self_args[0] in self.REQUEST_PARAM_NAMES:
            return True

        # 4. CBV method heuristic: method name is an HTTP verb AND
        #    first arg is ``self`` AND second arg is a request-like name.
        if func_name in self.CBV_HTTP_METHODS and args:
            if args[0] == "self":
                if len(args) >= 2 and args[1] in self.REQUEST_PARAM_NAMES:
                    return True
                # Some CBV methods only have ``self`` + path kwargs — still mark them.
                return True

        return False

    def get_tainted_params(self, func_meta: Dict[str, Any]) -> List[str]:
        """Return the names of params that carry tainted HTTP input.

        For Django views the ``request`` object (first non-self arg) is the
        primary taint source; all other path/query kwargs are also tainted.
        """
        args: List[str] = func_meta.get("args", []) or []
        tainted: List[str] = []
        for a in args:
            if a == "self":
                continue
            tainted.append(a)  # request + all URL kwargs
        return tainted
