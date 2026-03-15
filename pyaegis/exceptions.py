class PyAegisError(Exception):
    """Base exception class for all PyAegis errors."""

    pass


class ConfigurationError(PyAegisError):
    """Raised when there is an issue with the configuration or rules loading."""

    pass


class ParserError(PyAegisError):
    """
    Raised when the AST parser encounters an unrecoverable syntax issue.
    """

    pass
