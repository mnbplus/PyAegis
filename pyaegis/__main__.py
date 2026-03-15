"""PyAegis package entrypoint.

Allows: python -m pyaegis ...
"""

from .cli import main


if __name__ == "__main__":
    raise SystemExit(main())
