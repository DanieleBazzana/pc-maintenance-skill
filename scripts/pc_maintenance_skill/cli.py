"""Compatibility adapter for the canonical CLI boundary."""

from .cli import main

__all__ = ["main"]


if __name__ == "__main__":
    raise SystemExit(main())
