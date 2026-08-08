"""Compatibility adapter for the canonical process boundary."""

import subprocess

from .process import awareness as _awareness


def check_many(paths, timeout=60.0):
    _awareness.subprocess = subprocess
    return _awareness.check_many(paths, timeout=timeout)


def check_in_use(path, timeout=1.5):
    _awareness.subprocess = subprocess
    return _awareness.check_in_use(path, timeout=timeout)


__all__ = ["check_in_use", "check_many", "subprocess"]
