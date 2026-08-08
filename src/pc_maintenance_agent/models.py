"""Compatibility adapter for the Phase 2 canonical domain models."""

from .domain.models import *
from .domain.models import __all__ as _domain_all

__all__ = list(_domain_all)
