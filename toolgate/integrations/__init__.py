"""Framework integrations. `generic` works with anything that calls
plain Python functions; framework-specific adapters live alongside it."""
from .generic import guard_callable, guard_tools, infer_category

__all__ = ["guard_callable", "guard_tools", "infer_category"]
