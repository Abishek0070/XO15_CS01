"""Framework integrations. `generic` works with anything that calls
plain Python functions; framework-specific adapters live alongside it."""
from .generic import guard_callable, guard_tools, scan_content, escalate_call, infer_category

__all__ = ["guard_callable", "guard_tools", "scan_content", "escalate_call", "infer_category"]
