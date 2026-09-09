"""
toolgate — an adaptive authorization layer between AI agents and their tools.

    pip install toolgate

    from toolgate import TaskSession, guarded_tool, untrusted

Every call to a @guarded_tool function is evaluated (ALLOW / DENY /
ESCALATE) by a rule-based policy engine using the provenance of the
instruction and of every parameter, plus session-level cumulative risk.
See README.md for the full model.
"""
from .decorator import (
    TaskSession, guarded_tool, current_session,
    untrusted, from_tool_output, from_tool_metadata, Sourced,
)
from .mediator import AuthorizationMediator, AuthorizationError, ToolDenied, ToolEscalated
from .models import Decision, ToolCategory, TrustLevel, ProposedAction, PolicyResult
from .policy_engine import PolicyEngine
from .session import SessionContext, SessionStore
from .runtime import GLOBAL_STORE, GLOBAL_MEDIATOR
from .dashboard_server import serve_dashboard, stop_dashboard
from .integrations.generic import guard_callable, guard_tools

__version__ = "0.1.0"

__all__ = [
    "TaskSession", "guarded_tool", "current_session",
    "untrusted", "from_tool_output", "from_tool_metadata", "Sourced",
    "AuthorizationMediator", "AuthorizationError", "ToolDenied", "ToolEscalated",
    "Decision", "ToolCategory", "TrustLevel", "ProposedAction", "PolicyResult",
    "PolicyEngine", "SessionContext", "SessionStore",
    "GLOBAL_STORE", "GLOBAL_MEDIATOR",
    "serve_dashboard", "stop_dashboard", "guard_callable", "guard_tools",
]
