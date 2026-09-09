"""
The pip-installable developer surface.

    from toolgate import TaskSession, guarded_tool, untrusted

    @guarded_tool(category="messaging", operation="send")
    def send_message(to: str, body: str):
        ...actually send it...

    with TaskSession(intent="Read the invoice and summarize it",
                     scope={"read:file_ops"}) as session:
        # ordinary call: params default to USER provenance
        content = read_file(path="inbox/invoice.txt")

        # a value that came from somewhere untrusted is wrapped, so the
        # policy engine knows its real origin:
        send_message(to=untrusted("evil@example.com", origin="invoice.txt"),
                     body="...")   # -> ToolDenied / ToolEscalated

        # when the agent is acting BECAUSE of something it read (not
        # because the user asked), declare it:
        with session.acting_on_retrieved_content("invoice.txt"):
            send_message(...)      # directive provenance = the document

Design notes:
- The active session travels via contextvars, so decorated functions
  don't need a session argument and the pattern is async/thread safe.
- Anything not wrapped in a Sourced marker defaults to USER provenance.
  That default is deliberate: this SDK's honest claim is "if you label
  your untrusted data, the policy engine will never let it become
  authority" — it cannot conjure labels the caller never provided.
- DENY raises ToolDenied; ESCALATE raises ToolEscalated, which can be
  passed to session.confirm(exc) after a human approves, executing the
  original call exactly once without re-running policy.
"""
from __future__ import annotations

import contextvars
import functools
import inspect
from typing import Any, Callable, Iterator, Optional
from contextlib import contextmanager

from .mediator import AuthorizationMediator, ToolDenied, ToolEscalated
from .models import (
    ParamProvenance, ProposedAction, ProvenanceTag, ToolCategory, TrustLevel,
)
from .runtime import GLOBAL_MEDIATOR, GLOBAL_STORE
from .session import SessionContext

_current_session: contextvars.ContextVar[Optional["TaskSession"]] = \
    contextvars.ContextVar("toolgate_session", default=None)

# Fallback for frameworks that execute tools in worker threads, where
# contextvars set in the caller's context are not visible. The most
# recently entered TaskSession is the process-wide default. Fine for
# the common one-agent-at-a-time case; for true multi-session
# concurrency, pass sessions explicitly or keep work on one context.
_fallback_session: Optional["TaskSession"] = None


# ---------------------------------------------------------------------------
# Provenance markers for parameter values
# ---------------------------------------------------------------------------
class Sourced:
    """Wraps a value with its true origin. Unwrapped before the real
    function is called, so the function body never sees the marker."""
    __slots__ = ("value", "source", "origin_id")

    def __init__(self, value: Any, source: TrustLevel, origin_id: str):
        self.value = value
        self.source = source
        self.origin_id = origin_id


def untrusted(value: Any, origin: str = "retrieved_content") -> Sourced:
    """Mark a value as coming from a webpage/document/email/etc."""
    return Sourced(value, TrustLevel.RETRIEVED_CONTENT, origin)


def from_tool_output(value: Any, origin: str = "tool_output") -> Sourced:
    """Mark a value as coming from a previous tool's result."""
    return Sourced(value, TrustLevel.TOOL_OUTPUT, origin)


def from_tool_metadata(value: Any, origin: str = "tool_metadata") -> Sourced:
    """Mark a value as coming from third-party tool/plugin metadata."""
    return Sourced(value, TrustLevel.THIRD_PARTY_METADATA, origin)


# ---------------------------------------------------------------------------
# TaskSession: one user task == one session
# ---------------------------------------------------------------------------
class TaskSession:
    def __init__(self, intent: str, scope: set[str] | list[str],
                 mediator: AuthorizationMediator | None = None):
        self.ctx: SessionContext = GLOBAL_STORE.create(
            user_intent=intent, declared_scope=set(scope))
        self.mediator = mediator or GLOBAL_MEDIATOR
        self._directive = ProvenanceTag(source=TrustLevel.USER, origin_id="user")
        self._token = None

    # -- context management ------------------------------------------------
    def __enter__(self) -> "TaskSession":
        global _fallback_session
        self._token = _current_session.set(self)
        self._prev_fallback = _fallback_session
        _fallback_session = self
        return self

    def __exit__(self, *exc) -> None:
        global _fallback_session
        _current_session.reset(self._token)
        _fallback_session = self._prev_fallback

    # -- directive provenance ----------------------------------------------
    def current_directive(self) -> ProvenanceTag:
        return self._directive

    @contextmanager
    def acting_on(self, source: TrustLevel, origin_id: str) -> Iterator[None]:
        """Declare that upcoming actions are being taken *because of*
        content from `source` (not because the user asked directly)."""
        prev = self._directive
        self._directive = ProvenanceTag(source=source, origin_id=origin_id)
        try:
            yield
        finally:
            self._directive = prev

    def acting_on_retrieved_content(self, origin_id: str):
        return self.acting_on(TrustLevel.RETRIEVED_CONTENT, origin_id)

    def acting_on_tool_output(self, origin_id: str):
        return self.acting_on(TrustLevel.TOOL_OUTPUT, origin_id)

    # -- escalation resolution ----------------------------------------------
    def confirm(self, escalation: ToolEscalated, *, reusable: bool = False) -> Any:
        """A human has approved the escalated action out of band. Records
        the override and executes the original call exactly once.

        reusable=False (default): the approval covers only this call.
        reusable=True: an IDENTICAL later call (same params, directive
        source, scope, phase, taint and risk state) is allowed without
        asking again. Any difference at all — another destination, file,
        account, operation, phase, or a directive that now comes from
        retrieved content — makes the approval stale and the call is
        evaluated fresh. Approvals are never permission for a tool."""
        self.mediator.record_human_override(
            escalation.action, self.ctx, escalation.result, reusable=reusable)
        retry: Callable | None = getattr(escalation, "_retry", None)
        if retry is None:
            raise RuntimeError("This escalation has no bound callable to retry.")
        return retry()

    # -- context changes ------------------------------------------------------
    def enter_phase(self, phase: str, scope: set[str] | list[str] | None = None) -> None:
        """Move to a new task phase, optionally changing the declared scope.
        Everything decided before this point was decided for the old phase."""
        self.ctx.enter_phase(phase, set(scope) if scope is not None else None)

    def set_scope(self, scope: set[str] | list[str]) -> None:
        self.ctx.set_scope(set(scope))

    # -- introspection -------------------------------------------------------
    @property
    def risk(self) -> float:
        return self.ctx.cumulative_risk

    @property
    def audit_log(self):
        return self.ctx.audit_log


def current_session() -> "TaskSession":
    sess = _current_session.get() or _fallback_session
    if sess is None:
        raise RuntimeError(
            "No active TaskSession. Wrap your agent turn in "
            "`with TaskSession(intent=..., scope=...):` before calling guarded tools."
        )
    return sess


# ---------------------------------------------------------------------------
# The decorator
# ---------------------------------------------------------------------------
def guarded_tool(category: str, operation: str, tool_name: str | None = None):
    """Route every call to the wrapped function through the authorization
    mediator. The function only ever runs on ALLOW."""
    tool_category = ToolCategory(category)

    def decorate(fn: Callable):
        sig = inspect.signature(fn)
        name = tool_name or fn.__name__

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            sess = current_session()
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()

            params: dict[str, ParamProvenance] = {}
            clean_kwargs: dict[str, Any] = {}
            for pname, val in bound.arguments.items():
                if isinstance(val, Sourced):
                    params[pname] = ParamProvenance(
                        val.value, ProvenanceTag(source=val.source, origin_id=val.origin_id))
                    clean_kwargs[pname] = val.value
                else:
                    params[pname] = ParamProvenance(
                        val, ProvenanceTag(source=TrustLevel.USER, origin_id="user"))
                    clean_kwargs[pname] = val

            action = ProposedAction(
                session_id=sess.ctx.session_id,
                tool_category=tool_category,
                tool_name=name,
                operation=operation,
                params=params,
                directive_provenance=sess.current_directive(),
            )

            try:
                sess.mediator.authorize(action, sess.ctx)
            except ToolEscalated as e:
                # bind the exact call so session.confirm(e) can run it once
                e._retry = lambda: fn(**clean_kwargs)
                raise
            return fn(**clean_kwargs)

        wrapper.__toolgate__ = {"category": category, "operation": operation, "tool_name": name}
        return wrapper

    return decorate
