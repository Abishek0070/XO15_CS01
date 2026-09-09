"""
SessionContext holds everything the policy engine needs to reason about
a task as it unfolds, rather than evaluating each tool call in isolation.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import time
import uuid

from .models import AuditEntry, ProposedAction, ToolCategory


@dataclass
class SessionContext:
    session_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    user_intent: str = ""                 # the user's original stated task, verbatim
    declared_scope: set[str] = field(default_factory=set)   # e.g. {"read:reports/", "send:team-channel"}
    created_at: float = field(default_factory=time.time)

    # Running state used for cumulative-risk reasoning
    cumulative_risk: float = 0.0
    touched_resources: set[str] = field(default_factory=set)
    categories_used: set[ToolCategory] = field(default_factory=set)
    tainted: bool = False                 # True once an action's DIRECTIVE came from an untrusted source
    taint_origin: str | None = None       # what tainted the session (tool name / doc id)
    # Tools whose OUTPUT contained sensitive-looking data (salaries, secrets,
    # credentials...). Set by the framework adapters, which see tool output;
    # the policy engine itself only sees parameters. Feeds chain rule R7.
    sensitive_outputs: set[str] = field(default_factory=set)
    audit_log: list[AuditEntry] = field(default_factory=list)

    RISK_ESCALATE_THRESHOLD = 6.0
    RISK_DENY_THRESHOLD = 10.0

    def record(self, entry: AuditEntry) -> None:
        self.cumulative_risk = max(0.0, self.cumulative_risk + entry.result.risk_delta)
        entry.session_risk_after = self.cumulative_risk
        self.audit_log.append(entry)
        self.categories_used.add(entry.action.tool_category)
        for p in entry.action.params.values():
            if isinstance(p.value, str):
                self.touched_resources.add(p.value)

    def recent_actions(self, n: int = 10) -> list[AuditEntry]:
        return self.audit_log[-n:]

    def has_prior_action_on(self, resource: str) -> bool:
        return resource in self.touched_resources

    def category_count(self, category: ToolCategory) -> int:
        return sum(1 for e in self.audit_log if e.action.tool_category == category)

    def risk_state(self) -> str:
        if self.cumulative_risk >= self.RISK_DENY_THRESHOLD:
            return "critical"
        if self.cumulative_risk >= self.RISK_ESCALATE_THRESHOLD:
            return "elevated"
        return "normal"

    def executed_actions(self) -> list[AuditEntry]:
        """Only actions that actually ran (ALLOW, incl. human overrides).
        Denied/escalated actions never executed, so they moved no data and
        must not count toward the chain's effective privilege."""
        return [e for e in self.audit_log if e.result.decision.value == "ALLOW"]

    def effective_privileges(self) -> set[str]:
        """What the session, as a whole, has effectively done so far: the
        union of every executed action's effects plus sensitive data seen
        in tool outputs. This is what rule R7 compares against the next
        action — the chain's combined effect, not the single call."""
        eff: set[str] = set()
        for e in self.executed_actions():
            eff.update(e.result.effects)
        if self.sensitive_outputs:
            eff.add("read_sensitive")
        return eff


class SessionStore:
    """In-memory session store (swap for redis/db in production)."""
    def __init__(self):
        self._sessions: dict[str, SessionContext] = {}

    def create(self, user_intent: str, declared_scope: Optional[set[str]] = None) -> SessionContext:
        ctx = SessionContext(user_intent=user_intent, declared_scope=declared_scope or set())
        self._sessions[ctx.session_id] = ctx
        return ctx

    def get(self, session_id: str) -> Optional[SessionContext]:
        return self._sessions.get(session_id)

    def all(self) -> list[SessionContext]:
        return list(self._sessions.values())
