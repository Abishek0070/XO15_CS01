"""
AuthorizationMediator — the single choke point between an agent and its
tools.

Two execution modes share one authorization path:

  1. Registry mode (hackathon demo): mediator.execute() runs the built-in
     simulated tools in toolgate/tools/registry.py after authorization.
  2. Decorator mode (pip-installable SDK): @guarded_tool calls
     mediator.authorize() and, only on ALLOW, runs the user's own wrapped
     function. The mediator never needs to know what the function does —
     it authorizes the *action description*, the decorator supplies the
     execution.

Either way, authorize() is the only gate, and every evaluation (ALLOW,
DENY, or ESCALATE) is recorded to the session audit log.
"""
from __future__ import annotations

from .models import AuditEntry, Decision, PolicyResult, ProposedAction
from .policy_engine import PolicyEngine, action_effects
from .session import SessionContext
from .tools import registry as _tool_registry


class AuthorizationError(Exception):
    """Base for non-ALLOW outcomes. Carries the full PolicyResult."""
    def __init__(self, action: ProposedAction, result: PolicyResult):
        self.action = action
        self.result = result
        super().__init__(f"{result.decision.value}: {result.reason}")


class ToolDenied(AuthorizationError):
    pass


class ToolEscalated(AuthorizationError):
    """Raised on ESCALATE. Hold onto this exception and pass it to
    TaskSession.confirm(exc) / mediator.record_human_override() once a
    human has approved the action out of band."""
    pass


class AuthorizationMediator:
    def __init__(self, policy_engine: PolicyEngine | None = None):
        self.policy = policy_engine or PolicyEngine()

    # ------------------------------------------------------------------
    # The gate. Everything goes through here.
    # ------------------------------------------------------------------
    def authorize(self, action: ProposedAction, ctx: SessionContext) -> PolicyResult:
        """Evaluate + record. Returns the result on ALLOW; raises
        ToolDenied / ToolEscalated otherwise. This is the ONLY method that
        should ever stand between an agent and a side effect."""
        result = self.policy.evaluate(action, ctx)
        ctx.record(AuditEntry(action=action, result=result, session_risk_after=ctx.cumulative_risk))
        if result.decision == Decision.DENY:
            raise ToolDenied(action, result)
        if result.decision == Decision.ESCALATE:
            raise ToolEscalated(action, result)
        return result

    def record_human_override(self, action: ProposedAction, ctx: SessionContext,
                              escalate_result: PolicyResult) -> None:
        """Record that a human explicitly approved a previously-ESCALATEd
        action. Deliberately does NOT re-run policy evaluation — an
        escalation can only be cleared by a human, never re-argued by the
        content that triggered it. The caller performs the execution."""
        assert escalate_result.decision == Decision.ESCALATE
        override = PolicyResult(
            decision=Decision.ALLOW,
            reason=f"Human-confirmed override of escalation: {escalate_result.reason}",
            rule="human-override",
            risk_delta=0.0,
            effects=sorted(action_effects(action)),   # the action DID run: its effects join the chain
            chain=escalate_result.chain, chain_steps=escalate_result.chain_steps,
        )
        ctx.record(AuditEntry(action=action, result=override, session_risk_after=ctx.cumulative_risk))

    # ------------------------------------------------------------------
    # Registry mode (simulated-tools demo)
    # ------------------------------------------------------------------
    def execute(self, action: ProposedAction, ctx: SessionContext) -> dict:
        """Authorize, then run the built-in simulated tool. Kept for the
        hackathon demo/harness; SDK users use @guarded_tool instead."""
        self.authorize(action, ctx)  # raises on DENY/ESCALATE
        return _tool_registry._execute(
            action.tool_category.value, action.operation, action.raw_params()
        )

    def execute_after_human_confirmation(self, action: ProposedAction, ctx: SessionContext,
                                         confirmed_result: PolicyResult) -> dict:
        self.record_human_override(action, ctx, confirmed_result)
        return _tool_registry._execute(action.tool_category.value, action.operation, action.raw_params())
