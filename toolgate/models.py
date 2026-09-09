"""
Core data models for the Adaptive Authorization Mediation Layer.

Everything the agent knows about the world is either:
  - something the USER said (authorization-bearing), or
  - something the agent read/received from elsewhere (data-bearing only).

These models exist to make that distinction impossible to lose on the way
to a tool call.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone
from typing import Any, Optional
import uuid


# ---------------------------------------------------------------------------
# Trust levels (source authority, NOT data sensitivity)
# ---------------------------------------------------------------------------
class TrustLevel(int, Enum):
    """
    Ordered from most to least authoritative. Only USER and, narrowly,
    SYSTEM can ever *expand* what an action is allowed to do. Everything
    below that can only ever be *data* to act on, never a grant of new
    permission.
    """
    USER = 100          # The human's direct request in this session
    SYSTEM = 80          # Agent's own config / previously-ALLOWED session state
    TOOL_OUTPUT = 40      # Result of a tool the agent already ran (semi-trusted;
                          # structurally trustworthy, content is not)
    RETRIEVED_CONTENT = 10  # Webpages, documents, emails, search results
    THIRD_PARTY_METADATA = 5  # Tool/plugin descriptions, MCP server metadata

    @property
    def can_grant_authority(self) -> bool:
        return self >= TrustLevel.SYSTEM


class ToolCategory(str, Enum):
    FILE_OPS = "file_ops"
    COMMAND_EXEC = "command_exec"
    DB_ACCESS = "db_access"
    MESSAGING = "messaging"
    EXTERNAL_API = "external_api"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ESCALATE = "ESCALATE"


# ---------------------------------------------------------------------------
# Provenance: where did each piece of this proposed action come from?
# ---------------------------------------------------------------------------
@dataclass
class ProvenanceTag:
    source: TrustLevel
    origin_id: str  # e.g. "user_msg_1", "doc:invoice_47.pdf", "tool_result:list_files#3"
    note: str = ""


@dataclass
class ParamProvenance:
    """Tracks, per-parameter, which source actually determined its value."""
    value: Any
    provenance: ProvenanceTag


# ---------------------------------------------------------------------------
# A proposed tool call
# ---------------------------------------------------------------------------
@dataclass
class ProposedAction:
    session_id: str
    tool_category: ToolCategory
    tool_name: str
    operation: str                       # e.g. "read", "delete", "exec", "send"
    params: dict[str, ParamProvenance] = field(default_factory=dict)
    # The provenance of the *instruction to act at all* — separate from the
    # provenance of individual parameter values. This is what lets us catch
    # "a document told the agent to do this" even if the params look benign.
    directive_provenance: ProvenanceTag = None
    action_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def raw_params(self) -> dict[str, Any]:
        return {k: v.value for k, v in self.params.items()}

    def min_param_trust(self) -> TrustLevel:
        if not self.params:
            return self.directive_provenance.source
        return min(p.provenance.source for p in self.params.values())


@dataclass
class PolicyResult:
    decision: Decision
    reason: str
    rule: str                       # which rule fired (for audit/explainability)
    risk_delta: float = 0.0          # contribution to cumulative session risk
    llm_consulted: bool = False
    llm_suggestion: Optional[str] = None
    # Chain-effect analysis (rule R7). `effects` is what THIS action does on
    # its own (e.g. {"read", "read_sensitive"}); `chain` names the dangerous
    # multi-step pattern this action would complete, if any (e.g.
    # "data-exfiltration"), and `chain_steps` lists the earlier actions in
    # the session that contributed to it.
    effects: list[str] = field(default_factory=list)
    chain: Optional[str] = None
    chain_steps: list[str] = field(default_factory=list)
    # Stale-authorization analysis (rule R0). Every evaluation records the
    # session context version it was judged under. If a human approval
    # existed for this tool but was NOT reused, `stale_grant` says why —
    # exactly what changed between the approved action and this one.
    context_version: int = 0
    reused_grant: Optional[str] = None      # grant_id, when an approval was legitimately reused
    stale_grant: Optional[str] = None       # human-readable: "prior approval X not reused: ..."


# ---------------------------------------------------------------------------
# Human approvals are bound to context, never standing permissions
# ---------------------------------------------------------------------------
@dataclass
class AuthorizationGrant:
    """Issued when a human confirms an ESCALATEd action. It authorizes THAT
    action in THAT context. A later call is only covered if nothing
    relevant changed: same tool + operation, same parameters (resource,
    destination, account...), same directive provenance, same declared
    scope, same task phase, same taint and risk state. Anything else is a
    different action and goes back through the policy engine."""
    grant_id: str
    action_id: str
    tool_name: str
    operation: str
    params: dict[str, Any]
    directive_source: str
    scope: frozenset[str]
    phase: str
    tainted: bool
    risk_state: str
    context_version: int
    reusable: bool = False        # False: single-use; True: may cover an IDENTICAL later call
    uses: int = 0
    granted_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def diff(self, action: "ProposedAction", ctx) -> list[str]:
        """What differs between the approved action/context and this one.
        Empty list == identical."""
        changes: list[str] = []
        if action.tool_name != self.tool_name or action.operation != self.operation:
            changes.append(f"operation {self.tool_name}.{self.operation} -> {action.tool_name}.{action.operation}")
        now = action.raw_params()
        for key in sorted(set(self.params) | set(now)):
            if self.params.get(key) != now.get(key):
                changes.append(f"param '{key}': {self.params.get(key)!r} -> {now.get(key)!r}")
        src = action.directive_provenance.source.name
        if src != self.directive_source:
            changes.append(f"directive source {self.directive_source} -> {src}")
        if frozenset(ctx.declared_scope) != self.scope:
            changes.append(f"declared scope {sorted(self.scope)} -> {sorted(ctx.declared_scope)}")
        if ctx.phase != self.phase:
            changes.append(f"task phase '{self.phase}' -> '{ctx.phase}'")
        if ctx.tainted != self.tainted:
            changes.append(f"session became tainted ({ctx.taint_origin})" if ctx.tainted else "session taint cleared")
        if ctx.risk_state() != self.risk_state:
            changes.append(f"session risk state {self.risk_state} -> {ctx.risk_state()}")
        if not changes and ctx.context_version != self.context_version:
            changes.append(f"session context version {self.context_version} -> {ctx.context_version}")
        return changes


@dataclass
class AuditEntry:
    action: ProposedAction
    result: PolicyResult
    session_risk_after: float
