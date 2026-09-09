"""
Rule-based Policy Engine.

This is the ONLY component with authority to produce a final decision.
An LLM advisor may be consulted (see llm_advisor.py) but its output is
just another signal fed into these rules — it can never itself return
ALLOW/DENY/ESCALATE to the caller.

Design of the rule set (evaluated in order, first conclusive rule wins):

  R1  Directive-authority rule
      If the *instruction to act* originated from a source that cannot
      grant authority (RETRIEVED_CONTENT, THIRD_PARTY_METADATA, and even
      TOOL_OUTPUT) AND the action falls outside the user's declared scope,
      that is exactly the injected-instruction pattern => DENY.
      Untrusted content is allowed to supply *data* (e.g. a phone number
      to include in a message the user asked to send) but never a new
      *directive* to act.

  R2  Scope rule
      Is the action within declared_scope? Clean match => continue to risk
      rules. Ambiguous / no direct match => consult LLM for semantic
      match, then ESCALATE if still unclear, DENY if LLM+rules agree it's
      clearly out of scope.

  R3  Category/operation base risk
      Each (category, operation) has a base severity weight. High-severity
      single actions (delete, exec, external send to new domain) escalate
      by default even in-scope, unless previously explicitly approved in
      this session.

  R4  Novelty rule
      Resource/target never touched before in this session => risk bump.

  R5  Cumulative session risk
      Running risk score. Once it crosses RISK_ESCALATE_THRESHOLD, all
      further actions in categories that contributed get ESCALATE even if
      individually they'd be ALLOW. Crossing RISK_DENY_THRESHOLD => DENY.

  R6  Combination rule
      Specific known-dangerous *sequences* (e.g. read-sensitive-then-send-
      external) are flagged even though each step passes in isolation.

  R7  Chain-effect rule (chained privilege escalation)
      R1-R5 judge one call. R7 judges the *chain*. Every executed action is
      classified into effects ("read", "read_sensitive", "read_credential",
      "send_external", "exec", "destroy"), and the session accumulates the
      union of those effects = the chain's effective privilege. Before an
      action runs, R7 asks: does (privilege so far) + (this action's effect)
      complete a pattern whose combined effect the user never authorized —
      even though every individual step is inside declared scope?

        CHAIN_PATTERNS:
          read_sensitive  -> send_external   "data-exfiltration"
          read_credential -> exec            "credential-pivot"

      A pattern can be pre-authorized by an explicit scope tag for the
      COMBINED effect (e.g. "export:external"), because the user granting
      "read files" and "send messages" separately is not the same as the
      user granting "send our files outside the company". Otherwise:
        - directive trusted (USER/SYSTEM)  => ESCALATE (confirm with human)
        - directive untrusted / tainted    => DENY     (injection completing
                                                        an exfil chain)
      Only actions that actually ran count toward the chain: a DENY'd or
      still-pending ESCALATE'd step moved no data.
"""
from __future__ import annotations
from typing import Optional

from .models import (
    Decision, PolicyResult, ProposedAction, ToolCategory, TrustLevel,
)
from .session import SessionContext
from .llm_advisor import LLMAdvisor, ScopeMatchResult

# Base risk weight per (category, operation-keyword). Matched by substring.
BASE_RISK: dict[ToolCategory, dict[str, float]] = {
    ToolCategory.FILE_OPS: {"read": 0.5, "write": 2.0, "delete": 4.0, "move": 2.0},
    ToolCategory.COMMAND_EXEC: {"exec": 4.0, "shell": 4.0, "run": 4.0},
    ToolCategory.DB_ACCESS: {"query": 1.0, "read": 0.5, "write": 2.5, "delete": 4.5, "drop": 6.0},
    ToolCategory.MESSAGING: {"send": 1.5, "reply": 1.0, "broadcast": 3.5},
    ToolCategory.EXTERNAL_API: {"get": 0.8, "post": 2.5, "call": 1.5},
}

# Sequences: (first_category, second_category) that are riskier combined
# than either action alone, e.g. exfiltration pattern. Only actually applied
# when a sensitivity/externality signal is present (see _combo_is_flagged) —
# otherwise every ordinary "read then message" workflow would escalate,
# which the brief explicitly penalizes ("excessive blocking or escalation
# is not considered a successful solution").
DANGEROUS_COMBOS = {
    (ToolCategory.FILE_OPS, ToolCategory.MESSAGING): 3.5,
    (ToolCategory.FILE_OPS, ToolCategory.EXTERNAL_API): 3.5,
    (ToolCategory.DB_ACCESS, ToolCategory.EXTERNAL_API): 4.0,
    (ToolCategory.DB_ACCESS, ToolCategory.MESSAGING): 3.5,
    (ToolCategory.COMMAND_EXEC, ToolCategory.EXTERNAL_API): 4.5,
}

SENSITIVE_KEYWORDS = ("salar", "confidential", "secret", "ssn", "password", "credential", "hr/", "payroll")
CREDENTIAL_KEYWORDS = ("password", "secret", "credential", "token", "api_key", "apikey", ".pem", "private_key", ".env")
INTERNAL_DOMAINS = {"company.com", "internal.company.com", "team-channel"}


def _is_sensitive_value(value) -> bool:
    if not isinstance(value, str):
        return False
    low = value.lower()
    return any(k in low for k in SENSITIVE_KEYWORDS)


def _is_credential_value(value) -> bool:
    if not isinstance(value, str):
        return False
    low = value.lower()
    return any(k in low for k in CREDENTIAL_KEYWORDS)


# ---------------------------------------------------------------------------
# R7: chain-effect analysis
# ---------------------------------------------------------------------------
_READ_OPS = ("read", "query", "select", "list", "load", "open", "get_row", "fetch_row")
_DESTROY_OPS = ("delete", "drop", "truncate", "remove", "purge")


def action_effects(action: ProposedAction) -> set[str]:
    """Classify what ONE action does, independent of authorization. These
    tags are what the session accumulates into its effective privilege."""
    cat, op = action.tool_category, action.operation.lower()
    values = [p.value for p in action.params.values() if isinstance(p.value, str)]
    eff: set[str] = set()

    if cat in (ToolCategory.FILE_OPS, ToolCategory.DB_ACCESS) and any(k in op for k in _READ_OPS):
        eff.add("read")
        if any(_is_sensitive_value(v) for v in values):
            eff.add("read_sensitive")
        if any(_is_credential_value(v) for v in values):
            eff.add("read_credential")

    if cat == ToolCategory.MESSAGING:
        if any(_is_external_destination(v) for v in values):
            eff.add("send_external")
        else:
            eff.add("send_internal")
    elif cat == ToolCategory.EXTERNAL_API:
        external = any(_is_external_destination(v) for v in values)
        if external and any(k in op for k in ("post", "put", "upload", "call", "send", "webhook")):
            eff.add("send_external")
        elif external and any("?" in v and "=" in v for v in values):
            # a GET can still exfiltrate — through the query string.
            eff.add("send_external")
        elif external:
            eff.add("fetch_external")

    if any(k in op for k in _DESTROY_OPS):
        eff.add("destroy")
    if cat == ToolCategory.COMMAND_EXEC:
        eff.add("exec")
    if cat in (ToolCategory.FILE_OPS, ToolCategory.DB_ACCESS) and any(k in op for k in ("write", "insert", "update", "append")):
        eff.add("write")
    return eff


# (prior effect already in the session, effect of the proposed action,
#  pattern name, scope tag that pre-authorizes the COMBINED effect, severity bump)
CHAIN_PATTERNS: list[tuple[str, str, str, str | None, float]] = [
    ("read_sensitive", "send_external", "data-exfiltration", "export:external", 3.5),
    ("read_credential", "exec", "credential-pivot", None, 4.0),
]


def _describe_step(entry) -> str:
    a = entry.action
    return f"{a.tool_name}({', '.join(f'{k}={v!r}' for k, v in a.raw_params().items())})"


def _is_external_destination(value) -> bool:
    if not isinstance(value, str):
        return False
    if "@" in value:
        domain = value.split("@")[-1].lower()
        return domain not in INTERNAL_DOMAINS
    if value.lower() in ("team-channel", "internal", "internal-channel"):
        return False
    return "http" in value.lower() or "external" in value.lower()


def _op_base_risk(category: ToolCategory, operation: str) -> float:
    table = BASE_RISK.get(category, {})
    op_l = operation.lower()
    for key, weight in table.items():
        if key in op_l:
            return weight
    return 1.5  # unknown operation in a known category: moderate default


class PolicyEngine:
    def __init__(self, advisor: Optional[LLMAdvisor] = None):
        self.advisor = advisor or LLMAdvisor()

    def evaluate(self, action: ProposedAction, ctx: SessionContext) -> PolicyResult:
        effects = action_effects(action)
        result = self._evaluate(action, ctx, effects)
        result.effects = sorted(effects)   # every audit entry carries its effects, so
        return result                       # the session can compute the chain's privilege

    def _evaluate(self, action: ProposedAction, ctx: SessionContext, effects: set[str]) -> PolicyResult:
        # --- R1: directive authority -------------------------------------------------
        directive_source = action.directive_provenance.source
        in_scope, scope_confidence = self._scope_match(action, ctx)

        if not directive_source.can_grant_authority and not in_scope:
            return PolicyResult(
                decision=Decision.DENY,
                reason=(
                    f"The instruction to perform '{action.operation}' on "
                    f"{action.tool_name} originated from an untrusted source "
                    f"({directive_source.name}) and falls outside what the user "
                    f"authorized ({sorted(ctx.declared_scope)}). Untrusted content "
                    f"may supply data but cannot grant new authority."
                ),
                rule="R1-directive-authority",
                risk_delta=0.0,
            )

        # --- R2: scope rule (ambiguous case -> consult LLM) ---------------------------
        llm_consulted = False
        llm_suggestion = None
        if scope_confidence == "ambiguous":
            advice: ScopeMatchResult = self.advisor.check_scope_match(action, ctx)
            llm_consulted = True
            llm_suggestion = f"in_scope={advice.in_scope} confidence={advice.confidence:.2f}: {advice.rationale}"
            if advice.confidence < 0.55:
                return PolicyResult(
                    decision=Decision.ESCALATE,
                    reason=(
                        f"Action scope relative to the user's stated task "
                        f"('{ctx.user_intent}') is ambiguous even after semantic "
                        f"review. Needs explicit user confirmation. ({advice.rationale})"
                    ),
                    rule="R2-scope-ambiguous",
                    risk_delta=1.0,
                    llm_consulted=True, llm_suggestion=llm_suggestion,
                )
            in_scope = advice.in_scope
            if not in_scope and not directive_source.can_grant_authority:
                return PolicyResult(
                    decision=Decision.DENY,
                    reason=f"Semantic review found this action out of scope and its directive is untrusted. {advice.rationale}",
                    rule="R2-scope-deny",
                    risk_delta=0.0, llm_consulted=True, llm_suggestion=llm_suggestion,
                )

        if not in_scope:
            # Directive WAS trusted (e.g. user or system) but action still doesn't
            # match declared scope -> ask, don't assume.
            return PolicyResult(
                decision=Decision.ESCALATE,
                reason=(
                    f"'{action.operation}' on {action.tool_name} is not part of the "
                    f"declared scope {sorted(ctx.declared_scope)}. Confirming with the "
                    f"user before proceeding."
                ),
                rule="R2-scope-escalate",
                risk_delta=0.5, llm_consulted=llm_consulted, llm_suggestion=llm_suggestion,
            )

        # --- R3/R4: base risk + novelty ------------------------------------------------
        base_risk = _op_base_risk(action.tool_category, action.operation)
        novelty_bump = 0.0
        for p in action.params.values():
            if isinstance(p.value, str) and not ctx.has_prior_action_on(p.value):
                novelty_bump += 0.5
        risk_delta = base_risk + novelty_bump

        # A prompt-injection check even on in-scope, trusted-directive actions:
        # if any PARAMETER (not the directive) is low-trust AND looks like it's
        # trying to redirect behaviour, flag it (data smuggling an instruction).
        if self.advisor.enabled:
            for name, p in action.params.items():
                if p.provenance.source <= TrustLevel.RETRIEVED_CONTENT:
                    inj = self.advisor.check_injection(str(p.value))
                    if inj.is_injection:
                        llm_consulted = True
                        return PolicyResult(
                            decision=Decision.ESCALATE,
                            reason=(
                                f"Parameter '{name}' sourced from {p.provenance.source.name} "
                                f"appears to contain embedded instructions rather than plain data "
                                f"({inj.rationale}). Escalating for user review before use."
                            ),
                            rule="R-injection-in-data",
                            risk_delta=2.0, llm_consulted=True,
                            llm_suggestion=f"injection_suspected={inj.is_injection} conf={inj.confidence:.2f}",
                        )

        # --- R7: chain effect — does this step complete an unauthorized chain? ---------
        # Each step so far was in scope on its own. Here we look at what the
        # session has *already done* plus what this action *would do*, and ask
        # whether the combination is a privilege the user never granted.
        privilege_so_far = ctx.effective_privileges()
        for prior_eff, this_eff, pattern, authorizing_tag, bump in CHAIN_PATTERNS:
            if this_eff not in effects or prior_eff not in privilege_so_far:
                continue
            if authorizing_tag and authorizing_tag in ctx.declared_scope:
                continue  # user explicitly authorized the COMBINED effect
            steps = [_describe_step(e) for e in ctx.executed_actions() if prior_eff in e.result.effects]
            steps += [f"output_of:{t}" for t in sorted(ctx.sensitive_outputs)] if prior_eff == "read_sensitive" else []
            chain_desc = " -> ".join(steps + [f"{action.tool_name}({', '.join(f'{k}={v!r}' for k, v in action.raw_params().items())})"])
            scope_note = (
                f"Declared scope {sorted(ctx.declared_scope)} covers each step individually, "
                f"but not the combined effect '{pattern}'"
                + (f" (would need '{authorizing_tag}')." if authorizing_tag else " (cannot be pre-authorized).")
            )
            chain_delta = risk_delta + bump
            if not directive_source.can_grant_authority:
                return PolicyResult(
                    decision=Decision.DENY,
                    reason=(
                        f"Chain '{pattern}': {prior_eff} earlier in this session followed by "
                        f"{this_eff} now. {scope_note} The directive for this final step comes "
                        f"from an untrusted source ({directive_source.name}), so it cannot "
                        f"expand the session's authority. Chain: {chain_desc}"
                    ),
                    rule="R7-chain-deny", risk_delta=chain_delta,
                    llm_consulted=llm_consulted, llm_suggestion=llm_suggestion,
                    chain=pattern, chain_steps=steps,
                )
            return PolicyResult(
                decision=Decision.ESCALATE,
                reason=(
                    f"Chain '{pattern}': {prior_eff} earlier in this session followed by "
                    f"{this_eff} now. {scope_note} Session risk would reach "
                    f"{ctx.cumulative_risk + chain_delta:.1f}. Confirming with the user "
                    f"before completing the chain. Chain: {chain_desc}"
                ),
                rule="R7-chain-escalate", risk_delta=chain_delta,
                llm_consulted=llm_consulted, llm_suggestion=llm_suggestion,
                chain=pattern, chain_steps=steps,
            )

        # --- R6: dangerous combo with recent history (only when flagged) ----------------
        combo_bump = 0.0
        combo_hit = None
        current_flagged = any(_is_sensitive_value(p.value) or _is_external_destination(p.value)
                               for p in action.params.values())
        export_authorized = "send_external" in effects and "export:external" in ctx.declared_scope
        for entry in ctx.recent_actions(5):
            if export_authorized:
                break  # user explicitly authorized sending data outside; not a combo
            pair = (entry.action.tool_category, action.tool_category)
            if pair not in DANGEROUS_COMBOS:
                continue
            prior_flagged = any(_is_sensitive_value(p.value) for p in entry.action.params.values())
            if current_flagged or prior_flagged:
                combo_bump = max(combo_bump, DANGEROUS_COMBOS[pair])
                combo_hit = pair
        risk_delta += combo_bump

        projected_risk = ctx.cumulative_risk + risk_delta

        if combo_hit and projected_risk >= ctx.RISK_ESCALATE_THRESHOLD:
            return PolicyResult(
                decision=Decision.ESCALATE,
                reason=(
                    f"This action combined with a recent {combo_hit[0].value} action "
                    f"forms a pattern ({combo_hit[0].value} -> {combo_hit[1].value}) "
                    f"consistent with data exfiltration. Session risk would reach "
                    f"{projected_risk:.1f}. Escalating for confirmation."
                ),
                rule="R6-dangerous-combo",
                risk_delta=risk_delta, llm_consulted=llm_consulted, llm_suggestion=llm_suggestion,
            )

        # --- R5: cumulative session risk -------------------------------------------------
        if projected_risk >= ctx.RISK_DENY_THRESHOLD:
            return PolicyResult(
                decision=Decision.DENY,
                reason=(
                    f"Cumulative session risk would reach {projected_risk:.1f}, at/above "
                    f"the deny threshold ({ctx.RISK_DENY_THRESHOLD}). Too many elevated-risk "
                    f"actions in this task already."
                ),
                rule="R5-cumulative-deny",
                risk_delta=risk_delta, llm_consulted=llm_consulted, llm_suggestion=llm_suggestion,
            )
        if projected_risk >= ctx.RISK_ESCALATE_THRESHOLD:
            return PolicyResult(
                decision=Decision.ESCALATE,
                reason=(
                    f"Cumulative session risk would reach {projected_risk:.1f}, at/above "
                    f"the escalate threshold ({ctx.RISK_ESCALATE_THRESHOLD}). Confirming "
                    f"before continuing this sequence of actions."
                ),
                rule="R5-cumulative-escalate",
                risk_delta=risk_delta, llm_consulted=llm_consulted, llm_suggestion=llm_suggestion,
            )

        # --- default: ALLOW -----------------------------------------------------------
        return PolicyResult(
            decision=Decision.ALLOW,
            reason=f"In scope, directive from {directive_source.name}, risk {risk_delta:.1f} (session total after: {projected_risk:.1f}).",
            rule="default-allow",
            risk_delta=risk_delta, llm_consulted=llm_consulted, llm_suggestion=llm_suggestion,
        )

    # ------------------------------------------------------------------------------
    def _scope_match(self, action: ProposedAction, ctx: SessionContext) -> tuple[bool, str]:
        """
        Cheap, deterministic scope check first. Returns (in_scope, confidence)
        where confidence is 'clean', 'ambiguous', or 'clean' for a clear miss too
        (we only mark 'ambiguous' when a fuzzy/partial signal exists that a pure
        set-membership check can't resolve).
        """
        tag = f"{action.operation}:{action.tool_category.value}"
        if tag in ctx.declared_scope or action.tool_category.value in ctx.declared_scope:
            return True, "clean"

        # partial match heuristic: same category declared but different operation,
        # or same operation family declared for a different category -> ambiguous,
        # let semantic layer weigh in rather than flatly deny/allow.
        declared_categories = {s.split(":")[-1] for s in ctx.declared_scope}
        declared_ops = {s.split(":")[0] for s in ctx.declared_scope if ":" in s}
        if action.tool_category.value in declared_categories or action.operation in declared_ops:
            return False, "ambiguous"

        return False, "clean"
