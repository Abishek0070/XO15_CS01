"""
FastAPI surface for the mediation layer.

This is the "real-time" requirement: decisions are produced synchronously
as the agent (or a human testing via curl/Swagger) proposes each action,
not via offline batch analysis of a full transcript.

Endpoints:
  POST /session                  start a task, declare user intent + scope
  POST /session/{id}/actions      propose + execute an action (evaluates, then
                                   runs it only on ALLOW; DENY/ESCALATE returns
                                   the reason instead of raising an HTTP 500)
  POST /session/{id}/actions/{action_id}/confirm
                                   human confirms a previously-ESCALATEd action,
                                   which is then actually executed
  GET  /session/{id}/audit        full audit trail + current risk state
"""
from __future__ import annotations
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .mediator import AuthorizationMediator, AuthorizationError
from .models import (
    Decision, ParamProvenance, ProposedAction, ProvenanceTag, ToolCategory, TrustLevel,
)
from .runtime import GLOBAL_MEDIATOR, GLOBAL_STORE

app = FastAPI(title="toolgate — Adaptive Authorization Mediation Layer")
store = GLOBAL_STORE
mediator = GLOBAL_MEDIATOR

# Actions currently sitting in ESCALATE state, awaiting human confirmation.
_pending_escalations: dict[str, tuple[ProposedAction, Any]] = {}


class StartSessionRequest(BaseModel):
    user_intent: str
    declared_scope: list[str] = []


class ParamIn(BaseModel):
    value: Any
    source: str          # "USER" | "SYSTEM" | "TOOL_OUTPUT" | "RETRIEVED_CONTENT" | "THIRD_PARTY_METADATA"
    origin_id: str
    note: str = ""


class ProposeActionRequest(BaseModel):
    tool_category: str
    tool_name: str
    operation: str
    params: dict[str, ParamIn] = {}
    directive_source: str
    directive_origin_id: str


def _tag(source_str: str, origin_id: str, note: str = "") -> ProvenanceTag:
    try:
        level = TrustLevel[source_str.upper()]
    except KeyError:
        raise HTTPException(400, f"Unknown trust source '{source_str}'")
    return ProvenanceTag(source=level, origin_id=origin_id, note=note)


@app.post("/session")
def start_session(req: StartSessionRequest):
    ctx = store.create(user_intent=req.user_intent, declared_scope=set(req.declared_scope))
    return {"session_id": ctx.session_id, "user_intent": ctx.user_intent, "declared_scope": sorted(ctx.declared_scope)}


@app.post("/session/{session_id}/actions")
def propose_action(session_id: str, req: ProposeActionRequest):
    ctx = store.get(session_id)
    if ctx is None:
        raise HTTPException(404, "unknown session")
    try:
        category = ToolCategory(req.tool_category)
    except ValueError:
        raise HTTPException(400, f"unknown tool_category '{req.tool_category}'")

    action = ProposedAction(
        session_id=session_id,
        tool_category=category,
        tool_name=req.tool_name,
        operation=req.operation,
        params={k: ParamProvenance(v.value, _tag(v.source, v.origin_id, v.note)) for k, v in req.params.items()},
        directive_provenance=_tag(req.directive_source, req.directive_origin_id),
    )

    try:
        result_payload = mediator.execute(action, ctx)
        result = ctx.audit_log[-1].result
        return {
            "action_id": action.action_id,
            "decision": result.decision.value,
            "rule": result.rule,
            "reason": result.reason,
            "llm_consulted": result.llm_consulted,
            "session_risk": ctx.cumulative_risk,
            "result": result_payload,
        }
    except AuthorizationError as e:
        if e.result.decision == Decision.ESCALATE:
            _pending_escalations[action.action_id] = (action, e.result)
        return {
            "action_id": action.action_id,
            "decision": e.result.decision.value,
            "rule": e.result.rule,
            "reason": e.result.reason,
            "llm_consulted": e.result.llm_consulted,
            "session_risk": ctx.cumulative_risk,
            "result": None,
        }


@app.post("/session/{session_id}/actions/{action_id}/confirm")
def confirm_escalation(session_id: str, action_id: str):
    ctx = store.get(session_id)
    if ctx is None:
        raise HTTPException(404, "unknown session")
    pending = _pending_escalations.pop(action_id, None)
    if pending is None:
        raise HTTPException(404, "no pending escalation with that action_id")
    action, escalate_result = pending
    out = mediator.execute_after_human_confirmation(action, ctx, escalate_result)
    return {"action_id": action_id, "decision": "ALLOW", "rule": "human-override", "result": out}


@app.get("/session/{session_id}/audit")
def get_audit(session_id: str):
    ctx = store.get(session_id)
    if ctx is None:
        raise HTTPException(404, "unknown session")
    return {
        "session_id": session_id,
        "user_intent": ctx.user_intent,
        "declared_scope": sorted(ctx.declared_scope),
        "cumulative_risk": ctx.cumulative_risk,
        "risk_state": ctx.risk_state(),
        "tainted": ctx.tainted,
        "effective_privileges": sorted(ctx.effective_privileges()),
        "audit_log": [
            {
                "action_id": e.action.action_id,
                "tool": f"{e.action.tool_category.value}.{e.action.operation}",
                "params": e.action.raw_params(),
                "directive_source": e.action.directive_provenance.source.name,
                "decision": e.result.decision.value,
                "rule": e.result.rule,
                "reason": e.result.reason,
                "effects": e.result.effects,
                "chain": e.result.chain,
                "chain_steps": e.result.chain_steps,
                "session_risk_after": e.session_risk_after,
            }
            for e in ctx.audit_log
        ],
    }


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
import pathlib
from fastapi.responses import HTMLResponse

_DASHBOARD_HTML = (pathlib.Path(__file__).parent / "dashboard.html").read_text()


@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return _DASHBOARD_HTML


@app.get("/audit/recent")
def audit_recent(limit: int = 200):
    """Aggregated decision feed across ALL sessions in this process —
    what the dashboard polls."""
    entries = []
    counts = {"ALLOW": 0, "DENY": 0, "ESCALATE": 0}
    sessions = store.all()
    for ctx in sessions:
        for e in ctx.audit_log:
            counts[e.result.decision.value] = counts.get(e.result.decision.value, 0) + 1
            entries.append({
                "time": e.action.timestamp.strftime("%H:%M:%S"),
                "ts": e.action.timestamp.timestamp(),
                "session_id": ctx.session_id,
                "intent": ctx.user_intent,
                "tool": f"{e.action.tool_category.value}.{e.action.operation}",
                "decision": e.result.decision.value,
                "rule": e.result.rule,
                "reason": e.result.reason,
                "directive_source": e.action.directive_provenance.source.name,
                "effects": e.result.effects,
                "chain": e.result.chain,
                "session_risk_after": e.session_risk_after,
                "risk_state": ctx.risk_state(),
            })
    entries.sort(key=lambda x: x["ts"], reverse=True)
    return {"entries": entries[:limit], "counts": counts, "session_count": len(sessions)}


@app.post("/audit/clear")
def audit_clear():
    """Wipe all in-memory sessions/audit history for this process. Does not
    affect authorization behavior going forward — only clears the log the
    dashboard displays. Any TaskSession object a caller is still holding
    becomes orphaned (its writes are silently dropped)."""
    store._sessions.clear()
    _pending_escalations.clear()
    return {"ok": True}


def main():
    """Console entry point: `toolgate-dashboard` starts the API + dashboard."""
    import uvicorn
    uvicorn.run("toolgate.api:app", host="127.0.0.1", port=8000, reload=False)
