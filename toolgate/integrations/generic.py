"""
toolgate.integrations.generic — protect tools in ANY agent framework.

Most frameworks (OpenAI/Anthropic tool-use loops, CrewAI, smolagents,
custom executors) ultimately call plain Python callables. This module
wraps those callables so every invocation is authorized by toolgate,
WITHOUT requiring the framework to know anything about provenance.

    from toolgate import TaskSession
    from toolgate.integrations import guard_tools

    tools = guard_tools([read_file, send_email, run_shell])
    # hand `tools` to your framework instead of the raw functions

    with TaskSession(intent="Summarize the invoice",
                     scope={"read:file_ops"}):
        agent.run(...)   # every tool call now goes through the mediator

Because a framework can't label provenance, this adapter adds two
automatic protections that don't exist in the manual @guarded_tool path:

1. AUTO-INFERENCE — tool category/operation are guessed from the
   function name ("read_file" -> file_ops.read, "send_email" ->
   messaging.send, ...) and can be overridden per tool.

2. AUTO-TAINT — after every tool executes, its string output is scanned
   for embedded-instruction content (the same advisor used by the
   policy engine). If suspicious content is found, the session is
   marked TAINTED. From then on, any tool call whose directive is still
   the default USER provenance is automatically downgraded to
   TOOL_OUTPUT — because once the agent has ingested a suspected
   injection, "the user asked for this" can no longer be assumed. A
   downgraded directive cannot grant authority (policy rule R1), so
   out-of-scope follow-ups get DENIED instead of trusted.

   This is an honest, best-effort heuristic: it narrows the window in
   unlabeled-provenance environments, it does not replace real
   provenance labeling (see README "limitations").
"""
from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, Iterable, Optional

from ..decorator import Sourced, TaskSession, current_session
from ..models import (
    ParamProvenance, ProposedAction, ProvenanceTag, ToolCategory, TrustLevel,
)
from ..mediator import ToolEscalated
from ..runtime import GLOBAL_MEDIATOR

# ---------------------------------------------------------------------------
# Category/operation auto-inference from tool names
# ---------------------------------------------------------------------------
_NAME_RULES: list[tuple[tuple[str, ...], ToolCategory, str]] = [
    (("delete", "remove", "unlink", "rm_"), ToolCategory.FILE_OPS, "delete"),
    (("write", "save", "create_file", "append"), ToolCategory.FILE_OPS, "write"),
    (("read", "open", "load", "cat_", "list_dir", "ls_"), ToolCategory.FILE_OPS, "read"),
    (("drop_table", "truncate"), ToolCategory.DB_ACCESS, "drop"),
    (("insert", "update_row", "db_write"), ToolCategory.DB_ACCESS, "write"),
    (("query", "sql", "select", "db_read", "search_db"), ToolCategory.DB_ACCESS, "query"),
    (("send", "email", "message", "slack", "notify", "reply", "post_message"), ToolCategory.MESSAGING, "send"),
    (("broadcast",), ToolCategory.MESSAGING, "broadcast"),
    (("exec", "shell", "run_command", "bash", "terminal", "subprocess"), ToolCategory.COMMAND_EXEC, "exec"),
    (("http_post", "post_", "upload", "webhook"), ToolCategory.EXTERNAL_API, "post"),
    (("http", "fetch", "request", "api", "download", "get_url", "curl", "browse"), ToolCategory.EXTERNAL_API, "get"),
]

_FALLBACK = (ToolCategory.EXTERNAL_API, "call")


def infer_category(tool_name: str) -> tuple[ToolCategory, str]:
    low = tool_name.lower()
    for keywords, category, operation in _NAME_RULES:
        if any(k in low for k in keywords):
            return category, operation
    return _FALLBACK


# ---------------------------------------------------------------------------
# Output scanning -> session taint
# ---------------------------------------------------------------------------
_SCAN_LIMIT = 4000


def _scan_output_and_taint(sess: TaskSession, tool_name: str, result: Any) -> None:
    text = result if isinstance(result, str) else None
    if text is None and isinstance(result, dict):
        text = " ".join(str(v) for v in result.values() if isinstance(v, str))
    if not text:
        return
    # Chain rule R7 needs to know when sensitive data has been *seen*, not
    # just when a sensitive-looking path was requested. The policy engine
    # only sees parameters; the adapter is the one place that sees output.
    from ..policy_engine import _is_sensitive_value
    if _is_sensitive_value(text[:_SCAN_LIMIT]):
        sess.ctx.sensitive_outputs.add(tool_name)
    advisor = sess.mediator.policy.advisor
    check = advisor.check_injection(text[:_SCAN_LIMIT])
    if check.is_injection:
        sess.ctx.tainted = True
        sess.ctx.taint_origin = f"output_of:{tool_name}"


def _effective_directive(sess: TaskSession) -> ProvenanceTag:
    """If the developer explicitly declared a directive (acting_on...),
    respect it. Otherwise, in a tainted session, the default USER
    directive is no longer credible -> downgrade to TOOL_OUTPUT."""
    directive = sess.current_directive()
    if sess.ctx.tainted and directive.source == TrustLevel.USER and directive.origin_id == "user":
        return ProvenanceTag(
            source=TrustLevel.TOOL_OUTPUT,
            origin_id=sess.ctx.taint_origin or "tainted_session",
            note="auto-downgraded: session tainted by suspected injection in earlier tool output",
        )
    return directive


# ---------------------------------------------------------------------------
# The generic wrapper
# ---------------------------------------------------------------------------
def guard_callable(
    fn: Callable,
    category: str | ToolCategory | None = None,
    operation: str | None = None,
    *,
    name: str | None = None,
    scan_output: bool = True,
) -> Callable:
    """Wrap one plain callable so every invocation is authorized.
    Unlike @guarded_tool, values are NOT expected to carry Sourced
    markers (frameworks pass raw values) — but markers still work if
    present. Returns a callable with the same signature."""
    tool_name = name or getattr(fn, "__name__", "tool")
    if category is None or operation is None:
        inferred_cat, inferred_op = infer_category(tool_name)
        tool_category = ToolCategory(category) if category else inferred_cat
        op = operation or inferred_op
    else:
        tool_category = ToolCategory(category)
        op = operation

    sig = inspect.signature(fn)

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        sess = current_session()
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()

        params: dict[str, ParamProvenance] = {}
        clean_kwargs: dict[str, Any] = {}
        for pname, val in bound.arguments.items():
            if isinstance(val, Sourced):
                params[pname] = ParamProvenance(val.value, ProvenanceTag(val.source, val.origin_id))
                clean_kwargs[pname] = val.value
            else:
                params[pname] = ParamProvenance(val, ProvenanceTag(TrustLevel.USER, "user"))
                clean_kwargs[pname] = val

        action = ProposedAction(
            session_id=sess.ctx.session_id,
            tool_category=tool_category,
            tool_name=tool_name,
            operation=op,
            params=params,
            directive_provenance=_effective_directive(sess),
        )

        def _run():
            result = fn(**clean_kwargs)
            if scan_output:
                _scan_output_and_taint(sess, tool_name, result)
            return result

        try:
            sess.mediator.authorize(action, sess.ctx)
        except ToolEscalated as e:
            e._retry = _run
            raise
        return _run()

    wrapper.__toolgate__ = {"category": tool_category.value, "operation": op, "tool_name": tool_name}
    return wrapper


def guard_tools(
    tools: Iterable[Callable],
    overrides: Optional[dict[str, tuple[str, str]]] = None,
    *,
    scan_output: bool = True,
) -> list[Callable]:
    """Wrap a list of plain callables. `overrides` maps tool name ->
    (category, operation) for anything the name-based inference gets
    wrong:

        guard_tools([read_file, nuke], overrides={"nuke": ("file_ops", "delete")})
    """
    overrides = overrides or {}
    out = []
    for fn in tools:
        tool_name = getattr(fn, "__name__", "tool")
        cat, op = overrides.get(tool_name, (None, None))
        out.append(guard_callable(fn, cat, op, name=tool_name, scan_output=scan_output))
    return out
