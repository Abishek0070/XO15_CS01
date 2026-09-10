"""
toolgate.integrations.langchain — protect LangChain / LangGraph tools.

    pip install "toolgate-sdk[langchain]"

    from toolgate import TaskSession
    from toolgate.integrations.langchain import guard_langchain_tools

    safe_tools = guard_langchain_tools(my_tools)          # list[BaseTool]
    agent = create_react_agent(llm, safe_tools)            # LangGraph
    # or AgentExecutor(agent=..., tools=safe_tools)        # classic LangChain

    with TaskSession(intent="Summarize the invoice",
                     scope={"read:file_ops"}):
        agent.invoke({"messages": [...]})

Implementation notes:
- We do NOT monkey-patch BaseTool instances (they are pydantic models;
  attribute injection is version-fragile). Instead we build NEW
  StructuredTool objects whose func is the guarded wrapper around the
  original tool's callable — same name, description, and args_schema,
  so the LLM sees an identical tool surface.
- Category/operation are inferred from the tool's name (same rules as
  the generic adapter) and can be overridden per tool name.
- DENY raises ToolDenied out of the tool call. Frameworks surface tool
  exceptions back to the model/user; if you prefer the agent to see a
  polite string instead of an exception, pass soft_deny=True and the
  wrapper returns the denial reason as the tool's output.
"""
from __future__ import annotations

from typing import Iterable, Optional

from ..mediator import ToolDenied, ToolEscalated
from .generic import guard_callable, infer_category

try:
    from langchain_core.tools import BaseTool, StructuredTool
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "langchain-core is required for this integration: "
        "pip install 'toolgate-sdk[langchain]'"
    ) from e


def guard_langchain_tools(
    tools: Iterable[BaseTool],
    overrides: Optional[dict[str, tuple[str, str]]] = None,
    *,
    scan_output: bool = True,
    soft_deny: bool = False,
) -> list[BaseTool]:
    """Return a new list of tools, each routed through the toolgate
    mediator. Originals are not modified."""
    overrides = overrides or {}
    guarded: list[BaseTool] = []

    for tool in tools:
        cat, op = overrides.get(tool.name, (None, None))
        if cat is None:
            cat_enum, op_inferred = infer_category(tool.name)
            cat, op = cat_enum.value, (op or op_inferred)

        # The callable we ultimately execute: prefer the tool's own func
        # (Tool / StructuredTool), fall back to invoking the BaseTool.
        inner = getattr(tool, "func", None)
        if inner is None:
            _t = tool
            def inner(**kwargs):  # noqa: E306
                return _t.invoke(kwargs)
            inner.__name__ = tool.name

        core = guard_callable(inner, cat, op, name=tool.name, scan_output=scan_output)

        if soft_deny:
            def runner(*, __core=core, __name=tool.name, **kwargs):
                try:
                    return __core(**kwargs)
                except ToolDenied as e:
                    return f"[toolgate DENIED {__name}] {e.result.reason}"
                except ToolEscalated as e:
                    return f"[toolgate ESCALATED {__name}] {e.result.reason}"
        else:
            def runner(*, __core=core, **kwargs):
                return __core(**kwargs)

        guarded.append(
            StructuredTool.from_function(
                func=runner,
                name=tool.name,
                description=tool.description,
                args_schema=tool.args_schema,
            )
        )
    return guarded
