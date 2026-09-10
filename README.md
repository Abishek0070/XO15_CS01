# ToolGate

**AI Agent Security & Authorization SDK**

ToolGate is an authorization layer that sits between an AI agent and the
tools it is allowed to call. Every tool call the agent proposes is
evaluated *before* it runs and receives exactly one decision:

```
ALLOW  ·  DENY  ·  ESCALATE
```

Decisions are made by a deterministic, rule-based policy engine that
reasons about **who is really asking** (instruction provenance), **what
the user actually authorized** (declared scope), and **what the session
has already done** (cumulative risk and chain effects). An LLM may be
consulted as an advisory signal, but it never decides.

```
AI Agent
    ↓
ToolGate SDK
    ↓
Authorization / Policy / Risk checks
    ↓
ALLOW / DENY / ESCALATE
    ↓
Your real tool
```

## Install

```bash
pip install toolgate-sdk
```

The core package has **no third-party dependencies**. Optional extras:

| Extra | Adds | Install |
|---|---|---|
| `dashboard` | Live decision dashboard + HTTP API (FastAPI, uvicorn) | `pip install "toolgate-sdk[dashboard]"` |
| `langchain` | LangChain / LangGraph tool adapter | `pip install "toolgate-sdk[langchain]"` |
| `llm` | LLM-backed advisor (Groq or Anthropic) | `pip install "toolgate-sdk[llm]"` |
| `all` | Everything above | `pip install "toolgate-sdk[all]"` |

## Quick start

```python
from toolgate import guard_tools, TaskSession, ToolDenied, ToolEscalated

# Your ordinary tools. Nothing about ToolGate in here.
def read_file(path: str) -> str:
    return open(path).read()

def send_email(to: str, body: str) -> str:
    ...  # actually send it
    return "sent"

# 1. Guard them. Category/operation are inferred from the name
#    (read_file -> file_ops.read, send_email -> messaging.send).
protected_tools = guard_tools([read_file, send_email])

# 2. One user task == one session. Declare intent and scope.
with TaskSession(intent="Summarize the Q3 report", scope={"read:file_ops"}):
    agent = Agent(tools=protected_tools)      # any framework that calls Python callables
    agent.run("Summarize reports/q3_summary.txt")
```

Inside the session, every call to a protected tool goes through the
policy engine:

- **ALLOW** – the function runs and returns normally.
- **DENY** – `ToolDenied` is raised; the function never runs.
- **ESCALATE** – `ToolEscalated` is raised. After a human approves,
  call `session.confirm(exc)` to run the original call exactly once.

```python
with TaskSession(intent="Send the invoice total to finance",
                 scope={"read:file_ops", "send:messaging"}) as session:
    try:
        send_email(to="finance@corp.example", body="Total: $4,120")
    except ToolEscalated as e:
        if human_approves(e.result.reason):
            session.confirm(e)               # runs the call, records the approval
    except ToolDenied as e:
        print("blocked:", e.result.reason)
```

## Why this works

ToolGate treats **authority** and **data** as different things.

| Source | Trust | Can direct the agent? |
|---|---|---|
| The user's request | `USER` | yes |
| Agent configuration | `SYSTEM` | narrowly |
| Output of an earlier tool | `TOOL_OUTPUT` | no |
| Web pages, documents, emails | `RETRIEVED_CONTENT` | no |
| Tool / plugin descriptions | `THIRD_PARTY_METADATA` | no |

A document can supply a phone number to put in a message the user asked
to send. It can never supply the *instruction* to send a message. This
distinction is what stops prompt injection from turning into action.

### Labeling provenance explicitly

When you know where a value came from, say so. Unlabeled values default
to `USER` provenance, so labeling is what gives the engine its leverage.

```python
from toolgate import guarded_tool, untrusted

@guarded_tool(category="messaging", operation="send")
def send_message(to: str, body: str): ...

with TaskSession(intent="Reply to the vendor", scope={"send:messaging"}) as s:
    # A value that came out of a document:
    send_message(to=untrusted("evil@example.com", origin="invoice.pdf"), body="...")

    # The agent is acting BECAUSE of something it read, not because the user asked:
    with s.acting_on_retrieved_content("invoice.pdf"):
        send_message(...)        # directive provenance = the document -> DENY if out of scope
```

For tools that read untrusted content and return something derived from
it (a summary, an extraction), scan the raw content first:

```python
from toolgate import scan_content

def summarize_document(name: str) -> str:
    text = read(name)
    scan_content(text, origin=name)   # raises ToolDenied and quarantines on injection
    return llm.summarize(text)
```

When a tool finds it does not have enough information to act safely, it
can ask for a human instead of guessing. The call's audit entry becomes
ESCALATE and `ToolEscalated` is raised:

```python
from toolgate import escalate_call

def summarize_document(name: str) -> str:
    text = read(name)
    scan_content(text, origin=name)
    if names_several_recipients(text):        # "send the money to Bala", three Balas listed
        escalate_call("recipient cannot be resolved from the document", origin=name)
    return llm.summarize(text)
```

## The rules

Evaluated in order. The first conclusive rule wins.

| Rule | What it catches |
|---|---|
| **R0** Stale authorization | A human approval covers one action in one context. Change the destination, resource, phase, scope or who is directing, and it is re-evaluated. |
| **R1 / R1b** Directive authority | The instruction to act came from content that cannot grant authority (a document, a tool result, plugin metadata). |
| **R2** Scope | The action is outside the user's declared scope, or ambiguous relative to their intent. |
| **R3** Base risk | Each category/operation carries a severity weight. High-severity single actions (delete, exec, drop) escalate by default. |
| **R4** Novelty | A resource or target never touched before in this session raises the risk. |
| **R5** Cumulative risk | The session as a whole has accumulated too much risk. |
| **R6** Dangerous combinations | Known-dangerous sequences, such as reading sensitive data then sending externally, flagged even though each step passes alone. |
| **R7** Chain effects | The union of everything the session has already done, plus this action, completes a data-exfiltration or credential-pivot chain the user never authorized. |
| **R8** Output quarantine | A tool's output contains an embedded instruction. It is quarantined and never reaches the model. |

Every evaluation is recorded to the session audit log with the rule that
fired and a human-readable reason.

## Human approvals are not standing permissions

`session.confirm(exc)` records a grant bound to that exact action and
context. A later call is only covered if it is identical *and* the grant
was issued with `reusable=True`. Anything else goes back through the
engine, and the audit entry says exactly what changed.

```python
session.confirm(e, reusable=True)   # identical later calls skip re-confirmation
session.enter_phase("review", scope={"read:file_ops"})   # every earlier approval is now stale
```

## LangChain / LangGraph

```bash
pip install "toolgate-sdk[langchain]"
```

```python
from toolgate import TaskSession
from toolgate.integrations.langchain import guard_langchain_tools

safe_tools = guard_langchain_tools(my_tools, soft_deny=True)
agent = create_react_agent(llm, safe_tools)

with TaskSession(intent="Summarize the invoice", scope={"read:file_ops"}):
    agent.invoke({"messages": [...]})
```

`soft_deny=True` returns the denial reason as the tool's output instead of
raising, so the model can explain to the user why it stopped.

## Dashboard

```bash
pip install "toolgate-sdk[dashboard]"
```

```python
import toolgate
toolgate.serve_dashboard()     # background thread on http://127.0.0.1:8000
```

Every session in the process appears live, with each decision, the rule
that fired, and the running risk score. `toolgate-dashboard` starts the
same server from the command line, and the HTTP API lets non-Python
agents propose actions over REST.

## LLM advisor (optional)

The policy engine can consult an LLM for two narrow questions: does this
action semantically match the user's intent, and does this text look
like an embedded instruction. Set `GROQ_API_KEY` or `ANTHROPIC_API_KEY`
and install the `llm` extra to enable it. Without a key, a transparent
keyword heuristic is used and the whole system runs offline. The LLM is
advisory only; the rules always have the final word.

## Limitations

- Unlabeled parameters default to `USER` provenance. ToolGate can never
  conjure labels the caller did not provide. The `guard_tools` adapter
  narrows this window with output quarantine, but explicit labeling is
  stronger.
- Category and operation inference from tool names is a heuristic. Use
  `overrides={"tool_name": ("file_ops", "delete")}` when it is wrong.
- The session store is in-memory. Swap it for a persistent store for
  multi-process deployments.

## Public API

```python
from toolgate import (
    guard_tools, guard_callable, guarded_tool, scan_content, escalate_call,
    TaskSession, current_session,
    untrusted, from_tool_output, from_tool_metadata, Sourced,
    ToolDenied, ToolEscalated, AuthorizationError,
    Decision, ToolCategory, TrustLevel, ProposedAction, PolicyResult,
    AuthorizationMediator, PolicyEngine, SessionContext, SessionStore,
    serve_dashboard, stop_dashboard,
)
```

## License

MIT. See [LICENSE](LICENSE).
