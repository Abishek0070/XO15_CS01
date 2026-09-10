# Changelog

All notable changes to ToolGate are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-09-09

First public release of the SDK as the `toolgate-sdk` distribution
(Python import name `toolgate`).

### Added
- `guard_tools` / `guard_callable`: wrap plain Python callables so every
  invocation is authorized (ALLOW / DENY / ESCALATE) before it runs.
- `TaskSession`: one user task = one session, carrying intent, declared
  scope, phase, taint state and cumulative risk.
- `@guarded_tool` decorator plus provenance markers `untrusted`,
  `from_tool_output`, `from_tool_metadata` for explicit provenance labeling.
- Rule-based policy engine (R0 stale-authorization, R1/R1b directive
  authority, R2 scope, R5 cumulative risk, R6 dangerous combinations,
  R7 chain effects, R8 output quarantine) with an advisory-only LLM signal.
- Context-bound human approvals (`TaskSession.confirm`) that never become
  standing permissions.
- `scan_content` for tools that summarize or transform untrusted content.
- `escalate_call` for tools that cannot act safely on ambiguous or
  under-specified content: the call becomes ESCALATE and a human decides.
- LangChain adapter `toolgate.integrations.langchain.guard_langchain_tools`
  (`[langchain]` extra).
- Optional live decision dashboard and HTTP API (`[dashboard]` extra,
  `serve_dashboard()` / `toolgate-dashboard`).
- Optional LLM advisor providers, Groq or Anthropic (`[llm]` extra).

### Changed
- Distribution renamed from `agent-toolgate` to `toolgate-sdk`.
- The core package no longer depends on FastAPI, uvicorn or pydantic;
  they moved to the `[dashboard]` extra. `import toolgate` is dependency-free.
- Package ships a `py.typed` marker.
