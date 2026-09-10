"""
One-liner dashboard for any host application:

    import toolgate
    toolgate.serve_dashboard()            # background thread, :8000

    ...run your agent; open http://127.0.0.1:8000 ...

The dashboard reads the same in-process GLOBAL_STORE that every
TaskSession writes to, so decisions from @guarded_tool, guard_tools(),
and framework adapters all appear with no extra wiring.
"""
from __future__ import annotations

import threading
from typing import Any, Optional

# uvicorn / FastAPI are only needed when the dashboard is actually started,
# so they are imported lazily. `import toolgate` stays dependency-free.
_server: Optional[Any] = None          # uvicorn.Server once running
_thread: Optional[threading.Thread] = None


def _require_uvicorn():
    try:
        import uvicorn
    except ImportError as e:  # pragma: no cover
        raise ImportError(
            "The ToolGate dashboard needs the optional dashboard dependencies: "
            "pip install 'toolgate-sdk[dashboard]'"
        ) from e
    return uvicorn


def serve_dashboard(host: str = "127.0.0.1", port: int = 8000, *, background: bool = True):
    """Start the toolgate dashboard. background=True (default) runs it in
    a daemon thread and returns immediately; background=False blocks."""
    global _server, _thread
    uvicorn = _require_uvicorn()
    from .api import app  # deferred: importing api pulls FastAPI

    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)

    if not background:
        server.run()
        return server

    if _thread is not None and _thread.is_alive():
        return _server  # already running

    thread = threading.Thread(target=server.run, name="toolgate-dashboard", daemon=True)
    thread.start()
    _server, _thread = server, thread
    return server


def stop_dashboard():
    global _server
    if _server is not None:
        _server.should_exit = True
        _server = None
