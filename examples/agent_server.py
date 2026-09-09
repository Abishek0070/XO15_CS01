"""
Web frontend for the toolgate-guarded LangChain agent.

    ./venv/bin/python examples/agent_server.py

    agent UI:           http://127.0.0.1:8001
    toolgate audit UI:  http://127.0.0.1:8000   (embedded in the agent UI too)

Both run in this one process, so every tool call the agent makes shows up
in the toolgate dashboard the moment the policy engine decides on it.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent))
from langchain_agent import MODEL, UPLOAD_DIR, Agent, list_uploaded_documents  # noqa: E402

from toolgate import serve_dashboard  # noqa: E402

AGENT_PORT = int(os.environ.get("AGENT_PORT", "8001"))
DASHBOARD_PORT = int(os.environ.get("TOOLGATE_PORT", "8000"))
ALLOWED_SUFFIXES = {".txt", ".md", ".pdf", ".csv", ".json", ".html", ".py"}

app = FastAPI(title="toolgate example agent")
agent = Agent()


class ChatRequest(BaseModel):
    message: str
    scope: list[str] = ["get:external_api", "read:file_ops"]


@app.get("/", response_class=HTMLResponse)
def index():
    html = (Path(__file__).parent / "agent_ui.html").read_text()
    return html.replace("__DASHBOARD_PORT__", str(DASHBOARD_PORT)).replace("__MODEL__", MODEL)


@app.get("/documents")
def documents():
    return {"documents": list_uploaded_documents()}


@app.post("/upload")
async def upload(file: UploadFile):
    name = Path(file.filename or "").name
    if not name or Path(name).suffix.lower() not in ALLOWED_SUFFIXES:
        raise HTTPException(400, f"unsupported file type; allowed: {sorted(ALLOWED_SUFFIXES)}")
    (UPLOAD_DIR / name).write_bytes(await file.read())
    return {"saved": name, "documents": list_uploaded_documents()}


@app.post("/chat")
def chat(req: ChatRequest):
    # sync endpoint on purpose: runs in a worker thread, so the agent's
    # blocking LLM and HTTP calls don't stall the event loop.
    if not req.message.strip():
        raise HTTPException(400, "empty message")
    try:
        reply, audit = agent.chat(req.message, scope=set(req.scope))
    except Exception as e:
        raise HTTPException(500, f"{type(e).__name__}: {e}")
    return {"reply": reply, "audit": audit}


@app.post("/reset")
def reset():
    agent.reset()
    return {"ok": True}


if __name__ == "__main__":
    if not os.environ.get("GROQ_API_KEY"):
        print("GROQ_API_KEY is not set. Put GROQ_API_KEY=gsk_... in the project's .env file first.")
        sys.exit(1)
    serve_dashboard(port=DASHBOARD_PORT)
    time.sleep(0.5)
    print(f"toolgate audit UI:  http://127.0.0.1:{DASHBOARD_PORT}")
    print(f"agent UI:           http://127.0.0.1:{AGENT_PORT}   (model: {MODEL})")
    uvicorn.run(app, host="127.0.0.1", port=AGENT_PORT, log_level="warning")
