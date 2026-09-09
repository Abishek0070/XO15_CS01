"""
Process-wide default runtime. The @guarded_tool decorator, the FastAPI
app, and the dashboard all share this store, so a session opened in user
code shows up live in the dashboard with zero wiring.
"""
from .mediator import AuthorizationMediator
from .session import SessionStore

GLOBAL_STORE = SessionStore()
GLOBAL_MEDIATOR = AuthorizationMediator()
