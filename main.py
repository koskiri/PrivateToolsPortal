from __future__ import annotations

from dotenv import load_dotenv

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.core.config import BASE_DIR, SESSION_COOKIE
from app.core.db import get_db_connection
from app.db.migrations import ensure_auth_tables
from app.routers import admin, auth, dashboard, vk

load_dotenv()

app = FastAPI(title="PrivateToolsPortal")

static_dir = BASE_DIR / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(admin.router)
app.include_router(vk.router)


@app.on_event("startup")
def startup() -> None:
    ensure_auth_tables()


@app.get("/logout")
async def logout(request: Request):
    session_id = request.cookies.get(SESSION_COOKIE)
    if session_id:
        with get_db_connection() as con:
            con.execute("DELETE FROM portal_sessions WHERE session_id = ?", (session_id,))
            con.commit()

    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response


@app.get("/", response_class=HTMLResponse)
async def root_redirect() -> RedirectResponse:
    return RedirectResponse("/dashboard", status_code=303)
