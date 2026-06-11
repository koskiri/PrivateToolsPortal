from __future__ import annotations

import asyncio
from contextlib import suppress
from dotenv import load_dotenv

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.core.config import BASE_DIR, SESSION_COOKIE
from app.core.db import get_db_connection
from app.core.security import get_current_user
from app.db.migrations import ensure_auth_tables
from app.routers import admin, auth, dashboard, mobile, vk
from app.services.portal import run_vk_subscription_reminder_loop

load_dotenv()

app = FastAPI(title="PrivateToolsPortal")

static_dir = BASE_DIR / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(admin.router)
app.include_router(vk.router)
app.include_router(mobile.router)


@app.on_event("startup")
async def startup() -> None:
    ensure_auth_tables()
    app.state.vk_subscription_reminder_task = asyncio.create_task(run_vk_subscription_reminder_loop())


@app.on_event("shutdown")
async def shutdown() -> None:
    reminder_task = getattr(app.state, "vk_subscription_reminder_task", None)
    if reminder_task is None:
        return

    reminder_task.cancel()
    with suppress(asyncio.CancelledError):
        await reminder_task


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
async def root_redirect(request: Request) -> RedirectResponse:
    if get_current_user(request):
        return RedirectResponse("/new-ui", status_code=303)
    return RedirectResponse("/login", status_code=303)
