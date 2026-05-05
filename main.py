from __future__ import annotations

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.core.config import BASE_DIR, SESSION_COOKIE
from app.core.db import get_db_connection
from app.db.migrations import ensure_auth_tables
from app.routers import admin, auth, dashboard
from app.services.portal import (
    get_vk_confirmation_code,
    get_vk_secret,
    handle_vk_message_new,
)

app = FastAPI(title="PrivateToolsPortal")

static_dir = BASE_DIR / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(admin.router)


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


@app.post("/vk/callback")
async def vk_callback(request: Request):
    try:
        body = await request.json()
    except Exception:
        return PlainTextResponse("invalid json", status_code=400)

    expected_secret = get_vk_secret()
    if expected_secret:
        incoming_secret = str(body.get("secret", "")).strip()
        if incoming_secret != expected_secret:
            return JSONResponse({"ok": False, "error": "invalid secret"}, status_code=403)

    event_type = str(body.get("type", "")).strip()

    if event_type == "confirmation":
        code = get_vk_confirmation_code()
        if not code:
            return PlainTextResponse("VK confirmation code is not configured", status_code=500)
        return PlainTextResponse(code)

    if event_type == "message_new":
        try:
            handle_vk_message_new(body)
        except Exception as exc:
            print(f"[vk_callback] message_new error: {exc}")
        return PlainTextResponse("ok")

    return PlainTextResponse("ok")


@app.get("/", response_class=HTMLResponse)
async def root_redirect() -> RedirectResponse:
    return RedirectResponse("/dashboard", status_code=303)
