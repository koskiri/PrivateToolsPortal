from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.core.config import BASE_DIR
from app.core.db import get_db_connection
from app.core.security import (
    create_password_hash,
    get_current_user,
    issue_session,
    verify_password,
)

router = APIRouter()
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def is_invite_used(invite_row: sqlite3.Row | None) -> bool:
    if not invite_row:
        return False
    used_at = invite_row["used_at"]
    if used_at is None:
        return False
    if isinstance(used_at, str):
        return bool(used_at.strip())
    return True

def is_invite_revoked(invite_row: sqlite3.Row | None) -> bool:
    if not invite_row or "revoked_at" not in invite_row.keys():
        return False
    revoked_at = invite_row["revoked_at"]
    if revoked_at is None:
        return False
    if isinstance(revoked_at, str):
        return bool(revoked_at.strip())
    return True


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, activated: int = 0, invite_used: int = 0, reason: str = "", error: str = ""):
    if get_current_user(request):
        return RedirectResponse("/dashboard", status_code=303)
    success_message = "Аккаунт успешно активирован. Войдите под своим логином и паролем." if activated else None
    invite_used_message = (
        "Этот инвайт уже был использован. Если вы уже зарегистрированы — войдите в аккаунт."
        if invite_used or reason == "invite_used"
        else None
    )

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"error": error or None, "success": success_message, "invite_used": invite_used_message},
    )


@router.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request, login: str = Form(...), password: str = Form(...)):
    with get_db_connection() as con:
        user = con.execute("SELECT * FROM portal_users WHERE login = ?", (login.strip(),)).fetchone()

    if not user or not verify_password(password, user["password_salt"], user["password_hash"]):
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": "Неверный логин или пароль"},
            status_code=400,
        )
    
    if user["revoked_at"] is not None:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": "Доступ к аккаунту отключен администратором"},
            status_code=403,
        )

    response = RedirectResponse("/dashboard", status_code=303)
    issue_session(response, user["id"])
    return response


@router.get("/activate", response_class=HTMLResponse)
async def activate_page(request: Request, code: str = ""):
    invite_info = None
    error = None
    if code:
        with get_db_connection() as con:
            invite_info = con.execute(
                (
                    "SELECT i.invite_code, i.used_at, i.revoked_at, i.plan, i.key_limit, i.title, i.price_rub, i.duration_days "
                    "FROM portal_invites i "
                    "WHERE i.invite_code = ?"
                ),
                (code,),
            ).fetchone()

        elif is_invite_revoked(invite_info):
            error = "Инвайт отозван"
            invite_info = None
        elif is_invite_used(invite_info):
            return RedirectResponse("/login?invite_used=1&reason=invite_used", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="activate.html",
        context={"code": code, "invite": invite_info, "error": error, "success": None},
    )


@router.post("/activate", response_class=HTMLResponse)
async def activate_submit(
    request: Request,
    code: str = Form(...),
    login: str = Form(...),
    password: str = Form(...),
):
    current_user = get_current_user(request)
    login = login.strip()
    code = code.strip()

    if len(password) < 6:
        return templates.TemplateResponse(
            request=request,
            name="activate.html",
            context={"code": code, "invite": None, "error": "Пароль должен быть не менее 6 символов", "success": None},
            status_code=400,
        )

    with get_db_connection() as con:
        invite = con.execute(
            "SELECT * FROM portal_invites WHERE invite_code = ?",
            (code,),
        ).fetchone()

        if not invite:
            return templates.TemplateResponse(
                request=request,
                name="activate.html",
                context={"code": code, "invite": None, "error": "Инвайт не найден", "success": None},
                status_code=404,
            )
        
        if is_invite_revoked(invite):
            return templates.TemplateResponse(
                request=request,
                name="activate.html",
                context={"code": code, "invite": None, "error": "Инвайт отозван", "success": None},
                status_code=410,
            )

        if is_invite_used(invite):
            return RedirectResponse("/login?invite_used=1&reason=invite_used", status_code=303)
        if current_user and int(current_user["id"]) == int(invite["invited_by_user_id"] or -1):
            return templates.TemplateResponse(
                request=request,
                name="activate.html",
                context={"code": code, "invite": None, "error": "Нельзя использовать собственный инвайт", "success": None},
                status_code=403,
            )

        duplicate_login = con.execute(
            "SELECT id FROM portal_users WHERE login = ?",
            (login,),
        ).fetchone()
        if duplicate_login:
            return templates.TemplateResponse(
                request=request,
                name="activate.html",
                context={"code": code, "invite": None, "error": "Логин уже занят", "success": None},
                status_code=409,
            )

        salt, password_hash = create_password_hash(password)
        now = utcnow().isoformat()

        user_cursor = con.execute(
            (
                "INSERT INTO portal_users "
                "(telegram_id, login, password_salt, password_hash, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)"
            ),
            (invite["telegram_id"], login, salt, password_hash, now, now),
        )
        user_id = user_cursor.lastrowid
        resolved_telegram_id = invite["telegram_id"]
        if resolved_telegram_id is None:
            resolved_telegram_id = -int(user_id)
            con.execute(
                "UPDATE portal_users SET telegram_id = ? WHERE id = ?",
                (resolved_telegram_id, user_id),
            )
            con.execute(
                "UPDATE portal_invites SET telegram_id = ? WHERE id = ?",
                (resolved_telegram_id, invite["id"]),
            )
        con.execute(
            "UPDATE portal_invites SET used_at = ?, used_by_user_id = ? WHERE id = ?",
            (now, user_id, invite["id"]),
        )
        con.execute(
            "UPDATE portal_users SET invited_by_user_id = ? WHERE id = ?",
            (invite["invited_by_user_id"], user_id),
        )
        if invite["key_limit"] is not None:
            duration_days = invite["duration_days"] or 30
            active_until = (utcnow() + timedelta(days=duration_days)).isoformat()
            con.execute(
                (
                    "INSERT INTO subscriptions (telegram_id, active_until, plan, key_limit, price_rub, title) "
                    "VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(telegram_id) DO UPDATE SET "
                    "active_until=excluded.active_until, "
                    "plan=excluded.plan, "
                    "key_limit=excluded.key_limit, "
                    "price_rub=excluded.price_rub, "
                    "title=excluded.title"
                ),
                (
                    resolved_telegram_id,
                    active_until,
                    invite["plan"],
                    invite["key_limit"],
                    invite["price_rub"],
                    invite["title"],
                ),
            )
        con.commit()

    return RedirectResponse("/login?activated=1", status_code=303)
