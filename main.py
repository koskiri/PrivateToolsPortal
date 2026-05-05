from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from urllib import error as urllib_error
from urllib.parse import quote_plus, urlencode
from urllib import request as urllib_request
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.core.config import (
    ADMIN_COOKIE,
    ADMIN_PASSWORD_ENV,
    APP_BASE_URL_ENV,
    BASE_DIR,
    MAX_SUPPORT_MESSAGE_LEN,
    MAX_SUPPORT_SUBJECT_LEN,
    SESSION_COOKIE,
    SESSION_DAYS,
    SUBSCRIPTION_RENEW_DAYS,
    TARIFF_PRESETS,
    USER_TARIFF_CHOICES,
    VK_BOT_LINK_ENV,
    VK_CONFIRMATION_CODE_ENV,
    VK_SECRET_ENV,
    VK_TOKEN_ENV,
    VPS_ISSUER_TOKEN_ENV,
    VPS_ISSUER_URL_ENV,
    YOOKASSA_API_URL,
    YOOKASSA_RETURN_URL_ENV,
    YOOKASSA_SECRET_KEY_ENV,
    YOOKASSA_SHOP_ID_ENV,
)
from app.core.db import get_db_connection
from app.core.security import (
    create_password_hash,
    get_admin_password,
    get_current_user,
    is_admin,
    issue_session,
    verify_password,
)
from app.db.migrations import ensure_auth_tables
from app.services.portal import (
    build_vk_keyboard,
    consume_vk_link_code,
    create_referral_invite,
    deactivate_user_keys,
    format_support_status,
    get_app_base_url,
    get_or_create_wallet_balance,
    get_subscription_stats,
    get_vk_confirmation_code,
    get_vk_secret,
    get_vk_token,
    get_vk_bot_link,
    get_vk_linked_account,
    handle_vk_message_new,
    increase_wallet_balance,
    utcnow,
)
from app.routers import auth, dashboard
app = FastAPI(title="PrivateToolsPortal")

static_dir = BASE_DIR / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app.include_router(auth.router)
app.include_router(dashboard.router)



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


@app.post("/invite")
async def create_invite(request: Request, tariff: str = Form(...), custom_key_limit: int = Form(0), custom_price_rub: int = Form(0), custom_duration_days: int = Form(30)):
    if not is_admin(request):
        return RedirectResponse("/admin/invites", status_code=303)
    plan = ""
    title = ""
    key_limit = 0
    price_rub = 0
    duration_days = 30

    if tariff == "custom":
        if custom_key_limit < 1 or custom_key_limit > 100:
            return RedirectResponse("/admin/invites?error=Лимит+ключей+должен+быть+от+1+до+100", status_code=303)
        if custom_price_rub < 0:
            return RedirectResponse("/admin/invites?error=Цена+не+может+быть+отрицательной", status_code=303)
        if custom_duration_days < 1 or custom_duration_days > 365:
            return RedirectResponse("/admin/invites?error=Срок+должен+быть+от+1+до+365+дней", status_code=303)
        key_limit = custom_key_limit
        price_rub = custom_price_rub
        duration_days = custom_duration_days
        plan = f"plan_custom_{key_limit}"
        title = f"{price_rub} ₽ / {key_limit} ключей"
    else:
        preset = TARIFF_PRESETS.get(tariff)
        if not preset:
            return RedirectResponse("/admin/invites?error=Неизвестный+тариф", status_code=303)
        plan = preset["plan"]
        title = preset["title"]
        key_limit = preset["key_limit"]
        price_rub = preset["price_rub"]
        duration_days = preset["duration_days"]
    invite_code = secrets.token_urlsafe(12)
    now = utcnow().isoformat()

    with get_db_connection() as con:
        con.execute(
            (
                "INSERT INTO portal_invites "
                "(invite_code, telegram_id, created_at, plan, title, key_limit, price_rub, duration_days) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            ),
            (invite_code, None, now, plan, title, key_limit, price_rub, duration_days),
        )
        con.commit()

    return RedirectResponse(f"/admin/invites?created={invite_code}", status_code=303)


def admin_user_redirect(user_id: int, success: str = "", error: str = "") -> RedirectResponse:
    query_parts: list[str] = []
    if success:
        query_parts.append(f"success={quote_plus(success)}")
    if error:
        query_parts.append(f"error={quote_plus(error)}")
    suffix = f"?{'&'.join(query_parts)}" if query_parts else ""
    return RedirectResponse(f"/admin/users/{user_id}{suffix}", status_code=303)


@app.get("/admin", response_class=HTMLResponse)
async def admin_home_page(request: Request, error: str = "", success: str = ""):
    admin_password = get_admin_password()
    if not admin_password:
        return templates.TemplateResponse(
            request=request,
            name="admin.html",
            context={"error": f"Нужно задать переменную окружения {ADMIN_PASSWORD_ENV}", "success": "", "is_admin": False, "users": []},
            status_code=503,
        )
    if not is_admin(request):
        return templates.TemplateResponse(
            request=request,
            name="admin.html",
            context={"error": error, "success": success, "is_admin": False, "users": []},
        )

    with get_db_connection() as con:
        users = con.execute(
            (
                "SELECT u.id, u.login, u.telegram_id, u.created_at, u.revoked_at, "
                "s.title AS subscription_title, s.active_until, s.key_limit, "
                "COALESCE(k.active_keys, 0) AS active_keys, "
                "COALESCE(w.balance_rub, 0) AS balance_rub, "
                "CASE WHEN vl.portal_user_id IS NULL THEN 0 ELSE 1 END AS vk_linked "
                "FROM portal_users u "
                "LEFT JOIN subscriptions s ON s.telegram_id = u.telegram_id "
                "LEFT JOIN ("
                "SELECT telegram_id, COUNT(*) AS active_keys FROM vpn_keys WHERE revoked_at IS NULL GROUP BY telegram_id"
                ") k ON k.telegram_id = u.telegram_id "
                "LEFT JOIN user_wallets w ON w.telegram_id = u.telegram_id "
                "LEFT JOIN vk_links vl ON vl.portal_user_id = u.id "
                "ORDER BY u.id DESC "
                "LIMIT 300"
            )
        ).fetchall()

    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={"error": error, "success": success, "is_admin": True, "users": users},
    )


@app.get("/admin/users/{user_id}", response_class=HTMLResponse)
async def admin_user_page(request: Request, user_id: int, error: str = "", success: str = ""):
    admin_password = get_admin_password()
    if not admin_password:
        return templates.TemplateResponse(
            request=request,
            name="admin_user.html",
            context={"error": f"Нужно задать переменную окружения {ADMIN_PASSWORD_ENV}", "success": "", "is_admin": False, "user": None},
            status_code=503,
        )
    if not is_admin(request):
        return templates.TemplateResponse(
            request=request,
            name="admin_user.html",
            context={"error": error, "success": success, "is_admin": False, "user": None},
        )

    with get_db_connection() as con:
        user = con.execute(
            (
                "SELECT u.id, u.login, u.telegram_id, u.created_at, u.updated_at, u.revoked_at, "
                "s.plan, s.title, s.price_rub, s.key_limit, s.active_until, "
                "COALESCE(w.balance_rub, 0) AS wallet_balance, "
                "vl.vk_user_id "
                "FROM portal_users u "
                "LEFT JOIN subscriptions s ON s.telegram_id = u.telegram_id "
                "LEFT JOIN user_wallets w ON w.telegram_id = u.telegram_id "
                "LEFT JOIN vk_links vl ON vl.portal_user_id = u.id "
                "WHERE u.id = ?"
            ),
            (user_id,),
        ).fetchone()
        if not user:
            return RedirectResponse("/admin?error=Пользователь+не+найден", status_code=303)

        keys = con.execute(
            (
                "SELECT id, kind, title, created_at, revoked_at "
                "FROM vpn_keys WHERE telegram_id = ? AND (revoked_at IS NULL OR revoked_at = '') "
                "ORDER BY id DESC LIMIT 100"
            ),
            (user["telegram_id"],),
        ).fetchall() if user["telegram_id"] is not None else []

        support_tickets = con.execute(
            (
                "SELECT id, status, subject, created_at, updated_at "
                "FROM support_tickets WHERE telegram_id = ? "
                "ORDER BY id DESC LIMIT 20"
            ),
            (user["telegram_id"],),
        ).fetchall() if user["telegram_id"] is not None else []

    return templates.TemplateResponse(
        request=request,
        name="admin_user.html",
        context={
            "error": error,
            "success": success,
            "is_admin": True,
            "user": user,
            "keys": keys,
            "support_tickets": support_tickets,
            "tariff_presets": TARIFF_PRESETS,
            "status_label": format_support_status,
        },
    )


@app.post("/admin/users/{user_id}/change-plan")
async def admin_user_change_plan(request: Request, user_id: int, tariff: str = Form(...)):
    if not is_admin(request):
        return admin_user_redirect(user_id, error="Нужна авторизация админа")
    preset = TARIFF_PRESETS.get(tariff)
    if not preset:
        return admin_user_redirect(user_id, error="Неизвестный тариф")

    now = utcnow()
    with get_db_connection() as con:
        user = con.execute("SELECT telegram_id FROM portal_users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            return RedirectResponse("/admin?error=Пользователь+не+найден", status_code=303)
        if user["telegram_id"] is None:
            return admin_user_redirect(user_id, error="У пользователя нет Telegram ID")

        existing = con.execute("SELECT active_until FROM subscriptions WHERE telegram_id = ?", (user["telegram_id"],)).fetchone()
        if existing and existing["active_until"]:
            try:
                active_until = datetime.fromisoformat(existing["active_until"])
            except Exception:
                active_until = now
        else:
            active_until = now
        if active_until <= now:
            active_until = now + timedelta(days=int(preset["duration_days"]))

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
                user["telegram_id"],
                active_until.isoformat(),
                preset["plan"],
                int(preset["key_limit"]),
                int(preset["price_rub"]),
                preset["title"],
            ),
        )
        con.commit()
    return admin_user_redirect(user_id, success="Тариф пользователя обновлен")


@app.post("/admin/users/{user_id}/add-days")
async def admin_user_add_days(request: Request, user_id: int, days: int = Form(...)):
    if not is_admin(request):
        return admin_user_redirect(user_id, error="Нужна авторизация админа")
    if days < 1 or days > 365:
        return admin_user_redirect(user_id, error="Можно добавить от 1 до 365 дней")

    now = utcnow()
    with get_db_connection() as con:
        user = con.execute("SELECT telegram_id FROM portal_users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            return RedirectResponse("/admin?error=Пользователь+не+найден", status_code=303)
        if user["telegram_id"] is None:
            return admin_user_redirect(user_id, error="У пользователя нет Telegram ID")
        sub = con.execute("SELECT active_until FROM subscriptions WHERE telegram_id = ?", (user["telegram_id"],)).fetchone()
        if not sub:
            return admin_user_redirect(user_id, error="У пользователя нет активной подписки")
        try:
            base = datetime.fromisoformat(sub["active_until"]) if sub["active_until"] else now
        except Exception:
            base = now
        if base < now:
            base = now
        new_active_until = base + timedelta(days=days)
        con.execute(
            "UPDATE subscriptions SET active_until = ? WHERE telegram_id = ?",
            (new_active_until.isoformat(), user["telegram_id"]),
        )
        con.commit()
    return admin_user_redirect(user_id, success=f"Срок подписки увеличен на {days} дн.")


@app.post("/admin/users/{user_id}/refund")
async def admin_user_refund(request: Request, user_id: int, amount_rub: int = Form(...)):
    if not is_admin(request):
        return admin_user_redirect(user_id, error="Нужна авторизация админа")
    if amount_rub < 1 or amount_rub > 1_000_000:
        return admin_user_redirect(user_id, error="Сумма возврата должна быть от 1 до 1000000 ₽")
    with get_db_connection() as con:
        user = con.execute("SELECT telegram_id FROM portal_users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            return RedirectResponse("/admin?error=Пользователь+не+найден", status_code=303)
        if user["telegram_id"] is None:
            return admin_user_redirect(user_id, error="У пользователя нет Telegram ID")
        increase_wallet_balance(con, int(user["telegram_id"]), amount_rub)
        con.commit()
    return admin_user_redirect(user_id, success=f"Возврат {amount_rub} ₽ начислен на внутренний баланс")


@app.post("/admin/users/{user_id}/reset-password")
async def admin_user_reset_password(request: Request, user_id: int, new_password: str = Form("")):
    if not is_admin(request):
        return admin_user_redirect(user_id, error="Нужна авторизация админа")
    password = new_password.strip() or secrets.token_urlsafe(8)
    if len(password) < 6:
        return admin_user_redirect(user_id, error="Пароль должен быть не короче 6 символов")
    salt_hex, password_hash = create_password_hash(password)
    now = utcnow().isoformat()
    with get_db_connection() as con:
        updated = con.execute(
            "UPDATE portal_users SET password_salt = ?, password_hash = ?, updated_at = ? WHERE id = ?",
            (salt_hex, password_hash, now, user_id),
        ).rowcount
        con.execute("DELETE FROM portal_sessions WHERE user_id = ?", (user_id,))
        con.commit()
    if not updated:
        return RedirectResponse("/admin?error=Пользователь+не+найден", status_code=303)
    return admin_user_redirect(user_id, success=f"Пароль обновлен. Временный пароль: {password}")


@app.post("/admin/users/{user_id}/revoke-access")
async def admin_user_revoke_access(request: Request, user_id: int):
    if not is_admin(request):
        return admin_user_redirect(user_id, error="Нужна авторизация админа")
    now = utcnow().isoformat()
    with get_db_connection() as con:
        user = con.execute("SELECT telegram_id FROM portal_users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            return RedirectResponse("/admin?error=Пользователь+не+найден", status_code=303)
        con.execute("UPDATE portal_users SET revoked_at = ?, updated_at = ? WHERE id = ?", (now, now, user_id))
        con.execute("DELETE FROM portal_sessions WHERE user_id = ?", (user_id,))
        failed_revocations = 0
        if user["telegram_id"] is not None:
            _, failed_revocations = deactivate_user_keys(con, int(user["telegram_id"]))
        con.commit()
    if failed_revocations:
        return admin_user_redirect(user_id, error="Доступ отозван, но часть ключей не удалось отозвать на VPS")
    return admin_user_redirect(user_id, success="Доступ пользователя к сайту отозван")


@app.post("/admin/users/{user_id}/restore-access")
async def admin_user_restore_access(request: Request, user_id: int):
    if not is_admin(request):
        return admin_user_redirect(user_id, error="Нужна авторизация админа")
    now = utcnow().isoformat()
    with get_db_connection() as con:
        updated = con.execute(
            "UPDATE portal_users SET revoked_at = NULL, updated_at = ? WHERE id = ?",
            (now, user_id),
        ).rowcount
        con.commit()
    if not updated:
        return RedirectResponse("/admin?error=Пользователь+не+найден", status_code=303)
    return admin_user_redirect(user_id, success="Доступ пользователя восстановлен")


@app.get("/admin/invites", response_class=HTMLResponse)
async def admin_invites_page(request: Request, error: str = "", created: str = ""):
    admin_password = get_admin_password()
    if not admin_password:
        return templates.TemplateResponse(
            request=request,
            name="admin_invites.html",
            context={"error": f"Нужно задать переменную окружения {ADMIN_PASSWORD_ENV}", "invites": [], "created": "", "is_admin": False, "tariff_presets": TARIFF_PRESETS},
            status_code=503,
        )

    if not is_admin(request):
        return templates.TemplateResponse(
            request=request,
            name="admin_invites.html",
            context={"error": error, "invites": [], "created": "", "is_admin": False, "tariff_presets": TARIFF_PRESETS},
        )

    with get_db_connection() as con:
        invites = con.execute(
            (
                "SELECT i.invite_code, i.created_at, i.used_at, i.title, i.key_limit, i.price_rub, "
                "u.id AS user_id, u.login AS user_login, u.revoked_at AS user_revoked_at "
                "FROM portal_invites i "
                "LEFT JOIN portal_users u ON u.telegram_id = i.telegram_id "
                "ORDER BY i.id DESC "
                "LIMIT 100"
            )
        ).fetchall()

    return templates.TemplateResponse(
        request=request,
        name="admin_invites.html",
        context={"error": "", "invites": invites, "created": created, "is_admin": True, "tariff_presets": TARIFF_PRESETS},
    )


@app.post("/admin/invites/login")
async def admin_invites_login(password: str = Form(...)):
    admin_password = get_admin_password()
    if not admin_password or not hmac.compare_digest(
        password.encode("utf-8"),
        admin_password.encode("utf-8"),
        ):
        return RedirectResponse("/admin/invites?error=Неверный+пароль+админа", status_code=303)

    response = RedirectResponse("/admin/invites", status_code=303)
    response.set_cookie(key=ADMIN_COOKIE, value=admin_password, httponly=True, samesite="lax", max_age=SESSION_DAYS * 24 * 60 * 60)
    return response


@app.post("/admin/invites/logout")
async def admin_invites_logout():
    response = RedirectResponse("/admin/invites", status_code=303)
    response.delete_cookie(ADMIN_COOKIE)
    return response

@app.post("/admin/invites/revoke")
async def admin_revoke_user(request: Request, user_id: int = Form(...)):
    if not is_admin(request):
        return RedirectResponse("/admin/invites?error=Нужна+авторизация+админа", status_code=303)

    now = utcnow().isoformat()
    with get_db_connection() as con:
        user = con.execute("SELECT id FROM portal_users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            return RedirectResponse("/admin/invites?error=Пользователь+не+найден", status_code=303)

        con.execute("UPDATE portal_users SET revoked_at = ?, updated_at = ? WHERE id = ?", (now, now, user_id))
        con.execute("DELETE FROM portal_sessions WHERE user_id = ?", (user_id,))
        con.commit()

    return RedirectResponse("/admin/invites", status_code=303)


@app.get("/admin/support", response_class=HTMLResponse)
async def admin_support_page(request: Request, error: str = "", success: str = ""):
    admin_password = get_admin_password()
    if not admin_password:
        return templates.TemplateResponse(
            request=request,
            name="admin_support.html",
            context={"error": f"Нужно задать переменную окружения {ADMIN_PASSWORD_ENV}", "success": "", "is_admin": False, "tickets": [], "messages_by_ticket": {}, "status_label": format_support_status},
            status_code=503,
        )
    if not is_admin(request):
        return templates.TemplateResponse(
            request=request,
            name="admin_support.html",
            context={"error": error, "success": "", "is_admin": False, "tickets": [], "messages_by_ticket": {}, "status_label": format_support_status},
        )

    with get_db_connection() as con:
        tickets = con.execute(
            (
                "SELECT t.*, u.login "
                "FROM support_tickets t "
                "LEFT JOIN portal_users u ON u.telegram_id = t.telegram_id "
                "ORDER BY CASE t.status "
                "WHEN 'open' THEN 0 "
                "WHEN 'in_progress' THEN 1 "
                "ELSE 2 END, t.updated_at DESC, t.id DESC "
                "LIMIT 60"
            )
        ).fetchall()
        messages = con.execute(
            (
                "SELECT m.ticket_id, m.sender_role, m.text, m.created_at, u.login AS sender_login "
                "FROM support_messages m "
                "LEFT JOIN portal_users u ON u.id = m.sender_id "
                "ORDER BY m.id ASC"
            )
        ).fetchall()
    messages_by_ticket: dict[int, list[sqlite3.Row]] = {}
    for msg in messages:
        messages_by_ticket.setdefault(int(msg["ticket_id"]), []).append(msg)

    return templates.TemplateResponse(
        request=request,
        name="admin_support.html",
        context={
            "error": error,
            "success": success,
            "is_admin": True,
            "tickets": tickets,
            "messages_by_ticket": messages_by_ticket,
            "status_label": format_support_status,
        },
    )


@app.post("/admin/support/tickets/{ticket_id}/reply")
async def admin_support_reply(request: Request, ticket_id: int, message: str = Form(...)):
    if not is_admin(request):
        return RedirectResponse("/admin/support?error=Нужна+авторизация+админа", status_code=303)
    message = message.strip()
    if not message:
        return RedirectResponse("/admin/support?error=Сообщение+не+может+быть+пустым", status_code=303)
    if len(message) > MAX_SUPPORT_MESSAGE_LEN:
        return RedirectResponse("/admin/support?error=Слишком+длинный+ответ", status_code=303)
    now = utcnow().isoformat()
    with get_db_connection() as con:
        ticket = con.execute("SELECT id, telegram_id FROM support_tickets WHERE id = ?", (ticket_id,)).fetchone()
        if not ticket:
            return RedirectResponse("/admin/support?error=Обращение+не+найдено", status_code=303)
        con.execute(
            (
                "INSERT INTO support_messages "
                "(ticket_id, telegram_id, sender_role, sender_id, text, created_at) "
                "VALUES (?, ?, 'support', 0, ?, ?)"
            ),
            (ticket_id, ticket["telegram_id"], message, now),
        )
        con.execute(
            "UPDATE support_tickets SET status = 'in_progress', updated_at = ? WHERE id = ?",
            (now, ticket_id),
        )
        con.commit()
    return RedirectResponse("/admin/support?success=Ответ+отправлен", status_code=303)


@app.post("/admin/support/tickets/{ticket_id}/status")
async def admin_support_set_status(request: Request, ticket_id: int, status: str = Form(...)):
    if not is_admin(request):
        return RedirectResponse("/admin/support?error=Нужна+авторизация+админа", status_code=303)
    status = status.strip().lower()
    if status not in {"open", "in_progress", "closed"}:
        return RedirectResponse("/admin/support?error=Неизвестный+статус+обращения", status_code=303)
    now = utcnow().isoformat()
    closed_at = now if status == "closed" else None
    with get_db_connection() as con:
        updated = con.execute(
            "UPDATE support_tickets SET status = ?, closed_at = ?, updated_at = ? WHERE id = ?",
            (status, closed_at, now, ticket_id),
        ).rowcount
        con.commit()
    if not updated:
        return RedirectResponse("/admin/support?error=Обращение+не+найдено", status_code=303)
    return RedirectResponse("/admin/support?success=Статус+обращения+обновлен", status_code=303)

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
