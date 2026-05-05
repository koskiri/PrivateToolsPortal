from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from urllib.parse import quote_plus

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response, JSONResponse
from fastapi.templating import Jinja2Templates

from app.core.config import (
    BASE_DIR,
    MAX_SUPPORT_MESSAGE_LEN,
    MAX_SUPPORT_SUBJECT_LEN,
    TARIFF_PRESETS,
    USER_TARIFF_CHOICES,
)
from app.core.db import get_db_connection
from app.core.security import get_current_user
from app.services.portal import (
    build_activate_link,
    build_plan_change_terms,
    create_referral_invite,
    create_vk_link_code,
    create_vpn_key_on_vps,
    create_yookassa_payment,
    deactivate_user_keys,
    decrease_wallet_balance,
    fetch_yookassa_payment_status,
    format_support_status,
    get_or_create_wallet_balance,
    get_user_invite_stats,
    get_vk_bot_link,
    get_vk_link_by_portal_user,
    increase_wallet_balance,
    revoke_vpn_key_on_vps,
    unlink_vk_by_portal_user,
    utcnow,
    yookassa_enabled,
)

router = APIRouter()
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, success: str = "", error: str = ""):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    with get_db_connection() as con:
        stats = con.execute(
            (
                "SELECT s.plan, s.title, s.key_limit, s.active_until, COALESCE(k.active_keys, 0) AS active_keys "
                "FROM subscriptions s "
                "LEFT JOIN ("
                "SELECT telegram_id, COUNT(*) AS active_keys FROM vpn_keys WHERE revoked_at IS NULL GROUP BY telegram_id"
                ") k ON k.telegram_id = s.telegram_id "
                "WHERE s.telegram_id = ?"
            ),
            (user["telegram_id"],),
        ).fetchone()
        if stats and stats["active_until"]:
            active_until = datetime.fromisoformat(stats["active_until"])
            if active_until <= utcnow():
                deactivate_user_keys(con, user["telegram_id"])
                con.commit()
        keys = con.execute(
            (
                "SELECT id, kind, title, payload, created_at "
                "FROM vpn_keys WHERE telegram_id = ? AND revoked_at IS NULL "
                "ORDER BY created_at DESC"
            ),
            (user["telegram_id"],),
        ).fetchall()
        balance_rub = get_or_create_wallet_balance(con, user["telegram_id"])
        support_tickets = con.execute(
            (
                "SELECT id, status, subject, category, priority, created_at, updated_at, closed_at, rating, feedback "
                "FROM support_tickets WHERE telegram_id = ? ORDER BY id DESC LIMIT 20"
            ),
            (user["telegram_id"],),
        ).fetchall()
        support_messages = con.execute(
            (
                "SELECT m.ticket_id, m.sender_role, m.text, m.created_at, u.login AS admin_login "
                "FROM support_messages m "
                "LEFT JOIN portal_users u ON u.id = m.sender_id "
                "WHERE m.telegram_id = ? "
                "ORDER BY m.id ASC"
            ),
            (user["telegram_id"],),
        ).fetchall()
        vk_link = get_vk_link_by_portal_user(con, int(user["id"]))
        referral_stats = get_user_invite_stats(con, int(user["id"]))
        invite_list = con.execute(
            (
                "SELECT invite_code, created_at, used_at "
                "FROM portal_invites WHERE invited_by_user_id = ? "
                "ORDER BY datetime(created_at) DESC"
            ),
            (user["id"],),
        ).fetchall()
        con.commit()

    referral_invites = [
        {
            "invite_code": inv["invite_code"],
            "activate_link": build_activate_link(inv["invite_code"]),
            "created_at": inv["created_at"],
            "used_at": inv["used_at"],
        }
        for inv in invite_list
    ]

    support_messages_by_ticket: dict[int, list[sqlite3.Row]] = {}
    for msg in support_messages:
        support_messages_by_ticket.setdefault(int(msg["ticket_id"]), []).append(msg)

    days_left = 0
    active_until_display = None
    if stats and stats["active_until"]:
        active_until = datetime.fromisoformat(stats["active_until"])
        delta_seconds = (active_until - utcnow()).total_seconds()
        if delta_seconds > 0:
            days_left = int((delta_seconds - 1) // 86400) + 1
        active_until_display = active_until.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "user": user,
            "stats": stats,
            "days_left": days_left,
            "active_until_display": active_until_display,
            "balance_rub": balance_rub,
            "keys": keys,
            "tariff_choices": {key: TARIFF_PRESETS[key] for key in USER_TARIFF_CHOICES},
            "yookassa_enabled": yookassa_enabled(),
            "success": success,
            "error": error,
            "support_tickets": support_tickets,
            "support_messages_by_ticket": support_messages_by_ticket,
            "support_status_label": format_support_status,
            "vk_bot_link": get_vk_bot_link(),
            "vk_linked": vk_link is not None,
            "invite_list": invite_list,
            "referral_invites": referral_invites,
            "referral_stats": referral_stats,
            "invite_limit_reached": int(referral_stats["available"] or 0) >= 10,
        },
    )

@router.post("/dashboard/referral-invite")
async def dashboard_create_referral_invite(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    with get_db_connection() as con:
        stats = get_user_invite_stats(con, int(user["id"]))
        if int(stats["available"] or 0) >= 10:
            return RedirectResponse(
                "/dashboard?error=У+вас+уже+есть+10+неиспользованных+инвайт-ссылок.+Отправьте+одну+из+них+другу+или+дождитесь+её+использования.",
                status_code=303,
            )
        referral = create_referral_invite(con, int(user["id"]))
        con.execute(
            "UPDATE user_referrals SET invite_code = ?, created_at = ? WHERE referrer_user_id = ?",
            (referral["invite_code"], referral["created_at"], user["id"]),
        )
        if con.total_changes == 0:
            con.execute(
                "INSERT INTO user_referrals (referrer_user_id, invite_code, created_at) VALUES (?, ?, ?)",
                (user["id"], referral["invite_code"], referral["created_at"]),
            )
        con.commit()

    return RedirectResponse("/dashboard?success=Новая+инвайт-ссылка+создана", status_code=303)

@router.post("/dashboard/vk-link")
async def dashboard_vk_link(request: Request):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"ok": False, "error": "Требуется авторизация."}, status_code=401)

    with get_db_connection() as con:
        existing_link = get_vk_link_by_portal_user(con, int(user["id"]))
        if existing_link:
            return JSONResponse(
                {"ok": False, "error": "К этому аккаунту уже привязан ВК."},
                status_code=409,
            )

        code = create_vk_link_code(con, int(user["id"]), int(user["telegram_id"]))
        con.commit()

    return JSONResponse({"ok": True, "code": code, "vk_bot_link": get_vk_bot_link()})


@router.post("/dashboard/vk-unlink")
async def dashboard_vk_unlink(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    with get_db_connection() as con:
        unlinked = unlink_vk_by_portal_user(con, int(user["id"]))
        con.commit()

    if unlinked:
        return RedirectResponse(
            "/dashboard?success=Бот+VK+успешно+отвязан",
            status_code=303,
        )
    return RedirectResponse(
        "/dashboard?error=VK+уже+не+привязан",
        status_code=303,
    )

@router.post("/dashboard/change-plan")
async def dashboard_change_plan(
    request: Request,
    plan_key: str = Form(...),
    comment: str = Form(""),
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    preset = TARIFF_PRESETS.get(plan_key)
    if not preset or plan_key not in USER_TARIFF_CHOICES:
        return RedirectResponse("/dashboard?error=Неизвестный+тариф", status_code=303)
    user_comment = comment.strip()
    if len(user_comment) > MAX_SUPPORT_MESSAGE_LEN:
        return RedirectResponse("/dashboard?error=Комментарий+слишком+длинный", status_code=303)

    now = utcnow().isoformat()
    subject = f"Смена тарифа на {preset['title']}"
    base_message = (
        f"Прошу сменить мой тариф на: {preset['title']}.\n"
        f"Текущий запрос создан из личного кабинета."
    )
    if user_comment:
        base_message += f"\n\nКомментарий пользователя:\n{user_comment}"
    with get_db_connection() as con:
        ticket_cursor = con.execute(
            (
                "INSERT INTO support_tickets "
                "(telegram_id, status, subject, category, priority, created_at, updated_at, closed_at, rating, feedback) "
                "VALUES (?, 'open', ?, 'billing', 'normal', ?, ?, NULL, NULL, NULL)"
            ),
            (user["telegram_id"], subject, now, now),
        )
        ticket_id = ticket_cursor.lastrowid
        con.execute(
            (
                "INSERT INTO support_messages "
                "(ticket_id, telegram_id, sender_role, sender_id, text, created_at) "
                "VALUES (?, ?, 'user', ?, ?, ?)"
            ),
            (ticket_id, user["telegram_id"], user["id"], base_message, now),
        )
        con.commit()

    success = quote_plus("Заявка на смену тарифа отправлена в поддержку")
    return RedirectResponse(f"/dashboard?success={success}", status_code=303)


@router.post("/dashboard/subscription")
async def dashboard_subscription_action(request: Request, action: str = Form(...)):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    now = utcnow()
    with get_db_connection() as con:
        subscription = con.execute(
            "SELECT * FROM subscriptions WHERE telegram_id = ?",
            (user["telegram_id"],),
        ).fetchone()
        if not subscription:
            return RedirectResponse("/dashboard?error=Подписка+не+найдена", status_code=303)

        if action == "renew":
            if not yookassa_enabled():
                return RedirectResponse("/dashboard?error=ЮKassa+не+настроена,+обратитесь+к+администратору", status_code=303)
            price_rub = int(subscription["price_rub"] or 0)
            if price_rub <= 0:
                return RedirectResponse("/dashboard?error=Не+получилось+определить+стоимость+тарифа", status_code=303)
            wallet_balance = get_or_create_wallet_balance(con, user["telegram_id"])
            if wallet_balance >= price_rub and decrease_wallet_balance(con, user["telegram_id"], price_rub):
                active_until = datetime.fromisoformat(subscription["active_until"])
                base = active_until if active_until > now else now
                new_active_until = base + timedelta(days=SUBSCRIPTION_RENEW_DAYS)
                con.execute(
                    "UPDATE subscriptions SET active_until = ? WHERE telegram_id = ?",
                    (new_active_until.isoformat(), user["telegram_id"]),
                )
                con.commit()
                return RedirectResponse(
                    "/dashboard?success=Подписка+продлена.+Оплачено+с+внутреннего+баланса",
                    status_code=303,
                )
            try:
                payment_id, confirmation_url = create_yookassa_payment(
                    amount_rub=price_rub,
                    description=f"Продление подписки {subscription['title'] or subscription['plan']}",
                    metadata={
                        "telegram_id": str(user["telegram_id"]),
                        "action": "renew",
                    },
                )
            except RuntimeError:
                return RedirectResponse("/dashboard?error=Не+удалось+создать+платеж+в+ЮKassa", status_code=303)

            now_iso = now.isoformat()
            con.execute(
                (
                    "INSERT INTO payments "
                    "(telegram_id, payment_id, amount, plan, key_limit, price_rub, title, status, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)"
                ),
                (
                    user["telegram_id"],
                    payment_id,
                    price_rub,
                    subscription["plan"],
                    subscription["key_limit"],
                    subscription["price_rub"],
                    subscription["title"],
                    now_iso,
                ),
            )
            con.execute(
                (
                    "INSERT INTO payment_actions "
                    "(payment_id, telegram_id, action, target_plan_key, amount_rub, status, created_at, updated_at) "
                    "VALUES (?, ?, 'renew', NULL, ?, 'pending', ?, ?)"
                ),
                (payment_id, user["telegram_id"], price_rub, now_iso, now_iso),
            )
            con.commit()
            return RedirectResponse(confirmation_url, status_code=303)

        if action == "cancel":
            active_until = datetime.fromisoformat(subscription["active_until"])
            refund_rub = 0
            if active_until > now and (subscription["price_rub"] or 0) > 0:
                remaining_seconds = (active_until - now).total_seconds()
                refund_rub = int((subscription["price_rub"] * remaining_seconds) / (SUBSCRIPTION_RENEW_DAYS * 86400))
                if refund_rub < 0:
                    refund_rub = 0
            if refund_rub > 0:
                increase_wallet_balance(con, user["telegram_id"], refund_rub)
            _, failed_revocations = deactivate_user_keys(con, user["telegram_id"])
            con.execute(
                "UPDATE subscriptions SET active_until = ? WHERE telegram_id = ?",
                (now.isoformat(), user["telegram_id"]),
            )
            con.commit()
            if failed_revocations > 0:
                return RedirectResponse(
                    f"/dashboard?success=Подписка+отключена.+{refund_rub}+₽+вернули+на+внутренний+баланс&error=Часть+ключей+не+удалось+отозвать+на+VPS,+но+в+портале+они+деактивированы",
                    status_code=303,
                )
            return RedirectResponse(
                f"/dashboard?success=Подписка+отключена.+{refund_rub}+₽+вернули+на+внутренний+баланс",
                status_code=303,
            )

    return RedirectResponse("/dashboard?error=Неизвестное+действие", status_code=303)

@router.get("/dashboard/payment/return")
async def dashboard_payment_return(request: Request, payment_id: str = ""):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not payment_id:
        return RedirectResponse("/dashboard?error=Платеж+не+найден", status_code=303)

    with get_db_connection() as con:
        action_row = con.execute(
            "SELECT * FROM payment_actions WHERE payment_id = ? AND telegram_id = ? AND status = 'pending'",
            (payment_id, user["telegram_id"]),
        ).fetchone()
        if not action_row:
            return RedirectResponse("/dashboard?error=Платеж+уже+обработан+или+недоступен", status_code=303)
        try:
            payment_status = fetch_yookassa_payment_status(payment_id)
        except RuntimeError:
            return RedirectResponse("/dashboard?error=Не+удалось+проверить+статус+платежа", status_code=303)

        if payment_status != "succeeded":
            con.execute(
                "UPDATE payments SET status = ? WHERE payment_id = ?",
                (payment_status or "canceled", payment_id),
            )
            con.execute(
                "UPDATE payment_actions SET status = ?, updated_at = ? WHERE payment_id = ?",
                ("failed", utcnow().isoformat(), payment_id),
            )
            con.commit()
            return RedirectResponse("/dashboard?error=Платеж+не+завершен", status_code=303)

        now = utcnow()
        if action_row["action"] == "renew":
            subscription = con.execute(
                "SELECT active_until FROM subscriptions WHERE telegram_id = ?",
                (user["telegram_id"],),
            ).fetchone()
            if not subscription:
                return RedirectResponse("/dashboard?error=Подписка+не+найдена", status_code=303)
            active_until = datetime.fromisoformat(subscription["active_until"])
            base = active_until if active_until > now else now
            new_active_until = base + timedelta(days=SUBSCRIPTION_RENEW_DAYS)
            con.execute(
                "UPDATE subscriptions SET active_until = ? WHERE telegram_id = ?",
                (new_active_until.isoformat(), user["telegram_id"]),
            )
        elif action_row["action"] == "change_plan":
            plan_key = action_row["target_plan_key"]
            preset = TARIFF_PRESETS.get(plan_key)
            if not preset:
                return RedirectResponse("/dashboard?error=Неизвестный+тариф+в+платеже", status_code=303)
            current_subscription = con.execute(
                "SELECT plan, price_rub, active_until FROM subscriptions WHERE telegram_id = ?",
                (user["telegram_id"],),
            ).fetchone()
            if current_subscription and current_subscription["plan"] == preset["plan"]:
                active_until = datetime.fromisoformat(current_subscription["active_until"])
                base = active_until if active_until > now else now
                new_active_until = base + timedelta(days=SUBSCRIPTION_RENEW_DAYS)
            else:
                _, _, wallet_credit_rub, new_active_until = build_plan_change_terms(
                    current_subscription,
                    int(preset["price_rub"]),
                    now,
                )
                if wallet_credit_rub > 0:
                    increase_wallet_balance(con, user["telegram_id"], wallet_credit_rub)
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
                    new_active_until.isoformat(),
                    preset["plan"],
                    preset["key_limit"],
                    preset["price_rub"],
                    preset["title"],
                ),
            )
        else:
            return RedirectResponse("/dashboard?error=Неизвестное+действие+платежа", status_code=303)

        now_iso = now.isoformat()
        con.execute("UPDATE payments SET status = 'succeeded' WHERE payment_id = ?", (payment_id,))
        con.execute(
            "UPDATE payment_actions SET status = 'applied', updated_at = ? WHERE payment_id = ?",
            (now_iso, payment_id),
        )
        con.commit()
    return RedirectResponse("/dashboard?success=Платеж+подтвержден,+изменения+применены", status_code=303)


@router.post("/dashboard/create-key")
async def dashboard_create_key(request: Request, key_kind: str = Form(...), key_title: str = Form("")):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    key_kind = key_kind.strip().lower()
    if key_kind not in {"awg", "xray"}:
        return RedirectResponse("/dashboard?error=Неизвестный+тип+ключа", status_code=303)

    now = utcnow()
    with get_db_connection() as con:
        stats = con.execute(
            (
                "SELECT s.active_until, s.key_limit, COALESCE(k.active_keys, 0) AS active_keys "
                "FROM subscriptions s "
                "LEFT JOIN ("
                "SELECT telegram_id, COUNT(*) AS active_keys FROM vpn_keys WHERE revoked_at IS NULL GROUP BY telegram_id"
                ") k ON k.telegram_id = s.telegram_id "
                "WHERE s.telegram_id = ?"
            ),
            (user["telegram_id"],),
        ).fetchone()
        if not stats:
            return RedirectResponse("/dashboard?error=Сначала+подключите+подписку", status_code=303)

        active_until = datetime.fromisoformat(stats["active_until"])
        if active_until <= now:
            deactivate_user_keys(con, user["telegram_id"])
            con.commit()
            return RedirectResponse("/dashboard?error=Подписка+истекла,+продлите+ее", status_code=303)
        if stats["active_keys"] >= (stats["key_limit"] or 0):
            return RedirectResponse("/dashboard?error=Достигнут+лимит+ключей+для+тарифа", status_code=303)

        title = key_title.strip() or f"{'Amnezia WG' if key_kind == 'awg' else 'XRay'} ключ"
        created_at = now.isoformat()
        try:
            payload, vps_id, peer_pub, peer_ip = create_vpn_key_on_vps(
                kind=key_kind,
                title=title,
                telegram_id=user["telegram_id"],
            )
        except RuntimeError as exc:
            return RedirectResponse(f"/dashboard?error={str(exc).replace(' ', '+')}", status_code=303)
        con.execute(
            (
                "INSERT INTO vpn_keys "
                "(telegram_id, kind, title, payload, created_at, revoked_at, vps_id, peer_pub, peer_ip) "
                "VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?)"
            ),
            (user["telegram_id"], key_kind, title, payload, created_at, vps_id, peer_pub, peer_ip),
        )
        con.commit()

    return RedirectResponse("/dashboard?success=Ключ+успешно+создан", status_code=303)

@router.post("/dashboard/keys/{key_id}/rename")
async def dashboard_rename_key(request: Request, key_id: int, key_title: str = Form(...)):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    key_title = key_title.strip()
    if not key_title:
        return RedirectResponse("/dashboard?error=Название+ключа+не+может+быть+пустым", status_code=303)

    with get_db_connection() as con:
        updated = con.execute(
            "UPDATE vpn_keys SET title = ? WHERE id = ? AND telegram_id = ? AND revoked_at IS NULL",
            (key_title, key_id, user["telegram_id"]),
        ).rowcount
        con.commit()
    if not updated:
        return RedirectResponse("/dashboard?error=Ключ+не+найден+или+уже+удален", status_code=303)
    return RedirectResponse("/dashboard?success=Название+ключа+обновлено", status_code=303)


@router.post("/dashboard/keys/{key_id}/delete")
async def dashboard_delete_key(request: Request, key_id: int):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    with get_db_connection() as con:
        key = con.execute(
            (
                "SELECT id, kind, vps_id, peer_pub, peer_ip "
                "FROM vpn_keys "
                "WHERE id = ? AND telegram_id = ? AND revoked_at IS NULL"
            ),
            (key_id, user["telegram_id"]),
        ).fetchone()
    if not key:
        return RedirectResponse("/dashboard?error=Ключ+не+найден+или+уже+удален", status_code=303)

    try:
        revoke_vpn_key_on_vps(
            kind=key["kind"],
            vps_id=key["vps_id"],
            peer_pub=key["peer_pub"],
            peer_ip=key["peer_ip"],
        )
    except Exception as exc:
        return RedirectResponse(f"/dashboard?error={quote_plus(str(exc))}", status_code=303)

    with get_db_connection() as con:
        updated = con.execute(
            "UPDATE vpn_keys SET revoked_at = ? WHERE id = ? AND telegram_id = ? AND revoked_at IS NULL",
            (utcnow().isoformat(), key_id, user["telegram_id"]),
        ).rowcount
        con.commit()
    if not updated:
        return RedirectResponse("/dashboard?error=Ключ+не+найден+или+уже+удален", status_code=303)
    return RedirectResponse("/dashboard?success=Ключ+удален", status_code=303)


@router.get("/dashboard/keys/{key_id}/download")
async def dashboard_download_key(request: Request, key_id: int):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    with get_db_connection() as con:
        key = con.execute(
            (
                "SELECT id, kind, title, payload "
                "FROM vpn_keys "
                "WHERE id = ? AND telegram_id = ? AND revoked_at IS NULL"
            ),
            (key_id, user["telegram_id"]),
        ).fetchone()

    if not key:
        return RedirectResponse("/dashboard?error=Ключ+не+найден+или+уже+удален", status_code=303)

    safe_title = "".join(
        ch
        for ch in (key["title"] or "vpn_key")
        if (ch.isascii() and ch.isalnum()) or ch in ("-", "_")
    ).strip("_")
    if not safe_title:
        safe_title = "vpn_key"
    filename = f"{safe_title}_{key['id']}.conf"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return Response(content=key["payload"], media_type="application/octet-stream", headers=headers)


@router.post("/dashboard/support/tickets")
async def dashboard_support_create_ticket(
    request: Request,
    subject: str = Form(...),
    category: str = Form("general"),
    priority: str = Form("normal"),
    message: str = Form(...),
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    subject = subject.strip()
    message = message.strip()
    category = category.strip().lower() or "general"
    priority = priority.strip().lower() or "normal"
    if category not in {"general", "billing", "technical", "access"}:
        return RedirectResponse("/dashboard?error=Неизвестная+категория+обращения", status_code=303)
    if priority not in {"low", "normal", "high"}:
        return RedirectResponse("/dashboard?error=Неизвестный+приоритет+обращения", status_code=303)
    if not subject:
        return RedirectResponse("/dashboard?error=Тема+обращения+не+может+быть+пустой", status_code=303)
    if len(subject) > MAX_SUPPORT_SUBJECT_LEN:
        return RedirectResponse("/dashboard?error=Тема+обращения+слишком+длинная", status_code=303)
    if not message:
        return RedirectResponse("/dashboard?error=Сообщение+в+поддержку+не+может+быть+пустым", status_code=303)
    if len(message) > MAX_SUPPORT_MESSAGE_LEN:
        return RedirectResponse("/dashboard?error=Слишком+длинное+сообщение+в+поддержку", status_code=303)

    now = utcnow().isoformat()
    with get_db_connection() as con:
        ticket_cursor = con.execute(
            (
                "INSERT INTO support_tickets "
                "(telegram_id, status, subject, category, priority, created_at, updated_at, closed_at, rating, feedback) "
                "VALUES (?, 'open', ?, ?, ?, ?, ?, NULL, NULL, NULL)"
            ),
            (user["telegram_id"], subject, category, priority, now, now),
        )
        ticket_id = ticket_cursor.lastrowid
        con.execute(
            (
                "INSERT INTO support_messages "
                "(ticket_id, telegram_id, sender_role, sender_id, text, created_at) "
                "VALUES (?, ?, 'user', ?, ?, ?)"
            ),
            (ticket_id, user["telegram_id"], user["id"], message, now),
        )
        con.commit()

    return RedirectResponse("/dashboard?success=Обращение+в+поддержку+создано", status_code=303)


@router.get("/dashboard/support/tickets")
async def dashboard_support_tickets_redirect(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return RedirectResponse("/dashboard", status_code=303)


@router.post("/dashboard/support/tickets/{ticket_id}/reply")
async def dashboard_support_reply(request: Request, ticket_id: int, message: str = Form(...)):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    message = message.strip()
    if not message:
        return RedirectResponse("/dashboard?error=Сообщение+не+может+быть+пустым", status_code=303)
    if len(message) > MAX_SUPPORT_MESSAGE_LEN:
        return RedirectResponse("/dashboard?error=Слишком+длинное+сообщение+в+поддержку", status_code=303)
    now = utcnow().isoformat()
    with get_db_connection() as con:
        ticket = con.execute(
            "SELECT id, status FROM support_tickets WHERE id = ? AND telegram_id = ?",
            (ticket_id, user["telegram_id"]),
        ).fetchone()
        if not ticket:
            return RedirectResponse("/dashboard?error=Обращение+не+найдено", status_code=303)
        if ticket["status"] == "closed":
            return RedirectResponse("/dashboard?error=Обращение+закрыто,+создайте+новое", status_code=303)
        con.execute(
            (
                "INSERT INTO support_messages "
                "(ticket_id, telegram_id, sender_role, sender_id, text, created_at) "
                "VALUES (?, ?, 'user', ?, ?, ?)"
            ),
            (ticket_id, user["telegram_id"], user["id"], message, now),
        )
        con.execute(
            "UPDATE support_tickets SET status = 'open', updated_at = ? WHERE id = ?",
            (now, ticket_id),
        )
        con.commit()
    return RedirectResponse("/dashboard?success=Ответ+в+обращение+отправлен", status_code=303)


@router.post("/dashboard/support/tickets/{ticket_id}/close")
async def dashboard_support_close_ticket(request: Request, ticket_id: int):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    now = utcnow().isoformat()
    with get_db_connection() as con:
        updated = con.execute(
            (
                "UPDATE support_tickets "
                "SET status = 'closed', closed_at = ?, updated_at = ? "
                "WHERE id = ? AND telegram_id = ? AND status != 'closed'"
            ),
            (now, now, ticket_id, user["telegram_id"]),
        ).rowcount
        con.commit()
    if not updated:
        return RedirectResponse("/dashboard?error=Обращение+не+найдено+или+уже+закрыто", status_code=303)
    return RedirectResponse("/dashboard?success=Обращение+закрыто", status_code=303)


@router.post("/dashboard/support/tickets/{ticket_id}/rate")
async def dashboard_support_rate_ticket(
    request: Request,
    ticket_id: int,
    rating: int = Form(...),
    feedback: str = Form(""),
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if rating < 1 or rating > 5:
        return RedirectResponse("/dashboard?error=Оценка+должна+быть+от+1+до+5", status_code=303)
    feedback = feedback.strip()
    if len(feedback) > MAX_SUPPORT_MESSAGE_LEN:
        return RedirectResponse("/dashboard?error=Комментарий+к+оценке+слишком+длинный", status_code=303)

    with get_db_connection() as con:
        updated = con.execute(
            (
                "UPDATE support_tickets "
                "SET rating = ?, feedback = COALESCE(NULLIF(?, ''), feedback) "
                "WHERE id = ? AND telegram_id = ? AND status = 'closed'"
            ),
            (rating, feedback, ticket_id, user["telegram_id"]),
        ).rowcount
        con.commit()
    if not updated:
        return RedirectResponse("/dashboard?error=Оценку+можно+оставить+только+для+закрытого+обращения", status_code=303)
    return RedirectResponse("/dashboard?success=Спасибо+за+оценку+поддержки", status_code=303)


