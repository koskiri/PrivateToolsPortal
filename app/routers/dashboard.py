from __future__ import annotations

import html
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl, quote_plus, urlencode, urlsplit, urlunsplit

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response, JSONResponse
from fastapi.templating import Jinja2Templates

from app.core.config import (
    APP_BASE_URL_ENV,
    BASE_DIR,
    MAX_SUPPORT_MESSAGE_LEN,
    MAX_SUPPORT_SUBJECT_LEN,
    SPONSOR_UPGRADE_ACTION,
    SPONSOR_UPGRADE_AMOUNT_RUB,
    SPONSOR_UPGRADE_DESCRIPTION,
    SUBSCRIPTION_RENEW_DAYS,
    TARIFF_PRESETS,
    USER_TARIFF_CHOICES,
)
from app.core.db import get_db_connection
from app.core.security import get_current_user
from app.services.portal import (
    build_activate_link,
    build_sponsor_referral_link,
    apply_sponsor_upgrade,
    build_plan_change_terms,
    create_referral_invite,
    ensure_sponsor_referral_code,
    get_or_create_invite_for_referral_code,
    create_vk_link_code,
    create_vpn_key_on_vps,
    create_yookassa_payment,
    deactivate_user_keys,
    decrease_wallet_balance,
    fetch_yookassa_payment_status,
    format_support_status,
    get_user_role_label,
    get_or_create_wallet_balance,
    get_user_invite_stats,
    get_vk_bot_link,
    get_vk_link_by_portal_user,
    increase_wallet_balance,
    is_sponsor_role,
    revoke_referral_invite,
    revoke_vpn_key_on_vps,
    unlink_vk_by_portal_user,
    utcnow,
    yookassa_enabled,
)

router = APIRouter()
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

TELEGRAM_SUPPORT_LINK = "https://t.me/OnlyUs_Support"

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
                "FROM portal_invites WHERE invited_by_user_id = ? AND revoked_at IS NULL "
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

    role_label = get_user_role_label(user["role"] if "role" in user.keys() else None)

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
            "role_label": role_label,
            "is_sponsor": is_sponsor,
        },
    )

CONNECTION_DEVICES = ("Android", "Windows", "iPhone / macOS")
APPLE_CONNECTION_DEVICE = "iphone_macos"
APPLE_CONNECTION_LABEL = "iPhone / macOS"


def _normalize_connection_device(device: str | None) -> str:
    raw_device = (device or "").strip()
    value = raw_device.lower().replace(" ", "").replace("_", "").replace("/", "")
    if value in {"android", "андроид"}:
        return "android"
    if value in {"windows", "win", "виндовс"}:
        return "windows"
    if value in {
        "iphone",
        "ios",
        "айфон",
        "macos",
        "macoc",
        "mac",
        "macosx",
        "мак",
        "макос",
        "apple",
        "iphonemacos",
        "iosmacos",
    }:
        return APPLE_CONNECTION_DEVICE
    return "android"


def _issuer_connection_device(device: str) -> str:
    if device == APPLE_CONNECTION_DEVICE:
        return "iphone"
    return device


def _display_connection_device(device: str) -> str:
    return {
        "android": "Android",
        "windows": "Windows",
        APPLE_CONNECTION_DEVICE: APPLE_CONNECTION_LABEL,
        "iphone": APPLE_CONNECTION_LABEL,
        "macos": APPLE_CONNECTION_LABEL,
    }.get(device, "Android")

def _device_from_key_title(title: str | None) -> str:
    value = (title or "").strip().lower()
    if value.startswith("android") or "android" in value:
        return "Android"
    if value.startswith("windows") or "win" in value:
        return "Windows"
    if (
        value.startswith("iphone / macos")
        or value.startswith("iphone")
        or value.startswith("macos")
        or value.startswith("mac os")
        or "ios" in value
        or "айфон" in value
        or "mac" in value
    ):
        return APPLE_CONNECTION_LABEL
    return "Android"

def _protocol_label_for_profile(kind: str | None, device: str) -> str:
    if kind == "awg":
        return "WG"
    if device == APPLE_CONNECTION_LABEL:
        return "Reality + WS"
    return "Reality"

def _profile_title_from_key_title(title: str | None, device: str) -> str:
    value = (title or "").strip()
    if not value:
        return "Профиль подключения"

    separators = (" · ", " - ", " — ", ": ")
    device_prefixes = (device, "iPhone", "macOS", "Android", "Windows")
    for device_prefix in device_prefixes:
        for separator in separators:
            prefix = f"{device_prefix}{separator}"
            if value.lower().startswith(prefix.lower()):
                value = value[len(prefix):].strip()
                break
        else:
            continue
        break

    protocol_prefixes = (
        "Reality + WS · ",
        "Reality + WS - ",
        "Reality + WS — ",
        "Reality + WS: ",
        "Reality · ",
        "Reality - ",
        "Reality — ",
        "Reality: ",
        "WG · ",
        "WG - ",
        "WG — ",
        "WG: ",
        "WireGuard · ",
        "WireGuard - ",
        "WireGuard — ",
        "WireGuard: ",
        "VLESS ",
        "Vless ",
        "vless ",
    )
    for prefix in protocol_prefixes:
        if value.lower().startswith(prefix.lower()):
            value = value[len(prefix):].strip()
            break

    return value or "Профиль подключения"

def safe_return_to(value: str | None, default: str = "/dashboard") -> str:
    if not value:
        return default

    parsed = urlsplit(value.strip())
    if parsed.scheme or parsed.netloc or not parsed.path.startswith("/") or parsed.path.startswith("//"):
        return default

    allowed_roots = ("/new-ui", "/dashboard")
    if parsed.path in allowed_roots or any(parsed.path.startswith(f"{root}/") for root in allowed_roots):
        return urlunsplit(("", "", parsed.path, parsed.query, parsed.fragment))

    return default

def _safe_new_ui_redirect(return_to: str | None, fallback: str = "/dashboard") -> str:
    return safe_return_to(return_to, fallback)


def _redirect_with_status(return_to: str | None, status_key: str, message: str, default: str = "/dashboard") -> RedirectResponse:
    redirect_to = safe_return_to(return_to, default)
    parsed = urlsplit(redirect_to)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query.append((status_key, message))
    target = urlunsplit(("", "", parsed.path, urlencode(query), parsed.fragment))
    return RedirectResponse(target, status_code=303)


def _build_inline_qr_svg(payload: str) -> str:
    # Lightweight backend-provided QR placeholder for the modal while keeping the technical payload hidden.
    # The encoded connection string stays in the SVG metadata/title and is never rendered as visible text.
    escaped_payload = html.escape(payload or "")
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 240 240" role="img" '
        'aria-label="QR-код подключения">'
        f'<title>OnlyUs connection QR</title><metadata>{escaped_payload}</metadata>'
        '<rect width="240" height="240" rx="18" fill="#fff"/>'
        '<g fill="#0f172a">'
        '<rect x="20" y="20" width="54" height="54" rx="6"/><rect x="32" y="32" width="30" height="30" rx="3" fill="#fff"/>'
        '<rect x="166" y="20" width="54" height="54" rx="6"/><rect x="178" y="32" width="30" height="30" rx="3" fill="#fff"/>'
        '<rect x="20" y="166" width="54" height="54" rx="6"/><rect x="32" y="178" width="30" height="30" rx="3" fill="#fff"/>'
        '<rect x="94" y="30" width="14" height="14"/><rect x="122" y="30" width="14" height="14"/><rect x="94" y="58" width="14" height="14"/>'
        '<rect x="94" y="94" width="14" height="14"/><rect x="122" y="94" width="14" height="14"/><rect x="150" y="94" width="14" height="14"/><rect x="178" y="94" width="14" height="14"/>'
        '<rect x="86" y="122" width="14" height="14"/><rect x="114" y="122" width="14" height="14"/><rect x="142" y="122" width="14" height="14"/><rect x="198" y="122" width="14" height="14"/>'
        '<rect x="94" y="150" width="14" height="14"/><rect x="122" y="150" width="14" height="14"/><rect x="170" y="150" width="14" height="14"/><rect x="198" y="150" width="14" height="14"/>'
        '<rect x="94" y="178" width="14" height="14"/><rect x="122" y="198" width="14" height="14"/><rect x="150" y="178" width="14" height="14"/><rect x="178" y="198" width="14" height="14"/><rect x="206" y="178" width="14" height="14"/>'
        '</g></svg>'
    )

def _format_new_ui_date(value: str | None) -> str:
    if not value:
        return "—"
    try:
        return datetime.fromisoformat(value).astimezone(timezone.utc).strftime("%d.%m.%Y")
    except ValueError:
        return value[:10]

def _build_sponsor_payment_return_url(request: Request) -> str:
    base_url = (os.getenv(APP_BASE_URL_ENV) or str(request.base_url)).rstrip("/")
    query = urlencode({"return_to": "/new-ui?payment=sponsor"})
    return f"{base_url}/dashboard/payment/return?{query}"


def _safe_payment_return_to(return_to: str) -> str:
    if return_to.startswith("/new-ui"):
        return return_to
    return "/dashboard"


def _apply_payment_action(con: sqlite3.Connection, action_row: sqlite3.Row) -> str | None:
    now = utcnow()
    action = action_row["action"]

    if action == "renew":
        subscription = con.execute(
            "SELECT active_until FROM subscriptions WHERE telegram_id = ?",
            (action_row["telegram_id"],),
        ).fetchone()
        if not subscription:
            return "Подписка+не+найдена"
        active_until = datetime.fromisoformat(subscription["active_until"])
        base = active_until if active_until > now else now
        new_active_until = base + timedelta(days=SUBSCRIPTION_RENEW_DAYS)
        con.execute(
            "UPDATE subscriptions SET active_until = ? WHERE telegram_id = ?",
            (new_active_until.isoformat(), action_row["telegram_id"]),
        )
    elif action == "change_plan":
        plan_key = action_row["target_plan_key"]
        preset = TARIFF_PRESETS.get(plan_key)
        if not preset:
            return "Неизвестный+тариф+в+платеже"
        current_subscription = con.execute(
            "SELECT plan, price_rub, active_until FROM subscriptions WHERE telegram_id = ?",
            (action_row["telegram_id"],),
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
                increase_wallet_balance(con, action_row["telegram_id"], wallet_credit_rub)
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
                action_row["telegram_id"],
                new_active_until.isoformat(),
                preset["plan"],
                preset["key_limit"],
                preset["price_rub"],
                preset["title"],
            ),
        )
    elif action == SPONSOR_UPGRADE_ACTION:
        apply_sponsor_upgrade(con, action_row["telegram_id"], now)
    else:
        return "Неизвестное+действие+платежа"

    now_iso = now.isoformat()
    con.execute("UPDATE payments SET status = 'succeeded' WHERE payment_id = ?", (action_row["payment_id"],))
    con.execute(
        "UPDATE payment_actions SET status = 'applied', updated_at = ? WHERE payment_id = ?",
        (now_iso, action_row["payment_id"]),
    )
    return None




def _get_new_ui_context(request: Request, active_page: str) -> dict | RedirectResponse:
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
        referral_stats = get_user_invite_stats(con, int(user["id"]))
        invite_rows = con.execute(
            (
                "SELECT i.id, i.invite_code, i.created_at, i.used_at, i.revoked_at, u.login AS used_by_login "
                "FROM portal_invites i "
                "LEFT JOIN portal_users u ON u.id = i.used_by_user_id "
                "WHERE i.invited_by_user_id = ? "
                "ORDER BY datetime(i.created_at) DESC"
            ),
            (user["id"],),
        ).fetchall()
        vk_link = get_vk_link_by_portal_user(con, int(user["id"]))
        key_rows = con.execute(
            (
                "SELECT id, kind, title, payload, created_at "
                "FROM vpn_keys WHERE telegram_id = ? AND revoked_at IS NULL "
                "ORDER BY datetime(created_at) DESC"
            ),
            (user["telegram_id"],),
        ).fetchall()

        is_sponsor = is_sponsor_role(user["role"] if "role" in user.keys() else None)
        sponsor_referral_code = ensure_sponsor_referral_code(con, int(user["id"])) if is_sponsor else ""
        con.commit()

    now = utcnow()
    active_until = None
    subscription_active = False
    days_left = 0
    if stats and stats["active_until"]:
        active_until = datetime.fromisoformat(stats["active_until"])
        subscription_active = active_until > now
        if subscription_active:
            days_left = int(((active_until - now).total_seconds() - 1) // 86400) + 1

    total_invites = int(referral_stats["total"] or 0)
    used_invites = int(referral_stats["used"] or 0)
    available_invites = int(referral_stats["available"] or 0)
    role_label = get_user_role_label(user["role"] if "role" in user.keys() else None)

    invite_history = [
        {
            "id": row["id"],
            "user": row["used_by_login"] or ("Отозвано" if row["revoked_at"] else "Ожидает регистрации"),
            "registered_at": _format_new_ui_date(row["used_at"] or row["revoked_at"]),
            "status": "Отозвано" if row["revoked_at"] else ("Активен" if row["used_at"] else "Ожидает"),
            "can_revoke": not row["used_at"] and not row["revoked_at"],
            "invite_code": row["invite_code"],
            "invite_link": "" if row["revoked_at"] else build_activate_link(row["invite_code"]),
        }
        for row in invite_rows
    ]
    primary_invite_link = next(
        (item["invite_link"] for item in invite_history if item["status"] == "Ожидает"),
        "",
    )
    sponsor_referral_link = build_sponsor_referral_link(sponsor_referral_code) if sponsor_referral_code else ""

    connection_devices = tuple(
        {
            "device": device,
            "value": _normalize_connection_device(device),
            "icon": "i" if device == APPLE_CONNECTION_LABEL else device[0],
        }
        for device in CONNECTION_DEVICES
    )
    
    vless_profiles_by_device: dict[str, list[dict]] = {device["device"]: [] for device in connection_devices}
    for row in key_rows:
        kind = (row["kind"] or "").strip().lower()
        if kind not in {"xray", "awg"}:
            continue
        device = _device_from_key_title(row["title"])
        if kind == "awg" and device not in {"Android", "Windows", APPLE_CONNECTION_LABEL}:
            device = "Android"
        profile = {
            "id": row["id"],
            "title": _profile_title_from_key_title(row["title"], device),
            "device": device,
            "kind": kind,
            "protocol_label": _protocol_label_for_profile(kind, device),
            "status": "Готово",
            "link": row["payload"] or "",
            "qr_url": f"https://api.qrserver.com/v1/create-qr-code/?size=260x260&margin=12&data={quote_plus(row['payload'] or '')}",
            "download_url": f"/dashboard/keys/{row['id']}/download",
            "delete_url": f"/dashboard/keys/{row['id']}/delete",
            "created_at": _format_new_ui_date(row["created_at"]),
        }
        vless_profiles_by_device.setdefault(device, []).append(profile)
    connection_device_cards = []
    for device_meta in connection_devices:
        device = device_meta["device"]
        profiles = vless_profiles_by_device.get(device, [])
        connection_device_cards.append({
            "device": device,
            "value": device_meta["value"],
            "icon": device_meta["icon"],
            "hint": "VLESS профиль для приложения VPN",
            "profiles": profiles,
            "ready": bool(profiles),
        })

    connection_profiles = [profile for card in connection_device_cards for profile in card["profiles"]]

    login = user["login"] or ""
    # В portal_users нет отдельных полей email/telegram username; показываем безопасные значения без технических ID.
    profile = {
        "email": login if "@" in login else "Не указан",
        "telegram": "Подключен" if user["telegram_id"] and int(user["telegram_id"]) > 0 else "Не указан",
        "vk": "Подключен" if vk_link else "Не подключен",
    }

    return {
        "user": user,
        "active_page": active_page,
        "stats": stats,
        "subscription": {
            "active": subscription_active,
            "title": (stats["title"] if stats else None) or "Подписка не выбрана",
            "active_until": _format_new_ui_date(active_until.isoformat() if active_until else None),
            "days_left": days_left,
        },
        "role_label": "Спонсор" if is_sponsor else "Пользователь",
        "is_sponsor": is_sponsor,
        "invite_stats": {
            "available": available_invites,
            "used": used_invites,
            "active_users": used_invites,
            "total": total_invites,
        },
        "invite_history": invite_history,
        "primary_invite_link": primary_invite_link,
        "sponsor_referral_link": sponsor_referral_link,
        "sponsor_referral_qr_url": f"https://api.qrserver.com/v1/create-qr-code/?size=260x260&margin=12&data={quote_plus(sponsor_referral_link)}" if sponsor_referral_link else "",
        "invite_limit_reached": available_invites >= 10,
        "profile": profile,
        "vk_bot_link": get_vk_bot_link() or "#",
        "telegram_support_link": TELEGRAM_SUPPORT_LINK,
        "connection_profiles": connection_profiles,
        "connection_device_cards": connection_device_cards,
        "connections_limit": int(stats["key_limit"] or 0) if stats else 0,
        "connections_active": len(connection_profiles),
    }


@router.get("/new-ui", response_class=HTMLResponse)
async def new_ui_dashboard(request: Request):
    context = _get_new_ui_context(request, "dashboard")
    if isinstance(context, RedirectResponse):
        return context
    return templates.TemplateResponse(request=request, name="new/dashboard.html", context=context)


@router.get("/new-ui/invites", response_class=HTMLResponse)
async def new_ui_invites(request: Request):
    context = _get_new_ui_context(request, "invites")
    if isinstance(context, RedirectResponse):
        return context
    return templates.TemplateResponse(request=request, name="new/invites.html", context=context)

@router.get("/r/{referral_code}")
async def sponsor_referral_redirect(referral_code: str):
    with get_db_connection() as con:
        try:
            invite = get_or_create_invite_for_referral_code(con, referral_code.strip())
        except PermissionError as exc:
            return RedirectResponse(f"/login?error={quote_plus(str(exc))}", status_code=303)
        except OverflowError as exc:
            return RedirectResponse(f"/login?error={quote_plus(str(exc))}", status_code=303)
        con.commit()

    return RedirectResponse(f"/activate?code={quote_plus(invite['invite_code'])}", status_code=303)


@router.post("/new-ui/invites/{invite_id}/revoke")
async def new_ui_revoke_invite(request: Request, invite_id: int):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not is_sponsor_role(user["role"] if "role" in user.keys() else None):
        return RedirectResponse("/new-ui/invites?error=Отзывать+приглашения+могут+только+спонсоры", status_code=303)

    with get_db_connection() as con:
        revoked = revoke_referral_invite(con, int(user["id"]), invite_id)
        con.commit()

    if not revoked:
        return RedirectResponse("/new-ui/invites?error=Приглашение+не+найдено,+уже+использовано+или+отозвано", status_code=303)
    return RedirectResponse("/new-ui/invites?success=Приглашение+отозвано", status_code=303)


@router.get("/new-ui/profile", response_class=HTMLResponse)
async def new_ui_profile(request: Request):
    context = _get_new_ui_context(request, "profile")
    if isinstance(context, RedirectResponse):
        return context
    return templates.TemplateResponse(request=request, name="new/profile.html", context=context)

@router.post("/dashboard/sponsor-upgrade")
async def dashboard_sponsor_upgrade(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if is_sponsor_role(user["role"] if "role" in user.keys() else None):
        return RedirectResponse("/new-ui", status_code=303)
    if not yookassa_enabled():
        return RedirectResponse("/new-ui?error=ЮKassa+не+настроена,+обратитесь+к+администратору", status_code=303)

    now_iso = utcnow().isoformat()
    try:
        payment_id, confirmation_url = create_yookassa_payment(
            amount_rub=SPONSOR_UPGRADE_AMOUNT_RUB,
            description=SPONSOR_UPGRADE_DESCRIPTION,
            metadata={
                "telegram_id": str(user["telegram_id"]),
                "action": SPONSOR_UPGRADE_ACTION,
            },
            return_url=_build_sponsor_payment_return_url(request),
        )
    except RuntimeError:
        return RedirectResponse("/new-ui?error=Не+удалось+создать+платеж+в+ЮKassa", status_code=303)

    with get_db_connection() as con:
        con.execute(
            (
                "INSERT INTO payments "
                "(telegram_id, payment_id, amount, plan, key_limit, price_rub, title, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)"
            ),
            (
                user["telegram_id"],
                payment_id,
                SPONSOR_UPGRADE_AMOUNT_RUB,
                SPONSOR_UPGRADE_ACTION,
                0,
                SPONSOR_UPGRADE_AMOUNT_RUB,
                SPONSOR_UPGRADE_DESCRIPTION,
                now_iso,
            ),
        )
        con.execute(
            (
                "INSERT INTO payment_actions "
                "(payment_id, telegram_id, action, target_plan_key, amount_rub, status, created_at, updated_at) "
                "VALUES (?, ?, ?, NULL, ?, 'pending', ?, ?)"
            ),
            (
                payment_id,
                user["telegram_id"],
                SPONSOR_UPGRADE_ACTION,
                SPONSOR_UPGRADE_AMOUNT_RUB,
                now_iso,
                now_iso,
            ),
        )
        con.commit()

    return RedirectResponse(confirmation_url, status_code=303)

@router.post("/dashboard/referral-invite")
async def dashboard_create_referral_invite(request: Request, return_to: str = Form("/dashboard")):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not is_sponsor_role(user["role"] if "role" in user.keys() else None):
        return RedirectResponse(
            f"{_safe_new_ui_redirect(return_to)}?error=Инвайт-ссылки+доступны+только+спонсорам",
            status_code=303,
        )

    with get_db_connection() as con:
        stats = get_user_invite_stats(con, int(user["id"]))
        if int(stats["available"] or 0) >= 10:
            return RedirectResponse(
                f"{_safe_new_ui_redirect(return_to)}?error=У+вас+уже+есть+10+неиспользованных+инвайт-ссылок.+Отправьте+одну+из+них+другу+или+дождитесь+её+использования.",
                status_code=303,
            )
        referral = create_referral_invite(con, int(user["id"]))
        referral_cursor = con.execute(
            "UPDATE user_referrals SET invite_code = ?, created_at = ? WHERE referrer_user_id = ?",
            (referral["invite_code"], referral["created_at"], user["id"]),
        )
        if referral_cursor.rowcount == 0:
            con.execute(
                "INSERT INTO user_referrals (referrer_user_id, invite_code, created_at) VALUES (?, ?, ?)",
                (user["id"], referral["invite_code"], referral["created_at"]),
            )
        con.commit()

    return RedirectResponse(
        f"{_safe_new_ui_redirect(return_to)}?success=Новая+инвайт-ссылка+создана",
        status_code=303,
    )

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

@router.post("/yookassa/webhook")
async def yookassa_webhook(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return {"ok": False}

    payment_object = payload.get("object") or {}
    payment_id = payment_object.get("id")
    event = payload.get("event")

    if not payment_id:
        return {"ok": True}

    with get_db_connection() as con:
        action_row = con.execute(
            "SELECT * FROM payment_actions WHERE payment_id = ?",
            (payment_id,),
        ).fetchone()

        if not action_row:
            return {"ok": True}

        if action_row["status"] == "applied":
            return {"ok": True}

        try:
            payment_status = fetch_yookassa_payment_status(payment_id)
        except RuntimeError:
            return {"ok": False}

        if payment_status != "succeeded":
            con.execute(
                "UPDATE payments SET status = ? WHERE payment_id = ?",
                (payment_status or "pending", payment_id),
            )
            con.commit()
            return {"ok": True}
        apply_error = _apply_payment_action(con, action_row)
        if apply_error:
            return {"ok": False}
        con.commit()

    return {"ok": True}

@router.get("/dashboard/payment/return")
async def dashboard_payment_return(request: Request, payment_id: str = "", return_to: str = ""):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    redirect_to = _safe_payment_return_to(return_to)
    redirect_sep = "&" if "?" in redirect_to else "?"
    if not payment_id:
        with get_db_connection() as con:
            pending_payment = con.execute(
                """
                SELECT payment_id
                FROM payment_actions
                WHERE telegram_id = ? AND status = 'pending'
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (user["telegram_id"],),
            ).fetchone()

        if not pending_payment:
            return RedirectResponse(f"{redirect_to}{redirect_sep}error=Платеж+не+найден", status_code=303)

        payment_id = pending_payment["payment_id"]

    with get_db_connection() as con:
        action_row = con.execute(
            "SELECT * FROM payment_actions WHERE payment_id = ? AND telegram_id = ? AND status = 'pending'",
            (payment_id, user["telegram_id"]),
        ).fetchone()
        if not action_row:
            return RedirectResponse(f"{redirect_to}{redirect_sep}error=Платеж+уже+обработан+или+недоступен", status_code=303)
        try:
            payment_status = fetch_yookassa_payment_status(payment_id)
        except RuntimeError:
            return RedirectResponse(f"{redirect_to}{redirect_sep}error=Не+удалось+проверить+статус+платежа", status_code=303)

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
            return RedirectResponse(f"{redirect_to}{redirect_sep}error=Платеж+не+завершен", status_code=303)

        apply_error = _apply_payment_action(con, action_row)
        if apply_error:
            return RedirectResponse(f"{redirect_to}{redirect_sep}error={apply_error}", status_code=303)
        con.commit()
    return RedirectResponse(f"{redirect_to}{redirect_sep}success=Платеж+подтвержден,+изменения+применены", status_code=303)


@router.post("/dashboard/create-key")
async def dashboard_create_key(
    request: Request,
    key_kind: str = Form(""),
    key_title: str = Form(""),
    return_to: str = Form(""),
    connection_device: str = Form(""),
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    key_kind = key_kind.strip().lower()
    if key_kind == "vless":
        key_kind = "xray"
    if key_kind not in {"awg", "xray"}:
        return _redirect_with_status(return_to, "error", "Неизвестный тип ключа")

    normalized_device = _normalize_connection_device(connection_device)
    issuer_device = _issuer_connection_device(normalized_device)

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
            return _redirect_with_status(return_to, "error", "Сначала подключите подписку")

        active_until = datetime.fromisoformat(stats["active_until"])
        if active_until <= now:
            deactivate_user_keys(con, user["telegram_id"])
            con.commit()
            return _redirect_with_status(return_to, "error", "Подписка истекла, продлите ее")
        if stats["active_keys"] >= (stats["key_limit"] or 0):
            return _redirect_with_status(return_to, "error", "Достигнут лимит ключей для тарифа")

        if key_title.strip():
            title = key_title.strip()
        else:
            protocol_label = "WireGuard" if key_kind == "awg" else "Reality"
            title = f"{_display_connection_device(normalized_device)} · {protocol_label} · профиль"
        created_at = now.isoformat()
        try:
            payload, vps_id, peer_pub, peer_ip = create_vpn_key_on_vps(
                kind=key_kind,
                title=title,
                telegram_id=user["telegram_id"],
                device=issuer_device,
            )
        except RuntimeError as exc:
            return _redirect_with_status(return_to, "error", str(exc))
        con.execute(
            (
                "INSERT INTO vpn_keys "
                "(telegram_id, kind, title, payload, created_at, revoked_at, vps_id, peer_pub, peer_ip) "
                "VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?)"
            ),
            (user["telegram_id"], key_kind, title, payload, created_at, vps_id, peer_pub, peer_ip),
        )
        con.commit()

    return _redirect_with_status(return_to, "success", "Подключение создано")

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
async def dashboard_delete_key(request: Request, key_id: int, return_to: str = Form("")):
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
        return RedirectResponse(f"{_safe_new_ui_redirect(return_to)}?error=Подключение+не+найдено+или+уже+удалено", status_code=303)

    try:
        revoke_vpn_key_on_vps(
            kind=key["kind"],
            vps_id=key["vps_id"],
            peer_pub=key["peer_pub"],
            peer_ip=key["peer_ip"],
        )
    except Exception as exc:
        return RedirectResponse(f"{_safe_new_ui_redirect(return_to)}?error={quote_plus(str(exc))}", status_code=303)

    with get_db_connection() as con:
        updated = con.execute(
            "UPDATE vpn_keys SET revoked_at = ? WHERE id = ? AND telegram_id = ? AND revoked_at IS NULL",
            (utcnow().isoformat(), key_id, user["telegram_id"]),
        ).rowcount
        con.commit()
    if not updated:
        return RedirectResponse(f"{_safe_new_ui_redirect(return_to)}?error=Подключение+не+найдено+или+уже+удалено", status_code=303)
    return RedirectResponse(f"{_safe_new_ui_redirect(return_to)}?success=Подключение+удалено", status_code=303)


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


