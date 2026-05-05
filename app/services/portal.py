from __future__ import annotations

import base64
import json
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib import error as urllib_error
from urllib.parse import quote_plus, urlencode
from urllib import request as urllib_request

from app.core.config import (
    APP_BASE_URL_ENV,
    BASE_DIR,
    MAX_SUPPORT_MESSAGE_LEN,
    SUBSCRIPTION_RENEW_DAYS,
    TARIFF_PRESETS,
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


def build_activate_link(invite_code: str) -> str:
    base_url = (os.getenv(APP_BASE_URL_ENV, "") or "").strip().rstrip("/")
    if not base_url:
        base_url = "http://localhost:8000"
    return f"{base_url}/activate?code={quote_plus(invite_code)}"


def create_referral_invite(con: sqlite3.Connection, user_id: int) -> dict[str, str]:
    code = secrets.token_urlsafe(12)
    now = utcnow().isoformat()
    referral_preset = TARIFF_PRESETS["plan_5"]
    con.execute(
        (
            "INSERT INTO portal_invites "
            "(invite_code, telegram_id, created_at, used_at, plan, title, key_limit, price_rub, duration_days, invited_by_user_id, created_by_user_id) "
            "VALUES (?, NULL, ?, NULL, ?, ?, ?, ?, ?, ?, ?)"
        ),
        (
            code,
            now,
            referral_preset["plan"],
            "Реферальный тариф: 100 ₽ / 30 дней",
            referral_preset["key_limit"],
            referral_preset["price_rub"],
            referral_preset["duration_days"],
            user_id,
            user_id,
        ),
    )
    return {"invite_code": code, "created_at": now}


def get_user_invite_stats(con: sqlite3.Connection, user_id: int) -> sqlite3.Row:
    return con.execute(
        (
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN used_at IS NOT NULL THEN 1 ELSE 0 END) AS used, "
            "SUM(CASE WHEN used_at IS NULL THEN 1 ELSE 0 END) AS available "
            "FROM portal_invites WHERE invited_by_user_id = ?"
        ),
        (user_id,),
    ).fetchone()



















    
def get_or_create_wallet_balance(con: sqlite3.Connection, telegram_id: int) -> int:
    wallet = con.execute(
        "SELECT balance_rub FROM user_wallets WHERE telegram_id = ?",
        (telegram_id,),
    ).fetchone()
    if wallet:
        return int(wallet["balance_rub"] or 0)

    now = utcnow().isoformat()
    con.execute(
        "INSERT INTO user_wallets (telegram_id, balance_rub, updated_at) VALUES (?, 0, ?)",
        (telegram_id, now),
    )
    return 0


def increase_wallet_balance(con: sqlite3.Connection, telegram_id: int, amount_rub: int) -> None:
    current = get_or_create_wallet_balance(con, telegram_id)
    now = utcnow().isoformat()
    con.execute(
        "UPDATE user_wallets SET balance_rub = ?, updated_at = ? WHERE telegram_id = ?",
        (current + amount_rub, now, telegram_id),
    )

def decrease_wallet_balance(con: sqlite3.Connection, telegram_id: int, amount_rub: int) -> bool:
    amount_rub = max(int(amount_rub), 0)
    if amount_rub == 0:
        return True
    current = get_or_create_wallet_balance(con, telegram_id)
    if current < amount_rub:
        return False
    now = utcnow().isoformat()
    con.execute(
        "UPDATE user_wallets SET balance_rub = ?, updated_at = ? WHERE telegram_id = ?",
        (current - amount_rub, now, telegram_id),
    )
    return True

def calculate_unused_subscription_refund(subscription: sqlite3.Row | None, now: datetime) -> int:
    if not subscription or not subscription["active_until"]:
        return 0
    try:
        active_until = datetime.fromisoformat(subscription["active_until"])
    except (TypeError, ValueError):
        return 0
    price_rub = int(subscription["price_rub"] or 0)
    if active_until <= now or price_rub <= 0:
        return 0
    remaining_seconds = (active_until - now).total_seconds()
    refund_rub = int((price_rub * remaining_seconds) / (SUBSCRIPTION_RENEW_DAYS * 86400))
    return max(refund_rub, 0)


def build_plan_change_terms(
    subscription: sqlite3.Row | None,
    target_price_rub: int,
    now: datetime,
) -> tuple[int, int, int, datetime]:
    refund_rub = calculate_unused_subscription_refund(subscription, now)
    amount_due_rub = max(int(target_price_rub) - refund_rub, 0)
    wallet_credit_rub = max(refund_rub - int(target_price_rub), 0)
    base = now
    if subscription and subscription["active_until"]:
        try:
            existing_active_until = datetime.fromisoformat(subscription["active_until"])
        except (TypeError, ValueError):
            existing_active_until = None
        if existing_active_until and existing_active_until > now:
            base = existing_active_until
    new_active_until = base + timedelta(days=SUBSCRIPTION_RENEW_DAYS)
    return amount_due_rub, refund_rub, wallet_credit_rub, new_active_until

def yookassa_enabled() -> bool:
    return bool(os.getenv(YOOKASSA_SHOP_ID_ENV) and os.getenv(YOOKASSA_SECRET_KEY_ENV))


def create_yookassa_payment(amount_rub: int, description: str, metadata: dict[str, str]) -> tuple[str, str]:
    shop_id = os.getenv(YOOKASSA_SHOP_ID_ENV)
    secret_key = os.getenv(YOOKASSA_SECRET_KEY_ENV)
    if not shop_id or not secret_key:
        raise RuntimeError("YooKassa credentials are not configured")

    auth_token = base64.b64encode(f"{shop_id}:{secret_key}".encode("utf-8")).decode("utf-8")
    return_url = os.getenv(YOOKASSA_RETURN_URL_ENV) or "http://localhost:8000/dashboard/payment/return"
    payload = {
        "amount": {"value": f"{amount_rub:.2f}", "currency": "RUB"},
        "capture": True,
        "confirmation": {"type": "redirect", "return_url": return_url},
        "description": description[:128],
        "metadata": metadata,
    }
    req = urllib_request.Request(
        YOOKASSA_API_URL,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Basic {auth_token}",
            "Content-Type": "application/json",
            "Idempotence-Key": str(uuid.uuid4()),
        },
    )
    try:
        with urllib_request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8")
    except urllib_error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"YooKassa payment create failed: {detail}") from exc
    except urllib_error.URLError as exc:
        raise RuntimeError("YooKassa unavailable") from exc

    body = json.loads(raw)
    payment_id = body.get("id")
    confirmation_url = (body.get("confirmation") or {}).get("confirmation_url")
    if not payment_id or not confirmation_url:
        raise RuntimeError("YooKassa returned invalid payment response")
    return payment_id, confirmation_url

def create_vpn_key_on_vps(kind: str, title: str, telegram_id: int) -> tuple[str, Optional[int], Optional[str], Optional[str]]:
    issuer_url = os.getenv(VPS_ISSUER_URL_ENV, "").strip().rstrip("/")
    if not issuer_url:
        raise RuntimeError("Не настроен адрес сервиса выдачи ключей на VPS")

    req = urllib_request.Request(
        f"{issuer_url}/keys",
        data=json.dumps({"kind": kind, "title": title, "telegram_id": telegram_id}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    issuer_token = os.getenv(VPS_ISSUER_TOKEN_ENV, "").strip()
    if issuer_token:
        req.add_header("Authorization", f"Bearer {issuer_token}")

    try:
        with urllib_request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8")
    except urllib_error.HTTPError as exc:
        raise RuntimeError(f"VPS вернул ошибку {exc.code}") from exc
    except urllib_error.URLError as exc:
        raise RuntimeError("Не удалось подключиться к VPS для выдачи ключа") from exc

    try:
        key_data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Сервис VPS вернул некорректный ответ") from exc

    key_payload = (key_data.get("payload") or key_data.get("config") or "").strip()
    if not key_payload:
        raise RuntimeError("Сервис VPS не вернул конфиг ключа")

    vps_id = key_data.get("vps_id")
    if vps_id is not None:
        try:
            vps_id = int(vps_id)
        except (TypeError, ValueError):
            vps_id = None
    return key_payload, vps_id, key_data.get("peer_pub"), key_data.get("peer_ip")


def revoke_vpn_key_on_vps(kind: str, vps_id: Optional[int], peer_pub: Optional[str], peer_ip: Optional[str]) -> None:
    issuer_url = os.getenv(VPS_ISSUER_URL_ENV, "").strip().rstrip("/")
    if not issuer_url:
        # В некоторых окружениях портал работает без issuer-сервиса.
        # Не блокируем удаление ключа в интерфейсе — просто пропускаем отзыв на VPS.
        return
    if vps_id is None:
        # Legacy-ключи могли создаваться без привязки к серверу.
        return
    if not (peer_pub or peer_ip):
        # Для части старых записей нет технических данных для отзыва.
        return

    issuer_token = os.getenv(VPS_ISSUER_TOKEN_ENV, "").strip()
    payload = json.dumps(
        {
            "kind": kind,
            "vps_id": vps_id,
            "peer_pub": peer_pub,
            "peer_ip": peer_ip,
        }
    ).encode("utf-8")
    endpoints = ("/keys/revoke", "/revoke")
    saw_not_found = False

    for endpoint in endpoints:
        req = urllib_request.Request(
            f"{issuer_url}{endpoint}",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        if issuer_token:
            req.add_header("Authorization", f"Bearer {issuer_token}")

        try:
            with urllib_request.urlopen(req, timeout=15):
                return
        except urllib_error.HTTPError as exc:
            # 404 может означать, что endpoint не существует на issuer.
            # Пробуем fallback endpoint, но если оба вернули 404 —
            # считаем отзыв неуспешным и не удаляем ключ только в БД.
            if exc.code == 404:
                saw_not_found = True
                if endpoint != endpoints[-1]:
                    continue
                break
            if endpoint != endpoints[-1]:
                continue
            raise RuntimeError(f"VPS вернул ошибку {exc.code}") from exc
        except urllib_error.URLError as exc:
            raise RuntimeError("Не удалось подключиться к VPS для отзыва ключа") from exc

    if saw_not_found:
        # Некоторые инсталляции issuer работают без endpoint отзыва ключей.
        # В таком случае не блокируем удаление ключа в портале:
        # запись будет помечена удаленной только в локальной БД.
        return


def deactivate_user_keys(con: sqlite3.Connection, telegram_id: int) -> tuple[int, int]:
    active_keys = con.execute(
        "SELECT id, kind, vps_id, peer_pub, peer_ip FROM vpn_keys WHERE telegram_id = ? AND revoked_at IS NULL",
        (telegram_id,),
    ).fetchall()
    if not active_keys:
        return 0, 0

    revoked_ids: list[int] = []
    failed_count = 0
    for key in active_keys:
        try:
            revoke_vpn_key_on_vps(
                kind=key["kind"],
                vps_id=key["vps_id"],
                peer_pub=key["peer_pub"],
                peer_ip=key["peer_ip"],
            )
        except Exception:
            failed_count += 1
        revoked_ids.append(int(key["id"]))

    now_iso = utcnow().isoformat()
    placeholders = ",".join("?" for _ in revoked_ids)
    con.execute(
        f"""
        UPDATE vpn_keys
        SET revoked_at = ?, payload = ''
        WHERE telegram_id = ? AND id IN ({placeholders}) AND revoked_at IS NULL
        """,
        (now_iso, telegram_id, *revoked_ids),
    )
    return len(revoked_ids), failed_count

def format_support_status(status: str) -> str:
    labels = {
        "open": "Открыт",
        "in_progress": "В работе",
        "closed": "Закрыт",
    }
    return labels.get(status, status or "—")



def fetch_yookassa_payment_status(payment_id: str) -> str:
    shop_id = os.getenv(YOOKASSA_SHOP_ID_ENV)
    secret_key = os.getenv(YOOKASSA_SECRET_KEY_ENV)
    if not shop_id or not secret_key:
        raise RuntimeError("YooKassa credentials are not configured")
    auth_token = base64.b64encode(f"{shop_id}:{secret_key}".encode("utf-8")).decode("utf-8")
    req = urllib_request.Request(
        f"{YOOKASSA_API_URL}/{payment_id}",
        method="GET",
        headers={"Authorization": f"Basic {auth_token}"},
    )
    try:
        with urllib_request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8")
    except urllib_error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"YooKassa payment status failed: {detail}") from exc
    except urllib_error.URLError as exc:
        raise RuntimeError("YooKassa unavailable") from exc
    body = json.loads(raw)
    return body.get("status", "")




def get_vk_confirmation_code() -> str:
    return os.getenv(VK_CONFIRMATION_CODE_ENV, "").strip()


def get_vk_secret() -> str:
    return os.getenv(VK_SECRET_ENV, "").strip()

def get_vk_token() -> str:
    return os.getenv(VK_TOKEN_ENV, "").strip()


def get_vk_bot_link() -> str:
    return os.getenv(VK_BOT_LINK_ENV, "").strip()


def get_app_base_url() -> str:
    return os.getenv(APP_BASE_URL_ENV, "").strip().rstrip("/")

def generate_vk_link_code() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(6))


def create_vk_link_code(con: sqlite3.Connection, portal_user_id: int, telegram_id: int) -> str:
    now = utcnow()
    expires_at = now + timedelta(minutes=10)

    # Удаляем старые неиспользованные коды пользователя
    con.execute(
        "DELETE FROM vk_link_codes WHERE portal_user_id = ? AND used_at IS NULL",
        (portal_user_id,),
    )

    code = generate_vk_link_code()
    con.execute(
        (
            "INSERT INTO vk_link_codes "
            "(code, portal_user_id, telegram_id, created_at, expires_at, used_at, vk_user_id) "
            "VALUES (?, ?, ?, ?, ?, NULL, NULL)"
        ),
        (code, portal_user_id, telegram_id, now.isoformat(), expires_at.isoformat()),
    )
    return code


def get_vk_link_by_portal_user(con: sqlite3.Connection, portal_user_id: int) -> Optional[sqlite3.Row]:
    return con.execute(
        "SELECT * FROM vk_links WHERE portal_user_id = ?",
        (portal_user_id,),
    ).fetchone()


def unlink_vk_by_portal_user(con: sqlite3.Connection, portal_user_id: int) -> bool:
    result = con.execute(
        "DELETE FROM vk_links WHERE portal_user_id = ?",
        (portal_user_id,),
    )
    return result.rowcount > 0


def consume_vk_link_code(con: sqlite3.Connection, code: str, vk_user_id: int) -> tuple[bool, str]:
    row = con.execute(
        "SELECT * FROM vk_link_codes WHERE code = ?",
        (code,),
    ).fetchone()

    if not row:
        return False, "Код привязки не найден."

    if row["used_at"] is not None:
        return False, "Этот код уже использован."

    try:
        expires_at = datetime.fromisoformat(row["expires_at"])
    except Exception:
        return False, "Код привязки поврежден."

    if expires_at <= utcnow():
        return False, "Срок действия кода истек. Создайте новый код в кабинете."

    existing_vk = con.execute(
        "SELECT * FROM vk_links WHERE vk_user_id = ?",
        (vk_user_id,),
    ).fetchone()
    if existing_vk:
        return False, "Этот аккаунт ВК уже привязан."

    existing_user_link = con.execute(
        "SELECT * FROM vk_links WHERE portal_user_id = ?",
        (row["portal_user_id"],),
    ).fetchone()
    if existing_user_link:
        return False, "К этому аккаунту сайта уже привязан ВК."

    now_iso = utcnow().isoformat()
    con.execute(
        "INSERT INTO vk_links (vk_user_id, portal_user_id, telegram_id, created_at) VALUES (?, ?, ?, ?)",
        (vk_user_id, row["portal_user_id"], row["telegram_id"], now_iso),
    )
    con.execute(
        "UPDATE vk_link_codes SET used_at = ?, vk_user_id = ? WHERE code = ?",
        (now_iso, vk_user_id, code),
    )
    return True, "Аккаунт ВК успешно привязан."


def vk_api(method: str, payload: dict) -> dict:
    token = get_vk_token()
    if not token:
        raise RuntimeError("VK token is not configured")

    data = dict(payload)
    data["access_token"] = token
    data["v"] = "5.199"

    req = urllib_request.Request(
        f"https://api.vk.com/method/{method}",
        data=urlencode(data).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with urllib_request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8")
    except urllib_error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"VK API HTTP error: {detail}") from exc
    except urllib_error.URLError as exc:
        raise RuntimeError("VK API unavailable") from exc

    body = json.loads(raw)
    if "error" in body:
        raise RuntimeError(f"VK API error: {body['error']}")
    return body.get("response", {})


def send_vk_message(user_id: int, text: str) -> None:
    send_vk_message_with_keyboard(user_id=user_id, text=text, keyboard=None)


def build_vk_keyboard(*, linked: bool) -> str:
    buttons = []
    if linked:
        buttons.append(
            [
                {"action": {"type": "text", "label": "📊 Подписка"}, "color": "primary"},
                {"action": {"type": "text", "label": "🔑 AWG ключ"}, "color": "positive"},
                {"action": {"type": "text", "label": "🔑 XRay ключ"}, "color": "positive"},
            ]
        )
        buttons.append(
            [
                {"action": {"type": "text", "label": "🌐 Кабинет"}, "color": "secondary"},
                {"action": {"type": "text", "label": "❓ Помощь"}, "color": "secondary"},
            ]
        )
    else:
        buttons.append(
            [
                {"action": {"type": "text", "label": "🔗 Привязать аккаунт"}, "color": "primary"},
                {"action": {"type": "text", "label": "🌐 Кабинет"}, "color": "secondary"},
            ]
        )
        buttons.append(
            [
                {"action": {"type": "text", "label": "❓ Помощь"}, "color": "secondary"},
            ]
        )
    return json.dumps({"one_time": False, "buttons": buttons}, ensure_ascii=False)


def send_vk_message_with_keyboard(user_id: int, text: str, keyboard: Optional[str]) -> None:
    payload = {
        "user_id": user_id,
        "random_id": secrets.randbelow(2_147_483_647),
        "message": text[:4000],
    }
    if keyboard:
        payload["keyboard"] = keyboard
    vk_api(
        "messages.send",
        payload,
    )


def get_vk_linked_account(con: sqlite3.Connection, vk_user_id: int) -> Optional[sqlite3.Row]:
    return con.execute(
        (
            "SELECT l.vk_user_id, l.telegram_id, l.portal_user_id, u.login "
            "FROM vk_links l "
            "JOIN portal_users u ON u.id = l.portal_user_id "
            "WHERE l.vk_user_id = ?"
        ),
        (vk_user_id,),
    ).fetchone()


def get_subscription_stats(con: sqlite3.Connection, telegram_id: int) -> Optional[sqlite3.Row]:
    return con.execute(
        (
            "SELECT s.active_until, s.key_limit, s.title, s.plan, COALESCE(k.active_keys, 0) AS active_keys "
            "FROM subscriptions s "
            "LEFT JOIN ("
            "SELECT telegram_id, COUNT(*) AS active_keys FROM vpn_keys WHERE revoked_at IS NULL GROUP BY telegram_id"
            ") k ON k.telegram_id = s.telegram_id "
            "WHERE s.telegram_id = ?"
        ),
        (telegram_id,),
    ).fetchone()


def maybe_send_vk_subscription_reminder(con: sqlite3.Connection, vk_user_id: int, telegram_id: int) -> None:
    stats = get_subscription_stats(con, telegram_id)
    if not stats:
        return
    try:
        active_until = datetime.fromisoformat(stats["active_until"])
    except Exception:
        return
    now = utcnow()
    if active_until <= now:
        return

    days_left = (active_until - now).total_seconds() / 86400
    if days_left > 3:
        return

    reminder = con.execute(
        "SELECT last_sent_at FROM vk_subscription_reminders WHERE vk_user_id = ?",
        (vk_user_id,),
    ).fetchone()
    if reminder:
        try:
            last_sent_at = datetime.fromisoformat(reminder["last_sent_at"])
            if (now - last_sent_at) < timedelta(hours=24):
                return
        except Exception:
            pass

    until_local = active_until.astimezone().strftime("%d.%m.%Y %H:%M")
    send_vk_message_with_keyboard(
        vk_user_id,
        (
            "⏰ Напоминание: ваша подписка скоро закончится.\n"
            f"Действует до: {until_local}\n"
            "Продлить подписку можно в личном кабинете."
        ),
        keyboard=build_vk_keyboard(linked=True),
    )
    now_iso = now.isoformat()
    con.execute(
        (
            "INSERT INTO vk_subscription_reminders (vk_user_id, last_sent_at) "
            "VALUES (?, ?) "
            "ON CONFLICT(vk_user_id) DO UPDATE SET last_sent_at = excluded.last_sent_at"
        ),
        (vk_user_id, now_iso),
    )


def build_vk_subscription_status_text(stats: sqlite3.Row) -> str:
    try:
        active_until = datetime.fromisoformat(stats["active_until"])
        now = utcnow()
        seconds_left = max(0, int((active_until - now).total_seconds()))
        days_left = seconds_left // 86400
        hours_left = (seconds_left % 86400) // 3600
        until_local = active_until.astimezone().strftime("%d.%m.%Y %H:%M")
        expiry_line = f"До: {until_local} (осталось ~{days_left} дн. {hours_left} ч.)"
    except Exception:
        expiry_line = "До: неизвестно"
    return (
        "📊 Статус подписки:\n"
        f"Тариф: {stats['title'] or stats['plan']}\n"
        f"{expiry_line}\n"
        f"Ключи: {int(stats['active_keys'] or 0)}/{int(stats['key_limit'] or 0)}"
    )


def create_key_for_vk_user(con: sqlite3.Connection, telegram_id: int, key_kind: str) -> tuple[bool, str]:
    stats = get_subscription_stats(con, telegram_id)
    if not stats:
        return False, "Сначала подключите подписку в личном кабинете."

    now = utcnow()
    try:
        active_until = datetime.fromisoformat(stats["active_until"])
    except Exception:
        return False, "Не удалось проверить срок подписки."
    if active_until <= now:
        deactivated_count, failed_count = deactivate_user_keys(con, telegram_id)
        con.commit()
        if failed_count:
            return False, "Подписка истекла. Не все старые ключи удалось деактивировать, попробуйте позже."
        return False, f"Подписка истекла. Ключей деактивировано: {deactivated_count}. Продлите подписку."
    if int(stats["active_keys"] or 0) >= int(stats["key_limit"] or 0):
        return False, "Достигнут лимит ключей для вашего тарифа."

    key_title = f"{'Amnezia WG' if key_kind == 'awg' else 'XRay'} ключ (VK)"
    try:
        payload, vps_id, peer_pub, peer_ip = create_vpn_key_on_vps(
            kind=key_kind,
            title=key_title,
            telegram_id=telegram_id,
        )
    except RuntimeError as exc:
        return False, f"Не удалось создать ключ: {exc}"

    created_at = now.isoformat()
    cur = con.execute(
        (
            "INSERT INTO vpn_keys "
            "(telegram_id, kind, title, payload, created_at, revoked_at, vps_id, peer_pub, peer_ip) "
            "VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?)"
        ),
        (telegram_id, key_kind, key_title, payload, created_at, vps_id, peer_pub, peer_ip),
    )
    key_id = int(cur.lastrowid)
    con.commit()

    if len(payload) > 3500:
        payload_preview = payload[:3200]
        payload_suffix = "\n\n…(ключ длинный, остаток скачайте в кабинете)"
    else:
        payload_preview = payload
        payload_suffix = ""
    return (
        True,
        f"✅ Ключ создан (ID {key_id}, тип {key_kind.upper()}).\n\n{payload_preview}{payload_suffix}",
    )


def handle_vk_message_new(event: dict) -> None:
    obj = event.get("object") or {}
    message = obj.get("message") or {}

    vk_user_id = int(message.get("from_id") or 0)
    text = (message.get("text") or "").strip().lower()

    if vk_user_id <= 0:
        return

    if text.startswith("привязать "):
        code = text.replace("привязать", "", 1).strip().upper()
        if not code:
            send_vk_message(vk_user_id, "Укажите код: привязать ABC123")
            return

        with get_db_connection() as con:
            ok, message_text = consume_vk_link_code(con, code, vk_user_id)
            con.commit()

        send_vk_message_with_keyboard(
            vk_user_id,
            message_text,
            keyboard=build_vk_keyboard(linked=ok),
        )
        return

    cabinet_url = get_app_base_url()
    if cabinet_url:
        cabinet_url = f"{cabinet_url}/login"
    else:
        cabinet_url = "Ссылка на кабинет пока не настроена"

    with get_db_connection() as con:
        linked_account = get_vk_linked_account(con, vk_user_id)
        if linked_account:
            maybe_send_vk_subscription_reminder(con, vk_user_id, int(linked_account["telegram_id"]))
            con.commit()

    if text in {"привет", "start", "/start", "начать", "меню"}:
        if linked_account:
            send_vk_message_with_keyboard(
                vk_user_id,
                "Привет! Я бот вашего VPN-кабинета. Выберите действие на кнопках 👇",
                keyboard=build_vk_keyboard(linked=True),
            )
        else:
            send_vk_message_with_keyboard(
                vk_user_id,
                "Привет! Чтобы пользоваться ботом, сначала привяжите ВК-аккаунт.\n"
                "Отправьте: привязать ABC123 (код выдается в кабинете сайта).",
                keyboard=build_vk_keyboard(linked=False),
            )
        return

    if text in {"кабинет", "сайт", "логин", "🌐 кабинет"}:
        send_vk_message_with_keyboard(vk_user_id, f"Открыть кабинет: {cabinet_url}", keyboard=build_vk_keyboard(linked=linked_account is not None))
        return

    if text in {"помощь", "help", "/help", "❓ помощь", "🔗 привязать аккаунт"}:
        send_vk_message_with_keyboard(
            vk_user_id,
            "Возможности бота:\n"
            "• Кнопки для удобной навигации\n"
            "• Напоминания о скором окончании подписки\n"
            "• Генерация ключей AWG/XRay\n\n"
            "Если аккаунт не привязан, отправьте: привязать ABC123",
            keyboard=build_vk_keyboard(linked=linked_account is not None),
        )
        return

    if text in {"📊 подписка"}:
        if not linked_account:
            send_vk_message_with_keyboard(
                vk_user_id,
                "Сначала привяжите аккаунт: отправьте `привязать ABC123`.",
                keyboard=build_vk_keyboard(linked=False),
            )
            return
        with get_db_connection() as con:
            stats = get_subscription_stats(con, int(linked_account["telegram_id"]))
        if not stats:
            send_vk_message_with_keyboard(
                vk_user_id,
                "Подписка не найдена. Оформите ее в личном кабинете.",
                keyboard=build_vk_keyboard(linked=True),
            )
            return
        send_vk_message_with_keyboard(
            vk_user_id,
            build_vk_subscription_status_text(stats),
            keyboard=build_vk_keyboard(linked=True),
        )
        return

    if text in {"🔑 awg ключ", "🔑 xray ключ"}:
        if not linked_account:
            send_vk_message_with_keyboard(
                vk_user_id,
                "Сначала привяжите аккаунт: отправьте `привязать ABC123`.",
                keyboard=build_vk_keyboard(linked=False),
            )
            return
        key_kind = "awg" if "awg" in text else "xray"
        with get_db_connection() as con:
            ok, result_text = create_key_for_vk_user(con, int(linked_account["telegram_id"]), key_kind)
        send_vk_message_with_keyboard(
            vk_user_id,
            result_text,
            keyboard=build_vk_keyboard(linked=True),
        )
        return

    send_vk_message_with_keyboard(
        vk_user_id,
        "Я не понял запрос. Нажмите кнопку ниже 👇",
        keyboard=build_vk_keyboard(linked=linked_account is not None),
    )




