from __future__ import annotations

import asyncio
import base64
import json
import os
import subprocess
import secrets
import sqlite3
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Optional
from urllib import error as urllib_error
from urllib.parse import quote_plus, urlencode
from urllib import request as urllib_request

from app.core.config import (
    APP_BASE_URL_ENV,
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

# Через сколько дней до окончания подписки отправлять VK-уведомление.
# Измените значение здесь, если нужно другое время уведомлений.
VK_SUBSCRIPTION_REMINDER_DAYS = 3
VK_SUBSCRIPTION_REMINDER_INTERVAL_SECONDS = 24 * 60 * 60

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

USER_ROLES = {"user", "sponsor"}
ROLE_LABELS = {"user": "Пользователь", "sponsor": "Спонсор"}


SPONSOR_ACCESS_DAYS = 365


def parse_subscription_active_until(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def apply_sponsor_upgrade(con: sqlite3.Connection, telegram_id: int, now: datetime | None = None) -> bool:
    now = now or utcnow()
    now_iso = now.isoformat()
    user = con.execute(
        "SELECT role FROM portal_users WHERE telegram_id = ?",
        (telegram_id,),
    ).fetchone()
    if not user or is_sponsor_role(user["role"] if "role" in user.keys() else None):
        return False

    con.execute(
        "UPDATE portal_users SET role = 'sponsor', updated_at = ? WHERE telegram_id = ?",
        (now_iso, telegram_id),
    )

    subscription = con.execute(
        "SELECT active_until FROM subscriptions WHERE telegram_id = ?",
        (telegram_id,),
    ).fetchone()
    active_until = parse_subscription_active_until(subscription["active_until"] if subscription else None)
    base = active_until if active_until and active_until > now else now
    new_active_until = base + timedelta(days=SPONSOR_ACCESS_DAYS)
    sponsor_subscription_preset = TARIFF_PRESETS["plan_5"]
    con.execute(
        (
            "INSERT INTO subscriptions (telegram_id, active_until, plan, key_limit, price_rub, title) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(telegram_id) DO UPDATE SET active_until = excluded.active_until"
        ),
        (
            telegram_id,
            new_active_until.isoformat(),
            sponsor_subscription_preset["plan"],
            int(sponsor_subscription_preset["key_limit"]),
            int(sponsor_subscription_preset["price_rub"]),
            sponsor_subscription_preset["title"],
        ),
    )
    return True

def normalize_user_role(role: str | None) -> str:
    normalized = (role or "user").strip().lower()
    return normalized if normalized in USER_ROLES else "user"


def get_user_role_label(role: str | None) -> str:
    return ROLE_LABELS[normalize_user_role(role)]


def is_sponsor_role(role: str | None) -> bool:
    return normalize_user_role(role) == "sponsor"


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


def _portal_base_url() -> str:
    base_url = (os.getenv(APP_BASE_URL_ENV, "") or "").strip().rstrip("/")
    if not base_url:
        base_url = "http://localhost:8000"
    return base_url


def build_activate_link(invite_code: str) -> str:
    return f"{_portal_base_url()}/activate?code={quote_plus(invite_code)}"


def build_sponsor_referral_link(referral_code: str) -> str:
    return f"{_portal_base_url()}/r/{quote_plus(referral_code)}"


def _generate_unique_referral_code(con: sqlite3.Connection) -> str:
    for _ in range(20):
        code = secrets.token_urlsafe(9).rstrip("=")
        exists = con.execute("SELECT 1 FROM portal_users WHERE referral_code = ?", (code,)).fetchone()
        if not exists:
            return code
    raise RuntimeError("Unable to generate unique referral code")


def ensure_sponsor_referral_code(con: sqlite3.Connection, user_id: int) -> str:
    user = con.execute(
        "SELECT referral_code FROM portal_users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if not user:
        raise ValueError("Sponsor not found")
    referral_code = (user["referral_code"] or "").strip()
    if referral_code:
        return referral_code

    referral_code = _generate_unique_referral_code(con)
    con.execute(
        "UPDATE portal_users SET referral_code = ?, updated_at = ? WHERE id = ?",
        (referral_code, utcnow().isoformat(), user_id),
    )
    return referral_code


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
            "SELECT "
            "SUM(CASE WHEN revoked_at IS NULL THEN 1 ELSE 0 END) AS total, "
            "SUM(CASE WHEN revoked_at IS NULL AND used_at IS NOT NULL THEN 1 ELSE 0 END) AS used, "
            "SUM(CASE WHEN revoked_at IS NULL AND used_at IS NULL THEN 1 ELSE 0 END) AS available "
            "FROM portal_invites WHERE invited_by_user_id = ?"
        ),
        (user_id,),
    ).fetchone()

def get_or_create_invite_for_referral_code(con: sqlite3.Connection, referral_code: str) -> sqlite3.Row:
    sponsor = con.execute(
        "SELECT id, role FROM portal_users WHERE referral_code = ?",
        (referral_code,),
    ).fetchone()
    if not sponsor or not is_sponsor_role(sponsor["role"]):
        raise PermissionError("Постоянная ссылка недоступна или спонсорство отключено")

    sponsor_id = int(sponsor["id"])
    available_invite = con.execute(
        (
            "SELECT * FROM portal_invites "
            "WHERE invited_by_user_id = ? AND used_at IS NULL AND revoked_at IS NULL "
            "ORDER BY datetime(created_at) ASC, id ASC LIMIT 1"
        ),
        (sponsor_id,),
    ).fetchone()
    if available_invite:
        return available_invite

    stats = get_user_invite_stats(con, sponsor_id)
    if int(stats["available"] or 0) >= 10:
        raise OverflowError("У спонсора уже есть 10 неиспользованных приглашений")

    create_referral_invite(con, sponsor_id)
    return con.execute(
        (
            "SELECT * FROM portal_invites "
            "WHERE invited_by_user_id = ? AND used_at IS NULL AND revoked_at IS NULL "
            "ORDER BY datetime(created_at) DESC, id DESC LIMIT 1"
        ),
        (sponsor_id,),
    ).fetchone()


def revoke_referral_invite(con: sqlite3.Connection, sponsor_id: int, invite_id: int) -> bool:
    invite = con.execute(
        "SELECT id, used_at, revoked_at FROM portal_invites WHERE id = ? AND invited_by_user_id = ?",
        (invite_id, sponsor_id),
    ).fetchone()
    if not invite or is_invite_used(invite) or is_invite_revoked(invite):
        return False

    con.execute(
        "UPDATE portal_invites SET revoked_at = ? WHERE id = ? AND invited_by_user_id = ? AND used_at IS NULL AND revoked_at IS NULL",
        (utcnow().isoformat(), invite_id, sponsor_id),
    )
    return con.total_changes > 0

    
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


def create_yookassa_payment(
    amount_rub: int,
    description: str,
    metadata: dict[str, str],
    return_url: str | None = None,
) -> tuple[str, str]:
    shop_id = os.getenv(YOOKASSA_SHOP_ID_ENV)
    secret_key = os.getenv(YOOKASSA_SECRET_KEY_ENV)
    if not shop_id or not secret_key:
        raise RuntimeError("YooKassa credentials are not configured")

    auth_token = base64.b64encode(f"{shop_id}:{secret_key}".encode("utf-8")).decode("utf-8")
    payment_return_url = return_url or os.getenv(YOOKASSA_RETURN_URL_ENV) or "http://localhost:8000/dashboard/payment/return"
    payload = {
        "amount": {"value": f"{amount_rub:.2f}", "currency": "RUB"},
        "capture": True,
        "confirmation": {"type": "redirect", "return_url": payment_return_url},
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

def create_vpn_key_on_vps(
    kind: str,
    title: str,
    telegram_id: int,
    device: Optional[str] = None,
) -> tuple[str, Optional[int], Optional[str], Optional[str]]:
    issuer_url = os.getenv(VPS_ISSUER_URL_ENV, "").strip().rstrip("/")
    if not issuer_url:
        raise RuntimeError("Не настроен адрес сервиса выдачи ключей на VPS")

    payload = {"kind": kind, "title": title, "telegram_id": telegram_id}
    if device:
        payload["device"] = device

    req = urllib_request.Request(
        f"{issuer_url}/keys",
        data=json.dumps(payload).encode("utf-8"),
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



def _try_revoke_local_ws_key(client_id: Optional[str]) -> bool:
    if not client_id:
        return False
    script = "/usr/local/bin/revoke_ws_key.py"
    if not os.path.exists(script):
        return False
    try:
        result = subprocess.run(
            [script, client_id],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
        return result.returncode == 0
    except Exception:
        return False


def revoke_vpn_key_on_vps(kind: str, vps_id: Optional[int], peer_pub: Optional[str], peer_ip: Optional[str]) -> None:
    # peer_pub может содержать несколько UUID через запятую:
    # WS UUID, Reality UUID
    peer_values = [x.strip() for x in (peer_pub or "").split(",") if x.strip()]

    if not peer_values and not peer_ip:
        return

    # 1) Локально удаляем WS UUID из /usr/local/etc/xray/config.json на VM-980621.
    # Скрипт сам вернёт NOT_FOUND для Reality UUID, это нормально.
    for client_id in peer_values:
        _try_revoke_local_ws_key(client_id)

    # 2) Дальше старая логика: удаляем Reality/AWG через issuer.
    issuer_url = os.getenv(VPS_ISSUER_URL_ENV, "").strip().rstrip("/")
    if not issuer_url:
        return
    if vps_id is None:
        return

    issuer_token = os.getenv(VPS_ISSUER_TOKEN_ENV, "").strip()
    endpoints = ("/keys/revoke", "/revoke")
    last_error: Optional[Exception] = None

    # Для issuer отправляем каждый UUID отдельно.
    # Если UUID уже не найден на конкретном сервере, issuer сам обработает это.
    targets = peer_values or [peer_pub]

    for client_id in targets:
        payload = json.dumps(
            {
                "kind": kind,
                "vps_id": vps_id,
                "peer_pub": client_id,
                "peer_ip": peer_ip,
            }
        ).encode("utf-8")

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
                    last_error = None
                    break
            except urllib_error.HTTPError as exc:
                last_error = exc
                if endpoint != endpoints[-1]:
                    continue
                # Если конкретный UUID не найден, не валим весь revoke:
                # например WS удалился локально, а на Reality его нет.
                if exc.code == 404:
                    last_error = None
                    break
            except urllib_error.URLError as exc:
                last_error = exc
                if endpoint != endpoints[-1]:
                    continue

    if last_error:
        raise RuntimeError(f"Не удалось отозвать ключ на VPS: {last_error}")

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
                {"action": {"type": "text", "label": "🗑 Удалить ключ"}, "color": "negative"}, 
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

def build_delete_keys_keyboard(telegram_id: int) -> str:
    """Создаёт клавиатуру VK с кнопками для удаления каждого активного ключа."""
    with get_db_connection() as con:
        keys = con.execute(
            "SELECT id, title FROM vpn_keys WHERE telegram_id = ? AND revoked_at IS NULL",
            (telegram_id,),
        ).fetchall()

    buttons = []
    for key in keys:
        buttons.append([
            {"action": {"type": "text", "label": f"Удалить {key['title']}"}, "color": "negative"}
        ])

    if not buttons:
        buttons.append([
            {"action": {"type": "text", "label": "Нет активных ключей"}, "color": "secondary"}
        ])

    return json.dumps({"one_time": True, "buttons": buttons}, ensure_ascii=False)

def delete_key_by_title(telegram_id: int, key_title: str) -> bool:
    """Удаляет конкретный ключ по названию для пользователя. Возвращает True если удалено."""
    with get_db_connection() as con:
        row = con.execute(
            "SELECT id FROM vpn_keys WHERE telegram_id = ? AND title = ? AND revoked_at IS NULL",
            (telegram_id, key_title)
        ).fetchone()
        if not row:
            return False

        key_id = row["id"]
        now_iso = datetime.now(timezone.utc).isoformat()
        con.execute(
            "UPDATE vpn_keys SET revoked_at = ?, payload = '' WHERE id = ?",
            (now_iso, key_id)
        )
        con.commit()
    return True

def handle_vk_delete_key_button(vk_user_id: int, text: str) -> bool:
    if not text.startswith("Удалить "):
        return False

    key_label = text.replace("Удалить ", "", 1).strip()

    with get_db_connection() as con:
        linked = con.execute(
            "SELECT telegram_id FROM vk_links WHERE vk_user_id = ?",
            (vk_user_id,),
        ).fetchone()
        if not linked:
            send_vk_message(vk_user_id, "Сначала привяжите аккаунт.")
            return True
        telegram_id = linked["telegram_id"]

        rows = con.execute(
            "SELECT id, title FROM vpn_keys WHERE telegram_id = ? AND revoked_at IS NULL",
            (telegram_id,),
        ).fetchall()

        matched = None
        for r in rows:
            title = r["title"].replace(" (VK)", "").strip()
            if title in key_label:
                matched = r
                break

        if not matched:
            send_vk_message_with_keyboard(
                vk_user_id,
                f"Ключ {key_label} не найден или уже удалён ❌",
                keyboard=build_vk_keyboard(linked=True),
            )
            return True

        # удаляем ключ
        now_iso = datetime.now(timezone.utc).isoformat()
        con.execute(
            "UPDATE vpn_keys SET revoked_at = ?, payload = '' WHERE id = ?",
            (now_iso, matched["id"])
        )
        con.commit()

    # ✅ Отправляем сообщение с клавиатурой
    send_vk_message_with_keyboard(
        vk_user_id,
        f"Ключ {matched['title']} успешно удалён ✅",
        keyboard=build_vk_keyboard(linked=True),
    )
    return True

def delete_user_key(user_id: int, key: str) -> bool:
    """Удаляет ключ из таблицы keys, только если он принадлежит VK-пользователю."""
    normalized_key = key.strip()
    if not normalized_key:
        return False

    with get_db_connection() as con:
        result = con.execute(
            "DELETE FROM keys WHERE user_id = ? AND key = ?",
            (user_id, normalized_key),
        )
        con.commit()
    return result.rowcount > 0


def handle_vk_delete_key_command(vk_user_id: int, text: str) -> bool:
    """Обрабатывает команду /delete_key <ключ>. Возвращает True, если это была команда удаления."""
    command, _, key = text.partition(" ")
    if command.lower() != "/delete_key":
        return False

    key = key.strip()
    if not key:
        send_vk_message(vk_user_id, "Укажите ключ для удаления: /delete_key <ключ>")
        return True

    if delete_user_key(vk_user_id, key):
        send_vk_message(vk_user_id, f"Ключ {key} успешно удалён ✅")
    else:
        send_vk_message(vk_user_id, f"Ключ {key} не найден или не принадлежит вам ❌")
    return True


def _table_columns(con: sqlite3.Connection, table_name: str) -> set[str]:
    try:
        return {str(row["name"]) for row in con.execute(f"PRAGMA table_info({table_name})").fetchall()}
    except sqlite3.OperationalError:
        return set()


def _format_subscription_end(subscription_end: str) -> str:
    try:
        parsed = datetime.fromisoformat(subscription_end)
        return parsed.strftime("%d.%m.%Y")
    except (TypeError, ValueError):
        try:
            parsed_date = date.fromisoformat(str(subscription_end))
            return parsed_date.strftime("%d.%m.%Y")
        except (TypeError, ValueError):
            return str(subscription_end)


def get_subscriptions_ending_in_days(con: sqlite3.Connection, days_before_end: int) -> list[tuple[int, str]]:
    """Возвращает VK user_id и дату окончания подписки для уведомлений."""
    target_date = (utcnow().date() + timedelta(days=days_before_end)).isoformat()
    subscription_columns = _table_columns(con, "subscriptions")

    if {"user_id", "subscription_end"}.issubset(subscription_columns):
        rows = con.execute(
            """
            SELECT user_id AS vk_user_id, subscription_end AS subscription_end
            FROM subscriptions
            WHERE date(subscription_end) = date(?)
            """,
            (target_date,),
        ).fetchall()
        return [(int(row["vk_user_id"]), str(row["subscription_end"])) for row in rows]

    # Совместимость с текущей схемой портала: subscriptions.telegram_id/active_until + привязки VK.
    if {"telegram_id", "active_until"}.issubset(subscription_columns):
        rows = con.execute(
            """
            SELECT l.vk_user_id AS vk_user_id, s.active_until AS subscription_end
            FROM subscriptions s
            JOIN vk_links l ON l.telegram_id = s.telegram_id
            WHERE date(s.active_until) = date(?)
            """,
            (target_date,),
        ).fetchall()
        return [(int(row["vk_user_id"]), str(row["subscription_end"])) for row in rows]

    return []


def send_subscription_expiration_reminders(days_before_end: int = VK_SUBSCRIPTION_REMINDER_DAYS) -> int:
    """Отправляет VK-уведомления пользователям, чья подписка закончится через days_before_end дней."""
    sent_count = 0
    with get_db_connection() as con:
        subscriptions = get_subscriptions_ending_in_days(con, days_before_end)

    for user_id, subscription_end in subscriptions:
        end_text = _format_subscription_end(subscription_end)
        try:
            send_vk_message(
                user_id,
                f"Ваша подписка скоро заканчивается ({end_text}). Не забудьте продлить её!",
            )
            sent_count += 1
        except Exception as exc:
            print(f"[vk_subscription_reminders] failed for user {user_id}: {exc}")
    return sent_count


async def run_vk_subscription_reminder_loop() -> None:
    """Ежедневная фоновая проверка подписок при запущенном FastAPI."""
    while True:
        try:
            # Для изменения времени уведомлений поменяйте VK_SUBSCRIPTION_REMINDER_DAYS выше.
            send_subscription_expiration_reminders(VK_SUBSCRIPTION_REMINDER_DAYS)
        except Exception as exc:
            print(f"[vk_subscription_reminders] loop error: {exc}")
        await asyncio.sleep(VK_SUBSCRIPTION_REMINDER_INTERVAL_SECONDS)


def handle_vk_message_new(event: dict) -> None:
    obj = event.get("object") or {}
    message = obj.get("message") or {}

    vk_user_id = int(message.get("from_id") or 0)
    text_raw = (message.get("text") or "").strip()
    text = text_raw.lower()

    if vk_user_id <= 0:
        return

    with get_db_connection() as con:
        # Получаем привязанный telegram_id
        linked_account = get_vk_linked_account(con, vk_user_id)
        telegram_id = int(linked_account["telegram_id"]) if linked_account else None

        # Отправка напоминания о подписке
        if telegram_id:
            maybe_send_vk_subscription_reminder(con, vk_user_id, telegram_id)

    # 1️⃣ Проверяем, нажал ли пользователь на конкретный ключ для удаления
    if handle_vk_delete_key_button(vk_user_id, text_raw):
        return

    # 2️⃣ Кнопка "Удалить ключ" — показываем список активных ключей
    if text in {"🗑 удалить ключ"}:
        if not telegram_id:
            send_vk_message(vk_user_id, "Сначала привяжите аккаунт: привязать ABC123")
            return
        keyboard = build_delete_keys_keyboard(telegram_id)
        send_vk_message_with_keyboard(
            vk_user_id,
            "Выберите ключ для удаления:",
            keyboard=keyboard
        )
        return

    # 3️⃣ Команда /delete_key <ключ>
    if handle_vk_delete_key_command(vk_user_id, text_raw):
        return

    # 4️⃣ Привязка аккаунта
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

    # 5️⃣ Основное меню
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

    # 6️⃣ Кабинет
    if text in {"кабинет", "сайт", "логин", "🌐 кабинет"}:
        send_vk_message_with_keyboard(
            vk_user_id,
            f"Открыть кабинет: {cabinet_url}",
            keyboard=build_vk_keyboard(linked=linked_account is not None),
        )
        return

    # 7️⃣ Помощь
    if text in {"помощь", "help", "/help", "❓ помощь", "🔗 привязать аккаунт"}:
        send_vk_message_with_keyboard(
            vk_user_id,
            "Возможности бота:\n"
            "• Кнопки для удобной навигации\n"
            "• Напоминания о скором окончании подписки\n"
            "• Генерация ключей AWG/XRay\n"
            "• Удаление ключа кнопкой или командой /delete_key <ключ>\n\n"
            "Если аккаунт не привязан, отправьте: привязать ABC123",
            keyboard=build_vk_keyboard(linked=linked_account is not None),
        )
        return

    # 8️⃣ Статус подписки
    if text in {"📊 подписка"}:
        if not linked_account:
            send_vk_message_with_keyboard(
                vk_user_id,
                "Сначала привяжите аккаунт: отправьте `привязать ABC123`.",
                keyboard=build_vk_keyboard(linked=False),
            )
            return
        with get_db_connection() as con:
            stats = get_subscription_stats(con, telegram_id)
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

    # 9️⃣ Создание ключей AWG/XRay
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
            ok, result_text = create_key_for_vk_user(con, telegram_id, key_kind)
        send_vk_message_with_keyboard(
            vk_user_id,
            result_text,
            keyboard=build_vk_keyboard(linked=True),
        )
        return

    # 10️⃣ Любой другой текст
    send_vk_message_with_keyboard(
        vk_user_id,
        "Я не понял запрос. Нажмите кнопку ниже 👇",
        keyboard=build_vk_keyboard(linked=linked_account is not None),
    )

    send_vk_message_with_keyboard(
        vk_user_id,
        "Я не понял запрос. Нажмите кнопку ниже 👇",
        keyboard=build_vk_keyboard(linked=linked_account is not None),
    )




