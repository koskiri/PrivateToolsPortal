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

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "bot.db"
FALLBACK_DB_PATH = BASE_DIR / "bot.local.db"
SESSION_COOKIE = "portal_session"
SESSION_DAYS = 14
ADMIN_COOKIE = "portal_admin_session"
ADMIN_PASSWORD_ENV = "PORTAL_ADMIN_PASSWORD"
TARIFF_PRESETS = {
    "trial": {
        "plan": "trial_1w_1key",
        "title": "Бесплатно (1 ключ / 7 дней)",
        "key_limit": 1,
        "price_rub": 0,
        "duration_days": 7,
    },
    "plan_5": {
        "plan": "plan_5_keys",
        "title": "100 ₽ / 5 ключей",
        "key_limit": 5,
        "price_rub": 100,
        "duration_days": 30,
    },
    "plan_10": {
        "plan": "plan_10_keys",
        "title": "180 ₽ / 10 ключей",
        "key_limit": 10,
        "price_rub": 180,
        "duration_days": 30,
    },
    "plan_40": {
        "plan": "plan_40_keys",
        "title": "300 ₽ / 40 ключей",
        "key_limit": 40,
        "price_rub": 300,
        "duration_days": 30,
    },
}

USER_TARIFF_CHOICES = ("plan_5", "plan_10", "plan_40")
SUBSCRIPTION_RENEW_DAYS = 30
MAX_SUPPORT_MESSAGE_LEN = 2000
MAX_SUPPORT_SUBJECT_LEN = 160
YOOKASSA_API_URL = "https://api.yookassa.ru/v3/payments"
YOOKASSA_SHOP_ID_ENV = "YOOKASSA_SHOP_ID"
YOOKASSA_SECRET_KEY_ENV = "YOOKASSA_SECRET_KEY"
YOOKASSA_RETURN_URL_ENV = "YOOKASSA_RETURN_URL"
VPS_ISSUER_URL_ENV = "VPS_ISSUER_URL"
VPS_ISSUER_TOKEN_ENV = "VPS_ISSUER_TOKEN"
VK_CONFIRMATION_CODE_ENV = "VK_CONFIRMATION_CODE"
VK_SECRET_ENV = "VK_SECRET"
VK_TOKEN_ENV = "VK_TOKEN"
VK_BOT_LINK_ENV = "VK_BOT_LINK"
APP_BASE_URL_ENV = "APP_BASE_URL"

app = FastAPI(title="PrivateToolsPortal")

static_dir = BASE_DIR / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def get_db_connection() -> sqlite3.Connection:
    try:
        con = sqlite3.connect(DB_PATH)
    except sqlite3.OperationalError:
        # In dev/staging bot.db can be a broken symlink to external storage.
        # Fall back to a local SQLite file so the portal can still start.
        if Path(DB_PATH).is_symlink():
            con = sqlite3.connect(FALLBACK_DB_PATH)
        else:
            raise
    con.row_factory = sqlite3.Row
    return con


def ensure_auth_tables() -> None:
    with get_db_connection() as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS portal_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id INTEGER NOT NULL UNIQUE,
                login TEXT NOT NULL UNIQUE,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                revoked_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )

        con.execute(
            """
            CREATE TABLE IF NOT EXISTS portal_invites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                invite_code TEXT NOT NULL UNIQUE,
                telegram_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                used_at TEXT
            )
            """
        )

        con.execute(
            """
            CREATE TABLE IF NOT EXISTS portal_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL UNIQUE,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES portal_users(id)
            )
            """
        )
        # Legacy deployments can have strict telegram_id requirements.
        # We keep the column for compatibility with subscription stats,
        # but allow NULL so users/invites can exist without Telegram.
        migrate_telegram_columns(con)
        ensure_support_tables(con)
        ensure_billing_tables(con)
        ensure_vk_tables(con)


def ensure_support_tables(con: sqlite3.Connection) -> None:
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS support_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            closed_at TEXT,
            rating INTEGER,
            feedback TEXT
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS support_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL,
            telegram_id INTEGER NOT NULL,
            sender_role TEXT NOT NULL,
            sender_id INTEGER NOT NULL,
            text TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    ticket_columns = {row["name"] for row in con.execute("PRAGMA table_info(support_tickets)").fetchall()}
    if "subject" not in ticket_columns:
        con.execute("ALTER TABLE support_tickets ADD COLUMN subject TEXT")
    if "category" not in ticket_columns:
        con.execute("ALTER TABLE support_tickets ADD COLUMN category TEXT")
    if "priority" not in ticket_columns:
        con.execute("ALTER TABLE support_tickets ADD COLUMN priority TEXT")
    if "updated_at" not in ticket_columns:
        con.execute("ALTER TABLE support_tickets ADD COLUMN updated_at TEXT")

def ensure_billing_tables(con: sqlite3.Connection) -> None:
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS user_wallets (
            telegram_id INTEGER PRIMARY KEY,
            balance_rub INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS payment_actions (
            payment_id TEXT PRIMARY KEY,
            telegram_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            target_plan_key TEXT,
            amount_rub INTEGER NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )

def ensure_vk_tables(con: sqlite3.Connection) -> None:
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS vk_links (
            vk_user_id INTEGER PRIMARY KEY,
            portal_user_id INTEGER NOT NULL UNIQUE,
            telegram_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(portal_user_id) REFERENCES portal_users(id)
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS vk_link_codes (
            code TEXT PRIMARY KEY,
            portal_user_id INTEGER NOT NULL,
            telegram_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            vk_user_id INTEGER,
            FOREIGN KEY(portal_user_id) REFERENCES portal_users(id)
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS vk_subscription_reminders (
            vk_user_id INTEGER PRIMARY KEY,
            last_sent_at TEXT NOT NULL
        )
        """
    )

def migrate_telegram_columns(con: sqlite3.Connection) -> None:
    users_telegram_notnull = con.execute("PRAGMA table_info(portal_users)").fetchall()
    invites_telegram_notnull = con.execute("PRAGMA table_info(portal_invites)").fetchall()

    need_users_migration = any(
        row["name"] == "telegram_id" and row["notnull"] == 1 for row in users_telegram_notnull
    )
    need_invites_migration = any(
        row["name"] == "telegram_id" and row["notnull"] == 1 for row in invites_telegram_notnull
    )

    if need_users_migration:
        con.execute(
            """
            CREATE TABLE portal_users_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id INTEGER UNIQUE,
                login TEXT NOT NULL UNIQUE,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        con.execute(
            """
            INSERT INTO portal_users_new (id, telegram_id, login, password_salt, password_hash, created_at, updated_at)
            SELECT id, telegram_id, login, password_salt, password_hash, created_at, updated_at
            FROM portal_users
            """
        )
        con.execute("DROP TABLE portal_users")
        con.execute("ALTER TABLE portal_users_new RENAME TO portal_users")
    users_columns = {row["name"] for row in con.execute("PRAGMA table_info(portal_users)").fetchall()}
    if "revoked_at" not in users_columns:
        con.execute("ALTER TABLE portal_users ADD COLUMN revoked_at TEXT")

    if need_invites_migration:
        con.execute(
            """
            CREATE TABLE portal_invites_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                invite_code TEXT NOT NULL UNIQUE,
                telegram_id INTEGER,
                created_at TEXT NOT NULL,
                used_at TEXT
            )
            """
        )
        con.execute(
            """
            INSERT INTO portal_invites_new (id, invite_code, telegram_id, created_at, used_at)
            SELECT id, invite_code, telegram_id, created_at, used_at
            FROM portal_invites
            """
        )
        con.execute("DROP TABLE portal_invites")
        con.execute("ALTER TABLE portal_invites_new RENAME TO portal_invites")
    invite_columns = {row["name"] for row in con.execute("PRAGMA table_info(portal_invites)").fetchall()}
    if "plan" not in invite_columns:
        con.execute("ALTER TABLE portal_invites ADD COLUMN plan TEXT")
    if "title" not in invite_columns:
        con.execute("ALTER TABLE portal_invites ADD COLUMN title TEXT")
    if "key_limit" not in invite_columns:
        con.execute("ALTER TABLE portal_invites ADD COLUMN key_limit INTEGER")
    if "price_rub" not in invite_columns:
        con.execute("ALTER TABLE portal_invites ADD COLUMN price_rub INTEGER")
    if "duration_days" not in invite_columns:
        con.execute("ALTER TABLE portal_invites ADD COLUMN duration_days INTEGER")

    # Portal users can register without Telegram. To keep compatibility with
    # legacy tables keyed by telegram_id, assign deterministic synthetic IDs.
    con.execute(
        """
        UPDATE portal_users
        SET telegram_id = -id
        WHERE telegram_id IS NULL
        """
    )


@app.on_event("startup")
def startup() -> None:
    ensure_auth_tables()



def hash_password(password: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return digest.hex()


def create_password_hash(password: str) -> tuple[str, str]:
    salt_hex = secrets.token_hex(16)
    return salt_hex, hash_password(password, salt_hex)


def verify_password(password: str, salt_hex: str, password_hash: str) -> bool:
    candidate = hash_password(password, salt_hex)
    return hmac.compare_digest(candidate, password_hash)


def get_current_user(request: Request) -> Optional[sqlite3.Row]:
    session_id = request.cookies.get(SESSION_COOKIE)
    if not session_id:
        return None

    with get_db_connection() as con:
        row = con.execute(
            """
            SELECT u.*, s.expires_at
            FROM portal_sessions s
            JOIN portal_users u ON u.id = s.user_id
            WHERE s.session_id = ?
            """,
            (session_id,),
        ).fetchone()

        if not row:
            return None

        expires_at = datetime.fromisoformat(row["expires_at"])
        if expires_at <= utcnow():
            con.execute("DELETE FROM portal_sessions WHERE session_id = ?", (session_id,))
            con.commit()
            return None
        
        if row["revoked_at"] is not None:
            con.execute("DELETE FROM portal_sessions WHERE session_id = ?", (session_id,))
            con.commit()
            return None

        return row
    
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


def issue_session(response: RedirectResponse, user_id: int) -> None:
    session_id = secrets.token_urlsafe(32)
    created_at = utcnow()
    expires_at = created_at + timedelta(days=SESSION_DAYS)

    with get_db_connection() as con:
        con.execute(
            "INSERT INTO portal_sessions (session_id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (session_id, user_id, created_at.isoformat(), expires_at.isoformat()),
        )
        con.commit()

    response.set_cookie(
        key=SESSION_COOKIE,
        value=session_id,
        httponly=True,
        samesite="lax",
        max_age=SESSION_DAYS * 24 * 60 * 60,
    )

def get_admin_password() -> str:
    return os.getenv(ADMIN_PASSWORD_ENV, "").strip()

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


def is_admin(request: Request) -> bool:
    admin_password = get_admin_password()
    cookie_value = request.cookies.get(ADMIN_COOKIE, "")

    if not admin_password or not cookie_value:
        return False

    try:
        return hmac.compare_digest(
            cookie_value.encode("utf-8"),
            admin_password.encode("utf-8"),
        )
    except Exception:
        return False


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, activated: int = 0):
    if get_current_user(request):
        return RedirectResponse("/dashboard", status_code=303)
    success_message = "Аккаунт успешно активирован. Войдите под своим логином и паролем." if activated else None

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"error": None, "success": success_message},
    )


@app.post("/login", response_class=HTMLResponse)
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


@app.get("/activate", response_class=HTMLResponse)
async def activate_page(request: Request, code: str = ""):
    invite_info = None
    error = None
    if code:
        with get_db_connection() as con:
            invite_info = con.execute(
                (
                    "SELECT i.invite_code, i.used_at, i.plan, i.key_limit, i.title, i.price_rub, i.duration_days "
                    "FROM portal_invites i "
                    "WHERE i.invite_code = ?"
                ),
                (code,),
            ).fetchone()

        if not invite_info:
            error = "Инвайт не найден"
        elif invite_info["used_at"]:
            error = "Инвайт уже использован"

    return templates.TemplateResponse(
        request=request,
        name="activate.html",
        context={"code": code, "invite": invite_info, "error": error, "success": None},
    )


@app.post("/activate", response_class=HTMLResponse)
async def activate_submit(
    request: Request,
    code: str = Form(...),
    login: str = Form(...),
    password: str = Form(...),
):
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

        if invite["used_at"] is not None:
            return templates.TemplateResponse(
                request=request,
                name="activate.html",
                context={"code": code, "invite": None, "error": "Инвайт уже активирован", "success": None},
                status_code=400,
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
            "UPDATE portal_invites SET used_at = ? WHERE id = ?",
            (now, invite["id"]),
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


@app.get("/dashboard", response_class=HTMLResponse)
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
        con.commit()

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
        },
    )

@app.post("/dashboard/vk-link")
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


@app.post("/dashboard/vk-unlink")
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

@app.post("/dashboard/change-plan")
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


@app.post("/dashboard/subscription")
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

@app.get("/dashboard/payment/return")
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


@app.post("/dashboard/create-key")
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

@app.post("/dashboard/keys/{key_id}/rename")
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


@app.post("/dashboard/keys/{key_id}/delete")
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


@app.get("/dashboard/keys/{key_id}/download")
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


@app.post("/dashboard/support/tickets")
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


@app.get("/dashboard/support/tickets")
async def dashboard_support_tickets_redirect(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return RedirectResponse("/dashboard", status_code=303)


@app.post("/dashboard/support/tickets/{ticket_id}/reply")
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


@app.post("/dashboard/support/tickets/{ticket_id}/close")
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


@app.post("/dashboard/support/tickets/{ticket_id}/rate")
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
                "COALESCE(w.balance_rub, 0) AS balance_rub "
                "FROM portal_users u "
                "LEFT JOIN subscriptions s ON s.telegram_id = u.telegram_id "
                "LEFT JOIN ("
                "SELECT telegram_id, COUNT(*) AS active_keys FROM vpn_keys WHERE revoked_at IS NULL GROUP BY telegram_id"
                ") k ON k.telegram_id = u.telegram_id "
                "LEFT JOIN user_wallets w ON w.telegram_id = u.telegram_id "
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
                "COALESCE(w.balance_rub, 0) AS wallet_balance "
                "FROM portal_users u "
                "LEFT JOIN subscriptions s ON s.telegram_id = u.telegram_id "
                "LEFT JOIN user_wallets w ON w.telegram_id = u.telegram_id "
                "WHERE u.id = ?"
            ),
            (user_id,),
        ).fetchone()
        if not user:
            return RedirectResponse("/admin?error=Пользователь+не+найден", status_code=303)

        keys = con.execute(
            (
                "SELECT id, kind, title, created_at, revoked_at "
                "FROM vpn_keys WHERE telegram_id = ? "
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