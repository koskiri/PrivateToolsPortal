from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Request
from fastapi.responses import RedirectResponse

from app.core.config import ADMIN_COOKIE, ADMIN_PASSWORD_ENV, SESSION_COOKIE, SESSION_DAYS
from app.core.db import get_db_connection


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


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
        samesite="lax",    # гарантирует работу на переходах
        secure=True,        # можно оставить True, Cloudflare → HTTPS
        max_age=SESSION_DAYS * 24 * 60 * 60,
    )

def get_admin_password() -> str:
    return os.getenv(ADMIN_PASSWORD_ENV, "").strip()

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
