from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from app.core.db import get_db_connection
from app.core.security import verify_password

router = APIRouter(prefix="/api/mobile", tags=["mobile"])


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class MobileLoginRequest(BaseModel):
    login: str
    password: str


class MobileUserResponse(BaseModel):
    id: int
    login: str
    telegram_id: Optional[int] = None
    subscription_active: bool
    expires_at: Optional[str] = None


class MobileLoginResponse(BaseModel):
    access_token: str
    user: MobileUserResponse


class MobileVpnConfigResponse(BaseModel):
    id: int
    country: str
    server: str
    protocol: str
    config_url: Optional[str] = None
    expires_at: Optional[str] = None


def get_user_by_token(authorization: Optional[str]):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")

    token = authorization.removeprefix("Bearer ").strip()

    with get_db_connection() as con:
        session = con.execute(
            """
            SELECT * FROM portal_sessions
            WHERE session_id = ?
            """,
            (token,),
        ).fetchone()

        if not session:
            raise HTTPException(status_code=401, detail="Invalid token")

        if session["expires_at"]:
            try:
                if datetime.fromisoformat(session["expires_at"]) <= utcnow():
                    raise HTTPException(status_code=401, detail="Token expired")
            except HTTPException:
                raise
            except Exception:
                raise HTTPException(status_code=401, detail="Invalid token expiration")

        user = con.execute(
            "SELECT * FROM portal_users WHERE id = ?",
            (session["user_id"],),
        ).fetchone()

        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        if user["revoked_at"] is not None:
            raise HTTPException(status_code=403, detail="Account disabled")

        return dict(user)


def get_subscription_info(telegram_id: Optional[int]):
    subscription_active = False
    expires_at = None

    if telegram_id is None:
        return subscription_active, expires_at

    with get_db_connection() as con:
        sub = con.execute(
            "SELECT * FROM subscriptions WHERE telegram_id = ?",
            (telegram_id,),
        ).fetchone()

        if sub and sub["active_until"]:
            expires_at = sub["active_until"]

            try:
                subscription_active = datetime.fromisoformat(expires_at) > utcnow()
            except Exception:
                subscription_active = False

    return subscription_active, expires_at


@router.post("/auth/login", response_model=MobileLoginResponse)
def mobile_login(data: MobileLoginRequest):
    login = data.login.strip()

    with get_db_connection() as con:
        user = con.execute(
            "SELECT * FROM portal_users WHERE login = ?",
            (login,),
        ).fetchone()

        if not user or not verify_password(
            data.password,
            user["password_salt"],
            user["password_hash"],
        ):
            raise HTTPException(status_code=401, detail="Invalid login or password")

        if user["revoked_at"] is not None:
            raise HTTPException(status_code=403, detail="Account disabled")

        subscription_active, expires_at = get_subscription_info(user["telegram_id"])

        token = secrets.token_urlsafe(32)
        now = utcnow()
        token_expires_at = now + timedelta(days=30)

        con.execute(
            """
            INSERT INTO portal_sessions (session_id, user_id, created_at, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                token,
                user["id"],
                now.isoformat(),
                token_expires_at.isoformat(),
            ),
        )
        con.commit()

    return MobileLoginResponse(
        access_token=token,
        user=MobileUserResponse(
            id=user["id"],
            login=user["login"],
            telegram_id=user["telegram_id"],
            subscription_active=subscription_active,
            expires_at=expires_at,
        ),
    )


@router.get("/profile", response_model=MobileUserResponse)
def mobile_profile(authorization: Optional[str] = Header(None)):
    user = get_user_by_token(authorization)
    subscription_active, expires_at = get_subscription_info(user["telegram_id"])

    return MobileUserResponse(
        id=user["id"],
        login=user["login"],
        telegram_id=user["telegram_id"],
        subscription_active=subscription_active,
        expires_at=expires_at,
    )


@router.get("/vpn/config", response_model=MobileVpnConfigResponse)
def mobile_vpn_config(authorization: Optional[str] = Header(None)):
    user = get_user_by_token(authorization)
    subscription_active, expires_at = get_subscription_info(user["telegram_id"])

    if not subscription_active:
        raise HTTPException(status_code=403, detail="Subscription inactive")

    with get_db_connection() as con:
        vpn_key = con.execute(
            """
            SELECT * FROM vpn_keys
            WHERE telegram_id = ?
            AND revoked_at IS NULL
            AND kind = 'xray'
            ORDER BY id DESC
            LIMIT 1
            """,
            (user["telegram_id"],),
        ).fetchone()

        if not vpn_key:
            raise HTTPException(status_code=404, detail="VPN key not found")

    return MobileVpnConfigResponse(
        id=vpn_key["id"],
        country="Germany",
        server="onlyus-launcher.ru",
        protocol="vless-reality",
        config_url=vpn_key["payload"],
        expires_at=expires_at,
    )
