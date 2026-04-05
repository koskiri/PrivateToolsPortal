from __future__ import annotations

import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib import error as urllib_error
from urllib import request as urllib_request

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "bot.db"
FALLBACK_DB_PATH = BASE_DIR / "bot.local.db"

VPS_ISSUER_URL_ENV = "VPS_ISSUER_URL"
VPS_ISSUER_TOKEN_ENV = "VPS_ISSUER_TOKEN"

load_dotenv(BASE_DIR / ".env")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def log(message: str) -> None:
    print(f"[expire_subscriptions] {message}", flush=True)


def get_db_connection() -> sqlite3.Connection:
    try:
        con = sqlite3.connect(DB_PATH)
    except sqlite3.OperationalError:
        if Path(DB_PATH).is_symlink():
            con = sqlite3.connect(FALLBACK_DB_PATH)
        else:
            raise
    con.row_factory = sqlite3.Row
    return con


def revoke_vpn_key_on_vps(kind: str, vps_id: int | None, peer_pub: str | None, peer_ip: str | None) -> None:
    issuer_url = os.getenv(VPS_ISSUER_URL_ENV, "").strip().rstrip("/")
    if not issuer_url:
        raise RuntimeError("Не задан VPS_ISSUER_URL")
    if vps_id is None:
        raise RuntimeError("Нет vps_id для отзыва ключа")
    if not (peer_pub or peer_ip):
        raise RuntimeError("Нет peer_pub/peer_ip для отзыва ключа")

    issuer_token = os.getenv(VPS_ISSUER_TOKEN_ENV, "").strip()
    payload = json.dumps(
        {
            "kind": kind,
            "vps_id": vps_id,
            "peer_pub": peer_pub,
            "peer_ip": peer_ip,
        }
    ).encode("utf-8")

    req = urllib_request.Request(
        f"{issuer_url}/keys/revoke",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    if issuer_token:
        req.add_header("Authorization", f"Bearer {issuer_token}")

    try:
        with urllib_request.urlopen(req, timeout=20) as resp:
            body = resp.read().decode("utf-8", errors="ignore").strip()
            if body:
                log(f"issuer response: {body}")
    except urllib_error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"VPS revoke HTTP {exc.code}: {detail}") from exc
    except urllib_error.URLError as exc:
        raise RuntimeError(f"Не удалось подключиться к issuer: {exc}") from exc


def process_expired_subscriptions() -> tuple[int, int, int]:
    now = utcnow()
    now_iso = now.isoformat()

    with get_db_connection() as con:
        expired_keys = con.execute(
            """
            SELECT
                k.id,
                k.telegram_id,
                k.kind,
                k.vps_id,
                k.peer_pub,
                k.peer_ip,
                s.active_until
            FROM vpn_keys k
            JOIN subscriptions s ON s.telegram_id = k.telegram_id
            WHERE k.revoked_at IS NULL
              AND s.active_until IS NOT NULL
              AND s.active_until <= ?
            ORDER BY k.telegram_id, k.id
            """,
            (now_iso,),
        ).fetchall()

        if not expired_keys:
            log("Просроченных активных ключей не найдено")
            return 0, 0, 0

        total = len(expired_keys)
        revoked = 0
        failed = 0

        for key in expired_keys:
            key_id = int(key["id"])
            telegram_id = int(key["telegram_id"])
            kind = (key["kind"] or "").strip().lower()

            try:
                revoke_vpn_key_on_vps(
                    kind=kind,
                    vps_id=key["vps_id"],
                    peer_pub=key["peer_pub"],
                    peer_ip=key["peer_ip"],
                )

                con.execute(
                    """
                    UPDATE vpn_keys
                    SET revoked_at = ?, payload = ''
                    WHERE id = ? AND revoked_at IS NULL
                    """,
                    (now_iso, key_id),
                )
                revoked += 1
                log(f"OK revoked key_id={key_id} telegram_id={telegram_id} kind={kind}")

            except Exception as exc:
                failed += 1
                log(f"FAIL key_id={key_id} telegram_id={telegram_id} kind={kind}: {exc}")

        con.commit()
        return total, revoked, failed


if __name__ == "__main__":
    try:
        total, revoked, failed = process_expired_subscriptions()
        log(f"done total={total} revoked={revoked} failed={failed}")
        sys.exit(0 if failed == 0 else 1)
    except Exception as exc:
        log(f"fatal: {exc}")
        sys.exit(1)