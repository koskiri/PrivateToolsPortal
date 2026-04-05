import json
import os
import sqlite3
import subprocess
import uuid
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

load_dotenv()

app = FastAPI()

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "bot.db"
ISSUER_TOKEN = os.getenv("VPS_ISSUER_TOKEN", "").strip()


class KeyRequest(BaseModel):
    kind: str
    title: str
    telegram_id: int

class RevokeKeyRequest(BaseModel):
    kind: str
    vps_id: int
    peer_pub: Optional[str] = None
    peer_ip: Optional[str] = None


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def get_user_vps_id(telegram_id: int) -> Optional[int]:
    with db() as con:
        row = con.execute(
            "SELECT vps_id FROM user_vps WHERE telegram_id = ?",
            (telegram_id,),
        ).fetchone()
    return int(row["vps_id"]) if row and row["vps_id"] is not None else None


def get_vps_by_id(vps_id: int) -> Optional[dict]:
    with db() as con:
        row = con.execute(
            """
            SELECT id, name, host, ssh_port, ssh_user, ssh_key, iface, endpoint, endpoint_port,
                   xray_port, reality_port, reality_public_key, reality_sni, reality_short_id,
                   max_users, enabled
            FROM vps_servers
            WHERE id = ?
            """,
            (vps_id,),
        ).fetchone()

    if not row:
        return None

    return {
        "id": row["id"],
        "name": row["name"],
        "host": row["host"],
        "ssh_port": row["ssh_port"],
        "ssh_user": row["ssh_user"],
        "ssh_key": row["ssh_key"],
        "iface": row["iface"],
        "endpoint": row["endpoint"],
        "endpoint_port": row["endpoint_port"],
        "xray_port": row["xray_port"],
        "reality_port": row["reality_port"],
        "reality_public_key": row["reality_public_key"],
        "reality_sni": row["reality_sni"],
        "reality_short_id": row["reality_short_id"],
        "max_users": row["max_users"],
        "enabled": row["enabled"],
    }


def list_vps():
    with db() as con:
        rows = con.execute(
            """
            SELECT id, name, host, ssh_port, ssh_user, ssh_key, iface, endpoint, endpoint_port,
                   xray_port, reality_port, reality_public_key, reality_sni, reality_short_id,
                   max_users, enabled
            FROM vps_servers
            WHERE enabled = 1
            """
        ).fetchall()

    result = []
    for row in rows:
        result.append(
            {
                "id": row["id"],
                "name": row["name"],
                "host": row["host"],
                "ssh_port": row["ssh_port"],
                "ssh_user": row["ssh_user"],
                "ssh_key": row["ssh_key"],
                "iface": row["iface"],
                "endpoint": row["endpoint"],
                "endpoint_port": row["endpoint_port"],
                "xray_port": row["xray_port"],
                "reality_port": row["reality_port"],
                "reality_public_key": row["reality_public_key"],
                "reality_sni": row["reality_sni"],
                "reality_short_id": row["reality_short_id"],
                "max_users": row["max_users"],
                "enabled": row["enabled"],
            }
        )
    return result


def count_users_on_vps(vps_id: int) -> int:
    with db() as con:
        row = con.execute(
            "SELECT COUNT(*) AS cnt FROM user_vps WHERE vps_id = ?",
            (vps_id,),
        ).fetchone()
    return int(row["cnt"] or 0)


def assign_user_to_vps(telegram_id: int, vps_id: int):
    with db() as con:
        con.execute(
            """
            INSERT OR REPLACE INTO user_vps (telegram_id, vps_id, assigned_at)
            VALUES (?, ?, datetime('now'))
            """,
            (telegram_id, vps_id),
        )
        con.commit()


def unassign_user_vps(telegram_id: int):
    with db() as con:
        con.execute("DELETE FROM user_vps WHERE telegram_id = ?", (telegram_id,))
        con.commit()


def choose_vps_for_user(telegram_id: int) -> Optional[dict]:
    vps_id = get_user_vps_id(telegram_id)
    if vps_id:
        vps = get_vps_by_id(vps_id)
        if not vps or not vps.get("enabled"):
            unassign_user_vps(telegram_id)
        else:
            return vps

    servers = list_vps()
    if not servers:
        return None

    candidates = []
    for server in servers:
        users = count_users_on_vps(server["id"])
        max_users = int(server["max_users"] or 0)
        if users < max_users:
            candidates.append((users, server))

    if not candidates:
        return None

    candidates.sort(key=lambda x: x[0])
    chosen = candidates[0][1]
    assign_user_to_vps(telegram_id, chosen["id"])
    return chosen


def ssh_cmd(vps: dict, remote_cmd: str) -> str:
    key_path = vps["ssh_key"]

    if "BEGIN" in str(key_path):
        raise RuntimeError("ssh_key должен быть путем к файлу, а не PEM-строкой")

    if not os.path.exists(key_path):
        raise RuntimeError(f"SSH key not found: {key_path}")

    args = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=8",
        "-o", "ServerAliveInterval=5",
        "-o", "ServerAliveCountMax=1",
        "-p", str(vps["ssh_port"]),
        "-i", key_path,
        f'{vps["ssh_user"]}@{vps["host"]}',
        remote_cmd,
    ]

    try:
        p = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("SSH timeout (20s)")

    out = (p.stdout or "").strip()
    err = (p.stderr or "").strip()

    if p.returncode != 0:
        raise RuntimeError(err or out or f"ssh failed code={p.returncode}")

    return out


def create_awg_peer(vps: dict, name: str) -> dict:
    cmd = (
        f"/usr/local/bin/awg-bot create "
        f"--iface {vps['iface']} "
        f"--name {name} "
        f"--endpoint {vps['endpoint']} "
        f"--port {vps['endpoint_port']}"
    )
    out = ssh_cmd(vps, cmd)

    try:
        return json.loads(out)
    except Exception:
        raise RuntimeError(f"Bad JSON from VPS: {out[:2000]}")

def revoke_awg_peer(vps: dict, peer_pub: Optional[str], peer_ip: Optional[str]) -> None:
    if not (peer_pub or peer_ip):
        raise RuntimeError("Missing AWG peer identity")

    checks = []
    if peer_pub:
        checks.append(f"/usr/local/bin/awg-bot delete --iface {vps['iface']} --pub {peer_pub}")
        checks.append(f"/usr/local/bin/awg-bot remove --iface {vps['iface']} --pub {peer_pub}")
    if peer_ip:
        checks.append(f"/usr/local/bin/awg-bot delete --iface {vps['iface']} --peer-ip {peer_ip}")
        checks.append(f"/usr/local/bin/awg-bot remove --iface {vps['iface']} --peer-ip {peer_ip}")

    remote = " || ".join(f"({cmd})" for cmd in checks)
    ssh_cmd(vps, f"bash -lc {json.dumps(remote)}")

def ensure_awg_payload_is_compatible(payload: str) -> str:
    payload = (payload or "").strip()

    if "MTU" not in payload and "[Interface]" in payload:
        payload = payload.replace("[Interface]", "[Interface]\nMTU = 1280", 1)

    return payload


def sanitize_name(name: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "_-." else "_" for ch in (name or ""))
    return safe[:64] or f"user_{uuid.uuid4().hex[:8]}"


def create_xray_client(vps: dict, name: str) -> dict:
    preflight = ssh_cmd(
        vps,
        "if [ -x /usr/local/bin/xray-bot ]; then "
        "echo '__OK__'; "
        "else echo '__MISSING__'; "
        "ls -l /usr/local/bin/xray-bot 2>/dev/null || true; "
        "fi",
    )
    if not preflight.startswith("__OK__"):
        details = preflight.replace("__MISSING__", "").strip() or "file missing"
        raise RuntimeError(f"xray-bot not ready: {details}")

    safe_name = sanitize_name(name)
    client_id = str(uuid.uuid4())
    cmd = f"/usr/local/bin/xray-bot create {safe_name} {client_id}"
    out = ssh_cmd(vps, cmd)

    if "OK" not in out:
        raise RuntimeError(f"xray-bot failed: {out[:2000]}")

    endpoint = vps["endpoint"]
    port = vps.get("reality_port") or vps.get("xray_port") or 8443
    public_key = vps.get("reality_public_key")
    sni = vps.get("reality_sni") or "www.cloudflare.com"
    short_id = vps.get("reality_short_id") or ""
    flow = "xtls-rprx-vision"

    if not public_key:
        raise RuntimeError("reality_public_key is empty in vps_servers")

    payload = (
        f"vless://{client_id}@{endpoint}:{port}"
        f"?security=reality"
        f"&encryption=none"
        f"&type=tcp"
        f"&headerType=none"
        f"&fp=chrome"
        f"&pbk={public_key}"
        f"&sni={sni}"
        f"&sid={short_id}"
        f"&flow={flow}"
        f"#{safe_name}"
    )

    return {
        "payload": payload,
        "client_id": client_id,
    }

def revoke_xray_client(vps: dict, client_id: Optional[str]) -> None:
    if not client_id:
        raise RuntimeError("Missing XRay client id")
    cmd = (
        f"(/usr/local/bin/xray-bot delete {client_id})"
        f" || (/usr/local/bin/xray-bot remove {client_id})"
    )
    ssh_cmd(vps, f"bash -lc {json.dumps(cmd)}")

@app.get("/health")
def health():
    return {"ok": True}


@app.post("/keys")
def create_key(data: KeyRequest, authorization: Optional[str] = Header(default=None)):
    if ISSUER_TOKEN:
        expected = f"Bearer {ISSUER_TOKEN}"
        if authorization != expected:
            raise HTTPException(status_code=401, detail="Unauthorized")

    kind = data.kind.strip().lower()
    telegram_id = data.telegram_id

    if kind not in {"awg", "xray"}:
        raise HTTPException(status_code=400, detail="Unknown key kind")

    vps = choose_vps_for_user(telegram_id)
    if not vps:
        raise HTTPException(status_code=400, detail="No available VPS")

    try:
        name = sanitize_name(f"user_{telegram_id}_{uuid.uuid4().hex[:8]}")

        if kind == "awg":
            result = create_awg_peer(vps, name=name)
            payload = ensure_awg_payload_is_compatible(result["payload"])
            return {
                "payload": payload,
                "vps_id": vps["id"],
                "peer_pub": result.get("peer_pub"),
                "peer_ip": result.get("peer_ip"),
            }

        result = create_xray_client(vps, name=name)
        client_id = result.get("client_id") or result.get("uuid") or result.get("id")
        return {
            "payload": result["payload"],
            "vps_id": vps["id"],
            "peer_pub": client_id,
            "peer_ip": None,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/keys/revoke")
def revoke_key(data: RevokeKeyRequest, authorization: Optional[str] = Header(default=None)):
    if ISSUER_TOKEN:
        expected = f"Bearer {ISSUER_TOKEN}"
        if authorization != expected:
            raise HTTPException(status_code=401, detail="Unauthorized")

    kind = data.kind.strip().lower()
    if kind not in {"awg", "xray"}:
        raise HTTPException(status_code=400, detail="Unknown key kind")

    vps = get_vps_by_id(data.vps_id)
    if not vps:
        raise HTTPException(status_code=400, detail="Unknown VPS")

    try:
        if kind == "awg":
            revoke_awg_peer(vps, peer_pub=data.peer_pub, peer_ip=data.peer_ip)
        else:
            revoke_xray_client(vps, client_id=data.peer_pub)
        return {"ok": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
