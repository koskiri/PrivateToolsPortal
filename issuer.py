import shlex
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

# ===== AWG settings =====
AWG_INTERFACE = os.getenv("AWG_INTERFACE", "awg0").strip() or "awg0"
AWG_CONFIG_DIR = os.getenv("AWG_CONFIG_DIR", "/etc/amnezia/amneziawg").strip() or "/etc/amnezia/amneziawg"
AWG_DNS = os.getenv("AWG_DNS", "1.1.1.1").strip() or "1.1.1.1"
AWG_ALLOWED_IPS = os.getenv("AWG_ALLOWED_IPS", "0.0.0.0/0").strip() or "0.0.0.0/0"
AWG_KEEPALIVE = int(os.getenv("AWG_KEEPALIVE", "25").strip() or "25")

AWG_JC = int(os.getenv("AWG_JC", "4").strip() or "4")
AWG_JMIN = int(os.getenv("AWG_JMIN", "40").strip() or "40")
AWG_JMAX = int(os.getenv("AWG_JMAX", "80").strip() or "80")
AWG_S1 = int(os.getenv("AWG_S1", "60").strip() or "60")
AWG_S2 = int(os.getenv("AWG_S2", "40").strip() or "40")
AWG_H1 = int(os.getenv("AWG_H1", "12345678").strip() or "12345678")
AWG_H2 = int(os.getenv("AWG_H2", "87654321").strip() or "87654321")
AWG_H3 = int(os.getenv("AWG_H3", "23456789").strip() or "23456789")
AWG_H4 = int(os.getenv("AWG_H4", "98765432").strip() or "98765432")


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


def ssh_cmd_full(vps: dict, remote_cmd: str, timeout: int = 20) -> tuple[int, str, str]:
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
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"SSH timeout ({timeout}s)")

    out = (p.stdout or "").strip()
    err = (p.stderr or "").strip()
    return p.returncode, out, err


def restart_xray_reality(vps: dict) -> None:
    restart_cmd = (
        "sudo systemctl restart xray-reality.service && "
        "sudo systemctl is-active xray-reality.service"
    )
    code, out, err = ssh_cmd_full(vps, restart_cmd, timeout=30)
    if code != 0 or out.strip() != "active":
        raise RuntimeError(
            f"Не удалось перезапустить xray-reality.service: {(err or out or f'code={code}')[:2000]}"
        )


def sanitize_name(name: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "_-." else "_" for ch in (name or ""))
    return safe[:64] or f"user_{uuid.uuid4().hex[:8]}"


def get_awg_server_public_key(vps: dict) -> str:
    cmd = f"awg show {AWG_INTERFACE}"
    out = ssh_cmd(vps, f"bash -lc {shlex.quote(cmd)}")

    for line in out.splitlines():
        line = line.strip()
        if line.startswith("public key:"):
            pub = line.split("public key:", 1)[1].strip()
            if pub:
                return pub

    raise RuntimeError("Не удалось получить public key сервера AWG")


def get_next_awg_ip(vps: dict) -> str:
    remote_script = f"""
python3 - <<'PY'
import re
from pathlib import Path

path = Path("{AWG_CONFIG_DIR}/{AWG_INTERFACE}.conf")
text = path.read_text(encoding="utf-8") if path.exists() else ""

used = set(re.findall(r"AllowedIPs\\s*=\\s*(10\\.66\\.66\\.\\d+)/32", text))

for i in range(2, 255):
    ip = f"10.66.66.{{i}}"
    if ip not in used:
        print(ip)
        break
else:
    raise SystemExit(1)
PY
""".strip()
    out = ssh_cmd(vps, remote_script)
    ip_addr = (out or "").strip()
    if not ip_addr:
        raise RuntimeError("Не удалось подобрать свободный IP для AWG клиента")
    return ip_addr


def build_awg_client_payload(
    *,
    client_private_key: str,
    client_ip: str,
    server_public_key: str,
    endpoint: str,
    port: int,
) -> str:
    return (
        "[Interface]\n"
        f"PrivateKey = {client_private_key}\n"
        f"Address = {client_ip}/32\n"
        f"DNS = {AWG_DNS}\n"
        "\n"
        f"Jc = {AWG_JC}\n"
        f"Jmin = {AWG_JMIN}\n"
        f"Jmax = {AWG_JMAX}\n"
        f"S1 = {AWG_S1}\n"
        f"S2 = {AWG_S2}\n"
        f"H1 = {AWG_H1}\n"
        f"H2 = {AWG_H2}\n"
        f"H3 = {AWG_H3}\n"
        f"H4 = {AWG_H4}\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {server_public_key}\n"
        f"Endpoint = {endpoint}:{port}\n"
        f"AllowedIPs = {AWG_ALLOWED_IPS}\n"
        f"PersistentKeepalive = {AWG_KEEPALIVE}\n"
    )


def create_awg_peer(vps: dict, name: str) -> dict:
    client_ip = get_next_awg_ip(vps)

    remote_cmd = f"""
set -euo pipefail

export CLIENT_PRIV="$(awg genkey)"
export CLIENT_PUB="$(echo "$CLIENT_PRIV" | awg pubkey)"
export CLIENT_IP="{client_ip}"

if [ -z "$CLIENT_PRIV" ]; then
  echo "CLIENT_PRIV is empty" >&2
  exit 1
fi

if [ -z "$CLIENT_PUB" ]; then
  echo "CLIENT_PUB is empty" >&2
  exit 1
fi

awg set {AWG_INTERFACE} peer "$CLIENT_PUB" allowed-ips "$CLIENT_IP/32"
awg-quick save {AWG_INTERFACE} >/dev/null

python3 -c 'import json, os; print(json.dumps({{
    "client_private_key": os.environ["CLIENT_PRIV"],
    "client_public_key": os.environ["CLIENT_PUB"],
    "client_ip": os.environ["CLIENT_IP"]
}}))'
""".strip()

    out = ssh_cmd(vps, f"bash -lc {shlex.quote(remote_cmd)}")

    try:
        data = json.loads(out)
    except Exception:
        raise RuntimeError(f"Bad JSON from VPS while creating AWG peer: {out[:2000]}")

    client_private_key = (data.get("client_private_key") or "").strip()
    client_public_key = (data.get("client_public_key") or "").strip()
    client_ip = (data.get("client_ip") or "").strip()

    if not client_private_key or not client_public_key or not client_ip:
        raise RuntimeError("VPS не вернул данные AWG клиента")

    server_public_key = get_awg_server_public_key(vps)
    payload = build_awg_client_payload(
        client_private_key=client_private_key,
        client_ip=client_ip,
        server_public_key=server_public_key,
        endpoint=vps["endpoint"],
        port=int(vps["endpoint_port"]),
    )

    return {
        "payload": payload,
        "peer_pub": client_public_key,
        "peer_ip": client_ip,
    }


def revoke_awg_peer(vps: dict, peer_pub: Optional[str], peer_ip: Optional[str]) -> None:
    if not peer_pub:
        raise RuntimeError("Missing AWG peer public key")

    cmd = (
        f"set -euo pipefail; "
        f"awg set {AWG_INTERFACE} peer {shlex.quote(peer_pub)} remove; "
        f"awg-quick save {AWG_INTERFACE} >/dev/null"
    )
    ssh_cmd(vps, f"bash -lc {shlex.quote(cmd)}")


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

    restart_xray_reality(vps)

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
    restart_xray_reality(vps)


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
            return {
                "payload": result["payload"],
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