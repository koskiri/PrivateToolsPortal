from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from app.services.portal import (
    get_vk_confirmation_code,
    get_vk_secret,
    handle_vk_message_new,
)

router = APIRouter()


@router.post("/vk/callback")
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
