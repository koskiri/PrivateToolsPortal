from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv

# Корень проекта PrivateToolsPortal.
# config.py лежит в app/core/, поэтому поднимаемся на два уровня выше.
BASE_DIR = Path(__file__).resolve().parents[2]
load_dotenv(BASE_DIR / ".env")

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
