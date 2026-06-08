from __future__ import annotations

import asyncio
import importlib
import sqlite3
import sys
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

# The production environment provides python-dotenv, but these unit tests only
# need config constants loaded by app.core.config during service import.
dotenv_stub = types.ModuleType("dotenv")
dotenv_stub.load_dotenv = lambda *args, **kwargs: None
sys.modules.setdefault("dotenv", dotenv_stub)

from app.services.portal import apply_sponsor_upgrade  # noqa: E402


class SponsorUpgradeAccessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.con = sqlite3.connect(":memory:")
        self.con.row_factory = sqlite3.Row
        self.con.executescript(
            """
            CREATE TABLE portal_users (
                telegram_id INTEGER PRIMARY KEY,
                role TEXT,
                updated_at TEXT
            );
            CREATE TABLE subscriptions (
                telegram_id INTEGER PRIMARY KEY,
                active_until TEXT,
                plan TEXT,
                key_limit INTEGER,
                price_rub INTEGER,
                title TEXT
            );
            """
        )
        self.now = datetime(2026, 6, 8, 12, 0, tzinfo=timezone.utc)

    def tearDown(self) -> None:
        self.con.close()

    def test_user_sponsor_payment_grants_role_and_adds_365_days_to_active_subscription(self) -> None:
        telegram_id = 1001
        active_until = self.now + timedelta(days=10)
        self.con.execute("INSERT INTO portal_users (telegram_id, role, updated_at) VALUES (?, 'user', '')", (telegram_id,))
        self.con.execute(
            "INSERT INTO subscriptions (telegram_id, active_until) VALUES (?, ?)",
            (telegram_id, active_until.isoformat()),
        )

        self.assertTrue(apply_sponsor_upgrade(self.con, telegram_id, self.now))

        user = self.con.execute("SELECT role FROM portal_users WHERE telegram_id = ?", (telegram_id,)).fetchone()
        subscription = self.con.execute("SELECT active_until FROM subscriptions WHERE telegram_id = ?", (telegram_id,)).fetchone()
        self.assertEqual(user["role"], "sponsor")
        self.assertEqual(datetime.fromisoformat(subscription["active_until"]), active_until + timedelta(days=365))

    def test_existing_sponsor_payment_does_not_change_active_until(self) -> None:
        telegram_id = 1002
        active_until = self.now + timedelta(days=20)
        self.con.execute("INSERT INTO portal_users (telegram_id, role, updated_at) VALUES (?, 'sponsor', '')", (telegram_id,))
        self.con.execute(
            "INSERT INTO subscriptions (telegram_id, active_until) VALUES (?, ?)",
            (telegram_id, active_until.isoformat()),
        )

        self.assertFalse(apply_sponsor_upgrade(self.con, telegram_id, self.now))

        subscription = self.con.execute("SELECT active_until FROM subscriptions WHERE telegram_id = ?", (telegram_id,)).fetchone()
        self.assertEqual(datetime.fromisoformat(subscription["active_until"]), active_until)

    def test_reprocessing_same_user_after_role_change_does_not_add_extra_days(self) -> None:
        telegram_id = 1003
        active_until = self.now + timedelta(days=30)
        self.con.execute("INSERT INTO portal_users (telegram_id, role, updated_at) VALUES (?, 'user', '')", (telegram_id,))
        self.con.execute(
            "INSERT INTO subscriptions (telegram_id, active_until) VALUES (?, ?)",
            (telegram_id, active_until.isoformat()),
        )

        self.assertTrue(apply_sponsor_upgrade(self.con, telegram_id, self.now))
        after_first = self.con.execute("SELECT active_until FROM subscriptions WHERE telegram_id = ?", (telegram_id,)).fetchone()["active_until"]
        self.assertFalse(apply_sponsor_upgrade(self.con, telegram_id, self.now))
        after_second = self.con.execute("SELECT active_until FROM subscriptions WHERE telegram_id = ?", (telegram_id,)).fetchone()["active_until"]

        self.assertEqual(after_second, after_first)

    def test_expired_or_null_active_until_starts_from_now(self) -> None:
        telegram_id = 1004
        self.con.execute("INSERT INTO portal_users (telegram_id, role, updated_at) VALUES (?, 'user', '')", (telegram_id,))
        self.con.execute("INSERT INTO subscriptions (telegram_id, active_until) VALUES (?, NULL)", (telegram_id,))

        self.assertTrue(apply_sponsor_upgrade(self.con, telegram_id, self.now))

        subscription = self.con.execute("SELECT active_until FROM subscriptions WHERE telegram_id = ?", (telegram_id,)).fetchone()
        self.assertEqual(datetime.fromisoformat(subscription["active_until"]), self.now + timedelta(days=365))

    def test_user_without_subscription_row_gets_role_and_active_until_from_now(self) -> None:
        telegram_id = 1005
        self.con.execute("INSERT INTO portal_users (telegram_id, role, updated_at) VALUES (?, 'user', '')", (telegram_id,))

        self.assertTrue(apply_sponsor_upgrade(self.con, telegram_id, self.now))

        user = self.con.execute("SELECT role FROM portal_users WHERE telegram_id = ?", (telegram_id,)).fetchone()
        subscription = self.con.execute("SELECT active_until FROM subscriptions WHERE telegram_id = ?", (telegram_id,)).fetchone()
        self.assertEqual(user["role"], "sponsor")
        self.assertIsNotNone(subscription)
        self.assertEqual(datetime.fromisoformat(subscription["active_until"]), self.now + timedelta(days=365))

    def test_dashboard_hides_sponsor_upgrade_button_for_sponsor_and_shows_access_copy(self) -> None:
        template = Path("templates/new/dashboard.html").read_text(encoding="utf-8")
        sponsor_branch = template.split("{% if is_sponsor %}", 1)[1].split("{% else %}", 1)[0]
        self.assertNotIn("/dashboard/sponsor-upgrade", sponsor_branch)
        self.assertIn("Единоразово 5 000 ₽ · включает 1 год доступа", template)

class DashboardReferralInviteRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self._install_fastapi_stubs()
        sys.modules.pop("app.routers.dashboard", None)
        self.dashboard = importlib.import_module("app.routers.dashboard")

    def _install_fastapi_stubs(self) -> None:
        fastapi_stub = types.ModuleType("fastapi")

        class APIRouter:
            def get(self, *args, **kwargs):
                return lambda func: func

            def post(self, *args, **kwargs):
                return lambda func: func

        def Form(default=None, *args, **kwargs):
            return default

        class Request:
            pass

        fastapi_stub.APIRouter = APIRouter
        fastapi_stub.Form = Form
        fastapi_stub.Request = Request

        responses_stub = types.ModuleType("fastapi.responses")

        class RedirectResponse:
            def __init__(self, url, status_code=307, *args, **kwargs):
                self.headers = {"location": url}
                self.status_code = status_code
                self.url = url

        responses_stub.RedirectResponse = RedirectResponse
        responses_stub.HTMLResponse = type("HTMLResponse", (), {})
        responses_stub.Response = type("Response", (), {})
        responses_stub.JSONResponse = type("JSONResponse", (), {})

        templating_stub = types.ModuleType("fastapi.templating")

        class Jinja2Templates:
            def __init__(self, *args, **kwargs):
                pass

        templating_stub.Jinja2Templates = Jinja2Templates

        sys.modules["fastapi"] = fastapi_stub
        sys.modules["fastapi.responses"] = responses_stub
        sys.modules["fastapi.templating"] = templating_stub

    @staticmethod
    def _user(role: str) -> dict[str, object]:
        return {"id": 42, "telegram_id": 1006, "role": role}

    def test_referral_invite_redirects_unauthorized_before_using_user(self) -> None:
        self.dashboard.get_current_user = lambda request: None

        response = asyncio.run(self.dashboard.dashboard_create_referral_invite(object()))

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.url, "/login")

    def test_referral_invite_forbids_regular_user_without_creating_invite(self) -> None:
        self.dashboard.get_current_user = lambda request: self._user("user")
        self.dashboard.get_db_connection = lambda: self.fail("regular user must not open DB connection")

        response = asyncio.run(self.dashboard.dashboard_create_referral_invite(object()))

        self.assertEqual(response.status_code, 303)
        self.assertIn("только+спонсорам", response.url)

    def test_referral_invite_allows_sponsor_to_create_invite(self) -> None:
        self.dashboard.get_current_user = lambda request: self._user("sponsor")
        self.dashboard.get_user_invite_stats = lambda con, user_id: {"available": 0}
        self.dashboard.create_referral_invite = lambda con, user_id: {
            "invite_code": "invite-code",
            "created_at": "2026-06-08T12:00:00+00:00",
        }

        class FakeConnection:
            total_changes = 0

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def execute(self, *args, **kwargs):
                return None

            def commit(self):
                self.committed = True

        fake_connection = FakeConnection()
        self.dashboard.get_db_connection = lambda: fake_connection

        response = asyncio.run(self.dashboard.dashboard_create_referral_invite(object()))

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.url, "/dashboard?success=Новая+инвайт-ссылка+создана")
        self.assertTrue(getattr(fake_connection, "committed", False))

if __name__ == "__main__":
    unittest.main()