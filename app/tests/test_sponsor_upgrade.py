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

from app.services.portal import (  # noqa: E402
    apply_sponsor_upgrade,
    create_referral_invite,
    ensure_sponsor_referral_code,
    get_or_create_invite_for_referral_code,
    get_user_invite_stats,
    revoke_referral_invite,
)


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
    
class ReferralQrAndRevokeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.con = sqlite3.connect(":memory:")
        self.con.row_factory = sqlite3.Row
        self.con.executescript(
            """
            CREATE TABLE portal_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id INTEGER UNIQUE,
                login TEXT,
                role TEXT,
                referral_code TEXT UNIQUE,
                updated_at TEXT
            );
            CREATE TABLE portal_invites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                invite_code TEXT NOT NULL UNIQUE,
                telegram_id INTEGER,
                created_at TEXT NOT NULL,
                used_at TEXT,
                revoked_at TEXT,
                plan TEXT,
                title TEXT,
                key_limit INTEGER,
                price_rub INTEGER,
                duration_days INTEGER,
                invited_by_user_id INTEGER,
                created_by_user_id INTEGER,
                used_by_user_id INTEGER
            );
            """
        )
        self.con.execute(
            "INSERT INTO portal_users (id, telegram_id, login, role, updated_at) VALUES (1, 2001, 'sponsor', 'sponsor', '')"
        )
        self.con.execute(
            "INSERT INTO portal_users (id, telegram_id, login, role, updated_at) VALUES (2, 2002, 'user', 'user', '')"
        )

    def tearDown(self) -> None:
        self.con.close()

    def test_sponsor_gets_stable_referral_code(self) -> None:
        first = ensure_sponsor_referral_code(self.con, 1)
        second = ensure_sponsor_referral_code(self.con, 1)

        self.assertTrue(first)
        self.assertEqual(first, second)

    def test_referral_link_uses_existing_free_invite(self) -> None:
        code = ensure_sponsor_referral_code(self.con, 1)
        self.con.execute(
            "INSERT INTO portal_invites (invite_code, created_at, invited_by_user_id, created_by_user_id) VALUES ('free-invite', '2026-06-08T12:00:00+00:00', 1, 1)"
        )

        invite = get_or_create_invite_for_referral_code(self.con, code)

        self.assertEqual(invite["invite_code"], "free-invite")
        self.assertEqual(self.con.execute("SELECT COUNT(*) AS c FROM portal_invites").fetchone()["c"], 1)

    def test_referral_link_creates_invite_when_none_available(self) -> None:
        code = ensure_sponsor_referral_code(self.con, 1)

        invite = get_or_create_invite_for_referral_code(self.con, code)

        self.assertTrue(invite["invite_code"])
        self.assertEqual(invite["duration_days"], 3)
        self.assertIn("3 дня", invite["title"])
        stats = get_user_invite_stats(self.con, 1)
        self.assertEqual(int(stats["available"] or 0), 1)
    
    def test_new_referral_invite_defaults_to_three_free_days(self) -> None:
        referral = create_referral_invite(self.con, 1)

        invite = self.con.execute(
            "SELECT duration_days, title, used_at FROM portal_invites WHERE invite_code = ?",
            (referral["invite_code"],),
        ).fetchone()

        self.assertIsNotNone(invite)
        self.assertEqual(invite["duration_days"], 3)
        self.assertIn("3 дня", invite["title"])
        self.assertIsNone(invite["used_at"])

    def test_referral_link_rejects_regular_user_code(self) -> None:
        user_code = ensure_sponsor_referral_code(self.con, 2)

        with self.assertRaises(PermissionError):
            get_or_create_invite_for_referral_code(self.con, user_code)

    def test_sponsor_can_revoke_own_unused_invite_and_stats_exclude_it(self) -> None:
        self.con.execute(
            "INSERT INTO portal_invites (id, invite_code, created_at, invited_by_user_id, created_by_user_id) VALUES (10, 'unused', '2026-06-08T12:00:00+00:00', 1, 1)"
        )

        self.assertTrue(revoke_referral_invite(self.con, 1, 10))
        stats = get_user_invite_stats(self.con, 1)
        self.assertEqual(int(stats["available"] or 0), 0)

    def test_sponsor_cannot_revoke_used_invite(self) -> None:
        self.con.execute(
            "INSERT INTO portal_invites (id, invite_code, created_at, used_at, invited_by_user_id, created_by_user_id) VALUES (11, 'used', '2026-06-08T12:00:00+00:00', '2026-06-09T12:00:00+00:00', 1, 1)"
        )

        self.assertFalse(revoke_referral_invite(self.con, 1, 11))

    def test_sponsor_cannot_revoke_foreign_invite(self) -> None:
        self.con.execute(
            "INSERT INTO portal_invites (id, invite_code, created_at, invited_by_user_id, created_by_user_id) VALUES (12, 'foreign', '2026-06-08T12:00:00+00:00', 2, 2)"
        )

        self.assertFalse(revoke_referral_invite(self.con, 1, 12))

class InviteActivationAccessTests(unittest.TestCase):
    def setUp(self) -> None:
        self._install_fastapi_stubs()
        sys.modules.pop("app.core.security", None)
        sys.modules.pop("app.routers.auth", None)
        self.auth = importlib.import_module("app.routers.auth")
        self.con = sqlite3.connect(":memory:")
        self.con.row_factory = sqlite3.Row
        self.con.executescript(
            """
            CREATE TABLE portal_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id INTEGER UNIQUE,
                login TEXT NOT NULL UNIQUE,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                invited_by_user_id INTEGER,
                revoked_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE portal_invites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                invite_code TEXT NOT NULL UNIQUE,
                telegram_id INTEGER,
                created_at TEXT NOT NULL,
                used_at TEXT,
                revoked_at TEXT,
                plan TEXT,
                title TEXT,
                key_limit INTEGER,
                price_rub INTEGER,
                duration_days INTEGER,
                invited_by_user_id INTEGER,
                created_by_user_id INTEGER,
                used_by_user_id INTEGER
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
        self.auth.get_db_connection = lambda: self.con
        self.auth.get_current_user = lambda request: None

    def tearDown(self) -> None:
        self.con.close()

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

            def set_cookie(self, *args, **kwargs):
                pass

        responses_stub.RedirectResponse = RedirectResponse
        responses_stub.HTMLResponse = type("HTMLResponse", (), {})
        responses_stub.Response = type("Response", (), {})
        responses_stub.JSONResponse = type("JSONResponse", (), {})

        templating_stub = types.ModuleType("fastapi.templating")

        class Jinja2Templates:
            def __init__(self, *args, **kwargs):
                pass

            def TemplateResponse(self, *args, **kwargs):
                return kwargs

        templating_stub.Jinja2Templates = Jinja2Templates

        sys.modules["fastapi"] = fastapi_stub
        sys.modules["fastapi.responses"] = responses_stub
        sys.modules["fastapi.templating"] = templating_stub

    def _create_invite(self, code: str, duration_days: int | None = 3) -> None:
        self.con.execute(
            """
            INSERT INTO portal_invites
            (invite_code, created_at, plan, title, key_limit, price_rub, duration_days, invited_by_user_id, created_by_user_id)
            VALUES (?, '2026-06-08T12:00:00+00:00', 'plan_5_keys', 'Реферальный тариф', 5, 100, ?, 1, 1)
            """,
            (code, duration_days),
        )

    def test_new_user_registration_by_invite_grants_three_days(self) -> None:
        self._create_invite("three-day-invite", 3)
        before = datetime.now(timezone.utc) + timedelta(days=3)

        response = asyncio.run(
            self.auth.activate_submit(object(), code="three-day-invite", login="friend", password="secret1")
        )
        after = datetime.now(timezone.utc) + timedelta(days=3)

        self.assertEqual(response.status_code, 303)
        subscription = self.con.execute("SELECT active_until FROM subscriptions").fetchone()
        self.assertIsNotNone(subscription)
        active_until = datetime.fromisoformat(subscription["active_until"])
        self.assertGreaterEqual(active_until, before)
        self.assertLessEqual(active_until, after)

    def test_existing_invite_duration_is_preserved_on_activation(self) -> None:
        self._create_invite("old-duration-invite", 30)
        before = datetime.now(timezone.utc) + timedelta(days=30)

        asyncio.run(self.auth.activate_submit(object(), code="old-duration-invite", login="legacy", password="secret1"))
        after = datetime.now(timezone.utc) + timedelta(days=30)

        active_until = datetime.fromisoformat(
            self.con.execute("SELECT active_until FROM subscriptions").fetchone()["active_until"]
        )
        self.assertGreaterEqual(active_until, before)
        self.assertLessEqual(active_until, after)

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

        class FakeCursor:
            rowcount = 0

        class FakeConnection:
            total_changes = 0

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def execute(self, *args, **kwargs):
                return FakeCursor()

            def commit(self):
                self.committed = True

        fake_connection = FakeConnection()
        self.dashboard.get_db_connection = lambda: fake_connection

        response = asyncio.run(self.dashboard.dashboard_create_referral_invite(object()))

        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.url, "/dashboard?success=Новая+инвайт-ссылка+создана")
        self.assertTrue(getattr(fake_connection, "committed", False))

    def test_revoke_invite_forbids_regular_user_without_opening_db(self) -> None:
        self.dashboard.get_current_user = lambda request: self._user("user")
        self.dashboard.get_db_connection = lambda: self.fail("regular user must not open DB connection")

        response = asyncio.run(self.dashboard.new_ui_revoke_invite(object(), 10))

        self.assertEqual(response.status_code, 303)
        self.assertIn("только+спонсоры", response.url)

class DashboardRenewSubscriptionTests(unittest.TestCase):
    def setUp(self) -> None:
        DashboardReferralInviteRouteTests._install_fastapi_stubs(self)
        sys.modules.pop("app.routers.dashboard", None)
        self.dashboard = importlib.import_module("app.routers.dashboard")
        self.now = datetime(2026, 6, 8, 12, 0, tzinfo=timezone.utc)
        self.dashboard.utcnow = lambda: self.now
        self.con = sqlite3.connect(":memory:")
        self.con.row_factory = sqlite3.Row
        self.con.executescript(
            """
            CREATE TABLE subscriptions (
                telegram_id INTEGER PRIMARY KEY,
                active_until TEXT,
                plan TEXT,
                key_limit INTEGER,
                price_rub INTEGER,
                title TEXT
            );
            CREATE TABLE payments (
                payment_id TEXT PRIMARY KEY,
                status TEXT
            );
            CREATE TABLE payment_actions (
                payment_id TEXT PRIMARY KEY,
                telegram_id INTEGER,
                action TEXT,
                target_plan_key TEXT,
                amount_rub INTEGER,
                status TEXT,
                created_at TEXT,
                updated_at TEXT
            );
            CREATE TABLE user_wallets (
                telegram_id INTEGER PRIMARY KEY,
                balance_rub INTEGER,
                updated_at TEXT
            );
            """
        )

    def tearDown(self) -> None:
        self.con.close()

    def _insert_subscription(self, active_until: str | None, telegram_id: int = 3001) -> None:
        self.con.execute(
            (
                "INSERT INTO subscriptions "
                "(telegram_id, active_until, plan, key_limit, price_rub, title) "
                "VALUES (?, ?, 'plan_5_keys', 5, 100, '100 ₽ / 5 ключей')"
            ),
            (telegram_id, active_until),
        )

    def _payment_action_row(
        self, action: str = "renew", target_plan_key: str | None = None, telegram_id: int = 3001
    ) -> sqlite3.Row:
        self.con.execute("INSERT INTO payments (payment_id, status) VALUES ('payment-1', 'pending')")
        self.con.execute(
            (
                "INSERT INTO payment_actions "
                "(payment_id, telegram_id, action, target_plan_key, amount_rub, status, created_at, updated_at) "
                "VALUES ('payment-1', ?, ?, ?, 100, 'pending', '', '')"
            ),
            (telegram_id, action, target_plan_key),
        )
        return self.con.execute("SELECT * FROM payment_actions WHERE payment_id = 'payment-1'").fetchone()

    def test_payment_renew_future_active_until_adds_30_days_to_existing_date(self) -> None:
        active_until = self.now + timedelta(days=10)
        self._insert_subscription(active_until.isoformat())

        error = self.dashboard._apply_payment_action(self.con, self._payment_action_row())

        subscription = self.con.execute("SELECT active_until FROM subscriptions WHERE telegram_id = 3001").fetchone()
        self.assertIsNone(error)
        self.assertEqual(datetime.fromisoformat(subscription["active_until"]), active_until + timedelta(days=30))

    def test_payment_renew_expired_active_until_starts_from_now(self) -> None:
        active_until = self.now - timedelta(days=1)
        self._insert_subscription(active_until.isoformat())

        error = self.dashboard._apply_payment_action(self.con, self._payment_action_row())

        subscription = self.con.execute("SELECT active_until FROM subscriptions WHERE telegram_id = 3001").fetchone()
        self.assertIsNone(error)
        self.assertEqual(datetime.fromisoformat(subscription["active_until"]), self.now + timedelta(days=30))

    def test_payment_renew_null_active_until_starts_from_now_without_error(self) -> None:
        self._insert_subscription(None)

        error = self.dashboard._apply_payment_action(self.con, self._payment_action_row())

        subscription = self.con.execute("SELECT active_until FROM subscriptions WHERE telegram_id = 3001").fetchone()
        self.assertIsNone(error)
        self.assertEqual(datetime.fromisoformat(subscription["active_until"]), self.now + timedelta(days=30))

    def test_internal_balance_renew_null_active_until_starts_from_now_without_error(self) -> None:
        self._insert_subscription(None)
        self.con.execute(
            "INSERT INTO user_wallets (telegram_id, balance_rub, updated_at) VALUES (3001, 100, '')"
        )
        self.dashboard.get_current_user = lambda request: {"telegram_id": 3001}
        self.dashboard.get_db_connection = lambda: self.con
        self.dashboard.yookassa_enabled = lambda: True

        response = asyncio.run(self.dashboard.dashboard_subscription_action(object(), "renew"))

        subscription = self.con.execute("SELECT active_until FROM subscriptions WHERE telegram_id = 3001").fetchone()
        wallet = self.con.execute("SELECT balance_rub FROM user_wallets WHERE telegram_id = 3001").fetchone()
        self.assertEqual(response.status_code, 303)
        self.assertIn("Оплачено+с+внутреннего+баланса", response.url)
        self.assertEqual(datetime.fromisoformat(subscription["active_until"]), self.now + timedelta(days=30))
        self.assertEqual(wallet["balance_rub"], 0)

    def test_same_plan_change_null_active_until_starts_from_now_without_error(self) -> None:
        self._insert_subscription(None)

        error = self.dashboard._apply_payment_action(
            self.con,
            self._payment_action_row(action="change_plan", target_plan_key="plan_5"),
        )

        subscription = self.con.execute(
            "SELECT active_until, plan FROM subscriptions WHERE telegram_id = 3001"
        ).fetchone()
        self.assertIsNone(error)
        self.assertEqual(subscription["plan"], "plan_5_keys")
        self.assertEqual(datetime.fromisoformat(subscription["active_until"]), self.now + timedelta(days=30))

if __name__ == "__main__":
    unittest.main()