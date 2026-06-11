import sqlite3
import unittest
from datetime import timedelta

from app.db.migrations import ensure_vk_tables
from app.services.portal import consume_vk_link_code, create_vk_link_code, get_vk_link_by_portal_user, utcnow


class VkLinkingTests(unittest.TestCase):
    def setUp(self):
        self.con = sqlite3.connect(":memory:")
        self.con.row_factory = sqlite3.Row
        self.con.execute(
            """
            CREATE TABLE portal_users (
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
        self.con.execute(
            """
            INSERT INTO portal_users (id, telegram_id, login, password_salt, password_hash, created_at, updated_at)
            VALUES (1, NULL, 'site-user', '', '', '', '')
            """
        )
        ensure_vk_tables(self.con)

    def tearDown(self):
        self.con.close()

    def test_profile_vk_link_code_does_not_require_telegram_id(self):
        code = create_vk_link_code(self.con, portal_user_id=1, telegram_id=None)

        code_row = self.con.execute("SELECT portal_user_id, telegram_id FROM vk_link_codes WHERE code = ?", (code,)).fetchone()
        self.assertEqual(code_row["portal_user_id"], 1)
        self.assertIsNone(code_row["telegram_id"])

        ok, message = consume_vk_link_code(self.con, code, vk_user_id=12345)

        self.assertTrue(ok, message)
        link = get_vk_link_by_portal_user(self.con, 1)
        self.assertIsNotNone(link)
        self.assertEqual(link["vk_user_id"], 12345)
        self.assertEqual(link["portal_user_id"], 1)
        self.assertIsNone(link["telegram_id"])

    def test_legacy_telegram_only_vk_code_still_links_by_telegram_id(self):
        now = utcnow()
        expires_at = now + timedelta(minutes=10)
        self.con.execute(
            """
            INSERT INTO vk_link_codes (code, portal_user_id, telegram_id, created_at, expires_at)
            VALUES ('LEGACY', NULL, 777, ?, ?)
            """,
            (now.isoformat(), expires_at.isoformat()),
        )

        ok, message = consume_vk_link_code(self.con, "LEGACY", vk_user_id=54321)

        self.assertTrue(ok, message)
        link = self.con.execute("SELECT * FROM vk_links WHERE vk_user_id = ?", (54321,)).fetchone()
        self.assertIsNotNone(link)
        self.assertIsNone(link["portal_user_id"])
        self.assertEqual(link["telegram_id"], 777)


if __name__ == "__main__":
    unittest.main()