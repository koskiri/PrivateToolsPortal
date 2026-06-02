from __future__ import annotations

import sqlite3

from app.core.db import get_db_connection


def ensure_auth_tables() -> None:
    with get_db_connection() as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS portal_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id INTEGER NOT NULL UNIQUE,
                login TEXT NOT NULL UNIQUE,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                revoked_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )

        con.execute(
            """
            CREATE TABLE IF NOT EXISTS portal_invites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                invite_code TEXT NOT NULL UNIQUE,
                telegram_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                used_at TEXT
            )
            """
        )

        con.execute(
            """
            CREATE TABLE IF NOT EXISTS portal_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL UNIQUE,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES portal_users(id)
            )
            """
        )
        # Legacy deployments can have strict telegram_id requirements.
        # We keep the column for compatibility with subscription stats,
        # but allow NULL so users/invites can exist without Telegram.
        migrate_telegram_columns(con)
        ensure_support_tables(con)
        ensure_billing_tables(con)
        ensure_vk_tables(con)
        ensure_referral_tables(con)

def ensure_support_tables(con: sqlite3.Connection) -> None:
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS support_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            closed_at TEXT,
            rating INTEGER,
            feedback TEXT
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS support_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL,
            telegram_id INTEGER NOT NULL,
            sender_role TEXT NOT NULL,
            sender_id INTEGER NOT NULL,
            text TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    ticket_columns = {row["name"] for row in con.execute("PRAGMA table_info(support_tickets)").fetchall()}
    if "subject" not in ticket_columns:
        con.execute("ALTER TABLE support_tickets ADD COLUMN subject TEXT")
    if "category" not in ticket_columns:
        con.execute("ALTER TABLE support_tickets ADD COLUMN category TEXT")
    if "priority" not in ticket_columns:
        con.execute("ALTER TABLE support_tickets ADD COLUMN priority TEXT")
    if "updated_at" not in ticket_columns:
        con.execute("ALTER TABLE support_tickets ADD COLUMN updated_at TEXT")

def ensure_billing_tables(con: sqlite3.Connection) -> None:
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS user_wallets (
            telegram_id INTEGER PRIMARY KEY,
            balance_rub INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS payment_actions (
            payment_id TEXT PRIMARY KEY,
            telegram_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            target_plan_key TEXT,
            amount_rub INTEGER NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )

def ensure_vk_tables(con: sqlite3.Connection) -> None:
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS vk_links (
            vk_user_id INTEGER PRIMARY KEY,
            portal_user_id INTEGER NOT NULL UNIQUE,
            telegram_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(portal_user_id) REFERENCES portal_users(id)
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS vk_link_codes (
            code TEXT PRIMARY KEY,
            portal_user_id INTEGER NOT NULL,
            telegram_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            vk_user_id INTEGER,
            FOREIGN KEY(portal_user_id) REFERENCES portal_users(id)
        )
        """
    )
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS vk_subscription_reminders (
            vk_user_id INTEGER PRIMARY KEY,
            last_sent_at TEXT NOT NULL
        )
        """
    )

def ensure_referral_tables(con: sqlite3.Connection) -> None:
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS user_referrals (
            referrer_user_id INTEGER PRIMARY KEY,
            invite_code TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            FOREIGN KEY(referrer_user_id) REFERENCES portal_users(id)
        )
        """
    )
    invite_columns = {row["name"] for row in con.execute("PRAGMA table_info(portal_invites)").fetchall()}
    if "created_by_user_id" not in invite_columns:
        con.execute("ALTER TABLE portal_invites ADD COLUMN created_by_user_id INTEGER")
    if "used_by_user_id" not in invite_columns:
        con.execute("ALTER TABLE portal_invites ADD COLUMN used_by_user_id INTEGER")

    user_columns = {row["name"] for row in con.execute("PRAGMA table_info(portal_users)").fetchall()}
    if "invited_by_user_id" not in user_columns:
        con.execute("ALTER TABLE portal_users ADD COLUMN invited_by_user_id INTEGER")

def migrate_telegram_columns(con: sqlite3.Connection) -> None:
    users_telegram_notnull = con.execute("PRAGMA table_info(portal_users)").fetchall()
    invites_telegram_notnull = con.execute("PRAGMA table_info(portal_invites)").fetchall()

    need_users_migration = any(
        row["name"] == "telegram_id" and row["notnull"] == 1 for row in users_telegram_notnull
    )
    need_invites_migration = any(
        row["name"] == "telegram_id" and row["notnull"] == 1 for row in invites_telegram_notnull
    )

    if need_users_migration:
        con.execute(
            """
            CREATE TABLE portal_users_new (
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
        con.execute(
            """
            INSERT INTO portal_users_new (id, telegram_id, login, password_salt, password_hash, created_at, updated_at)
            SELECT id, telegram_id, login, password_salt, password_hash, created_at, updated_at
            FROM portal_users
            """
        )
        con.execute("DROP TABLE portal_users")
        con.execute("ALTER TABLE portal_users_new RENAME TO portal_users")
    users_columns = {row["name"] for row in con.execute("PRAGMA table_info(portal_users)").fetchall()}
    if "revoked_at" not in users_columns:
        con.execute("ALTER TABLE portal_users ADD COLUMN revoked_at TEXT")

    if need_invites_migration:
        con.execute(
            """
            CREATE TABLE portal_invites_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                invite_code TEXT NOT NULL UNIQUE,
                telegram_id INTEGER,
                created_at TEXT NOT NULL,
                used_at TEXT
            )
            """
        )
        con.execute(
            """
            INSERT INTO portal_invites_new (id, invite_code, telegram_id, created_at, used_at)
            SELECT id, invite_code, telegram_id, created_at, used_at
            FROM portal_invites
            """
        )
        con.execute("DROP TABLE portal_invites")
        con.execute("ALTER TABLE portal_invites_new RENAME TO portal_invites")
    invite_columns = {row["name"] for row in con.execute("PRAGMA table_info(portal_invites)").fetchall()}
    if "plan" not in invite_columns:
        con.execute("ALTER TABLE portal_invites ADD COLUMN plan TEXT")
    if "title" not in invite_columns:
        con.execute("ALTER TABLE portal_invites ADD COLUMN title TEXT")
    if "key_limit" not in invite_columns:
        con.execute("ALTER TABLE portal_invites ADD COLUMN key_limit INTEGER")
    if "price_rub" not in invite_columns:
        con.execute("ALTER TABLE portal_invites ADD COLUMN price_rub INTEGER")
    if "duration_days" not in invite_columns:
        con.execute("ALTER TABLE portal_invites ADD COLUMN duration_days INTEGER")
    if "invited_by_user_id" not in invite_columns:
        con.execute("ALTER TABLE portal_invites ADD COLUMN invited_by_user_id INTEGER")
    if "created_by_user_id" not in invite_columns:
        con.execute("ALTER TABLE portal_invites ADD COLUMN created_by_user_id INTEGER")
    if "used_by_user_id" not in invite_columns:
        con.execute("ALTER TABLE portal_invites ADD COLUMN used_by_user_id INTEGER")

    # Portal users can register without Telegram. To keep compatibility with
    # legacy tables keyed by telegram_id, assign deterministic synthetic IDs.
    con.execute(
        """
        UPDATE portal_users
        SET telegram_id = -id
        WHERE telegram_id IS NULL
        """
    )
