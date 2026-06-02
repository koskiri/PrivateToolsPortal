from __future__ import annotations

import sqlite3
from pathlib import Path

from app.core.config import DB_PATH, FALLBACK_DB_PATH


def get_db_connection() -> sqlite3.Connection:
    try:
        con = sqlite3.connect(DB_PATH)
    except sqlite3.OperationalError:
        # In dev/staging bot.db can be a broken symlink to external storage.
        # Fall back to a local SQLite file so the portal can still start.
        if Path(DB_PATH).is_symlink():
            con = sqlite3.connect(FALLBACK_DB_PATH)
        else:
            raise
    con.row_factory = sqlite3.Row
    return con
