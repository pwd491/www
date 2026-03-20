import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from ..core.config import settings


class Storage:
    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or settings.app_db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _initialize(self) -> None:
        with self.connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS wireguard_clients (
                    name TEXT PRIMARY KEY,
                    ipv4 TEXT NOT NULL,
                    ipv6 TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    private_key TEXT NOT NULL,
                    preshared_key TEXT NOT NULL,
                    config_file TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
                """
            )
            cur.execute(
                "CREATE TABLE IF NOT EXISTS hashtags (tag TEXT PRIMARY KEY)"
            )
            cur.execute(
                "CREATE TABLE IF NOT EXISTS dns_keywords (keyword TEXT PRIMARY KEY)"
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS adguard_clients (
                    ip TEXT PRIMARY KEY,
                    name TEXT NOT NULL
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS app_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )


storage = Storage()
