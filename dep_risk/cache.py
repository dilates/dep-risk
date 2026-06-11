from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


class Cache:
    _local = threading.local()

    def __init__(self, db_path: Optional[Path] = None) -> None:
        if db_path is None:
            db_path = Path.home() / ".cache" / "dep-risk" / "cache.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db_path = str(db_path)
        self._init_schema()
        self.clear_expired()

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def _init_schema(self) -> None:
        self._conn().execute(
            """
            CREATE TABLE IF NOT EXISTS cache (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                fetched_at DATETIME NOT NULL,
                ttl_seconds INTEGER NOT NULL
            )
            """
        )
        self._conn().commit()

    def get(self, key: str) -> Optional[Any]:
        row = self._conn().execute(
            "SELECT value, fetched_at, ttl_seconds FROM cache WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        fetched_at = datetime.fromisoformat(row["fetched_at"])
        if fetched_at.tzinfo is None:
            fetched_at = fetched_at.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - fetched_at).total_seconds()
        if age > row["ttl_seconds"]:
            self._conn().execute("DELETE FROM cache WHERE key = ?", (key,))
            self._conn().commit()
            return None
        return json.loads(row["value"])

    def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        self._conn().execute(
            """
            INSERT OR REPLACE INTO cache (key, value, fetched_at, ttl_seconds)
            VALUES (?, ?, ?, ?)
            """,
            (key, json.dumps(value), datetime.now(timezone.utc).isoformat(), ttl_seconds),
        )
        self._conn().commit()

    def clear(self) -> None:
        self._conn().execute("DELETE FROM cache")
        self._conn().commit()

    def clear_expired(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self._conn().execute(
            """
            DELETE FROM cache
            WHERE (julianday(?) - julianday(fetched_at)) * 86400 > ttl_seconds
            """,
            (now,),
        )
        self._conn().commit()


TTL_REGISTRY = 3600
TTL_GITHUB = 21600
TTL_TYPOSQUAT = 86400


_default_cache: Optional[Cache] = None
_cache_lock = threading.Lock()


def get_default_cache() -> Cache:
    global _default_cache
    if _default_cache is None:
        with _cache_lock:
            if _default_cache is None:
                _default_cache = Cache()
    return _default_cache
