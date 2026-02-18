# db_utils.py
"""
DB helper utilities for robust SQLite writes.
- open_db(path): returns sqlite3.Connection with WAL and sensible timeout
- execute_with_retry(conn, sql, params): executes SQL with retry on "database is locked"
"""

import sqlite3
import time
import typing

DEFAULT_BUSY_TIMEOUT_MS = 30000  # PRAGMA busy_timeout
RETRY_SLEEP = 0.1  # 100ms between retries
RETRY_MAX_SECONDS = 15  # total retry window for writes

def open_db(path: str = "artifacts.db") -> sqlite3.Connection:
    """
    Open SQLite DB with WAL mode and longer timeout.
    check_same_thread=False so that a background thread can use it (be careful).
    """
    conn = sqlite3.connect(path, timeout=30, check_same_thread=False)
    # Try to set PRAGMAs; ignore failures on restricted environments.
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute(f"PRAGMA busy_timeout={DEFAULT_BUSY_TIMEOUT_MS};")
        conn.execute("PRAGMA synchronous=NORMAL;")
    except Exception:
        pass
    return conn

def execute_with_retry(conn: sqlite3.Connection, sql: str, params: typing.Tuple = (), max_wait_seconds: float = RETRY_MAX_SECONDS):
    """
    Execute SQL with simple retry for sqlite3.OperationalError containing 'database is locked'.
    Commits for write statements (basic heuristic). Returns cursor on success. Raises after max_wait_seconds.
    """
    start = time.time()
    while True:
        try:
            cur = conn.cursor()
            cur.execute(sql, params)
            # commit heuristic
            first_word = sql.strip().split()[0].upper() if sql and isinstance(sql, str) else ""
            if first_word in ("INSERT", "UPDATE", "DELETE", "REPLACE", "CREATE", "ALTER", "DROP"):
                try:
                    conn.commit()
                except Exception:
                    pass
            return cur
        except sqlite3.OperationalError as e:
            msg = str(e).lower()
            if "database is locked" in msg or "database table is locked" in msg:
                if (time.time() - start) > max_wait_seconds:
                    raise
                time.sleep(RETRY_SLEEP)
                continue
            raise
