# schema.py
import sqlite3
import os
from typing import List, Dict, Any

# Try to import db_utils if available (useful for execute_with_retry/open_db)
try:
    from .db_utils import execute_with_retry, open_db
except Exception:
    execute_with_retry = None
    open_db = None


DB_NAME = "artifacts.db"

def init_db(db_path=DB_NAME):
    """
    Initialize SQLite DB if not exists.
    Creates a simple artifacts table and performs a safe migration:
    - If the artifacts table is present but missing the 'details' column, add it with ALTER TABLE.
    """
    # Create folder if missing
    folder = os.path.dirname(db_path)
    if folder and not os.path.exists(folder):
        os.makedirs(folder)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create table if missing (older DBs may not have it).
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS artifacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            artifact_type TEXT,
            name TEXT,
            path TEXT,
            timestamp TEXT,
            last_access TEXT,
            extra TEXT,
            details TEXT
        )
        """
    )
    conn.commit()

    # Now ensure the column 'details' exists (safe migration for older DBs)
    try:
        cursor.execute("PRAGMA table_info(artifacts)")
        cols = [row[1] for row in cursor.fetchall()]  # row[1] is column name
        if "details" not in cols:
            # Add details column without losing data
            cursor.execute("ALTER TABLE artifacts ADD COLUMN details TEXT")
            conn.commit()
    except Exception:
        # If anything goes wrong, ignore (table may not exist or PRAGMA unavailable)
        pass
    finally:
        conn.close()



def insert_artifact(db_path_or_conn, artifact: Dict[str, Any]):
    """
    Insert a single artifact.
    If db_path_or_conn is a string, opens its own connection, commits and closes.
    If it's an sqlite3.Connection, uses it and does NOT commit (caller expected to commit).
    This mirrors the lightweight original behaviour while using execute_with_retry when a Connection is provided.
    """
    close_conn = False
    if isinstance(db_path_or_conn, str):
        conn = sqlite3.connect(db_path_or_conn)
        close_conn = True
    else:
        conn = db_path_or_conn

    try:
        # If we have execute_with_retry and conn is a sqlite3.Connection (i.e. caller provided one),
        # prefer execute_with_retry to avoid 'database is locked' in concurrent scenarios.
        sql = """
            INSERT INTO artifacts (artifact_type, name, path, timestamp, last_access, extra, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """
        params = (
            artifact.get("artifact_type"),
            artifact.get("name"),
            artifact.get("path"),
            artifact.get("timestamp"),
            artifact.get("last_access"),
            artifact.get("extra"),
            artifact.get("details"),
        )

        if not close_conn and execute_with_retry:
            # caller supplied a connection -> safe write with retry
            execute_with_retry(conn, sql, params)
        else:
            # original behavior for string path or no execute_with_retry
            cursor = conn.cursor()
            cursor.execute(sql, params)
            if close_conn:
                conn.commit()
    finally:
        if close_conn:
            try:
                conn.close()
            except Exception:
                pass


def insert_artifacts_bulk(db_path_or_conn, artifact_list: List[Dict[str, Any]]):
    """
    Insert multiple artifacts at once.
    Accepts either:
      - db_path_or_conn: str -> path to DB file (this function opens/closes and commits)
      - db_path_or_conn: sqlite3.Connection -> uses provided connection (does NOT commit here)
    """
    close_conn = False
    if isinstance(db_path_or_conn, str):
        conn = sqlite3.connect(db_path_or_conn)
        close_conn = True
    else:
        conn = db_path_or_conn

    try:
        cursor = conn.cursor()

        rows = [
            (
                a.get("artifact_type"),
                a.get("name"),
                a.get("path"),
                a.get("timestamp"),
                a.get("last_access"),
                a.get("extra"),
                a.get("details"),
            )
            for a in artifact_list
        ]

        # Bulk insert; if execute_with_retry is available and caller supplied a connection,
        # we'll try executemany under a retry loop; else fallback to simple executemany.
        if not close_conn and execute_with_retry:
            # Insert in chunks to reduce transaction size
            CHUNK = 200
            for i in range(0, len(rows), CHUNK):
                chunk_rows = rows[i:i+CHUNK]
                # Use a retry loop around executemany
                import time
                start = time.time()
                while True:
                    try:
                        cur = conn.cursor()
                        cur.executemany(
                            """
                            INSERT INTO artifacts (artifact_type, name, path, timestamp, last_access, extra, details)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            chunk_rows,
                        )
                        conn.commit()
                        break
                    except sqlite3.OperationalError as e:
                        if "database is locked" in str(e).lower():
                            if (time.time() - start) > 15:
                                raise
                            time.sleep(0.1)
                            continue
                        raise
        else:
            # fallback: open/close connection behavior (original)
            cursor.executemany(
                """
                INSERT INTO artifacts (artifact_type, name, path, timestamp, last_access, extra, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            if close_conn:
                conn.commit()

    finally:
        if close_conn:
            try:
                conn.close()
            except Exception:
                pass


def query_artifacts(db_path=DB_NAME):
    """
    Fetch all artifacts ordered by timestamp (or last_access fallback).
    Returns a list of dict rows (column names -> values).
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Return everything, ordering by coalesced event time if available
    cursor.execute(
        """
        SELECT *,
               COALESCE(timestamp, last_access) AS event_time
        FROM artifacts
        ORDER BY event_time DESC
        """
    )

    rows = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return rows


def clear_database(db_path=DB_NAME):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM artifacts")
    conn.commit()
    conn.close()


if __name__ == "__main__":
    print("Initializing DB...")
    init_db()
    print("Done.")
