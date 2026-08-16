import sqlite3

from ..db import now_iso


def get(conn: sqlite3.Connection, name: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM credentials WHERE name = ?", (name,)).fetchone()


def list_all(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM credentials ORDER BY name").fetchall()


def all_names(conn: sqlite3.Connection) -> set[str]:
    return {row["name"] for row in conn.execute("SELECT name FROM credentials")}


def put(conn: sqlite3.Connection, name: str, command: str, ttl_seconds: int) -> tuple[sqlite3.Row, bool]:
    existing = get(conn, name)
    now = now_iso()
    if existing is None:
        conn.execute(
            "INSERT INTO credentials (name, command, ttl_seconds, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (name, command, ttl_seconds, now, now),
        )
        return get(conn, name), True
    conn.execute(
        "UPDATE credentials SET command = ?, ttl_seconds = ?, updated_at = ? WHERE name = ?",
        (command, ttl_seconds, now, name),
    )
    return get(conn, name), False


def referenced_by_rule(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        """
        SELECT 1 FROM rules
        WHERE json_extract(action_json, '$.type') = 'allow_with_credential'
          AND json_extract(action_json, '$.credential') = ?
        LIMIT 1
        """,
        (name,),
    ).fetchone()
    return row is not None


def delete(conn: sqlite3.Connection, name: str) -> None:
    conn.execute("DELETE FROM credentials WHERE name = ?", (name,))
