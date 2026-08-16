import json
import sqlite3

from ..db import now_iso


def get(conn: sqlite3.Connection, name: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM rules WHERE name = ?", (name,)).fetchone()


def list_all(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM rules ORDER BY priority").fetchall()


def priority_in_use_by_other(conn: sqlite3.Connection, priority: int, exclude_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM rules WHERE priority = ? AND name != ?", (priority, exclude_name)
    ).fetchone()
    return row is not None


def put(
    conn: sqlite3.Connection,
    name: str,
    priority: int,
    vm_selector: dict,
    hostname: str,
    action: dict,
) -> tuple[sqlite3.Row, bool]:
    existing = get(conn, name)
    now = now_iso()
    vm_selector_json = json.dumps(vm_selector)
    action_json = json.dumps(action)
    if existing is None:
        conn.execute(
            "INSERT INTO rules (name, priority, vm_selector_json, hostname, action_json, "
            "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (name, priority, vm_selector_json, hostname, action_json, now, now),
        )
        return get(conn, name), True
    conn.execute(
        "UPDATE rules SET priority = ?, vm_selector_json = ?, hostname = ?, action_json = ?, "
        "updated_at = ? WHERE name = ?",
        (priority, vm_selector_json, hostname, action_json, now, name),
    )
    return get(conn, name), False


def delete(conn: sqlite3.Connection, name: str) -> None:
    conn.execute("DELETE FROM rules WHERE name = ?", (name,))


def to_dict(row: sqlite3.Row) -> dict:
    """Shared shape consumed by both the Management API handlers and the
    proxy addon's rule_engine (which expects vm_selector/action as parsed
    dicts, not raw JSON text).
    """
    return {
        "name": row["name"],
        "priority": row["priority"],
        "vm_selector": json.loads(row["vm_selector_json"]),
        "hostname": row["hostname"],
        "action": json.loads(row["action_json"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
