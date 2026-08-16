import sqlite3
from datetime import datetime, timezone
from pathlib import Path

STATE_MIGRATIONS_DIR = Path(__file__).parent / "migrations"
REQUESTS_MIGRATIONS_DIR = Path(__file__).parent / "requests_migrations"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    return conn


def migrate(conn: sqlite3.Connection, migrations_dir: Path = STATE_MIGRATIONS_DIR) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        )
        """
    )
    applied = {row["version"] for row in conn.execute("SELECT version FROM schema_migrations")}

    pending = sorted(
        (int(p.name.split("_", 1)[0]), p) for p in migrations_dir.glob("*.sql")
    )
    for version, path in pending:
        if version in applied:
            continue
        # sqlite3's executescript() issues an implicit COMMIT before running,
        # which would break atomicity with the schema_migrations bookkeeping
        # insert below — so each statement is executed individually inside
        # one manually-managed transaction instead. Migration files are
        # authored in-repo (simple CREATE TABLE statements, one per
        # semicolon-terminated block), so a naive split is safe here.
        statements = [s.strip() for s in path.read_text().split(";") if s.strip()]
        conn.execute("BEGIN")
        try:
            for statement in statements:
                conn.execute(statement)
            conn.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                (version, now_iso()),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
