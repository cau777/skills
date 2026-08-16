"""Request-log persistence and query (design ticket #11).

Two-level schema: a connection row is always written for every completed TLS
handshake (or plain-Allow/Block decision); an HTTP-request child row exists
only for connections where `intercepted` is true. Writes are fail-open — a
logging failure never blocks the request the caller is trying to serve, it's
swallowed here and reported to stderr, matching #11's explicit failure
semantics (uniform fail-open, including Allow-with-credential traffic).

Retention is a fixed row-count cap on `connections`, pruned after each write;
`http_requests` rows are removed automatically via ON DELETE CASCADE (the
requests.sqlite connection enables `PRAGMA foreign_keys=ON` in db.connect()).
"""

import json
import sqlite3
import sys
from pathlib import Path

from . import db

DEFAULT_RETENTION_ROWS = 100_000
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200


def connect(requests_db_path: Path) -> sqlite3.Connection:
    conn = db.connect(requests_db_path)
    db.migrate(conn, migrations_dir=db.REQUESTS_MIGRATIONS_DIR)
    return conn


class RequestLog:
    def __init__(self, conn: sqlite3.Connection, retention_rows: int = DEFAULT_RETENTION_ROWS):
        self._conn = conn
        self._retention_rows = retention_rows

    # --- writes (fail-open) ---

    def log_connection(
        self,
        *,
        started_at: str,
        vm_name: str,
        destination_ip: str,
        destination_port: int,
        destination_hostname: str | None,
        sni_present: bool,
        ech_present: bool,
        duration_ms: int | None,
        intercepted: bool,
        outcome: str | None = None,
        matched_rule: dict | None = None,
        intercepted_by_rule: dict | None = None,
    ) -> int | None:
        try:
            cur = self._conn.execute(
                """
                INSERT INTO connections (
                    started_at, vm_name, destination_ip, destination_port,
                    destination_hostname, sni_present, ech_present, duration_ms,
                    intercepted, outcome, matched_rule_json, intercepted_by_rule_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    started_at,
                    vm_name,
                    destination_ip,
                    destination_port,
                    destination_hostname,
                    int(sni_present),
                    int(ech_present),
                    duration_ms,
                    int(intercepted),
                    outcome,
                    json.dumps(matched_rule) if matched_rule else None,
                    json.dumps(intercepted_by_rule) if intercepted_by_rule else None,
                ),
            )
            connection_id = cur.lastrowid
            self._prune()
            return connection_id
        except Exception as exc:  # fail-open (#11)
            print(f"log write failed: {exc}", file=sys.stderr)
            return None

    def log_http_request(
        self,
        *,
        connection_id: int,
        occurred_at: str,
        method: str,
        path: str,
        query_keys: list[str],
        status: int | None,
        status_origin: str | None,
        latency_ms: int | None,
        outcome: str,
        matched_rule: dict | None,
        matched_credential: str | None,
        trace: list[dict],
        headers: list[dict],
    ) -> int | None:
        try:
            cur = self._conn.execute(
                """
                INSERT INTO http_requests (
                    connection_id, occurred_at, method, path, query_keys_json,
                    status, status_origin, latency_ms, outcome, matched_rule_json,
                    matched_credential, trace_json, headers_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    connection_id,
                    occurred_at,
                    method,
                    path,
                    json.dumps(query_keys),
                    status,
                    status_origin,
                    latency_ms,
                    outcome,
                    json.dumps(matched_rule) if matched_rule else None,
                    matched_credential,
                    json.dumps(trace),
                    json.dumps(headers),
                ),
            )
            return cur.lastrowid
        except Exception as exc:  # fail-open (#11)
            print(f"log write failed: {exc}", file=sys.stderr)
            return None

    def _prune(self) -> None:
        self._conn.execute(
            "DELETE FROM connections WHERE id <= (SELECT COALESCE(MAX(id), 0) FROM connections) - ?",
            (self._retention_rows,),
        )

    # --- reads ---

    def list_connections(
        self,
        *,
        before: int | None = None,
        after: int | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        vm: str | None = None,
        host: str | None = None,
        decision: str | None = None,
        status: int | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> list[dict]:
        limit = max(1, min(limit, MAX_PAGE_SIZE))
        clauses = []
        params: list = []

        if before is not None:
            clauses.append("c.id < ?")
            params.append(before)
        if after is not None:
            clauses.append("c.id > ?")
            params.append(after)
        if vm is not None:
            clauses.append("c.vm_name = ?")
            params.append(vm)
        if host is not None:
            clauses.append("c.destination_hostname = ?")
            params.append(host)
        if since is not None:
            clauses.append("c.started_at >= ?")
            params.append(since)
        if until is not None:
            clauses.append("c.started_at <= ?")
            params.append(until)
        if decision is not None:
            clauses.append(
                "(c.outcome = ? OR EXISTS "
                "(SELECT 1 FROM http_requests r WHERE r.connection_id = c.id AND r.outcome = ?))"
            )
            params.extend([decision, decision])
        if status is not None:
            clauses.append(
                "EXISTS (SELECT 1 FROM http_requests r WHERE r.connection_id = c.id AND r.status = ?)"
            )
            params.append(status)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._conn.execute(
            f"SELECT * FROM connections c {where} ORDER BY c.id DESC LIMIT ?", (*params, limit)
        ).fetchall()
        return [_serialize_connection(row) for row in rows]

    def get_connection(self, connection_id: int) -> dict | None:
        row = self._conn.execute("SELECT * FROM connections WHERE id = ?", (connection_id,)).fetchone()
        if row is None:
            return None
        result = _serialize_connection(row)
        request_rows = self._conn.execute(
            "SELECT * FROM http_requests WHERE connection_id = ? ORDER BY id ASC", (connection_id,)
        ).fetchall()
        result["http_requests"] = [_serialize_http_request(r) for r in request_rows]
        return result


def _serialize_connection(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "started_at": row["started_at"],
        "vm_name": row["vm_name"],
        "destination_ip": row["destination_ip"],
        "destination_port": row["destination_port"],
        "destination_hostname": row["destination_hostname"],
        "sni_present": bool(row["sni_present"]),
        "ech_present": bool(row["ech_present"]),
        "duration_ms": row["duration_ms"],
        "intercepted": bool(row["intercepted"]),
        "outcome": row["outcome"],
        "matched_rule": json.loads(row["matched_rule_json"]) if row["matched_rule_json"] else None,
        "intercepted_by_rule": (
            json.loads(row["intercepted_by_rule_json"]) if row["intercepted_by_rule_json"] else None
        ),
    }


def _serialize_http_request(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "connection_id": row["connection_id"],
        "occurred_at": row["occurred_at"],
        "method": row["method"],
        "path": row["path"],
        "query_keys": json.loads(row["query_keys_json"]),
        "status": row["status"],
        "status_origin": row["status_origin"],
        "latency_ms": row["latency_ms"],
        "outcome": row["outcome"],
        "matched_rule": json.loads(row["matched_rule_json"]) if row["matched_rule_json"] else None,
        "matched_credential": row["matched_credential"],
        "trace": json.loads(row["trace_json"]),
        "headers": json.loads(row["headers_json"]),
    }
