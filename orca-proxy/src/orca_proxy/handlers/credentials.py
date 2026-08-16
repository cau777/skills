from aiohttp import web

from .. import validation
from ..errors import Conflict, NotFound, ValidationFailed
from ..repo import credentials as credentials_repo
from . import db_conn, read_json_body, reject_unknown_fields


def _serialize(row) -> dict:
    return {
        "name": row["name"],
        "command": row["command"],
        "ttl_seconds": row["ttl_seconds"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        # The execution/caching engine (design ticket #10) isn't built in this
        # slice, so live status is always "empty" — never a real ephemeral
        # state — until that engine exists. Never expose command output here.
        "status": "empty",
    }


def _validate_command(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationFailed("'command' must be a non-empty string", fields={"command": "required"})
    return value


def _validate_ttl_seconds(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValidationFailed(
            "'ttl_seconds' must be a non-negative integer", fields={"ttl_seconds": "must be >= 0"}
        )
    return value


async def list_credentials(request: web.Request) -> web.Response:
    conn = db_conn(request)
    rows = credentials_repo.list_all(conn)
    return web.json_response({"credentials": [_serialize(r) for r in rows]})


async def get_credential(request: web.Request) -> web.Response:
    conn = db_conn(request)
    name = request.match_info["name"]
    row = credentials_repo.get(conn, name)
    if row is None:
        raise NotFound(f"Credential '{name}' not found")
    return web.json_response(_serialize(row))


async def put_credential(request: web.Request) -> web.Response:
    conn = db_conn(request)
    name = validation.validate_name(request.match_info["name"])
    body = await read_json_body(request)
    reject_unknown_fields(body, {"command", "ttl_seconds"})
    command = _validate_command(body.get("command"))
    ttl_seconds = _validate_ttl_seconds(body.get("ttl_seconds"))

    row, created = credentials_repo.put(conn, name, command, ttl_seconds)
    status = 201 if created else 200
    return web.json_response(_serialize(row), status=status)


async def delete_credential(request: web.Request) -> web.Response:
    conn = db_conn(request)
    name = request.match_info["name"]
    row = credentials_repo.get(conn, name)
    if row is None:
        raise NotFound(f"Credential '{name}' not found")
    if credentials_repo.referenced_by_rule(conn, name):
        raise Conflict(f"Credential '{name}' is referenced by a Rule; update or delete it first")
    credentials_repo.delete(conn, name)
    return web.Response(status=204)
