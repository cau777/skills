import sqlite3

from aiohttp import web

from ..errors import InvalidJson


async def read_json_body(request: web.Request) -> dict:
    try:
        body = await request.json()
    except Exception as exc:
        raise InvalidJson("request body must be valid JSON") from exc
    if not isinstance(body, dict):
        raise InvalidJson("request body must be a JSON object")
    return body


def reject_unknown_fields(body: dict, allowed: set[str]) -> None:
    from ..errors import ValidationFailed

    unknown = set(body.keys()) - allowed
    if unknown:
        raise ValidationFailed(
            f"unexpected field(s): {', '.join(sorted(unknown))}",
            fields={f: "unexpected field" for f in unknown},
        )


def db_conn(request: web.Request) -> sqlite3.Connection:
    return request.app["db"]
