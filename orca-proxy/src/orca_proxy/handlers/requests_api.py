from aiohttp import web

from ..errors import NotFound, ValidationFailed
from ..request_log import RequestLog


def _log(request: web.Request) -> RequestLog:
    return request.app["request_log"]


def _int_param(request: web.Request, name: str) -> int | None:
    raw = request.query.get(name)
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError as exc:
        raise ValidationFailed(f"query parameter '{name}' must be an integer") from exc


async def list_requests(request: web.Request) -> web.Response:
    connections = _log(request).list_connections(
        before=_int_param(request, "before"),
        after=_int_param(request, "after"),
        limit=_int_param(request, "limit") or 50,
        vm=request.query.get("vm"),
        host=request.query.get("host"),
        decision=request.query.get("decision"),
        status=_int_param(request, "status"),
        since=request.query.get("since"),
        until=request.query.get("until"),
    )
    return web.json_response({"connections": connections})


async def get_request(request: web.Request) -> web.Response:
    try:
        connection_id = int(request.match_info["id"])
    except ValueError as exc:
        raise ValidationFailed("'id' must be an integer") from exc
    connection = _log(request).get_connection(connection_id)
    if connection is None:
        raise NotFound(f"connection '{connection_id}' not found")
    return web.json_response(connection)
