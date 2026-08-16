from aiohttp import web


class ApiError(Exception):
    status: int = 500
    code: str = "internal_error"

    def __init__(self, message: str, fields: dict[str, str] | None = None):
        super().__init__(message)
        self.message = message
        self.fields = fields

    def to_response(self) -> web.Response:
        body: dict = {"error": {"code": self.code, "message": self.message}}
        if self.fields:
            body["error"]["fields"] = self.fields
        return web.json_response(body, status=self.status)


class InvalidJson(ApiError):
    status = 400
    code = "invalid_json"


class NotFound(ApiError):
    status = 404
    code = "not_found"


class Conflict(ApiError):
    status = 409
    code = "conflict"


class ValidationFailed(ApiError):
    status = 422
    code = "validation_failed"


@web.middleware
async def error_middleware(request: web.Request, handler):
    try:
        return await handler(request)
    except ApiError as exc:
        return exc.to_response()
