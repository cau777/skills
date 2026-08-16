from aiohttp import web

from .. import ca
from . import db_conn


async def get_ca(request: web.Request) -> web.Response:
    conn = db_conn(request)
    row = ca.get(conn)
    return web.json_response(
        {
            "certificate_pem": row["certificate_pem"],
            "fingerprint_sha256": row["fingerprint_sha256"],
            "subject": ca.CA_SUBJECT_NAME,
            "not_before": row["not_before"],
            "not_after": row["not_after"],
        }
    )
