from aiohttp import web


async def readyz(request: web.Request) -> web.Response:
    app = request.app
    # This is the foundational version of /readyz for the core-service-skeleton
    # slice: migrations applied + CA materialized. The later firewall/DNAT
    # slice (design ticket #12) extends this with per-VM firewall-sync status
    # before it's the final contract — do not treat this as complete.
    checks = {
        "migrations": app.get("migrations_applied", False),
        "ca_materialized": app.get("ca_materialized", False),
    }
    ready = all(checks.values())
    return web.json_response({"ready": ready, "checks": checks}, status=200 if ready else 503)
