from aiohttp import web


async def readyz(request: web.Request) -> web.Response:
    app = request.app
    firewall_sync = app.get("firewall_sync")
    checks = {
        "migrations": app.get("migrations_applied", False),
        "ca_materialized": app.get("ca_materialized", False),
        # Per-VM firewall reconciliation status (#12's Q7) — folded directly
        # into /readyz's JSON body rather than a separate diagnostics
        # endpoint. Vacuously true with zero registered VMs.
        "firewall_synced": firewall_sync.is_synced if firewall_sync else False,
    }
    ready = all(checks.values())
    body = {"ready": ready, "checks": checks}
    if firewall_sync is not None:
        body["firewall_status"] = firewall_sync.status
    return web.json_response(body, status=200 if ready else 503)
