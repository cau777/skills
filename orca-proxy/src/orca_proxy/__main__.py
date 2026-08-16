from aiohttp import web

from .app import create_app

if __name__ == "__main__":
    # Loopback-only — the Management API requires no authentication because
    # nothing beyond the local host can reach it (design ticket #6).
    web.run_app(create_app(), host="127.0.0.1", port=8080)
