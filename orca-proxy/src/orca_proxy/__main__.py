from aiohttp import web

from . import config
from .app import create_app

if __name__ == "__main__":
    # Standalone dev entrypoint only — the deployed service starts this same
    # app from inside the mitmproxy addon's own event loop instead
    # (proxy_addon.py's running()/done() hooks), per #4's "same process"
    # decision. This remains useful for local development against just the
    # Management API, without needing mitmdump running at all.
    #
    # Loopback-only — the Management API requires no authentication because
    # nothing beyond the local host can reach it (design ticket #6).
    web.run_app(create_app(), host="127.0.0.1", port=config.management_api_port())
