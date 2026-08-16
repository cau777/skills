# orca-proxy

Core service skeleton for the unified VM credential-injection & logging proxy
(see `cau777/skills` issue #1 for the full design spec). This slice covers the
entity model, SQLite persistence, the Management API CRUD surface, and
Interception CA generation — not the mitmproxy addon, firewall enforcement,
Credential execution engine, request logging, or Web UI, which are later
slices.

## Development

```bash
uv sync
uv run pytest -v
uv run python -m orca_proxy   # dev server on loopback, data dir defaults to ~/.orca-proxy
```

Set `ORCA_PROXY_HOME` to override the data directory (used by tests to isolate
each run in a temp directory).
