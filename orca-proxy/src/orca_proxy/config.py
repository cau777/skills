import os
from pathlib import Path


def data_dir() -> Path:
    """Resolve the app's data directory.

    Defaults to ~/.orca-proxy (the runtime path fixed by the design spec's
    service-installation decision). Overridable via ORCA_PROXY_HOME so tests
    can isolate each run in a temp directory.
    """
    raw = os.environ.get("ORCA_PROXY_HOME")
    path = Path(raw) if raw else Path.home() / ".orca-proxy"
    path.mkdir(parents=True, exist_ok=True)
    return path


def db_path() -> Path:
    return data_dir() / "state.sqlite"


def requests_db_path() -> Path:
    return data_dir() / "requests.sqlite"


def ca_cert_path() -> Path:
    return data_dir() / "mitmproxy-ca-cert.pem"
