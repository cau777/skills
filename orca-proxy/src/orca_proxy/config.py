import os
import sys
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


def bridge_interface() -> str:
    return os.environ.get("ORCA_PROXY_BRIDGE", "mpqemubr0")


def proxy_port() -> int:
    return int(os.environ.get("ORCA_PROXY_PORT", "8443"))


def management_api_port() -> int:
    return int(os.environ.get("ORCA_PROXY_MANAGEMENT_PORT", "8080"))


def firewall_sync_script_path() -> Path:
    """Absolute path to the installed console-script entry point (#12) —
    the sudoers NOPASSWD entry names this exact path, so it has to be
    resolvable without relying on $PATH. Defaults to the sibling of the
    current Python interpreter's own bin/ directory (i.e. the same venv
    orca-proxy itself is running from), overridable for deployments that
    place it elsewhere.
    """
    raw = os.environ.get("ORCA_PROXY_FIREWALL_SCRIPT")
    if raw:
        return Path(raw)
    return Path(sys.executable).parent / "orca-proxy-firewall-sync"


def ca_cert_path() -> Path:
    return data_dir() / "mitmproxy-ca-cert.pem"
