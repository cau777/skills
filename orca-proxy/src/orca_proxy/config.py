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


def bridge_interface() -> str:
    return os.environ.get("ORCA_PROXY_BRIDGE", "mpqemubr0")


def proxy_port() -> int:
    return int(os.environ.get("ORCA_PROXY_PORT", "8443"))


def management_api_port() -> int:
    return int(os.environ.get("ORCA_PROXY_MANAGEMENT_PORT", "8080"))


def firewall_sync_script_path() -> Path:
    """Absolute path to the installed console-script entry point (#12) —
    the sudoers NOPASSWD entry names this exact path, so it must stay
    stable across upgrades. Deliberately built from the `current` symlink
    (~/.orca-proxy/current/venv/bin/...) rather than sys.executable — the
    running interpreter's own path resolves through the symlink to a
    version-specific target, which would change on every blue-green upgrade
    and require a fresh sudoers entry each time, defeating the point of the
    symlink. install.sh's layout (deploy/install.sh) is the source of truth
    this mirrors.
    """
    raw = os.environ.get("ORCA_PROXY_FIREWALL_SCRIPT")
    if raw:
        return Path(raw)
    return data_dir() / "current" / "venv" / "bin" / "orca-proxy-firewall-sync"


def mitm_confdir() -> Path:
    """mitmproxy's own --set confdir path (deploy/orca-proxy.service) — a
    subdirectory of data_dir(), not data_dir() itself, so ca_cert_path()
    can materialize into the exact spot mitmproxy's CertStore looks for its
    signing CA.
    """
    path = data_dir() / "mitm-confdir"
    path.mkdir(parents=True, exist_ok=True)
    return path


def ca_cert_path() -> Path:
    """Where the combined CA cert+key PEM is materialized.

    Must be <confdir>/mitmproxy-ca.pem exactly — mitmproxy's own
    CertStore.from_store() (basename="mitmproxy", mitmproxy's
    CONF_BASENAME) looks for precisely that filename inside --set confdir.
    Get this wrong (e.g. a different filename or directory) and mitmdump
    silently auto-generates its own unrelated CA on first run instead of
    loading this one — every intercepted handshake then fails cert
    validation inside the VM, since the Provisioning Agent installs *this*
    CA into the VM's trust store, not mitmproxy's auto-generated one.
    """
    return mitm_confdir() / "mitmproxy-ca.pem"
