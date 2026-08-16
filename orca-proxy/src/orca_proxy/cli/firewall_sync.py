"""The one script the sudoers NOPASSWD entry names (design ticket #12).

Deliberately narrow: read the VM table, rebuild the two iptables chains,
print a JSON per-VM status map to stdout. Runs as root; everything it
imports (db, repo.vms, firewall) is pure-stdlib/sqlite3, no aiohttp or
mitmproxy — no reason for a privileged process to carry either.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

from orca_proxy import db
from orca_proxy.firewall import reconcile
from orca_proxy.repo import vms as vms_repo


def main(argv: list[str] | None = None, runner=subprocess.run) -> int:
    parser = argparse.ArgumentParser(description="Rebuild orca-proxy's per-VM DNAT/DROP rules")
    parser.add_argument("--db", required=True, type=Path, help="path to state.sqlite")
    parser.add_argument("--bridge", required=True, help="Multipass bridge interface, e.g. mpqemubr0")
    parser.add_argument("--proxy-port", required=True, type=int)
    args = parser.parse_args(argv)

    conn = db.connect(args.db)
    vms = [(row["name"], row["ip_address"]) for row in vms_repo.list_all(conn)]
    conn.close()

    status = reconcile(vms, args.bridge, args.proxy_port, runner=runner)
    print(json.dumps(status))
    return 0 if all(v == "in_sync" for v in status.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
