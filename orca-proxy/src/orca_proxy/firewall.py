"""Per-VM DNAT reconciliation (design ticket #12).

Split deliberately into a pure command-generation half (`build_commands`,
fully unit-testable without root or a real iptables) and a thin execution
half (`reconcile`, `run_reconcile_script`) that shells out — this is the
sudoers-gated helper script's actual logic, invoked synchronously by the
Management API on every VM create/delete per #12's resolution.

Two dedicated chains, fully rebuilt (flushed + repopulated) on every call —
never incrementally patched, matching the idempotent-full-replace pattern
used everywhere else on this map:

- `ORCA_PROXY_NAT` (nat table, jumped to from PREROUTING): REDIRECTs each
  registered VM's 80/443 to the local proxy port.
- `ORCA_PROXY_FILTER` (filter table, jumped to from FORWARD): DROPs the same
  VM/port combinations. This is the fail-closed baseline from #12's Q5 — if
  the NAT redirect is ever missing (a startup race, a reconciliation
  failure), a registered VM's 80/443 traffic is blocked rather than
  reaching the internet unenforced, instead of silently bypassing
  enforcement. Once a NAT rule successfully redirects a packet to the local
  proxy, it takes the INPUT path, not FORWARD, so this DROP rule is inert
  for correctly-redirected traffic and only fires when redirection failed.
"""

import json
import subprocess
from pathlib import Path

NAT_CHAIN = "ORCA_PROXY_NAT"
FILTER_CHAIN = "ORCA_PROXY_FILTER"


def build_commands(vms: list[tuple[str, str]], bridge: str, proxy_port: int) -> list[list[str]]:
    """Return the full, idempotent sequence of iptables argv commands.

    `vms` is a list of (name, ip_address) pairs — only the IPs matter here,
    names are accepted for readability/logging by callers.
    """
    commands: list[list[str]] = [
        # Dedicated chains: create if absent (ignore failure if they already
        # exist), then flush unconditionally — this is what makes the whole
        # thing an idempotent full rebuild rather than an incremental patch.
        ["iptables", "-t", "nat", "-N", NAT_CHAIN],
        ["iptables", "-t", "nat", "-F", NAT_CHAIN],
        ["iptables", "-N", FILTER_CHAIN],
        ["iptables", "-F", FILTER_CHAIN],
    ]

    for _name, ip in vms:
        for port in (80, 443):
            commands.append(
                [
                    "iptables", "-t", "nat", "-A", NAT_CHAIN,
                    "-s", ip, "-p", "tcp", "--dport", str(port),
                    "-j", "REDIRECT", "--to-port", str(proxy_port),
                ]
            )
            commands.append(
                [
                    "iptables", "-A", FILTER_CHAIN,
                    "-s", ip, "-p", "tcp", "--dport", str(port), "-j", "DROP",
                ]
            )

    # Hook the chains in, once — -C checks whether the jump rule already
    # exists (idempotent: skip the -I if so). The FORWARD jump uses -I
    # (insert at position 1) so it's evaluated before Multipass's own
    # bridge ACCEPT rules; the PREROUTING jump position doesn't carry the
    # same risk since REDIRECT only ever narrows traffic, never widens it.
    commands.append(
        [
            "sh", "-c",
            f"iptables -t nat -C PREROUTING -i {bridge} -j {NAT_CHAIN} 2>/dev/null || "
            f"iptables -t nat -A PREROUTING -i {bridge} -j {NAT_CHAIN}",
        ]
    )
    commands.append(
        [
            "sh", "-c",
            f"iptables -C FORWARD -i {bridge} -j {FILTER_CHAIN} 2>/dev/null || "
            f"iptables -I FORWARD 1 -i {bridge} -j {FILTER_CHAIN}",
        ]
    )

    return commands


def reconcile(
    vms: list[tuple[str, str]], bridge: str, proxy_port: int, runner=subprocess.run
) -> dict[str, str]:
    """Run build_commands()'s sequence, returning a per-VM status map.

    Status is "in_sync" for every VM if every command succeeds, or "error"
    for every VM if any command fails (the chains are rebuilt as one unit —
    a partial failure leaves the whole rebuild's success ambiguous per VM,
    so this errs toward reporting all of them as unsynced rather than
    guessing which specific rule failed).
    """
    commands = build_commands(vms, bridge, proxy_port)
    for command in commands:
        result = runner(command, capture_output=True, text=True)
        if result.returncode != 0:
            return {name: "error" for name, _ in vms}
    return {name: "in_sync" for name, _ in vms}


def run_reconcile_script(
    script_path: Path, db_path: Path, bridge: str, proxy_port: int, runner=subprocess.run
) -> dict[str, str]:
    """What the aiohttp process actually calls: invoke the sudoers-gated
    helper script as a subprocess and parse its JSON stdout. Kept separate
    from `reconcile()` so the Management API side never needs its own
    passwordless-root — only the one auditable script does.
    """
    result = runner(
        [
            "sudo", "-n", str(script_path),
            "--db", str(db_path),
            "--bridge", bridge,
            "--proxy-port", str(proxy_port),
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return {"__error__": result.stderr.strip() or "firewall-sync script failed"}
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"__error__": "firewall-sync script returned malformed output"}


class FirewallSync:
    """aiohttp-side handle: triggers the sudoers-gated script and remembers
    the last-known per-VM status for `/readyz` (#12's Q7 — no separate
    diagnostics endpoint, everything folds into `/readyz`'s JSON body).
    """

    def __init__(self, script_path: Path, db_path: Path, bridge: str, proxy_port: int, runner=subprocess.run):
        self._script_path = script_path
        self._db_path = db_path
        self._bridge = bridge
        self._proxy_port = proxy_port
        self._runner = runner
        self._status: dict[str, str] = {}

    def reconcile(self, vm_count: int | None = None) -> dict[str, str]:
        """`vm_count`, when given, skips invoking the privileged script
        entirely once it's zero — there's nothing to reconcile, and no
        reason to shell out to sudo for a rebuild of empty chains. Callers
        that don't have a cheap count handy can omit it; the script itself
        is idempotent either way.
        """
        if vm_count == 0:
            self._status = {}
            return self._status
        try:
            self._status = run_reconcile_script(
                self._script_path, self._db_path, self._bridge, self._proxy_port, runner=self._runner
            )
        except Exception as exc:  # never let a firewall-sync failure break a VM CRUD response
            self._status = {"__error__": str(exc)}
        return self._status

    @property
    def status(self) -> dict[str, str]:
        return self._status

    @property
    def is_synced(self) -> bool:
        """Vacuously true with no registered VMs — nothing to reconcile yet,
        so a fresh install doesn't report unready before any VM exists.
        """
        return "__error__" not in self._status and all(v == "in_sync" for v in self._status.values())
