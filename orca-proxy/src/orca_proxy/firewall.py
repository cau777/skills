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

import asyncio
import json
import re
import subprocess
from functools import partial
from pathlib import Path

NAT_CHAIN = "ORCA_PROXY_NAT"
FILTER_CHAIN = "ORCA_PROXY_FILTER"

# Linux interface names: IFNAMSIZ is 16 bytes including the NUL, so 15
# usable characters; no shell metacharacters permitted. `bridge` reaches
# this module from the sudoers-gated helper's own --bridge argv (an
# operator-controlled but *unvalidated* string until this check), and gets
# interpolated into `sh -c` strings below — an unvalidated value here is a
# straight shell-injection-to-root primitive, since the sudoers entry only
# restricts the script path, not its arguments.
_BRIDGE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")


def build_commands(vms: list[tuple[str, str]], bridge: str, proxy_port: int) -> list[list[str]]:
    """Return the full, idempotent sequence of iptables argv commands.

    `vms` is a list of (name, ip_address) pairs — only the IPs matter here,
    names are accepted for readability/logging by callers.
    """
    if not _BRIDGE_NAME_RE.match(bridge):
        raise ValueError(f"invalid bridge interface name: {bridge!r}")

    commands: list[list[str]] = [
        # Dedicated chains: create-if-absent via `sh -c ... || true` (a
        # bare `iptables -N` exits 1 if the chain already exists — true on
        # every reconcile after the first — which reconcile() would treat
        # as a fatal abort before ever reaching the -F flush or per-VM
        # rules below), then flush unconditionally — this is what makes
        # the whole thing an idempotent full rebuild rather than an
        # incremental patch.
        ["sh", "-c", f"iptables -t nat -N {NAT_CHAIN} 2>/dev/null || true"],
        ["iptables", "-t", "nat", "-F", NAT_CHAIN],
        ["sh", "-c", f"iptables -N {FILTER_CHAIN} 2>/dev/null || true"],
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
        # Tracks whether this process has ever asked the script to populate
        # the chains — NOT whether any VM is registered right now. Needed
        # to distinguish "fresh install, chains never touched, nothing to
        # flush" (safe to skip — avoids requiring sudo to be configured
        # before the first VM is ever registered) from "we just deleted the
        # last VM" (the chains still hold that VM's REDIRECT/DROP rules
        # from the last real reconcile and MUST be flushed, or they persist
        # indefinitely and can later match an unrelated VM that's recycled
        # the same DHCP-leased IP).
        self._ever_reconciled_nonzero = False

    def reconcile(self, vm_count: int | None = None) -> dict[str, str]:
        """`vm_count`, when given, skips invoking the privileged script only
        on a fresh install with zero VMs ever registered this process —
        there's nothing to reconcile, and no reason to shell out to sudo for
        a rebuild of empty chains. Once any reconcile has populated the
        chains, a later zero-VM call (e.g. deleting the last registered VM)
        always runs the script, since skipping it would leave that VM's
        rules stale in the kernel. Callers that don't have a cheap count
        handy can omit it; the script itself is idempotent either way.
        """
        if vm_count == 0 and not self._ever_reconciled_nonzero:
            self._status = {}
            return self._status
        if vm_count:
            self._ever_reconciled_nonzero = True
        try:
            self._status = run_reconcile_script(
                self._script_path, self._db_path, self._bridge, self._proxy_port, runner=self._runner
            )
        except Exception as exc:  # never let a firewall-sync failure break a VM CRUD response
            self._status = {"__error__": str(exc)}
        return self._status

    async def reconcile_async(self, vm_count: int | None = None) -> dict[str, str]:
        """Same as reconcile(), but off the calling event loop.

        `reconcile()` shells out via a blocking `subprocess.run(sudo ...)`
        call — fine for app.py's one startup call (runs before the loop is
        serving anything), but fatal for the Management API's per-VM
        create/delete handlers, which run embedded on mitmdump's own
        asyncio loop (#4's "same process" decision): a blocking call there
        freezes every in-flight TLS handshake and proxied request on the
        data plane for the duration of the sudo+iptables round-trip. Offload
        to a thread via run_in_executor so the loop stays responsive.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, partial(self.reconcile, vm_count))

    @property
    def status(self) -> dict[str, str]:
        return self._status

    @property
    def is_synced(self) -> bool:
        """Vacuously true with no registered VMs — nothing to reconcile yet,
        so a fresh install doesn't report unready before any VM exists.
        """
        return "__error__" not in self._status and all(v == "in_sync" for v in self._status.values())
