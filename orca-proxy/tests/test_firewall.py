from types import SimpleNamespace

from orca_proxy.firewall import FILTER_CHAIN, NAT_CHAIN, FirewallSync, build_commands, reconcile


class FakeRunner:
    def __init__(self, fail_on: set[int] | None = None):
        self.calls: list[list[str]] = []
        self._fail_on = fail_on or set()

    def __call__(self, command, **kwargs):
        self.calls.append(command)
        returncode = 1 if len(self.calls) - 1 in self._fail_on else 0
        return SimpleNamespace(returncode=returncode, stdout="", stderr="boom" if returncode else "")


# --- build_commands (pure) ---

def test_build_commands_creates_and_flushes_both_chains():
    commands = build_commands([], "mpqemubr0", 8443)
    joined = [" ".join(c) if c[0] != "sh" else c[-1] for c in commands]
    # -N is tolerant-of-already-exists (sh -c ... || true) so a rebuild
    # after the first VM registration doesn't abort before the -F flush —
    # see test_build_commands_chain_create_tolerates_already_exists.
    assert any(f"-t nat -N {NAT_CHAIN}" in s for s in joined)
    assert any(f"-N {FILTER_CHAIN}" in s and "-t nat" not in s for s in joined)
    assert ["iptables", "-t", "nat", "-F", NAT_CHAIN] in commands
    assert ["iptables", "-F", FILTER_CHAIN] in commands


def test_build_commands_chain_create_tolerates_already_exists():
    """iptables -N exits 1 if the chain already exists — true on every
    reconcile after the first VM registration. reconcile() treats any
    non-zero exit as fatal, so the -N commands must never fail on their
    own; a real bug had this abort the whole rebuild before the -F flush.
    """
    commands = build_commands([], "mpqemubr0", 8443)
    create_commands = [c for c in commands if c[0] == "sh" and "-N" in c[-1]]
    assert len(create_commands) == 2
    for c in create_commands:
        assert "|| true" in c[-1]


def test_build_commands_rejects_unsafe_bridge_name():
    import pytest

    with pytest.raises(ValueError):
        build_commands([], "eth0; id > /tmp/pwned; #", 8443)


def test_build_commands_one_vm_gets_redirect_and_drop_for_both_ports():
    commands = build_commands([("skills-dev", "10.14.105.22")], "mpqemubr0", 8443)
    nat_rules = [c for c in commands if c[:4] == ["iptables", "-t", "nat", "-A"]]
    filter_rules = [c for c in commands if c[:3] == ["iptables", "-A", FILTER_CHAIN]]
    assert len(nat_rules) == 2  # 80 and 443
    assert len(filter_rules) == 2
    assert all("-s" in c and "10.14.105.22" in c for c in nat_rules)
    assert all("REDIRECT" in c and "8443" in c for c in nat_rules)
    assert all("DROP" in c for c in filter_rules)


def test_build_commands_multiple_vms_each_get_their_own_rules():
    commands = build_commands(
        [("vm-a", "10.0.0.1"), ("vm-b", "10.0.0.2")], "mpqemubr0", 8443
    )
    nat_rules = [c for c in commands if c[:4] == ["iptables", "-t", "nat", "-A"]]
    assert len(nat_rules) == 4  # 2 VMs x 2 ports


def test_build_commands_hooks_chains_via_idempotent_check_then_add():
    commands = build_commands([], "mpqemubr0", 8443)
    joined = [" ".join(c) if isinstance(c, list) and c[0] != "sh" else c[-1] for c in commands]
    assert any("PREROUTING" in s and NAT_CHAIN in s for s in joined)
    assert any("FORWARD" in s and FILTER_CHAIN in s and "-I FORWARD 1" in s for s in joined)


# --- reconcile (execution, fake runner) ---

def test_reconcile_reports_in_sync_when_every_command_succeeds():
    runner = FakeRunner()
    status = reconcile([("vm-a", "10.0.0.1")], "mpqemubr0", 8443, runner=runner)
    assert status == {"vm-a": "in_sync"}
    assert len(runner.calls) > 0


def test_reconcile_reports_error_for_every_vm_when_any_command_fails():
    runner = FakeRunner(fail_on={0})  # fail the very first command
    status = reconcile(
        [("vm-a", "10.0.0.1"), ("vm-b", "10.0.0.2")], "mpqemubr0", 8443, runner=runner
    )
    assert status == {"vm-a": "error", "vm-b": "error"}


def test_reconcile_stops_running_commands_after_first_failure():
    runner = FakeRunner(fail_on={0})
    reconcile([("vm-a", "10.0.0.1")], "mpqemubr0", 8443, runner=runner)
    total_commands = len(build_commands([("vm-a", "10.0.0.1")], "mpqemubr0", 8443))
    assert len(runner.calls) == 1 < total_commands


# --- FirewallSync (aiohttp-side wrapper) ---

class FakeScriptRunner:
    """Fakes the `sudo -n <script> ...` subprocess call itself, not the
    inner iptables commands — this is what FirewallSync actually invokes.
    """

    def __init__(self, stdout='{"vm-a": "in_sync"}', returncode=0, stderr=""):
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr
        self.calls: list[list[str]] = []

    def __call__(self, command, **kwargs):
        self.calls.append(command)
        return SimpleNamespace(returncode=self.returncode, stdout=self.stdout, stderr=self.stderr)


def test_firewall_sync_reconcile_updates_status():
    runner = FakeScriptRunner()
    sync = FirewallSync("/path/to/script", "/path/to/db", "mpqemubr0", 8443, runner=runner)
    status = sync.reconcile(vm_count=1)
    assert status == {"vm-a": "in_sync"}
    assert sync.status == {"vm-a": "in_sync"}
    assert sync.is_synced is True


def test_firewall_sync_skips_script_when_vm_count_zero():
    runner = FakeScriptRunner()
    sync = FirewallSync("/path/to/script", "/path/to/db", "mpqemubr0", 8443, runner=runner)
    status = sync.reconcile(vm_count=0)
    assert status == {}
    assert sync.is_synced is True
    assert runner.calls == []


def test_firewall_sync_marks_unsynced_on_script_failure():
    runner = FakeScriptRunner(returncode=1, stderr="permission denied")
    sync = FirewallSync("/path/to/script", "/path/to/db", "mpqemubr0", 8443, runner=runner)
    sync.reconcile(vm_count=1)
    assert sync.is_synced is False
    assert "__error__" in sync.status


def test_firewall_sync_marks_unsynced_on_malformed_output():
    runner = FakeScriptRunner(stdout="not json")
    sync = FirewallSync("/path/to/script", "/path/to/db", "mpqemubr0", 8443, runner=runner)
    sync.reconcile(vm_count=1)
    assert sync.is_synced is False


def test_firewall_sync_never_raises_even_if_runner_throws():
    def exploding_runner(*args, **kwargs):
        raise OSError("sudo not found")

    sync = FirewallSync("/path/to/script", "/path/to/db", "mpqemubr0", 8443, runner=exploding_runner)
    status = sync.reconcile(vm_count=1)
    assert "__error__" in status
    assert sync.is_synced is False


def test_firewall_sync_flushes_on_delete_to_zero_after_having_had_vms():
    """Deleting the last registered VM must still run the script — skipping
    it leaves that VM's REDIRECT/DROP rules stale in the kernel, which can
    later match an unrelated VM that recycles the same IP.
    """
    runner = FakeScriptRunner(stdout="{}")
    sync = FirewallSync("/path/to/script", "/path/to/db", "mpqemubr0", 8443, runner=runner)
    sync.reconcile(vm_count=1)
    assert len(runner.calls) == 1
    sync.reconcile(vm_count=0)
    assert len(runner.calls) == 2  # script actually ran the second time too
    assert sync.status == {}


def test_firewall_sync_invokes_sudo_n_with_the_named_script_path():
    runner = FakeScriptRunner()
    sync = FirewallSync("/opt/orca-proxy/bin/orca-proxy-firewall-sync", "/data/state.sqlite", "mpqemubr0", 8443, runner=runner)
    sync.reconcile(vm_count=1)
    assert runner.calls[0][:3] == ["sudo", "-n", "/opt/orca-proxy/bin/orca-proxy-firewall-sync"]
