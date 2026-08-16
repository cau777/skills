import json
from types import SimpleNamespace

from orca_proxy import db
from orca_proxy.cli.firewall_sync import main
from orca_proxy.repo import vms as vms_repo


def _db(tmp_path):
    conn = db.connect(tmp_path / "state.sqlite")
    db.migrate(conn)
    return conn


def _ok_runner(command, **kwargs):
    return SimpleNamespace(returncode=0, stdout="", stderr="")


def test_main_prints_json_status_and_returns_zero(tmp_path, capsys):
    conn = _db(tmp_path)
    vms_repo.put(conn, "skills-dev", "10.14.105.22")
    conn.close()

    exit_code = main(
        ["--db", str(tmp_path / "state.sqlite"), "--bridge", "mpqemubr0", "--proxy-port", "8443"],
        runner=_ok_runner,
    )

    assert exit_code == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed == {"skills-dev": "in_sync"}


def test_main_returns_nonzero_on_failure(tmp_path, capsys):
    conn = _db(tmp_path)
    vms_repo.put(conn, "skills-dev", "10.14.105.22")
    conn.close()

    def failing_runner(command, **kwargs):
        return SimpleNamespace(returncode=1, stdout="", stderr="permission denied")

    exit_code = main(
        ["--db", str(tmp_path / "state.sqlite"), "--bridge", "mpqemubr0", "--proxy-port", "8443"],
        runner=failing_runner,
    )
    assert exit_code == 1


def test_main_with_no_vms_still_prints_valid_json(tmp_path, capsys):
    _db(tmp_path).close()
    exit_code = main(
        ["--db", str(tmp_path / "state.sqlite"), "--bridge", "mpqemubr0", "--proxy-port", "8443"],
        runner=_ok_runner,
    )
    assert exit_code == 0
    assert json.loads(capsys.readouterr().out) == {}
