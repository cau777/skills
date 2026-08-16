import pytest

from orca_proxy import request_log


@pytest.fixture
def log(tmp_path):
    conn = request_log.connect(tmp_path / "requests.sqlite")
    yield request_log.RequestLog(conn, retention_rows=1000)
    conn.close()


def _log_conn(log, **overrides):
    defaults = dict(
        started_at="2026-08-16T00:00:00+00:00",
        vm_name="skills-dev",
        destination_ip="140.82.112.3",
        destination_port=443,
        destination_hostname="github.com",
        sni_present=True,
        ech_present=False,
        duration_ms=12,
        intercepted=False,
        outcome="allow_default",
        matched_rule=None,
        intercepted_by_rule=None,
    )
    defaults.update(overrides)
    return log.log_connection(**defaults)


def test_log_connection_roundtrips(log):
    connection_id = _log_conn(log)
    row = log.get_connection(connection_id)
    assert row["vm_name"] == "skills-dev"
    assert row["destination_hostname"] == "github.com"
    assert row["sni_present"] is True
    assert row["ech_present"] is False
    assert row["intercepted"] is False
    assert row["outcome"] == "allow_default"
    assert row["http_requests"] == []


def test_intercepted_connection_snapshots_matched_rule(log):
    connection_id = _log_conn(
        log,
        intercepted=True,
        outcome=None,
        intercepted_by_rule={"name": "inject-github", "priority": 10},
    )
    row = log.get_connection(connection_id)
    assert row["intercepted"] is True
    assert row["intercepted_by_rule"] == {"name": "inject-github", "priority": 10}


def test_http_request_nested_under_connection(log):
    connection_id = _log_conn(log, intercepted=True, outcome=None)
    log.log_http_request(
        connection_id=connection_id,
        occurred_at="2026-08-16T00:00:01+00:00",
        method="GET",
        path="/repos/cau777/issues",
        query_keys=["state"],
        status=200,
        status_origin="upstream",
        latency_ms=184,
        outcome="allow_credential",
        matched_rule={"name": "inject-github", "priority": 10},
        matched_credential="github-host-login",
        trace=[{"rule_name": "inject-github", "priority": 10, "action_type": "allow_with_credential", "result": "matched_terminal"}],
        headers=[{"name": "Host", "value": "api.github.com", "redacted": False, "redaction_reason": None}],
    )
    row = log.get_connection(connection_id)
    assert len(row["http_requests"]) == 1
    req = row["http_requests"][0]
    assert req["method"] == "GET"
    assert req["query_keys"] == ["state"]
    assert req["matched_credential"] == "github-host-login"
    assert req["trace"][0]["result"] == "matched_terminal"


def test_cascade_delete_removes_http_requests(log):
    connection_id = _log_conn(log, intercepted=True, outcome=None)
    log.log_http_request(
        connection_id=connection_id,
        occurred_at="t",
        method="GET",
        path="/x",
        query_keys=[],
        status=200,
        status_origin="upstream",
        latency_ms=1,
        outcome="allow_credential",
        matched_rule=None,
        matched_credential=None,
        trace=[],
        headers=[],
    )
    log._conn.execute("DELETE FROM connections WHERE id = ?", (connection_id,))
    remaining = log._conn.execute("SELECT COUNT(*) AS n FROM http_requests").fetchone()
    assert remaining["n"] == 0


def test_get_missing_connection_returns_none(log):
    assert log.get_connection(999) is None


def test_list_connections_newest_first(log):
    first = _log_conn(log, destination_hostname="a.com")
    second = _log_conn(log, destination_hostname="b.com")
    rows = log.list_connections()
    assert [r["id"] for r in rows] == [second, first]


def test_list_connections_keyset_pagination(log):
    ids = [_log_conn(log, destination_hostname=f"{i}.com") for i in range(5)]
    page1 = log.list_connections(limit=2)
    assert [r["id"] for r in page1] == [ids[4], ids[3]]
    page2 = log.list_connections(limit=2, before=page1[-1]["id"])
    assert [r["id"] for r in page2] == [ids[2], ids[1]]


def test_list_connections_filter_by_vm(log):
    _log_conn(log, vm_name="vm-a")
    keep = _log_conn(log, vm_name="vm-b")
    rows = log.list_connections(vm="vm-b")
    assert [r["id"] for r in rows] == [keep]


def test_list_connections_filter_by_host(log):
    _log_conn(log, destination_hostname="a.com")
    keep = _log_conn(log, destination_hostname="b.com")
    rows = log.list_connections(host="b.com")
    assert [r["id"] for r in rows] == [keep]


def test_list_connections_filter_by_decision_matches_connection_level(log):
    _log_conn(log, outcome="allow_default")
    keep = _log_conn(log, outcome="block_rule")
    rows = log.list_connections(decision="block_rule")
    assert [r["id"] for r in rows] == [keep]


def test_list_connections_filter_by_decision_reaches_child_rows(log):
    # An intercepted-but-later-blocked connection has no connection-level
    # outcome at all (per #14) — the decision filter must still surface it
    # via its child http_requests row (#11's Q15 resolution).
    connection_id = _log_conn(log, intercepted=True, outcome=None)
    log.log_http_request(
        connection_id=connection_id,
        occurred_at="t",
        method="GET",
        path="/user",
        query_keys=[],
        status=None,
        status_origin=None,
        latency_ms=None,
        outcome="block_rule",
        matched_rule=None,
        matched_credential=None,
        trace=[],
        headers=[],
    )
    rows = log.list_connections(decision="block_rule")
    assert [r["id"] for r in rows] == [connection_id]


def test_list_connections_does_not_nest_http_requests(log):
    connection_id = _log_conn(log, intercepted=True, outcome=None)
    log.log_http_request(
        connection_id=connection_id,
        occurred_at="t",
        method="GET",
        path="/x",
        query_keys=[],
        status=200,
        status_origin="upstream",
        latency_ms=1,
        outcome="allow_credential",
        matched_rule=None,
        matched_credential=None,
        trace=[],
        headers=[],
    )
    rows = log.list_connections()
    assert "http_requests" not in rows[0]


def test_retention_prunes_oldest_connections(log):
    log._retention_rows = 3
    ids = [_log_conn(log, destination_hostname=f"{i}.com") for i in range(5)]
    remaining = {r["id"] for r in log.list_connections(limit=200)}
    assert remaining == set(ids[-3:])


def test_write_failure_is_fail_open_not_raised(log, capsys):
    log._conn.close()  # force the next write to fail
    result = log.log_connection(
        started_at="t",
        vm_name="v",
        destination_ip="1.2.3.4",
        destination_port=443,
        destination_hostname="x.com",
        sni_present=True,
        ech_present=False,
        duration_ms=1,
        intercepted=False,
        outcome="allow_default",
    )
    assert result is None
    assert "log write failed" in capsys.readouterr().err
