from dataclasses import dataclass, field

import pytest
from mitmproxy import tls
from mitmproxy.proxy.context import Context
from mitmproxy.test import tflow

from orca_proxy import config
from orca_proxy.proxy_addon import ECH_EXTENSION_TYPE, OrcaProxyAddon
from orca_proxy.repo import credentials as credentials_repo
from orca_proxy.repo import rules as rules_repo
from orca_proxy.repo import vms as vms_repo


@dataclass
class FakeClientHello:
    sni: str | None
    extensions: list[tuple[int, bytes]] = field(default_factory=list)


@pytest.fixture
def addon(tmp_path, monkeypatch):
    monkeypatch.setenv("ORCA_PROXY_HOME", str(tmp_path))
    a = OrcaProxyAddon()
    a.load(None)
    yield a
    a._state_conn.close()
    a._requests_conn.close()


def _put_vm(addon, name="skills-dev", ip="10.14.105.22"):
    vms_repo.put(addon._state_conn, name, ip)


def _put_credential(addon, name="gh", command="echo token", ttl_seconds=60):
    credentials_repo.put(addon._state_conn, name, command, ttl_seconds)


def _put_rule(addon, name, priority, hostname, action, vm_selector=None):
    rules_repo.put(
        addon._state_conn,
        name,
        priority,
        vm_selector or {"type": "all"},
        hostname,
        action,
    )


def _client_hello_data(addon, *, sni, extensions=None, client_ip="10.14.105.22", dest=("140.82.112.3", 443)):
    client = tflow.tclient_conn()
    client.peername = (client_ip, 51234)
    ctx = Context(client, config_options())
    ctx.server = tflow.tserver_conn()
    ctx.server.address = dest
    return tls.ClientHelloData(context=ctx, client_hello=FakeClientHello(sni=sni, extensions=extensions or []))


def config_options():
    from mitmproxy.options import Options

    return Options()


# --- tls_clienthello ---

def test_unmatched_hostname_passes_through_default_allow(addon):
    data = _client_hello_data(addon, sni="example.com")
    addon.tls_clienthello(data)
    assert data.ignore_connection is True
    assert data.context.client.error is None

    row = addon._log.get_connection(data.context.client.orca_connection_id)
    assert row["outcome"] == "allow_default"
    assert row["intercepted"] is False


def test_matching_allow_rule_passes_through(addon):
    _put_vm(addon)
    _put_rule(addon, "allow-example", 10, "example.com", {"type": "allow"})
    data = _client_hello_data(addon, sni="example.com")
    addon.tls_clienthello(data)
    assert data.ignore_connection is True

    row = addon._log.get_connection(data.context.client.orca_connection_id)
    assert row["outcome"] == "allow_rule"
    assert row["matched_rule"]["name"] == "allow-example"


def test_matching_block_rule_kills_connection(addon):
    _put_vm(addon)
    _put_rule(addon, "block-evil", 10, "evil.example", {"type": "block"})
    data = _client_hello_data(addon, sni="evil.example")
    addon.tls_clienthello(data)
    assert data.context.client.error == "blocked by orca-proxy policy"
    assert data.ignore_connection is False

    row = addon._log.get_connection(data.context.client.orca_connection_id)
    assert row["outcome"] == "block_rule"


def test_allow_with_credential_forces_interception_no_kill_no_ignore(addon):
    _put_vm(addon)
    _put_credential(addon)
    _put_rule(
        addon, "inject-gh", 10, "api.github.com",
        {"type": "allow_with_credential", "credential": "gh", "path_prefix": "/repos/cau777",
         "injection": {"type": "bearer"}},
    )
    data = _client_hello_data(addon, sni="api.github.com")
    addon.tls_clienthello(data)
    assert data.ignore_connection is False
    assert data.context.client.error is None

    row = addon._log.get_connection(data.context.client.orca_connection_id)
    assert row["intercepted"] is True
    assert row["intercepted_by_rule"]["name"] == "inject-gh"
    assert row["outcome"] is None


def test_ech_and_no_sni_logged(addon):
    data = _client_hello_data(addon, sni=None, extensions=[(ECH_EXTENSION_TYPE, b"")])
    addon.tls_clienthello(data)
    row = addon._log.get_connection(data.context.client.orca_connection_id)
    assert row["sni_present"] is False
    assert row["ech_present"] is True
    assert row["destination_hostname"] is None
    assert row["outcome"] == "allow_default"  # no-SNI can never match a hostname Rule


def test_destination_recovered_from_context_server_address(addon):
    data = _client_hello_data(addon, sni="example.com", dest=("93.184.216.34", 443))
    addon.tls_clienthello(data)
    row = addon._log.get_connection(data.context.client.orca_connection_id)
    assert row["destination_ip"] == "93.184.216.34"
    assert row["destination_port"] == 443


def test_unregistered_vm_ip_still_logged_defensively(addon):
    data = _client_hello_data(addon, sni="example.com", client_ip="192.0.2.1")
    addon.tls_clienthello(data)
    row = addon._log.get_connection(data.context.client.orca_connection_id)
    assert row["vm_name"] == "192.0.2.1"


# --- request/response ---

def _flow_for(addon, client_conn, path="/repos/cau777/issues", host="api.github.com", method="GET"):
    flow = tflow.tflow()
    flow.client_conn = client_conn
    flow.request.host = host
    flow.request.path = path
    flow.request.method = method
    return flow


async def test_request_injects_bearer_header_on_matching_path(addon):
    _put_vm(addon)
    _put_credential(addon, command="echo secret-token")
    _put_rule(
        addon, "inject-gh", 10, "api.github.com",
        {"type": "allow_with_credential", "credential": "gh", "path_prefix": "/repos/cau777",
         "injection": {"type": "bearer"}},
    )
    data = _client_hello_data(addon, sni="api.github.com")
    addon.tls_clienthello(data)

    flow = _flow_for(addon, data.context.client)
    await addon.request(flow)

    assert flow.request.headers["Authorization"] == "Bearer secret-token"
    assert flow.response is None  # forwarded upstream


async def test_request_credential_failure_returns_502(addon):
    _put_vm(addon)
    _put_credential(addon, command="exit 1")
    _put_rule(
        addon, "inject-gh", 10, "api.github.com",
        {"type": "allow_with_credential", "credential": "gh", "path_prefix": "/repos/cau777",
         "injection": {"type": "bearer"}},
    )
    data = _client_hello_data(addon, sni="api.github.com")
    addon.tls_clienthello(data)

    flow = _flow_for(addon, data.context.client)
    await addon.request(flow)

    assert flow.response.status_code == 502
    assert b"credential_unavailable" in flow.response.content

    row = addon._log.get_connection(data.context.client.orca_connection_id)
    assert row["http_requests"][0]["status_origin"] == "proxy"
    assert row["http_requests"][0]["status"] == 502


async def test_request_non_matching_path_forwarded_without_credential(addon):
    _put_vm(addon)
    _put_credential(addon)
    _put_rule(
        addon, "inject-gh", 10, "api.github.com",
        {"type": "allow_with_credential", "credential": "gh", "path_prefix": "/repos/cau777",
         "injection": {"type": "bearer"}},
    )
    data = _client_hello_data(addon, sni="api.github.com")
    addon.tls_clienthello(data)

    flow = _flow_for(addon, data.context.client, path="/user")
    await addon.request(flow)

    assert "Authorization" not in flow.request.headers
    assert flow.response is None


async def test_intercepted_connection_still_blocked_by_lower_priority_rule(addon):
    _put_vm(addon)
    _put_credential(addon)
    _put_rule(
        addon, "inject-gh", 10, "api.github.com",
        {"type": "allow_with_credential", "credential": "gh", "path_prefix": "/repos/cau777",
         "injection": {"type": "bearer"}},
    )
    _put_rule(addon, "block-rest", 20, "api.github.com", {"type": "block"})
    data = _client_hello_data(addon, sni="api.github.com")
    addon.tls_clienthello(data)
    assert data.ignore_connection is False  # interception still forced by the AWC rule

    flow = _flow_for(addon, data.context.client, path="/user")
    await addon.request(flow)
    assert flow.response.status_code == 403


def test_response_hook_logs_upstream_status(addon):
    _put_vm(addon)
    data = _client_hello_data(addon, sni="example.com")
    addon.tls_clienthello(data)

    flow = _flow_for(addon, data.context.client, host="example.com", path="/")
    flow.response = tflow.tresp(status_code=200)
    flow.metadata["orca_started"] = 0.0
    flow.metadata["orca_query_keys"] = []
    from orca_proxy.rule_engine import RequestDecision, ALLOW_DEFAULT

    flow.metadata["orca_decision"] = RequestDecision(outcome=ALLOW_DEFAULT)
    flow.metadata["orca_injected_header"] = None
    flow.metadata["orca_credential_name"] = None

    addon.response(flow)

    row = addon._log.get_connection(data.context.client.orca_connection_id)
    assert row["http_requests"][0]["status"] == 200
    assert row["http_requests"][0]["status_origin"] == "upstream"


def test_response_does_not_double_log_when_already_logged(addon):
    _put_vm(addon)
    data = _client_hello_data(addon, sni="example.com")
    addon.tls_clienthello(data)
    flow = _flow_for(addon, data.context.client)
    flow.metadata["orca_logged"] = True

    addon.response(flow)  # should be a no-op

    row = addon._log.get_connection(data.context.client.orca_connection_id)
    assert row["http_requests"] == []


def test_client_disconnected_records_duration(addon):
    data = _client_hello_data(addon, sni="example.com")
    addon.tls_clienthello(data)
    connection_id = data.context.client.orca_connection_id

    addon.client_disconnected(data.context.client)

    row = addon._log.get_connection(connection_id)
    assert row["duration_ms"] is not None
    assert row["duration_ms"] >= 0


async def test_headers_redacted_in_logged_request(addon):
    _put_vm(addon)
    _put_credential(addon, command="echo secret-value")
    _put_rule(
        addon, "inject-gh", 10, "api.github.com",
        {"type": "allow_with_credential", "credential": "gh", "path_prefix": "/repos/cau777",
         "injection": {"type": "bearer"}},
    )
    data = _client_hello_data(addon, sni="api.github.com")
    addon.tls_clienthello(data)

    flow = _flow_for(addon, data.context.client)
    flow.request.headers["Cookie"] = "session=abc"

    await addon.request(flow)
    flow.response = tflow.tresp(status_code=201)
    addon.response(flow)

    row = addon._log.get_connection(data.context.client.orca_connection_id)
    headers = {h["name"]: h for h in row["http_requests"][0]["headers"]}
    assert headers["Cookie"]["value"] == "[REDACTED]"
    assert "secret-value" not in str(row)
    assert headers["Authorization"]["value"] == "[REDACTED · injected by gh]"
