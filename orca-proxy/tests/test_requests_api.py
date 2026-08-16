async def test_list_requests_empty(client):
    resp = await client.get("/api/v1/requests")
    body = await resp.json()
    assert resp.status == 200
    assert body["connections"] == []


async def test_list_and_get_request(client, app):
    log = app["request_log"]
    connection_id = log.log_connection(
        started_at="2026-08-16T00:00:00+00:00",
        vm_name="skills-dev",
        destination_ip="140.82.112.3",
        destination_port=443,
        destination_hostname="github.com",
        sni_present=True,
        ech_present=False,
        duration_ms=10,
        intercepted=False,
        outcome="allow_default",
    )

    resp = await client.get("/api/v1/requests")
    body = await resp.json()
    assert resp.status == 200
    assert len(body["connections"]) == 1
    assert body["connections"][0]["id"] == connection_id
    assert "http_requests" not in body["connections"][0]

    resp = await client.get(f"/api/v1/requests/{connection_id}")
    body = await resp.json()
    assert resp.status == 200
    assert body["id"] == connection_id
    assert body["http_requests"] == []


async def test_get_missing_request_404(client):
    resp = await client.get("/api/v1/requests/999")
    assert resp.status == 404


async def test_get_request_invalid_id_422(client):
    resp = await client.get("/api/v1/requests/not-a-number")
    assert resp.status == 422


async def test_list_requests_filter_by_vm(client, app):
    log = app["request_log"]
    log.log_connection(
        started_at="t", vm_name="vm-a", destination_ip="1.2.3.4", destination_port=443,
        destination_hostname="a.com", sni_present=True, ech_present=False, duration_ms=1,
        intercepted=False, outcome="allow_default",
    )
    keep = log.log_connection(
        started_at="t", vm_name="vm-b", destination_ip="1.2.3.4", destination_port=443,
        destination_hostname="b.com", sni_present=True, ech_present=False, duration_ms=1,
        intercepted=False, outcome="allow_default",
    )
    resp = await client.get("/api/v1/requests?vm=vm-b")
    body = await resp.json()
    assert [c["id"] for c in body["connections"]] == [keep]
