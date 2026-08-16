async def test_readyz_ready_after_startup(client):
    resp = await client.get("/readyz")
    body = await resp.json()
    assert resp.status == 200
    assert body["ready"] is True
    assert body["checks"] == {"migrations": True, "ca_materialized": True}
