import pytest

from orca_proxy.app import create_app


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("ORCA_PROXY_HOME", str(tmp_path))
    return create_app()


@pytest.fixture
async def client(app, aiohttp_client):
    return await aiohttp_client(app)
