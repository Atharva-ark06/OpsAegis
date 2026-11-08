import httpx
import pytest
from app.integrations.shannon import ShannonRunnerAdapter, ShannonRunnerError

@pytest.mark.asyncio
async def test_adapter_requires_https(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "shannon_enabled", True)
    monkeypatch.setattr(settings, "shannon_runner_url", "http://runner.internal")
    monkeypatch.setattr(settings, "shannon_runner_token", "test-token")
    with pytest.raises(ShannonRunnerError, match="HTTPS"):
        await ShannonRunnerAdapter().healthcheck()

@pytest.mark.asyncio
async def test_adapter_health_contract(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "shannon_enabled", True)
    monkeypatch.setattr(settings, "shannon_runner_url", "https://runner.example.test")
    monkeypatch.setattr(settings, "shannon_runner_token", "test-token")
    class MockClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return None
        async def request(self, *args, **kwargs):
            return httpx.Response(200, json={"engine": "shannon", "status": "healthy", "version": "test"})
    monkeypatch.setattr("app.integrations.shannon.httpx.AsyncClient", lambda **kwargs: MockClient())
    assert (await ShannonRunnerAdapter().healthcheck())["engine"] == "shannon"
