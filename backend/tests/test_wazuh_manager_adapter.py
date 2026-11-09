from types import SimpleNamespace
import httpx
import pytest
from app.integrations.wazuh_manager import WazuhManagerAdapter,WazuhManagerError

def config(**overrides):
    values={"wazuh_manager_url":"https://manager.example:55000","wazuh_manager_username":"readonly","wazuh_manager_password":"secret",
        "wazuh_manager_ca_cert":None,"wazuh_manager_timeout_seconds":5,"wazuh_manager_max_agents":500}
    values.update(overrides);return SimpleNamespace(**values)
def agent(agent_id="001",status="active"):
    return {"id":agent_id,"name":"web-01","ip":"10.0.0.12","status":status,"lastKeepAlive":"2026-11-08T10:00:00Z",
        "os":{"name":"Ubuntu","version":"24.04","platform":"ubuntu"},"version":"Wazuh v4.14.0"}

@pytest.mark.asyncio
async def test_authenticates_then_reads_agents_with_bearer_and_pagination():
    requests=[]
    def handler(request):
        requests.append(request)
        if request.url.path=="/security/user/authenticate":
            assert request.headers["authorization"].startswith("Basic ");return httpx.Response(200,json={"data":{"token":"test-jwt"}})
        assert request.headers["authorization"]=="Bearer test-jwt" and request.url.path=="/agents"
        return httpx.Response(200,json={"data":{"affected_items":[agent()],"total_affected_items":1}})
    results=await WazuhManagerAdapter(config(),transport=httpx.MockTransport(handler)).collect_agents()
    assert len(results)==1 and results[0]["id"]=="001" and requests[0].method=="POST" and requests[1].method=="GET"
    assert "os.name" in requests[1].url.params["select"].split(",")

@pytest.mark.asyncio
async def test_healthcheck_authenticates_and_reads_manager_root():
    def handler(request):
        if request.url.path=="/security/user/authenticate":return httpx.Response(200,json={"data":{"token":"jwt"}})
        assert request.headers["authorization"]=="Bearer jwt";return httpx.Response(200,json={"data":{"api_version":"4.14.0"}})
    assert await WazuhManagerAdapter(config(),transport=httpx.MockTransport(handler)).healthcheck()

@pytest.mark.asyncio
async def test_unconfigured_and_http_urls_fail_closed():
    with pytest.raises(WazuhManagerError,match="not configured"):await WazuhManagerAdapter(config(wazuh_manager_password="")).collect_agents()
    with pytest.raises(WazuhManagerError,match="HTTPS"):await WazuhManagerAdapter(config(wazuh_manager_url="http://manager.example")).collect_agents()

@pytest.mark.asyncio
async def test_auth_errors_are_sanitized():
    adapter=WazuhManagerAdapter(config(),transport=httpx.MockTransport(lambda request:httpx.Response(401)))
    with pytest.raises(WazuhManagerError,match="authentication failed"):await adapter.collect_agents()

@pytest.mark.asyncio
async def test_collection_is_bounded_to_configured_maximum():
    calls=[]
    def handler(request):
        if request.url.path.endswith("authenticate"):return httpx.Response(200,json={"data":{"token":"jwt"}})
        calls.append(request)
        offset=int(request.url.params["offset"])
        limit=int(request.url.params["limit"])
        items=[agent(str(i).zfill(3)) for i in range(offset,offset+limit)]
        return httpx.Response(200,json={"data":{"affected_items":items,"total_affected_items":1000}})
    results=await WazuhManagerAdapter(config(wazuh_manager_max_agents=503),transport=httpx.MockTransport(handler)).collect_agents()
    assert len(results)==503 and len(calls)==2
    assert [int(call.url.params["limit"]) for call in calls]==[500,3]

def test_normalizes_manager_status_os_and_last_seen():
    item=WazuhManagerAdapter.normalize_agent(agent("001","disconnected"))
    assert item["agent_status"]=="disconnected" and item["os_name"]=="Ubuntu 24.04" and item["ip_address"]=="10.0.0.12"
    assert item["last_seen_at"].isoformat()=="2026-11-08T10:00:00+00:00"
    assert WazuhManagerAdapter.normalize_agent(agent("000")) is None
    bad=agent();bad["lastKeepAlive"]="bad";bad["ip"]="any";normalized=WazuhManagerAdapter.normalize_agent(bad)
    assert normalized["last_seen_at"] is None and normalized["ip_address"] is None


@pytest.mark.asyncio
async def test_rejects_manager_url_with_path_or_invalid_port():
    for url in (
        "https://manager.example:55000/api",
        "https://manager.example:99999",
    ):
        adapter = WazuhManagerAdapter(
            config(wazuh_manager_url=url),
            transport=httpx.MockTransport(lambda request: httpx.Response(200)),
        )
        with pytest.raises(WazuhManagerError, match="URL"):
            await adapter.collect_agents()


@pytest.mark.asyncio
async def test_rejects_malformed_authentication_token():
    adapter = WazuhManagerAdapter(
        config(),
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"data": {"token": "bad token"}})
        ),
    )
    with pytest.raises(WazuhManagerError, match="invalid authentication"):
        await adapter.collect_agents()


@pytest.mark.asyncio
async def test_rejects_page_larger_than_requested_limit():
    def handler(request):
        if request.url.path.endswith("authenticate"):
            return httpx.Response(200, json={"data": {"token": "jwt"}})
        return httpx.Response(
            200,
            json={
                "data": {
                    "affected_items": [agent("001"), agent("002")],
                    "total_affected_items": 2,
                }
            },
        )

    adapter = WazuhManagerAdapter(
        config(wazuh_manager_max_agents=1),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(WazuhManagerError, match="page size"):
        await adapter.collect_agents()


@pytest.mark.asyncio
async def test_rejects_invalid_agent_limit_before_request():
    adapter = WazuhManagerAdapter(config(wazuh_manager_max_agents=0))
    with pytest.raises(WazuhManagerError, match="agent limit"):
        await adapter.collect_agents()


def test_rejects_boolean_total_in_manager_response():
    with pytest.raises(WazuhManagerError, match="invalid agent collection"):
        WazuhManagerAdapter._items(
            {"data": {"affected_items": [], "total_affected_items": True}}
        )
