from types import SimpleNamespace
import httpx
import pytest
from app.integrations.crowdsec import CrowdSecAdapterError, CrowdSecLapiAdapter

def config(**overrides):
    values = {"crowdsec_lapi_url":"https://crowdsec.example:8080","crowdsec_api_key":"test-bouncer-key",
        "crowdsec_ca_cert":None,"crowdsec_timeout_seconds":5,"crowdsec_max_results":100}
    values.update(overrides)
    return SimpleNamespace(**values)

@pytest.mark.asyncio
async def test_collects_active_decisions_with_bouncer_auth():
    captured=[]
    def handler(request):
        captured.append(request)
        return httpx.Response(200,json=[{"id":123,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf",
            "scope":"Ip","type":"ban","value":"203.0.113.8","duration":"2h"}])
    findings=await CrowdSecLapiAdapter(config(),transport=httpx.MockTransport(handler)).collect_findings()
    assert len(findings)==1
    item=findings[0]
    assert (item.source_engine,item.source_native_id,item.severity)==("crowdsec","123","high")
    assert item.asset_reference=="203.0.113.8"
    assert item.evidence["scenario"]=="crowdsecurity/ssh-bf"
    assert captured[0].url.path=="/v1/decisions"
    assert captured[0].headers["x-api-key"]=="test-bouncer-key"
    assert captured[0].url.params["limit"]=="100"

@pytest.mark.asyncio
async def test_healthcheck_uses_bounded_read_only_endpoint():
    def handler(request):
        assert request.url.path=="/v1/decisions" and request.url.params["limit"]=="1"
        return httpx.Response(200,json=[])
    assert await CrowdSecLapiAdapter(config(),transport=httpx.MockTransport(handler)).healthcheck()

@pytest.mark.asyncio
async def test_null_decisions_are_empty():
    def handler(request): return httpx.Response(200,content=b"null",headers={"Content-Type":"application/json"})
    assert await CrowdSecLapiAdapter(config(),transport=httpx.MockTransport(handler)).collect_findings()==[]

@pytest.mark.asyncio
async def test_missing_key_fails_closed():
    with pytest.raises(CrowdSecAdapterError,match="not configured"):
        await CrowdSecLapiAdapter(config(crowdsec_api_key="")).healthcheck()

@pytest.mark.asyncio
async def test_http_url_is_rejected():
    with pytest.raises(CrowdSecAdapterError,match="HTTPS"):
        await CrowdSecLapiAdapter(config(crowdsec_lapi_url="http://crowdsec:8080")).healthcheck()

@pytest.mark.asyncio
async def test_malformed_response_is_rejected():
    def handler(request): return httpx.Response(200,json={"decisions":[]})
    with pytest.raises(CrowdSecAdapterError,match="unexpected decisions"):
        await CrowdSecLapiAdapter(config(),transport=httpx.MockTransport(handler)).collect_findings()

@pytest.mark.asyncio
async def test_incomplete_decisions_are_skipped_unknown_actions_are_not_guessed():
    def handler(request):
        return httpx.Response(200,json=[{"id":1,"scope":"Ip","value":"203.0.113.1"},
            {"id":2,"scope":"Ip","value":"203.0.113.2","type":"custom"}])
    findings=await CrowdSecLapiAdapter(config(),transport=httpx.MockTransport(handler)).collect_findings()
    assert len(findings)==1 and findings[0].source_native_id=="2"
    assert findings[0].severity=="unknown"

@pytest.mark.asyncio
async def test_url_cannot_embed_credentials():
    with pytest.raises(CrowdSecAdapterError,match="credential-free"):
        await CrowdSecLapiAdapter(config(crowdsec_lapi_url="https://user:pass@crowdsec.example:8080")).healthcheck()
