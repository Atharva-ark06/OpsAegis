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


@pytest.mark.asyncio
async def test_collects_alert_history_with_machine_jwt_and_read_only_get():
    calls = []

    def handler(request):
        calls.append(request)
        if request.url.path == "/v1/watchers/login":
            assert request.method == "POST"
            assert request.read().decode()
            return httpx.Response(200, json={"token": "short-lived-test-jwt", "expire": "2030-01-01T00:00:00Z"})
        assert request.url.path == "/v1/alerts"
        assert request.method == "GET"
        assert request.headers["authorization"] == "Bearer short-lived-test-jwt"
        assert request.url.params["limit"] == "100"
        return httpx.Response(200, json=[{
            "id": 77,
            "scenario": "crowdsecurity/ssh-bf",
            "message": "SSH brute force detected",
            "start_at": "2026-11-09T10:00:00Z",
            "stop_at": "2026-11-09T10:02:00Z",
            "created_at": "2026-11-09T10:02:01Z",
            "kind": "crowdsec",
            "events_count": 8,
            "simulated": False,
            "remediation": True,
            "source": {"scope": "Ip", "value": "203.0.113.9", "ip": "203.0.113.9"},
            "decisions": [{"type": "ban", "scope": "Ip", "value": "203.0.113.9", "duration": "4h"}],
            "events": [{"meta": {"raw": "must-not-be-copied"}}],
        }])

    adapter = CrowdSecLapiAdapter(
        config(crowdsec_machine_id="opsaegis-reader", crowdsec_machine_password="machine-secret"),
        transport=httpx.MockTransport(handler),
    )
    findings = await adapter.collect_alerts()
    assert len(findings) == 1
    item = findings[0]
    assert item.source_engine == "crowdsec-alert"
    assert item.source_native_id == "77"
    assert item.severity == "high"
    assert item.observed_at.isoformat() == "2026-11-09T10:02:00+00:00"
    assert item.asset_reference == "203.0.113.9"
    assert item.evidence["events_count"] == 8
    assert "events" not in item.evidence
    assert "must-not-be-copied" not in repr(item.evidence)
    assert [request.method for request in calls] == ["POST", "GET"]
    assert all(request.url.path not in {"/v1/alerts/77", "/v1/decisions"} for request in calls)


@pytest.mark.asyncio
async def test_alert_history_requires_separate_machine_credentials():
    adapter = CrowdSecLapiAdapter(config())
    assert not adapter.is_alerts_configured
    with pytest.raises(CrowdSecAdapterError, match="dedicated machine credentials"):
        await adapter.collect_alerts()


@pytest.mark.asyncio
async def test_alert_history_rejects_unexpected_response_shape():
    def handler(request):
        if request.url.path == "/v1/watchers/login":
            return httpx.Response(200, json={"token": "jwt"})
        return httpx.Response(200, json={"items": []})

    adapter = CrowdSecLapiAdapter(
        config(crowdsec_machine_id="reader", crowdsec_machine_password="secret"),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(CrowdSecAdapterError, match="unexpected alerts"):
        await adapter.collect_alerts()


@pytest.mark.asyncio
async def test_alert_history_does_not_follow_redirects_or_accept_http_url():
    adapter = CrowdSecLapiAdapter(
        config(crowdsec_machine_id="reader", crowdsec_machine_password="secret",
               crowdsec_lapi_url="http://crowdsec.example:8080")
    )
    with pytest.raises(CrowdSecAdapterError, match="HTTPS"):
        await adapter.collect_alerts()
