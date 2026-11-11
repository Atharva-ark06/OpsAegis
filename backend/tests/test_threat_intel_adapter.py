from types import SimpleNamespace
import httpx,pytest
from app.integrations.threat_intel import AbuseIPDBAdapter,VirusTotalAdapter,normalize_indicator

def config(**overrides):
    values={"virustotal_api_key":"vt-test-key","abuseipdb_api_key":"abuse-test-key","threat_intel_timeout_seconds":5}
    values.update(overrides);return SimpleNamespace(**values)

@pytest.mark.parametrize("kind,value,expected",[("ip","8.8.8.8","8.8.8.8"),("domain","Example.COM.","example.com"),
    ("url","https://Example.com/a?b=1","https://example.com/a?b=1"),("url","https://[2001:4860:4860::8888]/","https://[2001:4860:4860::8888]/"),("hash","A"*64,"a"*64)])
def test_normalizes_supported_ioc_types(kind,value,expected): assert normalize_indicator(kind,value)==(kind,expected)

@pytest.mark.parametrize("kind,value",[("ip","127.0.0.1"),("ip","192.168.1.10"),("domain","host.local"),
    ("domain","not a domain"),("url","file:///etc/passwd"),("url","https://user:pass@example.com/"),
    ("url","http://127.0.0.1/"),("url","https://service.internal/"),("hash","not-a-hash"),("unknown","anything")])
def test_rejects_invalid_or_nonpublic_indicators(kind,value):
    with pytest.raises(ValueError): normalize_indicator(kind,value)

@pytest.mark.asyncio
async def test_virustotal_queries_encoded_url_without_visiting_it_and_returns_engine_flags():
    seen=[]
    def handler(request):
        seen.append(request)
        return httpx.Response(200,json={"data":{"attributes":{
            "last_analysis_stats":{"malicious":3,"suspicious":1,"harmless":6,"undetected":0},"reputation":-12,
            "asn":15169,"as_owner":"Google LLC","country":"US","network":"8.8.8.0/24","tags":["dns","public-dns"],
            "categories":{"Forcepoint":"Technology","alpha":"Search Engines"},
            "last_analysis_results":{"Vendor A":{"category":"malicious","result":"malware-site","method":"blacklist","engine_update":"20261110"},
                "Vendor B":{"category":"suspicious","result":"suspicious","method":"heuristic"},"Vendor C":{"category":"harmless","result":"clean"}}
        }}})
    result=await VirusTotalAdapter(config(),transport=httpx.MockTransport(handler)).enrich("url","https://example.com/path")
    assert result["status"]=="ok" and result["verdict"]=="malicious" and result["risk_score"]==35
    assert seen[0].url.host=="www.virustotal.com" and seen[0].url.path.startswith("/api/v3/urls/")
    assert seen[0].headers["x-apikey"]=="vt-test-key"
    assert result["details"]["detection_flags"][0]["engine"]=="Vendor A"
    assert len(result["details"]["detection_flags"])==2
    assert result["details"]["asn"]==15169 and result["details"]["as_owner"]=="Google LLC"
    assert result["details"]["tags"]==["dns","public-dns"] and "categories" in result["details"]

@pytest.mark.asyncio
async def test_abuseipdb_requests_verbose_reports_and_normalizes_report_context():
    seen=[]
    def handler(request):
        seen.append(request)
        return httpx.Response(200,json={"data":{"abuseConfidenceScore":87,"totalReports":18,"numDistinctUsers":7,
            "countryCode":"US","isp":"Example ISP","domain":"example.net","usageType":"Data Center/Web Hosting/Transit",
            "lastReportedAt":"2026-11-10T12:00:00+00:00","ipVersion":4,"isPublic":True,"isWhitelisted":False,
            "hostnames":["host.example.net"],"reports":[{"reportedAt":"2026-11-10T12:00:00+00:00","comment":"SSH brute force",
            "reporterCountryCode":"GB","categories":[18,22]}]}})
    result=await AbuseIPDBAdapter(config(),transport=httpx.MockTransport(handler)).enrich("ip","8.8.8.8")
    assert result["status"]=="ok" and result["verdict"]=="malicious" and result["risk_score"]==87
    assert result["details"]["total_reports"]==18 and result["details"]["distinct_reporters"]==7
    assert result["details"]["isp"]=="Example ISP" and result["details"]["domain"]=="example.net"
    assert result["details"]["reports"][0]["categories"][0]["name"]=="Brute-Force"
    assert seen[0].url.path=="/api/v2/check" and seen[0].url.params["ipAddress"]=="8.8.8.8"
    assert seen[0].url.params["verbose"]=="1" and seen[0].headers["key"]=="abuse-test-key"

@pytest.mark.asyncio
async def test_abuseipdb_marks_non_ip_as_not_applicable():
    assert (await AbuseIPDBAdapter(config()).enrich("domain","example.com"))["status"]=="not_applicable"

@pytest.mark.asyncio
async def test_unconfigured_provider_does_not_call_network():
    assert (await VirusTotalAdapter(config(virustotal_api_key="")).enrich("ip","8.8.8.8"))["status"]=="not_configured"

@pytest.mark.asyncio
async def test_provider_rate_limit_is_reported_without_leaking_response():
    def handler(request): return httpx.Response(429,json={"message":"sensitive provider response"})
    result=await VirusTotalAdapter(config(),transport=httpx.MockTransport(handler)).enrich("ip","8.8.8.8")
    assert result["status"]=="rate_limited" and "sensitive" not in str(result)

@pytest.mark.asyncio
async def test_provider_auth_error_and_not_found_are_distinct():
    for status,expected in ((403,"auth_error"),(404,"not_found")):
        result=await VirusTotalAdapter(config(),transport=httpx.MockTransport(lambda request:httpx.Response(status))).enrich("ip","8.8.8.8")
        assert result["status"]==expected and result["verdict"]=="unknown"
