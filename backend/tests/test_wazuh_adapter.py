from datetime import datetime, timezone
from types import SimpleNamespace

import httpx
import pytest

from app.integrations.wazuh import WazuhAdapterError, WazuhIndexerAdapter


def config(**overrides):
    values = {
        "wazuh_indexer_url": "https://wazuh-indexer.example:9200",
        "wazuh_indexer_username": "reader",
        "wazuh_indexer_password": "test-password",
        "wazuh_indexer_ca_cert": None,
        "wazuh_indexer_timeout_seconds": 5,
        "wazuh_indexer_index_pattern": "wazuh-alerts-*",
        "wazuh_indexer_max_results": 100,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def hit(doc_id="alert-1", level=12):
    return {
        "_id": doc_id,
        "_source": {
            "@timestamp": "2026-11-08T10:00:00Z",
            "rule": {"id": "5710", "level": level, "description": "Multiple authentication failures", "groups": ["authentication", "syslog"]},
            "agent": {"id": "004", "name": "lab-web-01", "ip": "10.0.0.12"},
            "manager": {"name": "wazuh-manager"},
            "location": "journald",
            "decoder": {"name": "systemd"},
            "full_log": "sensitive log payload must not be copied",
        },
    }


@pytest.mark.asyncio
async def test_collect_normalizes_alert_and_uses_authenticated_https():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"hits": {"hits": [hit()]}})

    adapter = WazuhIndexerAdapter(config(), transport=httpx.MockTransport(handler))
    results = await adapter.collect_findings(datetime(2026, 11, 8, 9, tzinfo=timezone.utc))

    assert len(results) == 1
    finding = results[0]
    assert finding.source_engine == "wazuh"
    assert finding.source_native_id == "alert-1"
    assert finding.severity == "high"
    assert finding.asset_reference == "lab-web-01"
    assert finding.evidence["rule_id"] == "5710"
    assert "full_log" not in finding.evidence
    assert "sensitive log payload" not in str(finding.evidence)
    assert requests[0].url.path == "/wazuh-alerts-*/_search"
    assert requests[0].headers["authorization"].startswith("Basic ")


@pytest.mark.asyncio
async def test_healthcheck_calls_indexer_cluster_health():
    def handler(request):
        assert request.url.path == "/_cluster/health"
        return httpx.Response(200, json={"status": "yellow"})

    adapter = WazuhIndexerAdapter(config(), transport=httpx.MockTransport(handler))
    assert await adapter.healthcheck() is True


@pytest.mark.asyncio
async def test_missing_credentials_fail_closed():
    adapter = WazuhIndexerAdapter(config(wazuh_indexer_password=""))
    with pytest.raises(WazuhAdapterError, match="not configured"):
        await adapter.healthcheck()


@pytest.mark.asyncio
async def test_non_https_endpoint_is_rejected():
    adapter = WazuhIndexerAdapter(config(wazuh_indexer_url="http://wazuh-indexer:9200"))
    with pytest.raises(WazuhAdapterError, match="HTTPS"):
        await adapter.healthcheck()


@pytest.mark.asyncio
async def test_invalid_index_pattern_is_rejected():
    adapter = WazuhIndexerAdapter(config(wazuh_indexer_index_pattern="../_all"))
    with pytest.raises(WazuhAdapterError, match="index pattern"):
        await adapter.collect_findings(datetime.now(timezone.utc))


def test_normalizer_skips_malformed_or_unidentified_documents():
    assert WazuhIndexerAdapter._normalize_hit({"_source": {}}) is None
    assert WazuhIndexerAdapter._normalize_hit({"_id": "x", "_source": {"@timestamp": "not-a-date"}}) is None
    mapped = WazuhIndexerAdapter._normalize_hit(hit(level=15))
    assert mapped.severity == "critical"

@pytest.mark.asyncio
async def test_endpoint_url_cannot_embed_credentials():
    adapter = WazuhIndexerAdapter(config(
        wazuh_indexer_url="https://embedded-user:embedded-pass@wazuh-indexer.example:9200"
    ))
    with pytest.raises(WazuhAdapterError, match="credential-free HTTPS"):
        await adapter.healthcheck()


@pytest.mark.asyncio
async def test_unexpected_indexer_response_shape_is_rejected():
    def handler(request):
        return httpx.Response(200, json={"unexpected": []})

    adapter = WazuhIndexerAdapter(config(), transport=httpx.MockTransport(handler))
    with pytest.raises(WazuhAdapterError, match="response shape"):
        await adapter.collect_findings(datetime(2026, 11, 8, 9, tzinfo=timezone.utc))


@pytest.mark.asyncio
async def test_query_is_bounded_and_uses_timestamp_lower_bound():
    captured = {}

    def handler(request):
        captured.update(__import__("json").loads(request.content))
        return httpx.Response(200, json={"hits": {"hits": []}})

    adapter = WazuhIndexerAdapter(
        config(wazuh_indexer_max_results=25),
        transport=httpx.MockTransport(handler),
    )
    await adapter.collect_findings(datetime(2026, 11, 8, 9, tzinfo=timezone.utc))
    assert captured["size"] == 25
    assert captured["query"]["range"]["@timestamp"]["gte"] == "2026-11-08T09:00:00+00:00"


@pytest.mark.asyncio
async def test_query_includes_exact_upper_bound_when_supplied():
    captured = {}

    def handler(request):
        captured.update(__import__("json").loads(request.content))
        return httpx.Response(200, json={"hits": {"hits": []}})

    adapter = WazuhIndexerAdapter(config(), transport=httpx.MockTransport(handler))
    await adapter.collect_findings(
        datetime(2026, 11, 8, 9, tzinfo=timezone.utc),
        datetime(2026, 11, 8, 10, tzinfo=timezone.utc),
    )
    bounds = captured["query"]["range"]["@timestamp"]
    assert bounds["gte"] == "2026-11-08T09:00:00+00:00"
    assert bounds["lte"] == "2026-11-08T10:00:00+00:00"


@pytest.mark.asyncio
async def test_query_rejects_invalid_upper_bound():
    adapter = WazuhIndexerAdapter(config(), transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json={"hits": {"hits": []}})
    ))
    with pytest.raises(WazuhAdapterError, match="end time"):
        await adapter.collect_findings(
            datetime(2026, 11, 8, 10, tzinfo=timezone.utc),
            datetime(2026, 11, 8, 9, tzinfo=timezone.utc),
        )
