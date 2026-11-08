from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

import httpx

from app.config import Settings, settings
from app.integrations.contracts import NormalizedFinding

_INDEX_PATTERN = re.compile(r"^[A-Za-z0-9_.*,-]+$")
_LEVEL_SEVERITY = (
    (3, "informational"),
    (6, "low"),
    (9, "medium"),
    (12, "high"),
    (15, "critical"),
)


class WazuhAdapterError(RuntimeError):
    """Sanitized adapter error; never includes credentials or response bodies."""


class WazuhIndexerAdapter:
    """Read alert documents from the Wazuh Indexer/OpenSearch API.

    Credentials are supplied only through backend environment settings.
    The adapter is read-only and never calls Wazuh response/action endpoints.
    """

    def __init__(
        self,
        config: Settings = settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.config = config
        self.transport = transport

    @property
    def is_configured(self) -> bool:
        return bool(
            self.config.wazuh_indexer_url
            and self.config.wazuh_indexer_username
            and self.config.wazuh_indexer_password
        )

    def _validate_configuration(self) -> tuple[str, str, str]:
        if not self.is_configured:
            raise WazuhAdapterError("Wazuh Indexer is not configured")
        url = self.config.wazuh_indexer_url.rstrip("/")
        if not url.startswith("https://"):
            raise WazuhAdapterError("Wazuh Indexer URL must use HTTPS")
        pattern = self.config.wazuh_indexer_index_pattern
        if not _INDEX_PATTERN.fullmatch(pattern):
            raise WazuhAdapterError("Wazuh index pattern contains unsupported characters")
        return url, self.config.wazuh_indexer_username, self.config.wazuh_indexer_password

    def _client(self) -> httpx.AsyncClient:
        url, username, password = self._validate_configuration()
        verify: bool | str = self.config.wazuh_indexer_ca_cert or self.config.wazuh_indexer_verify_tls
        return httpx.AsyncClient(
            base_url=url,
            auth=(username, password),
            timeout=httpx.Timeout(self.config.wazuh_indexer_timeout_seconds),
            verify=verify,
            follow_redirects=False,
            transport=self.transport,
        )

    async def healthcheck(self) -> bool:
        try:
            async with self._client() as client:
                response = await client.get("/_cluster/health")
                response.raise_for_status()
                return True
        except httpx.HTTPError as exc:
            raise WazuhAdapterError(f"Wazuh Indexer health request failed ({type(exc).__name__})") from None

    async def collect_findings(self, since: datetime) -> list[NormalizedFinding]:
        if since.tzinfo is None:
            raise WazuhAdapterError("Collection start time must include a timezone")
        size = self.config.wazuh_indexer_max_results
        query = {
            "size": size,
            "track_total_hits": False,
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {"range": {"@timestamp": {"gte": since.astimezone(timezone.utc).isoformat()}}},
            "_source": [
                "@timestamp", "rule.id", "rule.level", "rule.description", "rule.groups",
                "agent.id", "agent.name", "agent.ip", "manager.name", "location", "decoder.name",
            ],
        }
        try:
            async with self._client() as client:
                response = await client.post(
                    f"/{self.config.wazuh_indexer_index_pattern}/_search",
                    json=query,
                )
                response.raise_for_status()
                payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise WazuhAdapterError(f"Wazuh Indexer alert query failed ({type(exc).__name__})") from None

        hits = payload.get("hits", {}).get("hits", [])
        findings: list[NormalizedFinding] = []
        for hit in hits[:size]:
            finding = self._normalize_hit(hit)
            if finding is not None:
                findings.append(finding)
        return findings

    @classmethod
    def _normalize_hit(cls, hit: dict[str, Any]) -> NormalizedFinding | None:
        source = hit.get("_source")
        if not isinstance(source, dict):
            return None
        native_id = hit.get("_id") or source.get("id")
        if native_id is None:
            return None
        timestamp = source.get("@timestamp")
        if not isinstance(timestamp, str):
            return None
        try:
            observed_at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if observed_at.tzinfo is None:
                return None
            observed_at = observed_at.astimezone(timezone.utc)
        except ValueError:
            return None

        rule = source.get("rule") if isinstance(source.get("rule"), dict) else {}
        agent = source.get("agent") if isinstance(source.get("agent"), dict) else {}
        manager = source.get("manager") if isinstance(source.get("manager"), dict) else {}
        decoder = source.get("decoder") if isinstance(source.get("decoder"), dict) else {}
        try:
            level = int(rule.get("level", -1))
        except (TypeError, ValueError):
            level = -1
        severity = "unknown"
        for upper, mapped in _LEVEL_SEVERITY:
            if 0 <= level <= upper:
                severity = mapped
                break
        description = str(rule.get("description") or "").strip() or None
        rule_id = str(rule.get("id") or "unknown")
        title = (description or f"Wazuh alert {rule_id}")[:500]
        groups = rule.get("groups")
        if not isinstance(groups, list):
            groups = []

        # Deliberately omit full_log and arbitrary event payloads. Evidence is a
        # bounded set of useful metadata, not a copy of potentially sensitive logs.
        evidence = {
            "rule_id": rule_id,
            "rule_level": level if level >= 0 else None,
            "groups": [str(item)[:100] for item in groups[:20]],
            "agent_id": str(agent.get("id")) if agent.get("id") is not None else None,
            "agent_name": str(agent.get("name"))[:255] if agent.get("name") else None,
            "agent_ip": str(agent.get("ip"))[:64] if agent.get("ip") else None,
            "manager_name": str(manager.get("name"))[:255] if manager.get("name") else None,
            "location": str(source.get("location"))[:255] if source.get("location") else None,
            "decoder_name": str(decoder.get("name"))[:255] if decoder.get("name") else None,
        }
        asset_reference = evidence["agent_name"] or evidence["agent_id"]
        return NormalizedFinding(
            source_engine="wazuh",
            source_native_id=str(native_id)[:255],
            title=title,
            description=description[:4000] if description else None,
            severity=severity,
            observed_at=observed_at,
            asset_reference=asset_reference,
            evidence=evidence,
        )
