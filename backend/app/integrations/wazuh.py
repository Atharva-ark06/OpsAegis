from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

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
        parsed_url = urlsplit(url)
        if (
            parsed_url.scheme != "https"
            or not parsed_url.hostname
            or parsed_url.username is not None
            or parsed_url.password is not None
            or parsed_url.query
            or parsed_url.fragment
        ):
            raise WazuhAdapterError(
                "Wazuh Indexer URL must be a credential-free HTTPS URL without query or fragment"
            )
        pattern = self.config.wazuh_indexer_index_pattern
        if not _INDEX_PATTERN.fullmatch(pattern):
            raise WazuhAdapterError("Wazuh index pattern contains unsupported characters")
        return url, self.config.wazuh_indexer_username, self.config.wazuh_indexer_password

    def _client(self) -> httpx.AsyncClient:
        url, username, password = self._validate_configuration()
        # TLS verification is always enabled. Supply the internal CA bundle
        # when the Indexer certificate is issued by a private CA.
        verify: bool | str = self.config.wazuh_indexer_ca_cert or True
        return httpx.AsyncClient(
            base_url=url,
            auth=(username, password),
            timeout=httpx.Timeout(self.config.wazuh_indexer_timeout_seconds),
            verify=verify,
            follow_redirects=False,
            trust_env=False,
            transport=self.transport,
        )

    async def healthcheck(self) -> bool:
        try:
            async with self._client() as client:
                response = await client.get("/_cluster/health")
                response.raise_for_status()
                return True
        except httpx.HTTPError as exc:
            raise WazuhAdapterError(
                f"Wazuh Indexer health request failed ({type(exc).__name__})"
            ) from None

    async def collect_findings(self, since: datetime, until: datetime | None = None) -> list[NormalizedFinding]:
        if since.tzinfo is None:
            raise WazuhAdapterError("Collection start time must include a timezone")
        timestamp_range = {"gte": since.astimezone(timezone.utc).isoformat()}
        if until is not None:
            if until.tzinfo is None or until <= since:
                raise WazuhAdapterError("Collection end time must be timezone-aware and later than start time")
            timestamp_range["lte"] = until.astimezone(timezone.utc).isoformat()
        size = self.config.wazuh_indexer_max_results
        query = {
            "size": size,
            "track_total_hits": False,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "range": {
                    "@timestamp": timestamp_range
                }
            },
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
            raise WazuhAdapterError(
                f"Wazuh Indexer alert query failed ({type(exc).__name__})"
            ) from None

        if not isinstance(payload, dict) or not isinstance(payload.get("hits"), dict):
            raise WazuhAdapterError("Wazuh Indexer returned an unexpected response shape")
        hits = payload["hits"].get("hits", [])
        if not isinstance(hits, list):
            raise WazuhAdapterError("Wazuh Indexer returned an invalid alert collection")

        findings: list[NormalizedFinding] = []
        for hit in hits[:size]:
            if not isinstance(hit, dict):
                continue
            finding = self._normalize_hit(hit)
            if finding is not None:
                findings.append(finding)
        return findings


    async def collect_vulnerabilities(self) -> tuple[list[dict[str, Any]], int, bool]:
        """Read Wazuh's current vulnerability state index; never call manager scan/action APIs."""
        size = min(max(int(self.config.wazuh_indexer_max_results), 1), 500)
        query = {
            "size": size,
            "track_total_hits": True,
            "sort": [{"vulnerability.detected_at": {"order": "desc", "unmapped_type": "date"}}],
            "_source": [
                "agent.id", "agent.name", "host.os", "package.name", "package.version",
                "package.architecture", "package.type", "package.description",
                "vulnerability.id", "vulnerability.category", "vulnerability.classification",
                "vulnerability.description", "vulnerability.detected_at", "vulnerability.published_at",
                "vulnerability.enumeration", "vulnerability.score", "vulnerability.severity",
                "vulnerability.scanner.vendor",
            ],
            "query": {"term": {"vulnerability.enumeration": "CVE"}},
        }
        try:
            async with self._client() as client:
                response = await client.post("/wazuh-states-vulnerabilities*/_search", json=query)
                response.raise_for_status()
                payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise WazuhAdapterError(
                f"Wazuh vulnerability state query failed ({type(exc).__name__})"
            ) from None
        if not isinstance(payload, dict) or not isinstance(payload.get("hits"), dict):
            raise WazuhAdapterError("Wazuh vulnerability index returned an unexpected response shape")
        if payload.get("timed_out") is True:
            raise WazuhAdapterError("Wazuh vulnerability index query timed out")
        shards = payload.get("_shards")
        if isinstance(shards, dict) and int(shards.get("failed") or 0) > 0:
            raise WazuhAdapterError("Wazuh vulnerability index reported failed shards")
        hits_obj = payload["hits"]
        hits = hits_obj.get("hits")
        total_obj = hits_obj.get("total", 0)
        total = total_obj.get("value", 0) if isinstance(total_obj, dict) else total_obj
        relation = total_obj.get("relation", "eq") if isinstance(total_obj, dict) else "eq"
        if not isinstance(hits, list) or not isinstance(total, int) or total < 0:
            raise WazuhAdapterError("Wazuh vulnerability index returned an invalid collection")
        normalized = []
        for hit in hits[:size]:
            if isinstance(hit, dict):
                item = self.normalize_vulnerability_hit(hit)
                if item is not None:
                    normalized.append(item)
        return normalized, total, relation == "gte" or total > len(hits) or len(hits) >= size and total > size

    @staticmethod
    def normalize_vulnerability_hit(hit: dict[str, Any]) -> dict[str, Any] | None:
        import hashlib
        import re
        source = hit.get("_source")
        if not isinstance(source, dict):
            return None
        vulnerability = source.get("vulnerability") if isinstance(source.get("vulnerability"), dict) else {}
        agent = source.get("agent") if isinstance(source.get("agent"), dict) else {}
        package = source.get("package") if isinstance(source.get("package"), dict) else {}
        host = source.get("host") if isinstance(source.get("host"), dict) else {}
        host_os = host.get("os") if isinstance(host.get("os"), dict) else {}
        cve = str(vulnerability.get("id") or "").upper()
        if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cve):
            return None
        agent_id = str(agent.get("id") or "").strip()
        if not agent_id or agent_id == "000":
            return None
        package_name = str(package.get("name") or "").strip()
        package_version = str(package.get("version") or "").strip()
        if not package_name or not package_version:
            return None
        native = str(hit.get("_id") or "")
        index = str(hit.get("_index") or "")
        if not native:
            return None
        source_id = hashlib.sha256((index + ":" + native).encode()).hexdigest()
        score = vulnerability.get("score") if isinstance(vulnerability.get("score"), dict) else {}
        try:
            cvss_score = float(score.get("base")) if score.get("base") is not None else None
            if cvss_score is not None and not 0 <= cvss_score <= 10:
                cvss_score = None
        except (TypeError, ValueError):
            cvss_score = None
        try:
            cvss_version = str(score.get("version"))[:8] if score.get("version") else None
        except Exception:
            cvss_version = None
        severity = str(vulnerability.get("severity") or "").strip().lower()
        if severity not in {"critical", "high", "medium", "low"}:
            severity = "unknown"
        detected = vulnerability.get("detected_at")
        observed = None
        if isinstance(detected, str):
            try:
                parsed = datetime.fromisoformat(detected.replace("Z", "+00:00"))
                if parsed.tzinfo is not None:
                    observed = parsed.astimezone(timezone.utc)
            except ValueError:
                pass
        published = vulnerability.get("published_at")
        published_at = None
        if isinstance(published, str):
            try:
                parsed = datetime.fromisoformat(published.replace("Z", "+00:00"))
                if parsed.tzinfo is not None:
                    published_at = parsed.astimezone(timezone.utc)
            except ValueError:
                pass
        references = str(vulnerability.get("reference") or "")[:2000]
        return {
            "source_native_id": source_id, "cve_id": cve, "agent_id": agent_id,
            "agent_name": str(agent.get("name") or "")[:255] or None,
            "package_name": package_name[:255], "package_version": package_version[:255],
            "package_type": str(package.get("type") or "")[:80] or None,
            "package_architecture": str(package.get("architecture") or "")[:80] or None,
            "package_description": str(package.get("description") or "")[:1000] or None,
            "os_name": str(host_os.get("full") or host_os.get("name") or "")[:255] or None,
            "description": str(vulnerability.get("description") or "")[:4000] or None,
            "severity": severity, "cvss_score": cvss_score, "cvss_version": cvss_version,
            "observed_at": observed, "published_at": published_at, "references": references,
            "category": str(vulnerability.get("category") or "")[:80] or None,
            "scanner_vendor": str((vulnerability.get("scanner") or {}).get("vendor") or "Wazuh")[:80],
        }

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
