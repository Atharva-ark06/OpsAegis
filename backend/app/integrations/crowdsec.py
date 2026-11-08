from __future__ import annotations
from datetime import datetime, timezone
from urllib.parse import urlsplit
import httpx
from app.config import Settings, settings
from app.integrations.contracts import NormalizedFinding

class CrowdSecAdapterError(RuntimeError):
    """Sanitized CrowdSec LAPI error; never includes credentials or response bodies."""

class CrowdSecLapiAdapter:
    """Read active decisions from CrowdSec Local API using a read-only bouncer key."""
    def __init__(self, config: Settings = settings, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.config, self.transport = config, transport

    @property
    def is_configured(self) -> bool:
        return bool(self.config.crowdsec_lapi_url and self.config.crowdsec_api_key)

    def _client(self) -> httpx.AsyncClient:
        if not self.is_configured:
            raise CrowdSecAdapterError("CrowdSec Local API is not configured")
        parsed = urlsplit(self.config.crowdsec_lapi_url.rstrip("/"))
        if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
            raise CrowdSecAdapterError("CrowdSec Local API URL must be a credential-free HTTPS URL without query or fragment")
        verify: bool | str = self.config.crowdsec_ca_cert or True
        return httpx.AsyncClient(
            base_url=self.config.crowdsec_lapi_url.rstrip("/"),
            headers={"X-Api-Key": self.config.crowdsec_api_key, "Accept": "application/json"},
            timeout=httpx.Timeout(self.config.crowdsec_timeout_seconds),
            verify=verify, follow_redirects=False, transport=self.transport,
        )

    async def healthcheck(self) -> bool:
        try:
            async with self._client() as client:
                response = await client.get("/v1/decisions", params={"limit": 1})
                response.raise_for_status()
                payload = response.json()
        except httpx.HTTPError as exc:
            raise CrowdSecAdapterError(f"CrowdSec Local API health request failed ({type(exc).__name__})") from None
        except ValueError:
            raise CrowdSecAdapterError("CrowdSec Local API returned invalid JSON") from None
        if payload is not None and not isinstance(payload, list):
            raise CrowdSecAdapterError("CrowdSec Local API returned an unexpected decisions response")
        return True

    async def collect_findings(self, since: datetime | None = None) -> list[NormalizedFinding]:
        # CrowdSec LAPI decisions are active enforcement decisions, not a historical alert stream.
        # The since argument is accepted for adapter compatibility, not used to fabricate timestamps.
        del since
        try:
            async with self._client() as client:
                response = await client.get("/v1/decisions", params={"limit": self.config.crowdsec_max_results})
                response.raise_for_status()
                payload = response.json()
        except httpx.HTTPError as exc:
            raise CrowdSecAdapterError(f"CrowdSec Local API decision query failed ({type(exc).__name__})") from None
        except ValueError:
            raise CrowdSecAdapterError("CrowdSec Local API returned invalid JSON") from None
        if payload is None:
            return []
        if not isinstance(payload, list):
            raise CrowdSecAdapterError("CrowdSec Local API returned an unexpected decisions response")
        now = datetime.now(timezone.utc)
        findings: list[NormalizedFinding] = []
        for decision in payload[: self.config.crowdsec_max_results]:
            if not isinstance(decision, dict):
                continue
            native_id, value, scope, action = decision.get("id"), decision.get("value"), decision.get("scope"), decision.get("type")
            if native_id is None or value is None or not scope or not action:
                continue
            action_text, scope_text, value_text = str(action).lower()[:80], str(scope)[:40], str(value)[:255]
            scenario = str(decision.get("scenario") or "CrowdSec decision")[:500]
            severity = {"ban": "high", "captcha": "medium", "throttle": "low"}.get(action_text, "unknown")
            findings.append(NormalizedFinding(
                source_engine="crowdsec", source_native_id=str(native_id)[:255],
                title=f"CrowdSec {action_text}: {scope_text} {value_text}"[:500],
                description=scenario, severity=severity, observed_at=now,
                asset_reference=value_text if scope_text.lower() in {"ip", "range"} else None,
                evidence={"decision_id": str(native_id)[:255], "scope": scope_text, "value": value_text,
                    "type": action_text, "origin": str(decision.get("origin") or "")[:100],
                    "scenario": scenario, "duration": str(decision.get("duration") or "")[:100]},
            ))
        return findings
