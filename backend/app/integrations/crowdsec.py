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

    @property
    def is_alerts_configured(self) -> bool:
        return bool(
            self.config.crowdsec_lapi_url
            and getattr(self.config, "crowdsec_machine_id", None)
            and getattr(self.config, "crowdsec_machine_password", None)
        )

    def _validated_url(self) -> str:
        url = self.config.crowdsec_lapi_url.rstrip("/")
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
            raise CrowdSecAdapterError("CrowdSec Local API URL must be a credential-free HTTPS URL without query or fragment")
        return url

    def _client(self) -> httpx.AsyncClient:
        if not self.is_configured:
            raise CrowdSecAdapterError("CrowdSec Local API bouncer integration is not configured")
        verify: bool | str = self.config.crowdsec_ca_cert or True
        return httpx.AsyncClient(
            base_url=self._validated_url(),
            headers={"X-Api-Key": self.config.crowdsec_api_key, "Accept": "application/json"},
            timeout=httpx.Timeout(self.config.crowdsec_timeout_seconds),
            verify=verify, follow_redirects=False, trust_env=False, transport=self.transport,
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


    async def collect_alerts(self) -> list[NormalizedFinding]:
        """Read bounded alert history using a dedicated machine JWT; never call write endpoints."""
        if not self.is_alerts_configured:
            raise CrowdSecAdapterError("CrowdSec alert history requires dedicated machine credentials")
        verify: bool | str = self.config.crowdsec_ca_cert or True
        limit = min(max(int(self.config.crowdsec_max_results), 1), 1000)
        try:
            async with httpx.AsyncClient(
                base_url=self._validated_url(),
                headers={"Accept": "application/json"},
                timeout=httpx.Timeout(self.config.crowdsec_timeout_seconds),
                verify=verify,
                follow_redirects=False,
                trust_env=False,
                transport=self.transport,
            ) as client:
                login = await client.post(
                    "/v1/watchers/login",
                    json={
                        "machine_id": self.config.crowdsec_machine_id,
                        "password": self.config.crowdsec_machine_password,
                    },
                )
                login.raise_for_status()
                login_payload = login.json()
                token = login_payload.get("token") if isinstance(login_payload, dict) else None
                if not isinstance(token, str) or not token.strip():
                    raise CrowdSecAdapterError("CrowdSec Local API returned an invalid machine token")
                response = await client.get(
                    "/v1/alerts",
                    params={"limit": limit},
                    headers={"Authorization": f"Bearer {token}"},
                )
                response.raise_for_status()
                payload = response.json()
        except CrowdSecAdapterError:
            raise
        except httpx.HTTPError as exc:
            raise CrowdSecAdapterError(f"CrowdSec alert history request failed ({type(exc).__name__})") from None
        except ValueError:
            raise CrowdSecAdapterError("CrowdSec Local API returned invalid alert JSON") from None

        if payload is None:
            return []
        if not isinstance(payload, list):
            raise CrowdSecAdapterError("CrowdSec Local API returned an unexpected alerts response")

        findings: list[NormalizedFinding] = []
        for alert in payload[:limit]:
            if not isinstance(alert, dict) or alert.get("id") is None:
                continue
            scenario = str(alert.get("scenario") or "CrowdSec alert")[:500]
            message = str(alert.get("message") or scenario)[:1000]
            source = alert.get("source") if isinstance(alert.get("source"), dict) else {}
            scope = str(source.get("scope") or "")[:40]
            value = str(source.get("value") or source.get("ip") or source.get("range") or "")[:255]
            decisions = alert.get("decisions") if isinstance(alert.get("decisions"), list) else []
            decision_types = [
                str(item.get("type") or "").strip().lower()
                for item in decisions[:20] if isinstance(item, dict)
            ]
            severity = (
                "critical" if "ban" in decision_types and str(alert.get("kind") or "").lower() == "waf"
                else "high" if "ban" in decision_types
                else "medium" if "captcha" in decision_types
                else "low" if "throttle" in decision_types
                else "unknown"
            )
            observed_at = self._alert_timestamp(alert)
            if observed_at is None:
                continue
            decision_evidence = []
            for item in decisions[:20]:
                if not isinstance(item, dict):
                    continue
                decision_evidence.append({
                    "type": str(item.get("type") or "")[:80],
                    "scope": str(item.get("scope") or "")[:40],
                    "value": str(item.get("value") or "")[:255],
                    "duration": str(item.get("duration") or "")[:100],
                })
            evidence = {
                "alert_id": str(alert.get("id"))[:255],
                "scenario": scenario,
                "kind": str(alert.get("kind") or "")[:80],
                "source": {"scope": scope, "value": value},
                "events_count": alert.get("events_count") if isinstance(alert.get("events_count"), int) else None,
                "simulated": alert.get("simulated") if isinstance(alert.get("simulated"), bool) else None,
                "remediation": alert.get("remediation") if isinstance(alert.get("remediation"), bool) else None,
                "decisions": decision_evidence,
            }
            findings.append(NormalizedFinding(
                source_engine="crowdsec-alert",
                source_native_id=str(alert.get("id"))[:255],
                title=f"CrowdSec alert: {scenario}"[:500],
                description=message,
                severity=severity,
                observed_at=observed_at,
                asset_reference=value if scope.strip().lower() == "ip" else None,
                evidence=evidence,
            ))
        return findings

    @staticmethod
    def _alert_timestamp(alert: dict) -> datetime | None:
        for field in ("stop_at", "start_at", "created_at"):
            value = alert.get(field)
            if not isinstance(value, str) or not value.strip():
                continue
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed.astimezone(timezone.utc)
            except ValueError:
                continue
        return None

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
