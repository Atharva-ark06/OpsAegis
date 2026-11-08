from __future__ import annotations
from typing import Any
import httpx
from app.config import Settings, settings

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

class NVDAdapterError(RuntimeError):
    pass

class NVDAdapter:
    """Read-only single-CVE lookup against the official NVD CVE API 2.0."""
    def __init__(self, config: Settings = settings, *, transport: httpx.AsyncBaseTransport | None = None):
        self.config = config
        self.transport = transport

    async def lookup(self, cve_id: str) -> dict[str, Any]:
        headers = {"User-Agent": "OpsAegis-Vulnerability-Intelligence/1.0"}
        if self.config.nvd_api_key:
            headers["apiKey"] = self.config.nvd_api_key
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(self.config.nvd_timeout_seconds),
                verify=True, follow_redirects=False, trust_env=False, transport=self.transport) as client:
                response = await client.get(NVD_URL, params={"cveId": cve_id}, headers=headers)
                if response.status_code == 404:
                    raise NVDAdapterError("CVE record was not found by NVD")
                if response.status_code == 429:
                    raise NVDAdapterError("NVD rate limit reached; retry later")
                response.raise_for_status()
                payload = response.json()
        except NVDAdapterError:
            raise
        except (httpx.HTTPError, ValueError) as exc:
            raise NVDAdapterError("NVD lookup failed (" + type(exc).__name__ + ")") from None
        rows = payload.get("vulnerabilities") if isinstance(payload, dict) else None
        if not isinstance(rows, list) or not rows:
            raise NVDAdapterError("NVD has no record for this CVE")
        cve = rows[0].get("cve", {})
        descriptions = cve.get("descriptions", [])
        description = next((x.get("value") for x in descriptions if x.get("lang") == "en" and isinstance(x.get("value"), str)), None)
        score = version = severity = None
        metrics = cve.get("metrics", {})
        for key, ver in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
            entries = metrics.get(key) or []
            if entries:
                metric = entries[0].get("cvssData", {})
                score = metric.get("baseScore")
                severity = metric.get("baseSeverity") or entries[0].get("baseSeverity")
                version = ver
                break
        return {
            "cve_id": cve.get("id"),
            "description": description[:12000] if description else None,
            "cvss_score": float(score) if score is not None else None,
            "cvss_version": version,
            "cvss_severity": str(severity).lower() if severity else None,
            "published_at": cve.get("published"),
            "modified_at": cve.get("lastModified"),
            "nvd_url": "https://nvd.nist.gov/vuln/detail/" + cve_id,
            "source": "NVD",
        }
