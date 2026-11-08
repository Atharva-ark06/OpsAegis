from __future__ import annotations
from typing import Any
from urllib.parse import urljoin
import httpx
from app.config import settings

class ShannonRunnerError(RuntimeError):
    """Sanitized error from the isolated Shannon runner bridge."""

class ShannonRunnerAdapter:
    """HTTPS client for the separately deployed Shannon runner bridge."""
    @property
    def is_configured(self) -> bool:
        return bool(settings.shannon_enabled and settings.shannon_runner_url and settings.shannon_runner_token)

    def _base_url(self) -> str:
        value = (settings.shannon_runner_url or "").strip().rstrip("/") + "/"
        if not value.startswith("https://"):
            raise ShannonRunnerError("Shannon runner URL must use HTTPS")
        return value

    async def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.is_configured:
            raise ShannonRunnerError("Shannon runner is not configured")
        headers = {"Authorization": f"Bearer {settings.shannon_runner_token}", "Accept": "application/json"}
        try:
            async with httpx.AsyncClient(verify=True, timeout=httpx.Timeout(settings.shannon_timeout_seconds),
                                         follow_redirects=False, trust_env=False) as client:
                async with client.stream(method, urljoin(self._base_url(), path.lstrip("/")),
                                          headers=headers, json=payload) as response:
                    if response.status_code not in (200, 201, 202):
                        raise ShannonRunnerError(f"runner_http_{response.status_code}")
                    chunks = []
                    size = 0
                    async for chunk in response.aiter_bytes():
                        size += len(chunk)
                        if size > settings.shannon_max_response_bytes:
                            raise ShannonRunnerError("runner_response_too_large")
                        chunks.append(chunk)
                    raw = b"".join(chunks)
        except ShannonRunnerError:
            raise
        except (httpx.TimeoutException, httpx.NetworkError, ValueError) as exc:
            raise ShannonRunnerError(type(exc).__name__) from None
        try:
            data = httpx.Response(200, content=raw).json()
        except ValueError:
            raise ShannonRunnerError("runner_invalid_json") from None
        if not isinstance(data, dict):
            raise ShannonRunnerError("runner_invalid_response")
        return data

    async def healthcheck(self) -> dict[str, Any]:
        return await self._request("GET", "/v1/health")

    async def submit(self, *, scan_id: int, target_url: str, source_repository: str,
                     authorization_reference: str) -> dict[str, Any]:
        return await self._request("POST", "/v1/scans", {
            "client": "opsaegis", "scan_id": scan_id, "target_url": target_url,
            "source_repository": source_repository, "authorization_reference": authorization_reference,
            "profile": "authorized-staging",
        })

    async def get_scan(self, job_id: str) -> dict[str, Any]:
        return await self._request("GET", f"/v1/scans/{job_id}")
