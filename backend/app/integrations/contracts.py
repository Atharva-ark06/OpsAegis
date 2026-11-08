from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

@dataclass(frozen=True)
class NormalizedFinding:
    source_engine: str
    source_native_id: str | None
    title: str
    description: str | None
    severity: str
    observed_at: datetime
    asset_reference: str | None = None
    evidence: dict[str, Any] | None = None

class SecurityEngineAdapter(Protocol):
    """Contract for real adapters; implementations must authenticate, enforce scope and use timeouts."""
    async def healthcheck(self) -> bool: ...
    async def collect_findings(self, since: datetime) -> list[NormalizedFinding]: ...
