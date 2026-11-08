from datetime import datetime, timedelta, timezone
import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.integrations.wazuh import WazuhAdapterError, WazuhIndexerAdapter
from app.models.entities import AuditLog, Finding, FindingSeverity, User, UserRole
from app.security import require_roles

router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.get("/wazuh/health")
async def wazuh_health(
    actor: User = Depends(require_roles(UserRole.admin, UserRole.analyst)),
) -> dict[str, object]:
    adapter = WazuhIndexerAdapter()
    if not adapter.is_configured:
        return {"integration": "wazuh-indexer", "configured": False, "status": "not_configured"}
    try:
        healthy = await adapter.healthcheck()
    except WazuhAdapterError:
        return {"integration": "wazuh-indexer", "configured": True, "status": "unhealthy"}
    return {"integration": "wazuh-indexer", "configured": True, "status": "healthy" if healthy else "unhealthy"}


@router.post("/wazuh/collect")
async def collect_wazuh_alerts(
    since: datetime | None = Query(default=None, description="Timezone-aware lower bound for @timestamp"),
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(UserRole.admin, UserRole.analyst)),
) -> dict[str, object]:
    start = since or (datetime.now(timezone.utc) - timedelta(minutes=15))
    if start.tzinfo is None:
        raise HTTPException(status_code=422, detail="since must include a timezone")
    if start > datetime.now(timezone.utc):
        raise HTTPException(status_code=422, detail="since cannot be in the future")
    if start < datetime.now(timezone.utc) - timedelta(days=30):
        raise HTTPException(status_code=422, detail="since cannot be more than 30 days ago")

    adapter = WazuhIndexerAdapter()
    try:
        incoming = await adapter.collect_findings(start)
    except WazuhAdapterError as exc:
        if str(exc) == "Wazuh Indexer is not configured":
            raise HTTPException(status_code=503, detail="Wazuh Indexer integration is not configured") from None
        raise HTTPException(status_code=502, detail="Wazuh Indexer request failed; check backend integration logs") from None

    inserted = 0
    updated = 0
    try:
        for item in incoming:
            existing = db.scalar(
                select(Finding).where(
                    Finding.source_engine == "wazuh",
                    Finding.source_native_id == item.source_native_id,
                )
            )
            severity = FindingSeverity(item.severity) if item.severity in FindingSeverity._value2member_map_ else FindingSeverity.unknown
            if existing is None:
                db.add(Finding(
                    source_engine="wazuh",
                    source_native_id=item.source_native_id,
                    title=item.title,
                    description=item.description,
                    severity=severity,
                    first_seen_at=item.observed_at,
                    last_seen_at=item.observed_at,
                    evidence=item.evidence,
                ))
                inserted += 1
            else:
                existing.title = item.title
                existing.description = item.description
                existing.severity = severity
                existing.last_seen_at = max(existing.last_seen_at, item.observed_at)
                existing.evidence = item.evidence
                updated += 1

        db.add(AuditLog(
            actor_user_id=actor.id,
            action="integration.wazuh.collect",
            target="wazuh-indexer",
            detail=json.dumps({"since": start.isoformat(), "received": len(incoming), "inserted": inserted, "updated": updated}),
        ))
        db.commit()
    except Exception:
        db.rollback()
        raise

    limit = settings.wazuh_indexer_max_results
    return {
        "integration": "wazuh-indexer",
        "since": start.isoformat(),
        "received": len(incoming),
        "inserted": inserted,
        "updated": updated,
        "truncated_possible": len(incoming) >= limit,
        "max_results": limit,
    }
