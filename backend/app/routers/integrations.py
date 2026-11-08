from datetime import datetime, timedelta, timezone
import json
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.config import settings
from app.database import get_db
from app.integrations.crowdsec import CrowdSecAdapterError, CrowdSecLapiAdapter
from app.integrations.wazuh import WazuhAdapterError, WazuhIndexerAdapter
from app.models.entities import AuditLog, Finding, FindingSeverity, User, UserRole
from app.security import require_roles
router = APIRouter(prefix="/integrations", tags=["integrations"])
OPERATORS = (UserRole.admin, UserRole.analyst)

@router.get("/wazuh/health")
async def wazuh_health(actor: User = Depends(require_roles(*OPERATORS))) -> dict[str, object]:
    adapter=WazuhIndexerAdapter()
    if not adapter.is_configured: return {"integration":"wazuh-indexer","configured":False,"status":"not_configured"}
    try: healthy=await adapter.healthcheck()
    except WazuhAdapterError: return {"integration":"wazuh-indexer","configured":True,"status":"unhealthy"}
    return {"integration":"wazuh-indexer","configured":True,"status":"healthy" if healthy else "unhealthy"}

@router.post("/wazuh/collect")
async def collect_wazuh_alerts(since: datetime | None=Query(default=None,description="Timezone-aware lower bound for @timestamp"),
    db: Session=Depends(get_db),actor: User=Depends(require_roles(*OPERATORS))) -> dict[str,object]:
    start=since or (datetime.now(timezone.utc)-timedelta(minutes=15))
    if start.tzinfo is None: raise HTTPException(status_code=422,detail="since must include a timezone")
    if start>datetime.now(timezone.utc): raise HTTPException(status_code=422,detail="since cannot be in the future")
    if start<datetime.now(timezone.utc)-timedelta(days=30): raise HTTPException(status_code=422,detail="since cannot be more than 30 days ago")
    try: incoming=await WazuhIndexerAdapter().collect_findings(start)
    except WazuhAdapterError as exc:
        if str(exc)=="Wazuh Indexer is not configured": raise HTTPException(status_code=503,detail="Wazuh Indexer integration is not configured") from None
        raise HTTPException(status_code=502,detail="Wazuh Indexer request failed; check backend integration logs") from None
    inserted,updated=_persist_findings(db,actor,incoming,"wazuh","integration.wazuh.collect","wazuh-indexer",start)
    limit=settings.wazuh_indexer_max_results
    return {"integration":"wazuh-indexer","since":start.isoformat(),"received":len(incoming),"inserted":inserted,"updated":updated,"truncated_possible":len(incoming)>=limit,"max_results":limit}

@router.get("/crowdsec/health")
async def crowdsec_health(actor: User=Depends(require_roles(*OPERATORS))) -> dict[str,object]:
    adapter=CrowdSecLapiAdapter()
    if not adapter.is_configured: return {"integration":"crowdsec-lapi","configured":False,"status":"not_configured","capability":"read_active_decisions"}
    try: await adapter.healthcheck()
    except CrowdSecAdapterError: return {"integration":"crowdsec-lapi","configured":True,"status":"unhealthy","capability":"read_active_decisions"}
    return {"integration":"crowdsec-lapi","configured":True,"status":"healthy","capability":"read_active_decisions"}

@router.post("/crowdsec/collect")
async def collect_crowdsec_decisions(db: Session=Depends(get_db),
    actor: User=Depends(require_roles(*OPERATORS))) -> dict[str,object]:
    adapter=CrowdSecLapiAdapter()
    if not adapter.is_configured: raise HTTPException(status_code=503,detail="CrowdSec Local API integration is not configured")
    try: incoming=await adapter.collect_findings()
    except CrowdSecAdapterError: raise HTTPException(status_code=502,detail="CrowdSec Local API request failed; check backend integration logs") from None
    inserted,updated=_persist_findings(db,actor,incoming,"crowdsec","integration.crowdsec.collect","crowdsec-lapi",None)
    limit=settings.crowdsec_max_results
    return {"integration":"crowdsec-lapi","received":len(incoming),"inserted":inserted,"updated":updated,
        "truncated_possible":len(incoming)>=limit,"max_results":limit,"data_scope":"active_decisions_only"}

def _persist_findings(db: Session,actor: User,incoming: list,engine: str,audit_action: str,target: str,
    since: datetime | None) -> tuple[int,int]:
    inserted=updated=0
    try:
        for item in incoming:
            existing=db.scalar(select(Finding).where(Finding.source_engine==engine,Finding.source_native_id==item.source_native_id))
            severity=FindingSeverity(item.severity) if item.severity in FindingSeverity._value2member_map_ else FindingSeverity.unknown
            if existing is None:
                db.add(Finding(source_engine=engine,source_native_id=item.source_native_id,title=item.title,
                    description=item.description,severity=severity,first_seen_at=item.observed_at,last_seen_at=item.observed_at,evidence=item.evidence))
                inserted+=1
            else:
                existing.title,existing.description,existing.severity=item.title,item.description,severity
                previous=existing.last_seen_at
                if previous.tzinfo is None: previous=previous.replace(tzinfo=timezone.utc)
                existing.last_seen_at=max(previous,item.observed_at); existing.evidence=item.evidence
                # Keep analyst triage state and first_seen_at unchanged.
                updated+=1
        db.add(AuditLog(actor_user_id=actor.id,action=audit_action,target=target,detail=json.dumps({
            "since":since.isoformat() if since else None,"received":len(incoming),"inserted":inserted,"updated":updated})))
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409,detail=f"Concurrent {engine} collection conflict; retry the collection") from None
    except Exception:
        db.rollback(); raise
    return inserted,updated
