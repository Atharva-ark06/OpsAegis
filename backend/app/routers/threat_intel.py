from datetime import datetime,timedelta,timezone
import asyncio,hashlib,json
from fastapi import APIRouter,Depends,HTTPException,Query
from pydantic import BaseModel,Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.config import settings
from app.database import get_db
from app.integrations.threat_intel import AbuseIPDBAdapter,VirusTotalAdapter,normalize_indicator
from app.models.entities import AuditLog,ThreatIntelIOC,User,UserRole
from app.security import get_current_user,require_roles
router=APIRouter(prefix="/threat-intel",tags=["threat-intelligence"])
OPERATORS=(UserRole.admin,UserRole.analyst)
class EnrichmentRequest(BaseModel):
    indicator_type:str=Field(min_length=2,max_length=8)
    indicator_value:str=Field(min_length=1,max_length=2048)
    force_refresh:bool=False

def serialize(item:ThreatIntelIOC)->dict:
    return {"id":item.id,"indicator_type":item.indicator_type,"indicator_value":item.indicator_value,"verdict":item.verdict,
        "risk_score":item.risk_score,"provider_results":item.provider_results,"enriched_at":item.enriched_at.isoformat() if item.enriched_at else None,
        "created_at":item.created_at.isoformat()}

@router.get("/providers")
def provider_status(actor:User=Depends(get_current_user))->dict:
    return {"virustotal":{"configured":bool(settings.virustotal_api_key),"status":"configured" if settings.virustotal_api_key else "not_configured"},
        "abuseipdb":{"configured":bool(settings.abuseipdb_api_key),"status":"configured" if settings.abuseipdb_api_key else "not_configured"},
        "cache_ttl_seconds":settings.threat_intel_cache_ttl_seconds}

@router.get("/iocs")
def list_iocs(skip:int=Query(default=0,ge=0,le=100000),limit:int=Query(default=50,ge=1,le=100),db:Session=Depends(get_db),actor:User=Depends(get_current_user))->list[dict]:
    rows=db.scalars(select(ThreatIntelIOC).order_by(ThreatIntelIOC.created_at.desc(),ThreatIntelIOC.id.desc()).offset(skip).limit(limit)).all()
    return [serialize(row) for row in rows]

@router.post("/enrich")
async def enrich_indicator(payload:EnrichmentRequest,db:Session=Depends(get_db),actor:User=Depends(require_roles(*OPERATORS)))->dict:
    try: kind,value=normalize_indicator(payload.indicator_type,payload.indicator_value)
    except ValueError as exc: raise HTTPException(status_code=422,detail=str(exc)) from None
    if not settings.virustotal_api_key and not settings.abuseipdb_api_key: raise HTTPException(status_code=503,detail="No threat-intelligence provider is configured")
    digest=hashlib.sha256(f"{kind}:{value}".encode()).hexdigest()
    item=db.scalar(select(ThreatIntelIOC).where(ThreatIntelIOC.indicator_hash==digest)); now=datetime.now(timezone.utc)
    if item is not None and item.enriched_at is not None and not payload.force_refresh:
        previous=item.enriched_at if item.enriched_at.tzinfo else item.enriched_at.replace(tzinfo=timezone.utc)
        if now-previous<timedelta(seconds=settings.threat_intel_cache_ttl_seconds):
            db.add(AuditLog(actor_user_id=actor.id,action="threat_intel.enrich.cached",target=f"ioc:{item.id}",detail=json.dumps({"indicator_type":kind})))
            db.commit();return {**serialize(item),"cached":True}
    vt,abuse=await asyncio.gather(VirusTotalAdapter().enrich(kind,value),AbuseIPDBAdapter().enrich(kind,value))
    results={"virustotal":vt,"abuseipdb":abuse}; successful=[v for v in results.values() if v["status"]=="ok"]
    scores=[v["risk_score"] for v in successful if v["risk_score"] is not None]; verdicts=[v["verdict"] for v in successful]
    failed_configured = ((bool(settings.virustotal_api_key) and vt["status"] in {"error","auth_error","rate_limited"}) or
                         (bool(settings.abuseipdb_api_key) and abuse["status"] in {"error","auth_error","rate_limited"}))
    verdict="malicious" if "malicious" in verdicts else "suspicious" if "suspicious" in verdicts else "clean" if successful and all(v=="clean" for v in verdicts) and not failed_configured else "unknown"
    score=max(scores) if scores else None
    if item is None:
        item=ThreatIntelIOC(indicator_type=kind,indicator_value=value,indicator_hash=digest,verdict=verdict,risk_score=score,
            provider_results=results,enriched_at=now,created_by_user_id=actor.id);db.add(item)
    else: item.verdict,item.risk_score,item.provider_results,item.enriched_at=verdict,score,results,now
    db.add(AuditLog(actor_user_id=actor.id,action="threat_intel.enrich",target=f"ioc:{item.id or digest[:16]}",
        detail=json.dumps({"indicator_type":kind,"providers_succeeded":len(successful),"provider_statuses":{n:v["status"] for n,v in results.items()}})))
    db.commit();db.refresh(item);return {**serialize(item),"cached":False}

@router.get("/iocs/{ioc_id}")
def get_ioc(ioc_id:int,db:Session=Depends(get_db),actor:User=Depends(get_current_user))->dict:
    item=db.get(ThreatIntelIOC,ioc_id)
    if item is None: raise HTTPException(status_code=404,detail="IOC not found")
    return serialize(item)
