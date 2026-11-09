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
from app.integrations.wazuh_manager import WazuhManagerAdapter, WazuhManagerError
from app.models.entities import Asset, AuditLog, Finding, FindingSeverity, User, UserRole, Vulnerability
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



@router.get("/wazuh-vulnerabilities/health")
async def wazuh_vulnerability_health(actor: User = Depends(require_roles(*OPERATORS))) -> dict[str, object]:
    adapter=WazuhIndexerAdapter()
    if not adapter.is_configured:
        return {"integration":"wazuh-vulnerability-detector","configured":False,"status":"not_configured"}
    try:
        healthy=await adapter.healthcheck()
    except WazuhAdapterError:
        return {"integration":"wazuh-vulnerability-detector","configured":True,"status":"unhealthy"}
    return {"integration":"wazuh-vulnerability-detector","configured":True,"status":"healthy" if healthy else "unhealthy"}

@router.post("/wazuh-vulnerabilities/sync")
async def sync_wazuh_vulnerabilities(db: Session=Depends(get_db),actor: User=Depends(require_roles(*OPERATORS))) -> dict[str,object]:
    adapter=WazuhIndexerAdapter()
    if not adapter.is_configured:
        raise HTTPException(status_code=503,detail="Wazuh Indexer integration is not configured")
    try:
        incoming,total,truncated=await adapter.collect_vulnerabilities()
    except WazuhAdapterError:
        raise HTTPException(status_code=502,detail="Wazuh vulnerability inventory query failed; check backend integration logs") from None
    created=updated=unchanged=unmapped=skipped=0
    now=datetime.now(timezone.utc)
    try:
        for item in incoming:
            asset=db.scalar(select(Asset).where(Asset.source_engine=="wazuh",Asset.external_id==item["agent_id"]))
            severity=FindingSeverity(item["severity"]) if item["severity"] in FindingSeverity._value2member_map_ else FindingSeverity.unknown
            observed=item["observed_at"] or now
            native_id=item["source_native_id"]
            evidence={"provider":"Wazuh Vulnerability Detection","index":"wazuh-states-vulnerabilities*",
                "agent_id":item["agent_id"],"agent_name":item["agent_name"],
                "package":{"name":item["package_name"],"version":item["package_version"],"type":item["package_type"],
                    "architecture":item["package_architecture"],"description":item["package_description"]},
                "host_os":item["os_name"],"vulnerability":{"id":item["cve_id"],"category":item["category"],
                    "severity":item["severity"],"score":item["cvss_score"],"score_version":item["cvss_version"],
                    "published_at":item["published_at"].isoformat() if item["published_at"] else None,
                    "references":item["references"]}}
            finding=db.scalar(select(Finding).where(Finding.source_engine=="wazuh-vulnerability",Finding.source_native_id==native_id))
            if finding is None:
                finding=Finding(source_engine="wazuh-vulnerability",source_native_id=native_id,
                    title=f'{item["cve_id"]} affects {item["package_name"]} {item["package_version"]}',
                    description=item["description"],severity=severity,asset_id=asset.id if asset else None,
                    first_seen_at=observed,last_seen_at=observed,evidence=evidence)
                db.add(finding);db.flush()
                vuln=Vulnerability(cve_id=item["cve_id"],finding_id=finding.id,asset_id=finding.asset_id or (asset.id if asset else None),
                    cvss_score=item["cvss_score"],cvss_version=item["cvss_version"],cvss_severity=item["severity"],
                    description=item["description"],published_at=item["published_at"],
                    nvd_url=f'https://nvd.nist.gov/vuln/detail/{item["cve_id"]}',
                    first_seen_at=observed,last_seen_at=observed,created_at=now,updated_at=now)
                db.add(vuln);created+=1
                if asset is None:unmapped+=1
                continue
            finding.title=f'{item["cve_id"]} affects {item["package_name"]} {item["package_version"]}'
            finding.description=item["description"];finding.severity=severity
            if finding.asset_id is None and asset is not None:finding.asset_id=asset.id
            previous=finding.last_seen_at
            if previous.tzinfo is None:previous=previous.replace(tzinfo=timezone.utc)
            finding.last_seen_at=max(previous,observed);finding.evidence=evidence
            vuln=db.scalar(select(Vulnerability).where(Vulnerability.finding_id==finding.id,Vulnerability.cve_id==item["cve_id"]))
            if vuln is None:
                db.add(Vulnerability(cve_id=item["cve_id"],finding_id=finding.id,asset_id=asset.id if asset else finding.asset_id,
                    cvss_score=item["cvss_score"],cvss_version=item["cvss_version"],cvss_severity=item["severity"],
                    description=item["description"],published_at=item["published_at"],
                    nvd_url=f'https://nvd.nist.gov/vuln/detail/{item["cve_id"]}',
                    first_seen_at=observed,last_seen_at=observed,created_at=now,updated_at=now));created+=1
            else:
                if vuln.asset_id is None and (asset is not None or finding.asset_id is not None):vuln.asset_id=finding.asset_id or (asset.id if asset else None)
                vuln.cvss_score=item["cvss_score"];vuln.cvss_version=item["cvss_version"];vuln.cvss_severity=item["severity"]
                if item["description"]:vuln.description=item["description"]
                if item["published_at"]:vuln.published_at=item["published_at"]
                old=vuln.last_seen_at
                if old.tzinfo is None:old=old.replace(tzinfo=timezone.utc)
                vuln.last_seen_at=max(old,observed);vuln.updated_at=now
                # Keep analyst status, remediation notes, and any NVD cache metadata.
                updated+=1
            if asset is None:unmapped+=1
        db.add(AuditLog(actor_user_id=actor.id,action="integration.wazuh_vulnerabilities.sync",target="wazuh-states-vulnerabilities",
            detail=json.dumps({"received":len(incoming),"total_hits":total,"created":created,"updated":updated,
                "unmapped":unmapped,"skipped":skipped,"truncated":truncated})))
        db.commit()
    except IntegrityError:
        db.rollback();raise HTTPException(status_code=409,detail="Concurrent Wazuh vulnerability sync conflict; retry") from None
    except Exception:
        db.rollback();raise
    return {"integration":"wazuh-vulnerability-detector","received":len(incoming),"total_hits":total,
        "created":created,"updated":updated,"unmapped":unmapped,"skipped":skipped,"truncated_possible":truncated,
        "max_results":min(max(int(settings.wazuh_indexer_max_results),1),500),"data_scope":"current_vulnerability_state"}

@router.get("/wazuh-manager/health")
async def wazuh_manager_health(actor: User = Depends(require_roles(*OPERATORS))) -> dict[str, object]:
    adapter=WazuhManagerAdapter()
    if not adapter.is_configured: return {"integration":"wazuh-manager-api","configured":False,"status":"not_configured","capability":"read_agent_inventory"}
    try: healthy=await adapter.healthcheck()
    except WazuhManagerError: return {"integration":"wazuh-manager-api","configured":True,"status":"unhealthy","capability":"read_agent_inventory"}
    return {"integration":"wazuh-manager-api","configured":True,"status":"healthy" if healthy else "unhealthy","capability":"read_agent_inventory"}

@router.post("/wazuh-manager/sync")
async def sync_wazuh_manager_agents(db: Session=Depends(get_db),actor: User | None=Depends(require_roles(*OPERATORS))) -> dict[str,object]:
    adapter=WazuhManagerAdapter()
    if not adapter.is_configured: raise HTTPException(status_code=503,detail="Wazuh Manager API is not configured")
    try: incoming=await adapter.collect_agents()
    except WazuhManagerError: raise HTTPException(status_code=502,detail="Wazuh Manager API request failed; check backend integration logs") from None
    created=updated=unchanged=skipped=0
    try:
        for raw in incoming:
            item=adapter.normalize_agent(raw)
            if item is None: skipped+=1;continue
            asset=db.scalar(select(Asset).where(Asset.source_engine=="wazuh",Asset.external_id==item["external_id"]))
            if asset is None:
                db.add(Asset(name=item["name"],asset_type="endpoint",environment="unknown",source_engine="wazuh",external_id=item["external_id"],
                    ip_address=item["ip_address"],os_name=item["os_name"],agent_status=item["agent_status"],last_seen_at=item["last_seen_at"]))
                created+=1;continue
            changed=False
            if asset.name!=item["name"]:asset.name=item["name"];changed=True
            if item["ip_address"] and asset.ip_address!=item["ip_address"]:asset.ip_address=item["ip_address"];changed=True
            if item["os_name"] and asset.os_name!=item["os_name"]:asset.os_name=item["os_name"];changed=True
            if asset.agent_status!=item["agent_status"]:asset.agent_status=item["agent_status"];changed=True
            previous=asset.last_seen_at
            if previous is not None and previous.tzinfo is None:previous=previous.replace(tzinfo=timezone.utc)
            if item["last_seen_at"] and (previous is None or item["last_seen_at"]>previous):asset.last_seen_at=item["last_seen_at"];changed=True
            if changed:updated+=1
            else:unchanged+=1
        db.add(AuditLog(actor_user_id=actor.id if actor else None,action="integration.wazuh_manager.sync",target="wazuh-manager-api",
            detail=json.dumps({"received":len(incoming),"created":created,"updated":updated,"unchanged":unchanged,"skipped":skipped,
                "truncated_possible":len(incoming)>=settings.wazuh_manager_max_agents})))
        db.commit()
    except IntegrityError:
        db.rollback();raise HTTPException(status_code=409,detail="Concurrent Wazuh agent sync conflict; retry the sync") from None
    except Exception:
        db.rollback();raise
    return {"integration":"wazuh-manager-api","received":len(incoming),"created":created,"updated":updated,"unchanged":unchanged,"skipped":skipped,
        "truncated_possible":len(incoming)>=settings.wazuh_manager_max_agents,"max_agents":settings.wazuh_manager_max_agents,"data_scope":"registered_agents_only"}

@router.post("/wazuh/collect")
async def collect_wazuh_alerts(since: datetime | None=Query(default=None,description="Timezone-aware lower bound for @timestamp"),
    db: Session=Depends(get_db),actor: User | None=Depends(require_roles(*OPERATORS))) -> dict[str,object]:
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


@router.post("/crowdsec/alerts/collect")
async def collect_crowdsec_alerts(db: Session=Depends(get_db),
    actor: User=Depends(require_roles(*OPERATORS))) -> dict[str,object]:
    adapter=CrowdSecLapiAdapter()
    if not adapter.is_alerts_configured:
        raise HTTPException(status_code=503,detail="CrowdSec alert history is not configured; dedicated machine credentials are required")
    try:
        incoming=await adapter.collect_alerts()
    except CrowdSecAdapterError:
        raise HTTPException(status_code=502,detail="CrowdSec alert history request failed; check backend integration logs") from None
    inserted,updated=_persist_findings(db,actor,incoming,"crowdsec-alert",
        "integration.crowdsec.alerts.collect","crowdsec-lapi-alerts",None)
    limit=min(max(int(settings.crowdsec_max_results),1),1000)
    return {"integration":"crowdsec-lapi-alerts","received":len(incoming),"inserted":inserted,"updated":updated,
        "truncated_possible":getattr(adapter,"last_alert_count",len(incoming))>=limit,"max_results":limit,
        "data_scope":"bounded_alert_history","authentication":"dedicated_machine_jwt"}

def _match_crowdsec_asset(db: Session, item) -> Asset | None:
    """Link only a single-IP CrowdSec decision to one unambiguous existing asset."""
    evidence = item.evidence if isinstance(item.evidence, dict) else {}
    source = evidence.get("source") if isinstance(evidence.get("source"), dict) else {}
    scope = str(evidence.get("scope") or source.get("scope") or "").strip().lower()
    value = str(evidence.get("value") or source.get("value") or "").strip()
    if scope != "ip" or not value:
        return None
    try:
        import ipaddress
        normalized_ip = str(ipaddress.ip_address(value))
    except ValueError:
        return None
    matches = db.scalars(select(Asset).where(Asset.ip_address == normalized_ip)).all()
    return matches[0] if len(matches) == 1 else None


def _upsert_wazuh_asset(db: Session, item) -> Asset | None:
    evidence = item.evidence if isinstance(item.evidence, dict) else {}
    agent_id = evidence.get("agent_id")
    if item.source_engine != "wazuh" or agent_id is None:
        return None
    external_id = str(agent_id).strip()[:255]
    if not external_id:
        return None
    asset = db.scalar(select(Asset).where(
        Asset.source_engine == "wazuh", Asset.external_id == external_id
    ))
    name = str(evidence.get("agent_name") or item.asset_reference or ("Wazuh agent " + external_id))[:255]
    ip_address = str(evidence.get("agent_ip") or "").strip()[:64] or None
    if asset is None:
        asset = Asset(name=name, asset_type="endpoint", environment="unknown",
            source_engine="wazuh", external_id=external_id, ip_address=ip_address,
            agent_status="observed", last_seen_at=item.observed_at)
        db.add(asset)
        db.flush()
    else:
        asset.name = name
        if ip_address:
            asset.ip_address = ip_address
        previous = asset.last_seen_at
        if previous is not None and previous.tzinfo is None:
            previous = previous.replace(tzinfo=timezone.utc)
        asset.last_seen_at = max(previous, item.observed_at) if previous else item.observed_at
        asset.agent_status = "observed"
    return asset


def _persist_findings(db: Session,actor: User | None,incoming: list,engine: str,audit_action: str,target: str,
    since: datetime | None) -> tuple[int,int]:
    inserted=updated=0
    try:
        for item in incoming:
            existing=db.scalar(select(Finding).where(Finding.source_engine==engine,Finding.source_native_id==item.source_native_id))
            severity=FindingSeverity(item.severity) if item.severity in FindingSeverity._value2member_map_ else FindingSeverity.unknown
            if engine == "wazuh":
                asset = _upsert_wazuh_asset(db, item)
            elif engine in {"crowdsec", "crowdsec-alert"}:
                asset = _match_crowdsec_asset(db, item)
            else:
                asset = None
            if existing is None:
                db.add(Finding(source_engine=engine,source_native_id=item.source_native_id,title=item.title,
                    description=item.description,severity=severity,asset_id=asset.id if asset else None,
                    first_seen_at=item.observed_at,last_seen_at=item.observed_at,evidence=item.evidence))
                inserted+=1
            else:
                existing.title,existing.description,existing.severity=item.title,item.description,severity
                if existing.asset_id is None and asset is not None:
                    existing.asset_id = asset.id
                previous=existing.last_seen_at
                if previous.tzinfo is None: previous=previous.replace(tzinfo=timezone.utc)
                existing.last_seen_at=max(previous,item.observed_at); existing.evidence=item.evidence
                # Keep analyst triage state and first_seen_at unchanged.
                updated+=1
        db.add(AuditLog(actor_user_id=actor.id if actor else None,action=audit_action,target=target,detail=json.dumps({
            "since":since.isoformat() if since else None,"received":len(incoming),"inserted":inserted,"updated":updated})))
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409,detail=f"Concurrent {engine} collection conflict; retry the collection") from None
    except Exception:
        db.rollback(); raise
    return inserted,updated
