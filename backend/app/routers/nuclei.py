from __future__ import annotations
import asyncio,hashlib,json,re
import redis
from datetime import datetime,timezone
from ipaddress import ip_address
from urllib.parse import urlsplit,urlunsplit
from fastapi import APIRouter,Depends,HTTPException
from pydantic import BaseModel,Field,field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.config import settings
from app.database import get_db
from app.models.entities import Asset,AuditLog,Finding,FindingSeverity,NucleiScanRun,NucleiTarget,User,UserRole,Vulnerability
from app.security import require_roles
router=APIRouter(prefix="/integrations/nuclei",tags=["nuclei"])
OPS=(UserRole.admin,UserRole.analyst)

class TargetCreate(BaseModel):
    name:str=Field(min_length=2,max_length=120)
    url:str=Field(min_length=9,max_length=2048)
    authorization_reference:str=Field(min_length=12,max_length=500)
    asset_id:int|None=None
    @field_validator("url")
    @classmethod
    def validate_url(cls,value):
        p=urlsplit(value.strip())
        if p.scheme!="https" or not p.hostname or p.username or p.password or p.query or p.fragment: raise ValueError("Target must be HTTPS without credentials, query or fragment")
        host=p.hostname.lower().rstrip(".")
        if host=="localhost" or host.endswith((".localhost",".local")) or host=="metadata.google.internal": raise ValueError("Local and metadata hostnames are not accepted")
        try: ip=ip_address(host)
        except ValueError: ip=None
        if ip and (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved): raise ValueError("Loopback, link-local, multicast and reserved IPs are not accepted")
        return urlunsplit(("https",p.netloc,p.path.rstrip("/") or "/","",""))
class ScanRequest(BaseModel):
    profile:str=Field(default="safe",pattern="^safe$")
def target_out(t):
    return {"id":t.id,"name":t.name,"url":t.url,"authorization_reference":t.authorization_reference,"asset_id":t.asset_id,"enabled":t.enabled,"created_at":t.created_at.isoformat()}
def scan_out(r):
    return {"id":r.id,"target_id":r.target_id,"status":r.status,"profile":r.profile,"started_at":r.started_at.isoformat() if r.started_at else None,"finished_at":r.finished_at.isoformat() if r.finished_at else None,"findings_count":r.findings_count,"error_code":r.error_code,"attempts":r.attempts,"next_attempt_at":r.next_attempt_at.isoformat() if r.next_attempt_at else None,"created_at":r.created_at.isoformat()}
@router.get("/health")
def health(actor:User=Depends(require_roles(*OPS))):
    if not settings.nuclei_enabled:
        return {"integration":"nuclei","configured":False,"status":"not_configured","execution_enabled":False,"profile":"safe"}
    try:
        client=redis.Redis.from_url(settings.redis_url,decode_responses=True,socket_connect_timeout=2,socket_timeout=2)
        alive=bool(client.get("opsaegis:nuclei:worker:heartbeat"));client.close()
    except Exception: alive=False
    return {"integration":"nuclei","configured":alive,"status":"healthy" if alive else "unhealthy",
            "execution_enabled":alive,"profile":"safe","execution_mode":"isolated_worker"}

@router.post("/targets",status_code=201)
def add_target(data:TargetCreate,db:Session=Depends(get_db),actor:User=Depends(require_roles(UserRole.admin))):
    if data.asset_id is not None and db.get(Asset,data.asset_id) is None: raise HTTPException(404,"Asset not found")
    t=NucleiTarget(**data.model_dump(),created_by=actor.id);db.add(t)
    db.add(AuditLog(actor_user_id=actor.id,action="integration.nuclei.target.register",target=t.url,detail=json.dumps({"name":t.name,"authorization_reference":t.authorization_reference})))
    try: db.commit()
    except IntegrityError: db.rollback();raise HTTPException(409,"Target URL already registered") from None
    db.refresh(t);return target_out(t)
@router.get("/targets")
def list_targets(db:Session=Depends(get_db),actor:User=Depends(require_roles(*OPS))):
    return [target_out(t) for t in db.scalars(select(NucleiTarget).order_by(NucleiTarget.id.desc())).all()]
@router.get("/scans")
def list_scans(skip:int=0,limit:int=50,db:Session=Depends(get_db),actor:User=Depends(require_roles(*OPS))):
    if skip<0 or not 1<=limit<=100: raise HTTPException(422,"skip must be >= 0 and limit 1..100")
    return [scan_out(r) for r in db.scalars(select(NucleiScanRun).order_by(NucleiScanRun.id.desc()).offset(skip).limit(limit)).all()]
@router.post("/targets/{target_id}/scans",status_code=202)
def start_scan(target_id:int,data:ScanRequest,db:Session=Depends(get_db),actor:User=Depends(require_roles(*OPS))):
    t=db.get(NucleiTarget,target_id)
    if t is None or not t.enabled: raise HTTPException(404,"Enabled authorized target not found")
    if not settings.nuclei_enabled: raise HTTPException(503,"Nuclei execution is disabled")
    try:
        client=redis.Redis.from_url(settings.redis_url,decode_responses=True,socket_connect_timeout=2,socket_timeout=2)
        alive=bool(client.get("opsaegis:nuclei:worker:heartbeat"));client.close()
    except Exception: alive=False
    if not alive: raise HTTPException(503,"Isolated Nuclei worker is unavailable")
    run=NucleiScanRun(target_id=t.id,requested_by=actor.id,status="queued",profile=data.profile,
                      attempts=0,next_attempt_at=datetime.now(timezone.utc))
    db.add(run);db.flush()
    db.add(AuditLog(actor_user_id=actor.id,action="integration.nuclei.scan.enqueue",target=t.url,
        detail=json.dumps({"scan_id":run.id,"profile":"safe","authorization_reference":t.authorization_reference})))
    db.commit();db.refresh(run)
    try:
        client=redis.Redis.from_url(settings.redis_url,decode_responses=True,socket_connect_timeout=2,socket_timeout=2)
        client.lpush("opsaegis:nuclei:queue",str(run.id));client.close()
    except Exception:
        pass
    return {"scan":scan_out(run),"queued":True,"message":"Scan accepted by the isolated worker queue"}
class WorkerLeaseLost(RuntimeError):
    """Raised when the worker no longer owns the scanner lease."""

async def execute(url:str,lease_lost=None)->list[dict]:
    args=[settings.nuclei_binary,"-u",url,"-jsonl","-silent","-no-color","-disable-update-check","-no-interactsh",
          "-t",settings.nuclei_templates_path,"-rl",str(settings.nuclei_rate_limit),"-c","2","-timeout","5","-retries","0",
          "-severity","info,low,medium,high,critical","-pt","http","-exclude-tags","dos,fuzz,intrusive,headless"]
    try: proc=await asyncio.create_subprocess_exec(*args,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL)
    except OSError as exc: raise RuntimeError(type(exc).__name__) from None
    async def read_bounded():
        parts=[];size=0
        while True:
            chunk=await proc.stdout.read(65536)
            if not chunk: break
            size+=len(chunk)
            if size>settings.nuclei_max_output_bytes:
                if proc.returncode is None:
                    try: proc.kill()
                    except ProcessLookupError: pass
                await proc.wait()
                raise RuntimeError("scanner_output_limit")
            parts.append(chunk)
        await proc.wait();return b"".join(parts)
    reader=asyncio.create_task(read_bounded())
    if lease_lost is None:
        try: output=await asyncio.wait_for(reader,timeout=settings.nuclei_timeout_seconds)
        except asyncio.TimeoutError:
            if proc.returncode is None:
                try: proc.kill()
                except ProcessLookupError: pass
            await proc.wait()
            reader.cancel()
            await asyncio.gather(reader,return_exceptions=True)
            raise TimeoutError from None
    else:
        async def watch_lease():
            while not lease_lost.is_set():
                await asyncio.sleep(0.1)
        watcher=asyncio.create_task(watch_lease())
        done,_=await asyncio.wait({reader,watcher},timeout=settings.nuclei_timeout_seconds,return_when=asyncio.FIRST_COMPLETED)
        if watcher in done:
            if proc.returncode is None:
                try: proc.kill()
                except ProcessLookupError: pass
            await proc.wait()
            reader.cancel()
            await asyncio.gather(reader,return_exceptions=True)
            raise WorkerLeaseLost("Scanner stopped because the worker lease was lost")
        watcher.cancel()
        await asyncio.gather(watcher,return_exceptions=True)
        if reader not in done:
            if proc.returncode is None:
                try: proc.kill()
                except ProcessLookupError: pass
            await proc.wait()
            reader.cancel()
            await asyncio.gather(reader,return_exceptions=True)
            raise TimeoutError from None
        output=reader.result()
    if proc.returncode!=0: raise RuntimeError("scanner_nonzero_exit")
    parsed=[]
    for line in output.splitlines()[:500]:
        try: obj=json.loads(line)
        except (ValueError,UnicodeDecodeError): continue
        if isinstance(obj,dict) and isinstance(obj.get("info"),dict) and obj.get("template-id") and obj.get("matched-at"): parsed.append(obj)
    return parsed
def persist_findings(db:Session,records:list[dict],asset_id:int|None=None)->tuple[int,int]:
    levels={"info":FindingSeverity.informational,"informational":FindingSeverity.informational,"low":FindingSeverity.low,"medium":FindingSeverity.medium,"high":FindingSeverity.high,"critical":FindingSeverity.critical}
    inserted=updated=0;now=datetime.now(timezone.utc)
    for obj in records:
        info=obj["info"];template=str(obj["template-id"])[:120];matched=str(obj["matched-at"])[:1024];matcher=str(obj.get("matcher-name") or "")[:80]
        native=hashlib.sha256(f"{template}|{matched}|{matcher}".encode()).hexdigest()
        tags=info.get("tags",[])[:30] if isinstance(info.get("tags"),list) else []
        classification=info.get("classification") if isinstance(info.get("classification"),dict) else {}
        raw_cves=classification.get("cve-id") or classification.get("cve_id") or []
        if isinstance(raw_cves,str): raw_cves=[raw_cves]
        candidates=[template,*[str(x) for x in tags],*[str(x) for x in raw_cves if isinstance(raw_cves,list)]]
        cves=sorted({match.upper() for candidate in candidates for match in re.findall(r"CVE-\d{4}-\d{4,}",candidate,re.I)})[:20]
        evidence={"template_id":template,"matched_at":matched,"matcher_name":matcher,"host":str(obj.get("host",""))[:255],"tags":tags,"cve_ids":cves}
        severity=levels.get(str(info.get("severity","")).lower(),FindingSeverity.unknown)
        title=str(info.get("name") or template)[:500];description=str(info.get("description") or "")[:4000] or None
        existing=db.scalar(select(Finding).where(Finding.source_engine=="nuclei",Finding.source_native_id==native))
        if existing is None:
            finding=Finding(source_engine="nuclei",source_native_id=native,title=title,description=description,severity=severity,asset_id=asset_id,first_seen_at=now,last_seen_at=now,evidence=evidence);db.add(finding);db.flush();inserted+=1
        else:
            finding=existing
            existing.title=title;existing.description=description;existing.severity=severity;existing.last_seen_at=now;existing.evidence=evidence
            if existing.asset_id is None and asset_id is not None: existing.asset_id=asset_id
            updated+=1
        for cve_id in cves:
            vuln=db.scalar(select(Vulnerability).where(Vulnerability.finding_id==finding.id,Vulnerability.cve_id==cve_id))
            if vuln is None:
                db.add(Vulnerability(cve_id=cve_id,finding_id=finding.id,asset_id=finding.asset_id,
                    nvd_url="https://nvd.nist.gov/vuln/detail/"+cve_id,first_seen_at=now,last_seen_at=now))
            else:
                vuln.last_seen_at=now
                if vuln.asset_id is None and finding.asset_id is not None: vuln.asset_id=finding.asset_id
    db.flush();return inserted,updated
