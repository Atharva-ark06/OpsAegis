from __future__ import annotations
import asyncio, hashlib, hmac, ipaddress, json, os, re, socket, uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from fastapi import FastAPI, BackgroundTasks, Header, HTTPException
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    token: str = Field(default="", validation_alias="SHANNON_BRIDGE_TOKEN")
    enabled: bool = Field(default=False, validation_alias="SHANNON_BRIDGE_ENABLED")
    egress_ack: bool = Field(default=False, validation_alias="SHANNON_EGRESS_POLICY_ACKNOWLEDGED")
    proxy: str = Field(default="", validation_alias="SHANNON_EGRESS_PROXY_URL")
    target_hosts_csv: str = Field(default="", validation_alias="SHANNON_ALLOWED_TARGET_HOSTS")
    repositories_csv: str = Field(default="", validation_alias="SHANNON_ALLOWED_SOURCE_REPOSITORIES")
    work_root: Path = Field(default=Path("/var/lib/shannon-bridge"), validation_alias="SHANNON_WORK_ROOT")
    timeout: int = Field(default=14400, validation_alias="SHANNON_JOB_TIMEOUT_SECONDS")
    concurrency: int = Field(default=1, validation_alias="SHANNON_MAX_CONCURRENT_JOBS")
    cli_version: str = Field(default="3.5.0", validation_alias="SHANNON_CLI_VERSION")
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    @property
    def hosts(self): return {x.strip().lower().rstrip(".") for x in self.target_hosts_csv.split(",") if x.strip()}
    @property
    def repositories(self): return {x.strip().rstrip("/") for x in self.repositories_csv.split(",") if x.strip()}

settings = Settings()
app = FastAPI(title="OpsAegis Shannon Isolated Bridge", version="0.1.0", docs_url=None, redoc_url=None)
jobs: dict[str, dict] = {}
gate = asyncio.Semaphore(max(1, min(settings.concurrency, 2)))

class ScanRequest(BaseModel):
    client: str = Field(pattern="^opsaegis$")
    scan_id: int = Field(gt=0)
    target_url: str = Field(min_length=9, max_length=2048)
    source_repository: str = Field(min_length=25, max_length=500)
    authorization_reference: str = Field(min_length=12, max_length=500)
    profile: str = Field(pattern="^authorized-staging$")
    @field_validator("target_url")
    @classmethod
    def target(cls, value):
        p = urlsplit(value); host = (p.hostname or "").lower().rstrip(".")
        if p.scheme != "https" or not host or p.username or p.password or p.query or p.fragment or p.port not in (None,443) or p.path not in ("","/"):
            raise ValueError("Target must be a canonical HTTPS origin")
        if not re.fullmatch(r"[a-z0-9.-]+", host) or ".." in host:
            raise ValueError("Invalid target hostname")
        return "https://" + host
    @field_validator("source_repository")
    @classmethod
    def repository(cls, value):
        p=urlsplit(value); parts=[x for x in p.path.strip("/").split("/") if x]
        if p.scheme!="https" or p.hostname!="github.com" or p.username or p.password or p.query or p.fragment or len(parts)!=2 or not all(re.fullmatch(r"[A-Za-z0-9_.-]+",x) and x not in (".","..") for x in parts):
            raise ValueError("Source must be canonical GitHub owner/repository URL")
        return "https://github.com/" + parts[0] + "/" + parts[1].removesuffix(".git")

def now(): return datetime.now(timezone.utc).isoformat()
def authorize(value):
    if len(settings.token)<32 or not value or not value.startswith("Bearer ") or not hmac.compare_digest(value[7:],settings.token):
        raise HTTPException(401,"Unauthorized")

def blocker():
    if not settings.enabled: return "execution_disabled"
    if len(settings.token)<32: return "bridge_token_not_configured"
    if not settings.egress_ack: return "egress_policy_not_acknowledged"
    if not settings.proxy.startswith("http"): return "egress_proxy_required"
    if not settings.hosts or not settings.repositories: return "explicit_allowlists_required"
    if settings.cli_version != "3.5.0": return "unreviewed_cli_version"
    return None

def public_dns(host):
    try: addresses={x[4][0] for x in socket.getaddrinfo(host,443,type=socket.SOCK_STREAM)}
    except OSError: raise RuntimeError("target_dns_resolution_failed") from None
    if not addresses or any(not ipaddress.ip_address(x).is_global for x in addresses):
        raise RuntimeError("target_resolves_to_non_public_address")

def parse_sarif(path: Path, target_url: str):
    try: doc=json.loads(path.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError): return []
    host=urlsplit(target_url).hostname; found=[]
    for run in doc.get("runs",[]):
        for result in run.get("results",[]):
            props=result.get("properties") or {}; proof=props.get("proof"); affected=props.get("affected_url")
            rule=str(result.get("ruleId") or ""); message=result.get("message") or {}; title=str(message.get("text") or rule).strip()
            if not rule or not isinstance(proof,str) or not proof.strip() or not isinstance(affected,str): continue
            try:
                p=urlsplit(affected)
                if p.scheme!="https" or p.hostname!=host or p.port not in (None,443) or p.username or p.password: continue
            except ValueError: continue
            fp=(result.get("fingerprints") or {}).get("primaryLocationLineHash") or hashlib.sha256((rule+"|"+affected+"|"+title).encode()).hexdigest()
            level=str(result.get("level") or "warning").lower()
            found.append({"fingerprint":str(fp)[:255],"title":title[:500],"description":str(props.get("description") or title)[:4000],
              "severity":{"error":"high","warning":"medium","note":"low"}.get(level,"unknown"),"affected_url":affected,
              "validation_status":"exploited","proof":proof[:4000],
              "references":props.get("references",[])[:10] if isinstance(props.get("references"),list) else []})
    return found[:200]

async def run_scan(job_id, request):
    async with gate:
        job=jobs[job_id]; job.update(status="running",started_at=now())
        root=settings.work_root/job_id; repo=root/"source"; out=root/"output"
        try:
            root.mkdir(parents=True,exist_ok=False); out.mkdir()
            public_dns(urlsplit(request.target_url).hostname or "")
            env={"PATH":os.environ.get("PATH","/usr/local/bin:/usr/bin:/bin"),"HOME":str(root/"home"),
                 "CI":"1","HTTP_PROXY":settings.proxy,"HTTPS_PROXY":settings.proxy,
                 "http_proxy":settings.proxy,"https_proxy":settings.proxy}
            Path(env["HOME"]).mkdir()
            for key in ("ANTHROPIC_API_KEY","OPENAI_API_KEY","AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY","AWS_SESSION_TOKEN"):
                if os.environ.get(key): env[key]=os.environ[key]
            clone=await asyncio.create_subprocess_exec("git","clone","--depth","1","--no-tags","--filter=blob:none","--",request.source_repository,str(repo),
              cwd=str(root),env=env,stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL)
            try: await asyncio.wait_for(clone.wait(),timeout=300)
            except asyncio.TimeoutError:
                clone.kill(); raise RuntimeError("source_checkout_timeout") from None
            if clone.returncode: raise RuntimeError("source_checkout_failed")
            args=["npx","--yes","@keygraph/shannon@"+settings.cli_version,"start","-u",request.target_url,"-r",str(repo),
                  "--follow","-o",str(out),"-w","opsaegis-"+job_id]
            with (root/"shannon.log").open("wb") as log:
                proc=await asyncio.create_subprocess_exec(*args,cwd=str(root),env=env,stdout=log,stderr=asyncio.subprocess.STDOUT,start_new_session=True)
                try: code=await asyncio.wait_for(proc.wait(),timeout=settings.timeout)
                except asyncio.TimeoutError:
                    proc.kill(); await proc.wait(); raise RuntimeError("shannon_timeout") from None
            if code: raise RuntimeError("shannon_execution_failed")
            records=[]
            for sarif in (list(out.rglob("*.sarif"))+list(out.rglob("*.sarif.json")))[:5]:
                records.extend(parse_sarif(sarif,request.target_url))
            unique={x["fingerprint"]:x for x in records}
            job.update(status="completed",findings=list(unique.values())[:200],findings_count=len(unique),finished_at=now())
        except Exception as exc:
            allowed={"target_dns_resolution_failed","target_resolves_to_non_public_address","source_checkout_timeout","source_checkout_failed","shannon_timeout","shannon_execution_failed"}
            job.update(status="failed",error_code=str(exc) if str(exc) in allowed else "runner_internal_error",finished_at=now())

@app.get("/health")
async def health():
    why=blocker()
    return {"engine":"shannon","status":"healthy" if why is None else "not_ready","version":settings.cli_version,
            "execution_enabled":why is None,"blocker":why,"isolation":"dedicated-host-required"}

@app.post("/v1/scans",status_code=202)
async def submit(request:ScanRequest,background:BackgroundTasks,authorization:str|None=Header(default=None)):
    authorize(authorization); why=blocker()
    if why: raise HTTPException(503,"runner_not_ready:"+why)
    host=urlsplit(request.target_url).hostname or ""
    if host.lower().rstrip(".") not in settings.hosts: raise HTTPException(403,"Target host is not allowlisted")
    if request.source_repository.rstrip("/") not in settings.repositories: raise HTTPException(403,"Repository is not allowlisted")
    if any(x["status"] in ("queued","running") for x in jobs.values()): raise HTTPException(429,"One scan is already active")
    job_id=uuid.uuid4().hex
    jobs[job_id]={"job_id":job_id,"scan_id":request.scan_id,"status":"queued","created_at":now(),"findings":[]}
    background.add_task(run_scan,job_id,request)
    return {"job_id":job_id,"status":"queued"}

@app.get("/v1/scans/{job_id}")
async def get_scan(job_id:str,authorization:str|None=Header(default=None)):
    authorize(authorization)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",job_id) or job_id not in jobs: raise HTTPException(404,"Scan not found")
    item=jobs[job_id]
    if item["status"] in ("queued","running"): return {"status":item["status"]}
    if item["status"]=="failed": return {"status":"failed","error_code":item.get("error_code","runner_failed")}
    return {"status":"completed","findings":item.get("findings",[])}
