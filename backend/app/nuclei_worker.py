from __future__ import annotations
import asyncio, logging, os, secrets, signal, time, json
from datetime import datetime, timedelta, timezone
import redis
from sqlalchemy import select
from app.config import settings
from app.database import SessionLocal
from app.models.entities import AuditLog, NucleiScanRun, NucleiTarget
from app.routers.nuclei import execute, persist_findings

logging.basicConfig(level=os.getenv("LOG_LEVEL","INFO"))
log=logging.getLogger("opsaegis.nuclei-worker")
QUEUE="opsaegis:nuclei:queue"; LOCK="opsaegis:nuclei:worker:lock"; HEARTBEAT="opsaegis:nuclei:worker:heartbeat"
MAX_ATTEMPTS=3; RUNNING=True
RENEW="""if redis.call('get',KEYS[1])==ARGV[1] then redis.call('expire',KEYS[1],30); redis.call('set',KEYS[2],ARGV[2],'EX',20); return 1 end return 0"""
RELEASE="""if redis.call('get',KEYS[1])==ARGV[1] then redis.call('del',KEYS[2]); return redis.call('del',KEYS[1]) end return 0"""
def utcnow(): return datetime.now(timezone.utc)
def recover(db):
 rows=db.scalars(select(NucleiScanRun).where(NucleiScanRun.status=="running")).all()
 for run in rows:
  if run.attempts>=MAX_ATTEMPTS: run.status="failed"; run.error_code="worker_restart_max_attempts"; run.finished_at=utcnow()
  else: run.status="queued"; run.error_code="worker_restart_recovery"; run.next_attempt_at=utcnow()
 db.commit(); return len(rows)
def enqueue_due(db,client):
 rows=db.scalars(select(NucleiScanRun).where(NucleiScanRun.status=="queued",NucleiScanRun.next_attempt_at<=utcnow()).order_by(NucleiScanRun.created_at).limit(20)).all()
 n=0
 for run in rows:
  marker=f"opsaegis:nuclei:enqueue:{run.id}"
  if client.set(marker,"1",nx=True,ex=60): client.lpush(QUEUE,str(run.id)); n+=1
 return n
def process(scan_id):
 with SessionLocal() as db:
  run=db.get(NucleiScanRun,scan_id)
  if run is None or run.status!="queued": return
  target=db.get(NucleiTarget,run.target_id)
  if target is None or not target.enabled:
   run.status="failed"; run.error_code="target_unavailable"; run.finished_at=utcnow(); db.commit(); return
  run.status="running"; run.attempts+=1; run.started_at=utcnow(); run.error_code=None
  target_url=target.url; asset_id=target.asset_id; actor_id=run.requested_by; db.commit()
 try:
  records=asyncio.run(execute(target_url))
  with SessionLocal() as db:
   run=db.get(NucleiScanRun,scan_id)
   if run is None: return
   inserted,updated=persist_findings(db,records,asset_id=asset_id)
   run.status="completed"; run.findings_count=inserted+updated; run.finished_at=utcnow(); run.error_code=None
   db.add(AuditLog(actor_user_id=actor_id,action="integration.nuclei.scan.complete",target=str(scan_id),detail=json.dumps({"received":len(records),"inserted":inserted,"updated":updated,"attempts":run.attempts})))
   db.commit()
 except Exception as exc:
  with SessionLocal() as db:
   run=db.get(NucleiScanRun,scan_id)
   if run is None: return
   run.error_code=type(exc).__name__[:80]; run.finished_at=utcnow()
   if run.attempts<MAX_ATTEMPTS:
    run.status="queued"; run.next_attempt_at=utcnow()+timedelta(seconds=min(300,15*(2**(run.attempts-1))))
   else: run.status="failed"
   db.add(AuditLog(actor_user_id=actor_id,action="integration.nuclei.scan.retry" if run.status=="queued" else "integration.nuclei.scan.failed",target=str(scan_id),detail=json.dumps({"attempts":run.attempts,"error_code":run.error_code})))
   db.commit()
  log.exception("Scan %s failed",scan_id)
def run():
 if not settings.nuclei_enabled or not settings.nuclei_worker_enabled: log.error("Nuclei worker disabled"); return
 client=redis.Redis.from_url(settings.redis_url,decode_responses=True,socket_connect_timeout=3,socket_timeout=5)
 token=secrets.token_urlsafe(32)
 if not client.set(LOCK,token,nx=True,ex=30): log.error("Another worker owns the lease"); client.close(); return
 try:
  with SessionLocal() as db: log.warning("Recovered %s interrupted scan(s)",recover(db))
  client.set(HEARTBEAT,utcnow().isoformat(),ex=20)
  while RUNNING:
   if not client.eval(RENEW,2,LOCK,HEARTBEAT,token,utcnow().isoformat()): log.error("Worker lease lost"); break
   with SessionLocal() as db: enqueue_due(db,client)
   item=client.brpop(QUEUE,timeout=2)
   if item:
    scan_id=int(item[1]); client.delete(f"opsaegis:nuclei:enqueue:{scan_id}"); process(scan_id)
 finally:
  client.eval(RELEASE,2,LOCK,HEARTBEAT,token); client.close()
def stop(_sig,_frame):
 global RUNNING
 RUNNING=False
if __name__=="__main__":
 signal.signal(signal.SIGTERM,stop); signal.signal(signal.SIGINT,stop)
 while RUNNING:
  try: run()
  except Exception: log.exception("Worker loop failed")
  if RUNNING: time.sleep(5)
