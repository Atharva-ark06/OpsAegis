from __future__ import annotations

import asyncio
import logging
import os
import secrets
import signal
import time
import threading
from datetime import datetime, timedelta, timezone

import redis
from sqlalchemy import select, update

from app.config import settings
from app.database import SessionLocal
from app.models.entities import AuditLog, IntegrationCollectionRun, IntegrationSchedule, utc_now
from app.routers.integrations import collect_wazuh_alerts, sync_wazuh_manager_agents

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("opsaegis.collection-worker")
QUEUE_KEY = "opsaegis:collection:queue"
LOCK_KEY = "opsaegis:collection:worker:lock"
HEARTBEAT_KEY = "opsaegis:collection:worker:heartbeat"
MAX_ATTEMPTS = 3
RUNNING = True

RENEW_LOCK = """
if redis.call('get', KEYS[1]) == ARGV[1] then
  redis.call('expire', KEYS[1], ARGV[2])
  redis.call('set', KEYS[2], ARGV[3], 'EX', ARGV[2])
  return 1
end
return 0
"""
RELEASE_LOCK = """
if redis.call('get', KEYS[1]) == ARGV[1] then
  redis.call('del', KEYS[2])
  return redis.call('del', KEYS[1])
end
return 0
"""


def as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def schedule_due(db, now: datetime) -> int:
    count = 0
    schedules = db.scalars(select(IntegrationSchedule).where(
        IntegrationSchedule.enabled.is_(True),
        IntegrationSchedule.next_run_at.is_not(None),
        IntegrationSchedule.next_run_at <= now,
    ).order_by(IntegrationSchedule.next_run_at.asc()).limit(20)).all()
    for schedule in schedules:
        due_at = as_utc(schedule.next_run_at)
        slot = schedule.source + ":" + due_at.isoformat()
        existing = db.scalar(select(IntegrationCollectionRun).where(
            IntegrationCollectionRun.schedule_slot == slot
        ))
        if existing is None:
            db.add(IntegrationCollectionRun(
                schedule_id=schedule.id, schedule_slot=slot, source=schedule.source,
                lookback_minutes=schedule.lookback_minutes, status="queued", attempts=0,
                next_attempt_at=now, created_at=now,
            ))
            count += 1
        schedule.last_run_at = now
        # Skip missed intervals instead of creating an unbounded catch-up backlog.
        schedule.next_run_at = now + timedelta(seconds=schedule.interval_seconds)
    if count or schedules:
        db.commit()
    return count


def enqueue_pending(db, client, now: datetime) -> int:
    pending = db.scalars(select(IntegrationCollectionRun).where(
        IntegrationCollectionRun.status.in_(("queued", "retrying")),
        IntegrationCollectionRun.next_attempt_at <= now,
    ).order_by(IntegrationCollectionRun.created_at.asc()).limit(25)).all()
    count = 0
    for run in pending:
        marker = f"opsaegis:collection:enqueue:{run.id}"
        if client.set(marker, "1", nx=True, ex=30):
            client.lpush(QUEUE_KEY, str(run.id))
            count += 1
    return count


def _collect(run: IntegrationCollectionRun, db) -> dict[str, object]:
    if run.source == "wazuh-manager-agents":
        return sync_wazuh_manager_agents(db, None)
    if run.source == "wazuh-indexer-alerts":
        since = utc_now() - timedelta(minutes=run.lookback_minutes)
        return asyncio.run(collect_wazuh_alerts(since, db, None))
    raise ValueError("UnsupportedCollectionSource")


def process_run(run_id: int, lease_lost: threading.Event, worker_token: str) -> None:
    if lease_lost.is_set():
        return
    db = SessionLocal()
    try:
        run = db.get(IntegrationCollectionRun, run_id)
        if run is None or run.status in {"succeeded", "failed"}:
            return
        run.status = "running"
        run.attempts += 1
        run.started_at = utc_now()
        run.finished_at = None
        run.error_code = None
        run.worker_token = worker_token
        db.commit()
        result = _collect(run, db)
        if lease_lost.is_set():
            db.rollback()
            return
        received = int(result.get("received", 0))
        created = int(result.get("created", result.get("inserted", 0)))
        updated_count = int(result.get("updated", 0))
        skipped = int(result.get("skipped", 0))
        truncated = bool(result.get("truncated_possible", False))
        completed = db.execute(
            update(IntegrationCollectionRun)
            .where(IntegrationCollectionRun.id == run_id,
                   IntegrationCollectionRun.status == "running",
                   IntegrationCollectionRun.worker_token == worker_token)
            .values(status="succeeded", finished_at=utc_now(), received=received,
                    created_count=created, updated_count=updated_count, skipped_count=skipped,
                    truncated_possible=truncated, error_code=None, worker_token=None)
        )
        if completed.rowcount != 1:
            db.rollback()
            logger.warning("Collection run %s ownership changed; completion discarded", run_id)
            return
        db.add(AuditLog(actor_user_id=None, action="collection.run.complete",
                        target=f"collection-run:{run_id}",
                        detail=f"source:{run.source};received:{received};created:{created};updated:{updated_count};truncated:{truncated}"))
        db.commit()
    except Exception as exc:
        db.rollback()
        if lease_lost.is_set():
            return
        run = db.get(IntegrationCollectionRun, run_id)
        if run is None:
            return
        now = utc_now()
        status = "retrying" if run.attempts < MAX_ATTEMPTS else "failed"
        next_attempt = now + timedelta(seconds=min(300, 15 * (2 ** max(0, run.attempts - 1))))
        failed = db.execute(
            update(IntegrationCollectionRun)
            .where(IntegrationCollectionRun.id == run_id,
                   IntegrationCollectionRun.status == "running",
                   IntegrationCollectionRun.worker_token == worker_token)
            .values(status=status, error_code=type(exc).__name__[:80],
                    finished_at=now if status == "failed" else None,
                    next_attempt_at=next_attempt, worker_token=None)
        )
        if failed.rowcount != 1:
            db.rollback()
            return
        db.add(AuditLog(actor_user_id=None,
                        action="collection.run.retry" if status == "retrying" else "collection.run.failed",
                        target=f"collection-run:{run_id}",
                        detail=f"attempt:{run.attempts};error_code:{type(exc).__name__[:80]}"))
        db.commit()
        logger.error("Collection run %s failed with %s", run_id, type(exc).__name__)
    finally:
        db.close()


def recover_interrupted_runs(db) -> int:
    interrupted = db.scalars(select(IntegrationCollectionRun).where(
        IntegrationCollectionRun.status == "running"
    )).all()
    now = utc_now()
    for run in interrupted:
        run.status = "failed" if run.attempts >= MAX_ATTEMPTS else "queued"
        run.finished_at = now if run.status == "failed" else None
        run.next_attempt_at = now
        run.error_code = "WorkerRestartMaxAttempts" if run.status == "failed" else "WorkerRestartRecovery"
        run.worker_token = None
    db.commit()
    return len(interrupted)


def heartbeat_loop(client, token: str, stop: threading.Event, lease_lost: threading.Event) -> None:
    while not stop.wait(10):
        try:
            if not client.eval(RENEW_LOCK, 2, LOCK_KEY, HEARTBEAT_KEY, token, 30, utc_now().isoformat()):
                lease_lost.set()
                return
        except Exception:
            lease_lost.set()
            return


def run_worker() -> None:
    client = redis.Redis.from_url(settings.redis_url, decode_responses=True,
                                  socket_connect_timeout=3, socket_timeout=5)
    token = secrets.token_urlsafe(32)
    if not client.set(LOCK_KEY, token, nx=True, ex=30):
        logger.error("Another collection worker owns the Redis lease; exiting")
        client.close()
        return
    stop_heartbeat = threading.Event()
    lease_lost = threading.Event()
    heartbeat = threading.Thread(target=heartbeat_loop,
        args=(client, token, stop_heartbeat, lease_lost), daemon=True)
    heartbeat.start()
    try:
        with SessionLocal() as db:
            recovered = recover_interrupted_runs(db)
        if recovered:
            logger.warning("Recovered %s interrupted collection run(s)", recovered)
        logger.info("Read-only collection worker started")
        while RUNNING and not lease_lost.is_set():
            if not client.eval(RENEW_LOCK, 2, LOCK_KEY, HEARTBEAT_KEY, token, 30, utc_now().isoformat()):
                logger.error("Collection worker lease lost; stopping")
                break
            with SessionLocal() as db:
                schedule_due(db, utc_now())
                enqueue_pending(db, client, utc_now())
            item = client.brpop(QUEUE_KEY, timeout=2)
            if item:
                run_id = int(item[1])
                client.delete(f"opsaegis:collection:enqueue:{run_id}")
                process_run(run_id, lease_lost, token)
    finally:
        stop_heartbeat.set()
        heartbeat.join(timeout=2)
        try:
            client.eval(RELEASE_LOCK, 2, LOCK_KEY, HEARTBEAT_KEY, token)
        finally:
            client.close()
        logger.info("Read-only collection worker stopped")


def _stop(_signum, _frame):
    global RUNNING
    RUNNING = False


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    while RUNNING:
        try:
            run_worker()
        except Exception as exc:
            logger.error("Collection worker loop failed with %s; retrying", type(exc).__name__)
            time.sleep(5)
        if RUNNING:
            time.sleep(5)
