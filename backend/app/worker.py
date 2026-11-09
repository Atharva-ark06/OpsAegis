from __future__ import annotations

import json
import logging
import os
import secrets
import signal
import time
import threading
from datetime import datetime, timedelta, timezone

import redis
from sqlalchemy import select

from app.config import settings
from app.database import SessionLocal
from app.models.entities import AuditLog, DetectionSchedule, ScheduledDetectionRun
from app.routers.detections import evaluate_detections

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("opsaegis.detection-worker")
QUEUE_KEY = "opsaegis:detection:queue"
LOCK_KEY = "opsaegis:detection:worker:lock"
HEARTBEAT_KEY = "opsaegis:detection:worker:heartbeat"
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


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def schedule_due(db, client, now: datetime) -> int:
    config = db.get(DetectionSchedule, 1)
    if config is None:
        config = DetectionSchedule(id=1, enabled=False, interval_seconds=300,
                                   window_minutes=15, auth_threshold=3, updated_at=now)
        db.add(config)
        db.commit()
        return 0
    if not config.enabled or config.next_run_at is None:
        return 0
    due_at = as_utc(config.next_run_at)
    if due_at > now:
        return 0
    slot = due_at.isoformat()
    run = db.scalar(select(ScheduledDetectionRun).where(ScheduledDetectionRun.schedule_slot == slot))
    if run is None:
        run = ScheduledDetectionRun(schedule_slot=slot, status="queued", attempts=0,
                                    window_minutes=config.window_minutes, auth_threshold=config.auth_threshold,
                                    next_attempt_at=now, created_at=now)
        db.add(run)
    config.last_scheduled_at = now
    config.next_run_at = now + timedelta(seconds=config.interval_seconds)
    db.add(AuditLog(actor_user_id=config.updated_by_user_id, action="detection.schedule.enqueue",
                    target="detection-scheduler",
                    detail=json.dumps({"schedule_slot": slot, "interval_seconds": config.interval_seconds})))
    db.commit()
    return 1


def enqueue_pending(db, client, now: datetime) -> int:
    pending = db.scalars(select(ScheduledDetectionRun).where(
        ScheduledDetectionRun.status.in_(("queued", "retrying")),
        ScheduledDetectionRun.next_attempt_at <= now,
    ).order_by(ScheduledDetectionRun.created_at.asc()).limit(25)).all()
    count = 0
    for run in pending:
        marker = f"opsaegis:detection:enqueue:{run.id}"
        if client.set(marker, "1", nx=True, ex=30):
            client.lpush(QUEUE_KEY, str(run.id))
            count += 1
    return count


class WorkerLeaseLost(RuntimeError):
    """Raised when a worker must leave a run for the next lease owner."""


def process_run(run_id: int, lease_lost: threading.Event | None = None) -> None:
    if lease_lost is not None and lease_lost.is_set():
        return
    db = SessionLocal()
    try:
        run = db.get(ScheduledDetectionRun, run_id)
        if run is None or run.status in {"succeeded", "failed"}:
            return
        now = utc_now()
        run.status = "running"
        run.attempts += 1
        run.started_at = now
        run.error_code = None
        if lease_lost is not None and lease_lost.is_set():
            raise WorkerLeaseLost("Worker lease lost before evaluation")
        db.commit()
        result = evaluate_detections(run.window_minutes, run.auth_threshold, db, None, as_utc(run.created_at))
        if lease_lost is not None and lease_lost.is_set():
            # Evaluation writes are idempotent; leave the durable run as running
            # so the next lease owner can recover and repeat it safely.
            raise WorkerLeaseLost("Worker lease lost during evaluation")
        run = db.get(ScheduledDetectionRun, run_id)
        if run is None:
            return
        if lease_lost is not None and lease_lost.is_set():
            raise WorkerLeaseLost("Worker lease lost before completion")
        run.status = "succeeded"
        run.finished_at = utc_now()
        run.error_code = None
        db.add(AuditLog(actor_user_id=None, action="detection.schedule.complete",
                        target=f"scheduled-run:{run.id}",
                        detail=json.dumps({"attempts": run.attempts, "created": result["created"],
                                           "refreshed": result["refreshed"]})))
        if lease_lost is not None and lease_lost.is_set():
            raise WorkerLeaseLost("Worker lease lost immediately before completion commit")
        db.commit()
    except WorkerLeaseLost as exc:
        db.rollback()
        logger.warning("Scheduled detection run %s left for recovery after lease loss: %s", run_id, exc)
        return
    except Exception as exc:
        db.rollback()
        run = db.get(ScheduledDetectionRun, run_id)
        if run is not None:
            now = utc_now()
            run.status = "retrying" if run.attempts < MAX_ATTEMPTS else "failed"
            run.error_code = type(exc).__name__[:80]
            run.finished_at = now if run.status == "failed" else None
            run.next_attempt_at = now + timedelta(seconds=min(300, 15 * (2 ** max(0, run.attempts - 1))))
            db.add(AuditLog(actor_user_id=None, action="detection.schedule.retry" if run.status == "retrying" else "detection.schedule.failed",
                            target=f"scheduled-run:{run.id}",
                            detail=json.dumps({"attempt": run.attempts, "error_code": run.error_code})))
            db.commit()
        logger.exception("Scheduled detection run %s failed", run_id)
    finally:
        db.close()


def recover_interrupted_runs(db) -> int:
    interrupted = db.scalars(select(ScheduledDetectionRun).where(
        ScheduledDetectionRun.status == "running"
    )).all()
    now = utc_now()
    for run in interrupted:
        if run.attempts >= MAX_ATTEMPTS:
            run.status = "failed"
            run.finished_at = now
            run.error_code = "WorkerRestartMaxAttempts"
        else:
            run.status = "queued"
            run.next_attempt_at = now
            run.error_code = "WorkerRestartRecovery"
    db.commit()
    return len(interrupted)


def heartbeat_loop(client, token: str, stop: threading.Event, lease_lost: threading.Event) -> None:
    while not stop.wait(10):
        try:
            renewed = client.eval(RENEW_LOCK, 2, LOCK_KEY, HEARTBEAT_KEY, token, 30, utc_now().isoformat())
            if not renewed:
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
        logger.error("Another detection worker owns the Redis lease; exiting")
        client.close()
        return

    stop_heartbeat = threading.Event()
    lease_lost = threading.Event()
    heartbeat = threading.Thread(
        target=heartbeat_loop, args=(client, token, stop_heartbeat, lease_lost), daemon=True
    )
    heartbeat.start()
    try:
        with SessionLocal() as db:
            recovered = recover_interrupted_runs(db)
        if recovered:
            logger.warning("Recovered %s interrupted detection run(s)", recovered)
        logger.info("Detection worker started")
        while RUNNING and not lease_lost.is_set():
            renewed = client.eval(RENEW_LOCK, 2, LOCK_KEY, HEARTBEAT_KEY, token, 30, utc_now().isoformat())
            if not renewed:
                logger.error("Worker lease lost; stopping to avoid duplicate consumers")
                break
            with SessionLocal() as db:
                schedule_due(db, client, utc_now())
                enqueue_pending(db, client, utc_now())
            item = client.brpop(QUEUE_KEY, timeout=2)
            if item:
                run_id = int(item[1])
                client.delete(f"opsaegis:detection:enqueue:{run_id}")
                process_run(run_id, lease_lost)
    finally:
        stop_heartbeat.set()
        heartbeat.join(timeout=2)
        try:
            client.eval(RELEASE_LOCK, 2, LOCK_KEY, HEARTBEAT_KEY, token)
        finally:
            client.close()
        logger.info("Detection worker stopped")


def _stop(_signum, _frame):
    global RUNNING
    RUNNING = False


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    while RUNNING:
        try:
            run_worker()
        except Exception:
            logger.exception("Detection worker loop failed; retrying in 5 seconds")
            time.sleep(5)
        if RUNNING:
            time.sleep(5)
