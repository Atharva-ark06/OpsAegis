from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.entities import AuditLog, IntegrationCollectionRun, IntegrationSchedule, User, UserRole, utc_now
from app.security import get_current_user, require_roles

router = APIRouter(prefix="/collections", tags=["collection orchestration"])
OPERATORS = (UserRole.admin, UserRole.analyst)
SUPPORTED_SOURCES = {
    "wazuh-manager-agents": "Read registered Wazuh Manager agent inventory",
    "wazuh-indexer-alerts": "Read bounded Wazuh Indexer alert windows",
}


class ScheduleUpdate(BaseModel):
    enabled: bool
    interval_seconds: int = Field(ge=60, le=86400)
    lookback_minutes: int = Field(ge=1, le=43200)


def _schedule_payload(item: IntegrationSchedule | None, source: str) -> dict[str, object]:
    return {
        "source": source,
        "description": SUPPORTED_SOURCES[source],
        "enabled": bool(item.enabled) if item else False,
        "interval_seconds": item.interval_seconds if item else 300,
        "lookback_minutes": item.lookback_minutes if item else 15,
        "next_run_at": item.next_run_at.isoformat() if item and item.next_run_at else None,
        "last_run_at": item.last_run_at.isoformat() if item and item.last_run_at else None,
        "updated_at": item.updated_at.isoformat() if item else None,
    }


def _run_payload(run: IntegrationCollectionRun) -> dict[str, object]:
    return {
        "id": run.id, "source": run.source, "status": run.status, "attempts": run.attempts,
        "lookback_minutes": run.lookback_minutes, "received": run.received,
        "created": run.created_count, "updated": run.updated_count, "skipped": run.skipped_count,
        "truncated_possible": run.truncated_possible, "error_code": run.error_code,
        "next_attempt_at": run.next_attempt_at.isoformat(),
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "window_start_at": run.window_start_at.isoformat() if run.window_start_at else None,
        "window_end_at": run.window_end_at.isoformat() if run.window_end_at else None,
        "duration_ms": run.duration_ms,
        "created_at": run.created_at.isoformat(),
    }


@router.get("/schedules")
def list_schedules(db: Session = Depends(get_db), actor: User = Depends(get_current_user)):
    existing = {item.source: item for item in db.scalars(select(IntegrationSchedule)).all()}
    return [_schedule_payload(existing.get(source), source) for source in SUPPORTED_SOURCES]


@router.put("/schedules/{source}")
def update_schedule(source: str, payload: ScheduleUpdate, db: Session = Depends(get_db),
                    actor: User = Depends(require_roles(UserRole.admin))):
    if source not in SUPPORTED_SOURCES:
        raise HTTPException(404, "Collection source is not in the read-only allowlist")
    item = db.scalar(select(IntegrationSchedule).where(IntegrationSchedule.source == source))
    now = utc_now()
    if item is None:
        item = IntegrationSchedule(source=source, updated_at=now)
        db.add(item)
    item.enabled = payload.enabled
    item.interval_seconds = payload.interval_seconds
    item.lookback_minutes = payload.lookback_minutes
    item.updated_by_user_id = actor.id
    item.updated_at = now
    item.next_run_at = now + timedelta(seconds=payload.interval_seconds) if payload.enabled else None
    db.add(AuditLog(actor_user_id=actor.id, action="collection.schedule.update",
                    target=f"collection-schedule:{source}",
                    detail=f"enabled:{item.enabled};interval_seconds:{item.interval_seconds};lookback_minutes:{item.lookback_minutes}"))
    db.commit()
    db.refresh(item)
    return _schedule_payload(item, source)


@router.post("/{source}/run", status_code=202)
def request_collection(source: str, db: Session = Depends(get_db),
                       actor: User = Depends(require_roles(*OPERATORS))):
    if source not in SUPPORTED_SOURCES:
        raise HTTPException(404, "Collection source is not in the read-only allowlist")
    active_run = db.scalar(select(IntegrationCollectionRun).where(
        IntegrationCollectionRun.source == source,
        IntegrationCollectionRun.status.in_(("queued", "running", "retrying")),
    ).order_by(IntegrationCollectionRun.id.desc()))
    if active_run is not None:
        raise HTTPException(409, f"A collection run for this source is already pending or running (run {active_run.id})")
    schedule = db.scalar(select(IntegrationSchedule).where(IntegrationSchedule.source == source))
    if schedule is None:
        schedule = IntegrationSchedule(source=source, enabled=False, interval_seconds=300,
                                        lookback_minutes=15, updated_at=utc_now())
        db.add(schedule)
        db.flush()
    now = utc_now()
    run = IntegrationCollectionRun(
        schedule_id=schedule.id, schedule_slot="manual:" + uuid4().hex, source=source,
        lookback_minutes=schedule.lookback_minutes, status="queued", attempts=0,
        requested_by_user_id=actor.id, next_attempt_at=now, created_at=now,
    )
    db.add(run)
    db.flush()
    db.add(AuditLog(actor_user_id=actor.id, action="collection.run.request",
                    target=f"collection-run:{run.id}", detail=f"source:{source}"))
    db.commit()
    db.refresh(run)
    return _run_payload(run)


@router.get("/runs")
def list_collection_runs(source: str | None = None, limit: int = Query(default=50, ge=1, le=200),
                         db: Session = Depends(get_db), actor: User = Depends(get_current_user)):
    statement = select(IntegrationCollectionRun).order_by(IntegrationCollectionRun.id.desc()).limit(limit)
    if source is not None:
        if source not in SUPPORTED_SOURCES:
            raise HTTPException(404, "Collection source is not in the read-only allowlist")
        statement = statement.where(IntegrationCollectionRun.source == source)
    return [_run_payload(run) for run in db.scalars(statement).all()]
