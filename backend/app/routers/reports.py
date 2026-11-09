"""Privacy-minimized operational reporting from persisted OpsAegis records."""
from __future__ import annotations

import csv
import io
import re
from datetime import datetime, timedelta, timezone
from statistics import mean

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.entities import (
    AuditLog,
    CorrelatedDetection,
    Incident,
    IntegrationCollectionRun,
    IntegrationSchedule,
    User,
)
from app.routers.collections import SUPPORTED_SOURCES
from app.security import get_current_user

router = APIRouter(prefix="/reports", tags=["operational reporting"])
MAX_WINDOW_DAYS = 90
MAX_METRIC_ROWS = 10000
def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _window(since: datetime | None, until: datetime | None) -> tuple[datetime, datetime]:
    end = _utc(until) if until else datetime.now(timezone.utc)
    start = _utc(since) if since else end - timedelta(days=7)
    if end <= start:
        raise HTTPException(status_code=422, detail="until must be later than since")
    if end - start > timedelta(days=MAX_WINDOW_DAYS):
        raise HTTPException(status_code=422, detail="Report window cannot exceed 90 days")
    if end > datetime.now(timezone.utc) + timedelta(minutes=5):
        raise HTTPException(status_code=422, detail="until cannot be in the future")
    return start, end


def _average_seconds(values: list[float]) -> float | None:
    return round(mean(values), 2) if values else None


def build_operations_report(db: Session, start: datetime, end: datetime) -> dict:
    runs = db.scalars(
        select(IntegrationCollectionRun)
        .where(
            IntegrationCollectionRun.created_at >= start,
            IntegrationCollectionRun.created_at < end,
        )
        .order_by(IntegrationCollectionRun.created_at.desc())
        .limit(MAX_METRIC_ROWS)
    ).all()
    schedules = {
        item.source: item
        for item in db.scalars(select(IntegrationSchedule)).all()
    }

    sources = []
    for source, description in SUPPORTED_SOURCES.items():
        source_runs = [run for run in runs if run.source == source]
        successful = [run for run in source_runs if run.status == "succeeded"]
        failed = [run for run in source_runs if run.status == "failed"]
        terminal = len(successful) + len(failed)
        latest = db.scalar(
            select(IntegrationCollectionRun.finished_at)
            .where(
                IntegrationCollectionRun.source == source,
                IntegrationCollectionRun.status == "succeeded",
                IntegrationCollectionRun.finished_at.is_not(None),
                IntegrationCollectionRun.finished_at < end,
            )
            .order_by(IntegrationCollectionRun.finished_at.desc())
            .limit(1)
        )
        schedule = schedules.get(source)
        stale_after_seconds = max(900, (schedule.interval_seconds * 2) if schedule else 900)
        age_seconds = max(0, (end - _utc(latest)).total_seconds()) if latest else None
        freshness = (
            "never_succeeded" if latest is None
            else "stale" if age_seconds is not None and age_seconds > stale_after_seconds
            else "fresh"
        )
        sources.append({
            "source": source,
            "description": description,
            "enabled": bool(schedule.enabled) if schedule else False,
            "runs": len(source_runs),
            "successful_runs": len(successful),
            "failed_runs": len(failed),
            "failure_rate": round(len(failed) / terminal, 4) if terminal else None,
            "received": sum(run.received for run in source_runs),
            "created": sum(run.created_count for run in source_runs),
            "updated": sum(run.updated_count for run in source_runs),
            "skipped": sum(run.skipped_count for run in source_runs),
            "truncated_possible_runs": sum(1 for run in source_runs if run.truncated_possible),
            "latest_success_at": _utc(latest).isoformat() if latest else None,
            "freshness_age_seconds": round(age_seconds) if age_seconds is not None else None,
            "freshness": freshness,
        })

    detections = db.scalars(
        select(CorrelatedDetection)
        .where(
            CorrelatedDetection.created_at >= start,
            CorrelatedDetection.created_at < end,
            CorrelatedDetection.incident_id.is_not(None),
        )
        .order_by(CorrelatedDetection.created_at.asc())
        .limit(MAX_METRIC_ROWS)
    ).all()
    incident_ids = {item.incident_id for item in detections if item.incident_id is not None}
    incidents = {
        item.id: item
        for item in db.scalars(select(Incident).where(Incident.id.in_(incident_ids))).all()
    } if incident_ids else {}
    detection_delays = []
    for detection in detections:
        incident = incidents.get(detection.incident_id)
        if incident is not None:
            seconds = (_utc(incident.created_at) - _utc(detection.created_at)).total_seconds()
            if seconds >= 0:
                detection_delays.append(seconds)

    resolution_events = db.scalars(
        select(AuditLog)
        .where(
            AuditLog.action == "incident.update",
            AuditLog.created_at >= start,
            AuditLog.created_at < end,
            or_(AuditLog.detail.like("%->resolved%"), AuditLog.detail.like("%->closed%")),
        )
        .order_by(AuditLog.created_at.asc())
        .limit(MAX_METRIC_ROWS)
    ).all()
    # One first resolution transition per incident; audit details contain only
    # status transitions/resolution metadata, never the resolution text itself.
    first_resolution: dict[int, datetime] = {}
    for event in resolution_events:
        if not event.detail or not re.search(r"(?:^|;)status:[a-z_]+->(?:resolved|closed)(?:;|$)", event.detail):
            continue
        match = re.fullmatch(r"incident:(\d+)", event.target or "")
        if not match:
            continue
        incident_id = int(match.group(1))
        first_resolution.setdefault(incident_id, _utc(event.created_at))
    resolution_delays = []
    if first_resolution:
        resolved_incidents = db.scalars(
            select(Incident).where(Incident.id.in_(first_resolution.keys()))
        ).all()
        for incident in resolved_incidents:
            seconds = (first_resolution[incident.id] - _utc(incident.created_at)).total_seconds()
            if seconds >= 0:
                resolution_delays.append(seconds)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window": {"since": start.isoformat(), "until": end.isoformat(), "timezone": "UTC"},
        "collection": {
            "sources_configured": len(SUPPORTED_SOURCES),
            "sources_with_successful_runs": sum(1 for item in sources if item["successful_runs"]),
            "sources": sources,
            "rows_limited": len(runs) == MAX_METRIC_ROWS,
        },
        "response": {
            "detections_linked_to_incidents": len(detection_delays),
            "mean_detection_to_incident_seconds": _average_seconds(detection_delays),
            "incidents_resolved": len(resolution_delays),
            "mean_incident_to_resolution_seconds": _average_seconds(resolution_delays),
            "resolution_metric_source": "first audited transition to resolved",
            "rows_limited": len(detections) == MAX_METRIC_ROWS or len(resolution_events) == MAX_METRIC_ROWS,
        },
        "data_quality": {
            "stale_sources": [item["source"] for item in sources if item["freshness"] == "stale"],
            "never_succeeded_sources": [item["source"] for item in sources if item["freshness"] == "never_succeeded"],
            "truncated_collection_runs": sum(item["truncated_possible_runs"] for item in sources),
            "limitations": [
                "Metrics describe persisted application records, not proof of complete upstream telemetry.",
                "Collection freshness is based on the last successful run; disabled schedules may still have stale data.",
                "Resolution timing uses the first audited transition to resolved; historical transitions without audit records are not counted.",
                "Rows are bounded to 10,000 per metric query; rows_limited indicates a possible cap.",
            ],
        },
    }


@router.get("/operations")
def operations_report(
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
) -> dict:
    start, end = _window(since, until)
    return build_operations_report(db, start, end)


@router.get("/operations/export")
def export_operations_report(
    format: str = Query(default="json", pattern="^(json|csv)$"),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
):
    start, end = _window(since, until)
    report = build_operations_report(db, start, end)
    if format == "json":
        return report

    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["metric", "source", "value", "unit"])
    for source in report["collection"]["sources"]:
        for key in (
            "runs", "successful_runs", "failed_runs", "failure_rate", "received",
            "created", "updated", "skipped", "truncated_possible_runs",
            "latest_success_at", "freshness_age_seconds", "freshness",
        ):
            unit = "ratio" if key == "failure_rate" else "seconds" if key == "freshness_age_seconds" else ""
            writer.writerow([key, source["source"], source[key], unit])
    for key, value in report["response"].items():
        if key.endswith("_seconds"):
            unit = "seconds"
        else:
            unit = "count" if isinstance(value, int) else ""
        if not isinstance(value, str):
            writer.writerow([key, "all", value, unit])
    filename = f"opsaegis-operations-{start:%Y%m%dT%H%M%SZ}-{end:%Y%m%dT%H%M%SZ}.csv"
    return Response(
        content=output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
