"""Bounded operational trend buckets and administrator-managed alert thresholds."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.entities import (
    AuditLog, CorrelatedDetection, Incident, IntegrationCollectionRun,
    OperationalThreshold, User, UserRole, utc_now,
)
from app.routers.reports import MAX_METRIC_ROWS, _window
from app.security import get_current_user, require_roles

router = APIRouter(prefix="/reports/operations", tags=["operational reporting"])
DEFAULTS = {
    "collection_failure_rate_percent": 20,
    "source_stale_after_minutes": 30,
    "detection_to_incident_minutes": 15,
    "incident_resolution_minutes": 240,
}


def _threshold_row(db: Session) -> OperationalThreshold:
    row = db.get(OperationalThreshold, 1)
    if row is None:
        row = OperationalThreshold(id=1, **DEFAULTS, updated_at=utc_now())
        db.add(row)
        db.flush()
    return row


def _threshold_payload(row: OperationalThreshold, db: Session | None = None) -> dict:
    payload = {key: getattr(row, key) for key in DEFAULTS} | {
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }
    if db is not None:
        from app.routers.reports import build_operations_report
        end = utc_now()
        report = build_operations_report(db, end - timedelta(days=7), end)
        alerts = []
        for source in report["collection"]["sources"]:
            if source["failure_rate"] is not None and source["failure_rate"] * 100 > row.collection_failure_rate_percent:
                alerts.append({"code": "collection_failure_rate", "source": source["source"],
                               "message": f'{source["source"]} terminal failure rate exceeds {row.collection_failure_rate_percent}%.'})
            age = source["freshness_age_seconds"]
            if age is not None and age > row.source_stale_after_minutes * 60:
                alerts.append({"code": "source_stale", "source": source["source"],
                               "message": f'{source["source"]} has not succeeded within {row.source_stale_after_minutes} minutes.'})
        detection_delay = report["response"]["mean_detection_to_incident_seconds"]
        if detection_delay is not None and detection_delay > row.detection_to_incident_minutes * 60:
            alerts.append({"code": "detection_to_incident_sla", "source": None,
                           "message": f'Mean detection-to-incident time exceeds {row.detection_to_incident_minutes} minutes.'})
        resolution_delay = report["response"]["mean_incident_to_resolution_seconds"]
        if resolution_delay is not None and resolution_delay > row.incident_resolution_minutes * 60:
            alerts.append({"code": "incident_resolution_sla", "source": None,
                           "message": f'Mean incident resolution time exceeds {row.incident_resolution_minutes} minutes.'})
        payload["active_alerts"] = alerts
        payload["evaluation_window"] = report["window"]
    return payload


class ThresholdUpdate(BaseModel):
    collection_failure_rate_percent: int = Field(ge=1, le=100)
    source_stale_after_minutes: int = Field(ge=5, le=10080)
    detection_to_incident_minutes: int = Field(ge=1, le=1440)
    incident_resolution_minutes: int = Field(ge=1, le=10080)


@router.get("/thresholds")
def get_operational_thresholds(
    db: Session = Depends(get_db), actor: User = Depends(get_current_user)
) -> dict:
    row = _threshold_row(db)
    db.commit()
    return _threshold_payload(row, db)


@router.put("/thresholds")
def update_operational_thresholds(
    payload: ThresholdUpdate,
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(UserRole.admin)),
) -> dict:
    row = _threshold_row(db)
    for key, value in payload.model_dump().items():
        setattr(row, key, value)
    row.updated_by_user_id = actor.id
    row.updated_at = utc_now()
    db.add(row)
    db.add(AuditLog(
        actor_user_id=actor.id,
        action="operations.thresholds.update",
        target="operational-thresholds:1",
        detail=";" .join(f"{key}:{value}" for key, value in payload.model_dump().items()),
    ))
    db.commit()
    db.refresh(row)
    return _threshold_payload(row, db)


@router.get("/trends")
def get_operational_trends(
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    bucket: Literal["day", "week"] = Query(default="day"),
    db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
) -> dict:
    start, end = _window(since, until)
    runs = db.scalars(
        select(IntegrationCollectionRun)
        .where(IntegrationCollectionRun.created_at >= start, IntegrationCollectionRun.created_at < end)
        .order_by(IntegrationCollectionRun.created_at.asc())
        .limit(MAX_METRIC_ROWS)
    ).all()
    detections = db.scalars(
        select(CorrelatedDetection)
        .where(CorrelatedDetection.created_at >= start, CorrelatedDetection.created_at < end)
        .order_by(CorrelatedDetection.created_at.asc())
        .limit(MAX_METRIC_ROWS)
    ).all()
    incidents = db.scalars(
        select(Incident)
        .where(Incident.created_at >= start, Incident.created_at < end)
        .order_by(Incident.created_at.asc())
        .limit(MAX_METRIC_ROWS)
    ).all()
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

    def floor(value: datetime) -> datetime:
        value = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
        if bucket == "week":
            day = value.date()
            return datetime.combine(day - timedelta(days=day.weekday()), datetime.min.time(), timezone.utc)
        return datetime(value.year, value.month, value.day, tzinfo=timezone.utc)

    step = timedelta(days=7 if bucket == "week" else 1)
    cursor = floor(start)
    points = []
    while cursor < end:
        next_cursor = cursor + step
        points.append({
            "start": cursor.isoformat(),
            "collection_runs": 0,
            "collection_succeeded": 0,
            "collection_failed": 0,
            "detections": 0,
            "incidents": 0,
            "resolved_incidents": 0,
        })
        cursor = next_cursor
    by_start = {datetime.fromisoformat(item["start"]): item for item in points}

    def add(key: str, value: datetime | None, amount: int = 1) -> None:
        if value is None:
            return
        slot = floor(value)
        if slot in by_start:
            by_start[slot][key] += amount

    for run in runs:
        add("collection_runs", run.created_at)
        if run.status == "succeeded":
            add("collection_succeeded", run.created_at)
        elif run.status == "failed":
            add("collection_failed", run.created_at)
    for detection in detections:
        add("detections", detection.created_at)
    for incident in incidents:
        add("incidents", incident.created_at)
    resolved_ids = set()
    for event in resolution_events:
        import re
        match = re.fullmatch(r"incident:(\d+)", event.target or "")
        if not match or not event.detail:
            continue
        if "->resolved" not in event.detail and "->closed" not in event.detail:
            continue
        incident_id = int(match.group(1))
        if incident_id not in resolved_ids:
            resolved_ids.add(incident_id)
            add("resolved_incidents", event.created_at)

    return {
        "window": {"since": start.isoformat(), "until": end.isoformat(), "timezone": "UTC"},
        "bucket": bucket,
        "points": points,
        "rows_limited": len(runs) == MAX_METRIC_ROWS or len(detections) == MAX_METRIC_ROWS
        or len(incidents) == MAX_METRIC_ROWS or len(resolution_events) == MAX_METRIC_ROWS,
        "limitations": [
            "Buckets count persisted application records by their creation or audited transition time.",
            "Collection run counts do not measure complete upstream telemetry.",
            "Only the first resolved/closed transition per incident in this window is counted.",
        ],
    }

@router.get("/activity")
def get_overview_activity(
    days: int = Query(default=365, ge=30, le=365),
    limit: int = Query(default=16, ge=1, le=50),
    db: Session = Depends(get_db),
    actor: User = Depends(get_current_user),
) -> dict:
    """Return privacy-minimized, persisted audit activity for the Overview dashboard."""
    end = utc_now()
    start = end - timedelta(days=days)
    rows = db.scalars(
        select(AuditLog)
        .where(AuditLog.created_at >= start, AuditLog.created_at < end)
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(10000)
    ).all()

    sections = (
        "assets", "findings", "vulnerabilities", "detections", "incidents",
        "integrations", "threat-intel", "playbooks", "users", "reports", "settings",
    )

    def section_for(action: str) -> str | None:
        if action == "demo.dataset.seed":
            return None
        prefix = action.split(".", 1)[0].lower()
        if prefix == "threat_intel":
            return "threat-intel"
        if prefix in {"asset", "finding", "vulnerability", "detection", "incident", "playbook"}:
            return {"asset": "assets", "finding": "findings", "vulnerability": "vulnerabilities",
                    "detection": "detections", "incident": "incidents", "playbook": "playbooks"}[prefix]
        if prefix in {"collection", "integration"}:
            return "integrations"
        if prefix in {"user", "auth"}:
            return "users"
        if prefix == "operations":
            return "settings"
        if prefix == "report":
            return "reports"
        if prefix == "settings":
            return "settings"
        return None

    def floor_day(value: datetime) -> datetime:
        value = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
        return datetime(value.year, value.month, value.day, tzinfo=timezone.utc)

    daily = {}
    cursor = floor_day(start)
    while cursor < end:
        daily[cursor] = {"date": cursor.date().isoformat(), "total": 0, "by_section": {key: 0 for key in sections}}
        cursor += timedelta(days=1)
    monthly = {}
    month_cursor = datetime(end.year, end.month, 1, tzinfo=timezone.utc)
    for offset in range(11, -1, -1):
        month_index = month_cursor.month - offset
        year = month_cursor.year + (month_index - 1) // 12
        month = (month_index - 1) % 12 + 1
        key = f"{year:04d}-{month:02d}"
        monthly[key] = {"month": key, "label": datetime(year, month, 1).strftime("%b"), "total": 0}

    section_counts = {key: 0 for key in sections}
    recent = []
    for row in rows:
        section = section_for(row.action)
        if section is None:
            continue
        timestamp = row.created_at.replace(tzinfo=timezone.utc) if row.created_at.tzinfo is None else row.created_at.astimezone(timezone.utc)
        section_counts[section] += 1
        bucket = daily.get(floor_day(timestamp))
        if bucket is not None:
            bucket["total"] += 1
            bucket["by_section"][section] += 1
        month_key = timestamp.strftime("%Y-%m")
        if month_key in monthly:
            monthly[month_key]["total"] += 1
        if len(recent) < limit:
            action_labels = {
                "threat_intel.enrich": "Threat intelligence lookup completed",
                "threat_intel.enrich.cached": "Threat intelligence cached lookup",
                "finding.status.update": "Finding status updated",
                "incident.create": "Incident created",
                "incident.update": "Incident updated",
                "asset.create": "Asset registered",
                "vulnerability.nvd.enrich": "Vulnerability intelligence enriched",
                "vulnerability.nvd.cached": "Vulnerability cache returned",
                "collection.run.request": "Collection run requested",
                "collection.run.complete": "Collection run completed",
                "playbook.dry_run": "Playbook dry run completed",
                "playbook.approval_requested": "Playbook approval requested",
            }
            summary = action_labels.get(row.action, row.action.replace(".", " ").replace("_", " ").capitalize())
            target_match = __import__("re").search(r"^(asset|finding|vulnerability|incident|ioc|playbook_approval):(\d+)$", row.target or "")
            recent.append({
                "id": row.id,
                "section": section,
                "action": row.action,
                "summary": summary,
                "record": (target_match.group(1).replace("_", " ").title() + " #" + target_match.group(2)) if target_match else None,
                "actor": "System" if row.actor_user_id is None else "Operator",
                "occurred_at": timestamp.isoformat(),
            })

    daily_points = list(daily.values())
    return {
        "window": {"since": start.isoformat(), "until": end.isoformat(), "timezone": "UTC"},
        "days": days,
        "total_events": sum(section_counts.values()),
        "section_counts": section_counts,
        "daily": daily_points,
        "monthly": list(monthly.values()),
        "recent": recent,
        "rows_limited": len(rows) == 10000,
        "limitations": [
            "Activity counts are based on persisted audit records, not page views or unrecorded read-only actions.",
            "The event feed intentionally omits raw IP addresses, URLs, audit details, and operator email addresses.",
            "Sections with no audit events in this window are shown as zero; this does not mean their data stores are empty.",
            "Audit history is bounded to 10,000 records per request.",
        ],
    }

