from __future__ import annotations
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.config import settings
from app.database import get_db
from app.integrations.shannon import ShannonRunnerAdapter, ShannonRunnerError
from app.models.entities import AuditLog, Finding, FindingSeverity, ShannonScanRun, ShannonTarget, User, UserRole
from app.security import require_roles

router = APIRouter(prefix="/integrations/shannon", tags=["shannon"])
OPERATORS = (UserRole.admin, UserRole.analyst)
_JOB_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

class TargetCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    target_url: str = Field(min_length=9, max_length=2048)
    source_repository: str = Field(min_length=25, max_length=500)
    authorization_reference: str = Field(min_length=12, max_length=500)

    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, value: str) -> str:
        parsed = urlsplit(value.strip())
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme != "https" or not host or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Target must be HTTPS without credentials, query or fragment")
        if parsed.port not in (None, 443):
            raise ValueError("Only standard HTTPS port is accepted")
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal")) or host == "metadata.google.internal":
            raise ValueError("Local, internal and metadata targets are not accepted")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError("Register a DNS hostname rather than an IP address")
        return urlunsplit(("https", parsed.netloc, parsed.path.rstrip("/") or "/", "", ""))

    @field_validator("source_repository")
    @classmethod
    def validate_repository(cls, value: str) -> str:
        parsed = urlsplit(value.strip())
        parts = [part for part in parsed.path.strip("/").split("/") if part]
        if parsed.scheme != "https" or parsed.hostname != "github.com" or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Source repository must be an HTTPS GitHub repository URL")
        if len(parts) != 2 or any(part in (".", "..") for part in parts):
            raise ValueError("Use https://github.com/owner/repository")
        return f"https://github.com/{parts[0]}/{parts[1].removesuffix('.git')}"

def target_out(target: ShannonTarget) -> dict:
    return {"id": target.id, "name": target.name, "target_url": target.target_url,
            "source_repository": target.source_repository,
            "authorization_reference": target.authorization_reference,
            "enabled": target.enabled, "created_at": target.created_at.isoformat()}

def scan_out(scan: ShannonScanRun) -> dict:
    return {"id": scan.id, "target_id": scan.target_id, "runner_job_id": scan.runner_job_id,
            "status": scan.status, "findings_count": scan.findings_count,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            "error_code": scan.error_code, "created_at": scan.created_at.isoformat()}

@router.get("/health")
async def health(actor: User = Depends(require_roles(*OPERATORS))) -> dict:
    adapter = ShannonRunnerAdapter()
    if not adapter.is_configured:
        return {"integration": "shannon", "configured": False, "status": "not_configured",
                "execution_enabled": False, "mode": "external_isolated_runner"}
    try:
        result = await adapter.healthcheck()
    except ShannonRunnerError:
        return {"integration": "shannon", "configured": True, "status": "unhealthy",
                "execution_enabled": False, "mode": "external_isolated_runner"}
    healthy = result.get("status") == "healthy" and result.get("engine") == "shannon"
    return {"integration": "shannon", "configured": True,
            "status": "healthy" if healthy else "unhealthy", "execution_enabled": healthy,
            "mode": "external_isolated_runner"}

@router.post("/targets", status_code=201)
def register_target(data: TargetCreate, db: Session = Depends(get_db),
                    actor: User = Depends(require_roles(UserRole.admin))) -> dict:
    target = ShannonTarget(**data.model_dump(), created_by=actor.id)
    db.add(target)
    db.add(AuditLog(actor_user_id=actor.id, action="integration.shannon.target.register",
                    target=target.target_url, detail=json.dumps({
                        "source_repository": target.source_repository,
                        "authorization_reference": target.authorization_reference})))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Target URL and source repository combination already registered") from None
    db.refresh(target)
    return target_out(target)

@router.get("/targets")
def list_targets(db: Session = Depends(get_db), actor: User = Depends(require_roles(*OPERATORS))) -> list[dict]:
    return [target_out(item) for item in db.scalars(select(ShannonTarget).order_by(ShannonTarget.id.desc())).all()]

@router.get("/scans")
def list_scans(skip: int = 0, limit: int = 50, db: Session = Depends(get_db),
               actor: User = Depends(require_roles(*OPERATORS))) -> list[dict]:
    if skip < 0 or not 1 <= limit <= 100:
        raise HTTPException(422, "skip must be >= 0 and limit 1..100")
    return [scan_out(item) for item in db.scalars(
        select(ShannonScanRun).order_by(ShannonScanRun.id.desc()).offset(skip).limit(limit)).all()]

@router.post("/targets/{target_id}/scans", status_code=202)
async def start_scan(target_id: int, db: Session = Depends(get_db),
                     actor: User = Depends(require_roles(UserRole.admin))) -> dict:
    target = db.get(ShannonTarget, target_id)
    if target is None or not target.enabled:
        raise HTTPException(404, "Enabled authorized target not found")
    adapter = ShannonRunnerAdapter()
    if not adapter.is_configured:
        raise HTTPException(503, "Shannon isolated runner is not configured")
    scan = ShannonScanRun(target_id=target.id, requested_by=actor.id, status="dispatching")
    db.add(scan)
    db.add(AuditLog(actor_user_id=actor.id, action="integration.shannon.scan.request",
                    target=target.target_url, detail=json.dumps({
                        "source_repository": target.source_repository,
                        "authorization_reference": target.authorization_reference})))
    db.commit()
    db.refresh(scan)
    try:
        response = await adapter.submit(scan_id=scan.id, target_url=target.target_url,
                                        source_repository=target.source_repository,
                                        authorization_reference=target.authorization_reference)
        job_id = response.get("job_id")
        if not isinstance(job_id, str) or not _JOB_ID.fullmatch(job_id):
            raise ShannonRunnerError("runner_invalid_job_id")
        if response.get("status") not in ("queued", "running"):
            raise ShannonRunnerError("runner_invalid_initial_status")
        scan.runner_job_id = job_id
        scan.status = response["status"]
        scan.started_at = datetime.now(timezone.utc)
        db.add(AuditLog(actor_user_id=actor.id, action="integration.shannon.scan.dispatched",
                        target=str(scan.id), detail=json.dumps({"runner_job_id": job_id})))
        db.commit()
    except ShannonRunnerError as exc:
        scan.status = "failed"
        scan.error_code = str(exc)[:80]
        scan.finished_at = datetime.now(timezone.utc)
        db.add(AuditLog(actor_user_id=actor.id, action="integration.shannon.scan.dispatch_failed",
                        target=str(scan.id), detail=json.dumps({"error_code": scan.error_code})))
        db.commit()
        raise HTTPException(502, "Shannon runner dispatch failed; check runner health and server logs") from None
    return {"scan": scan_out(scan)}

@router.post("/scans/{scan_id}/sync")
async def sync_scan(scan_id: int, db: Session = Depends(get_db),
                    actor: User = Depends(require_roles(*OPERATORS))) -> dict:
    scan = db.get(ShannonScanRun, scan_id)
    if scan is None:
        raise HTTPException(404, "Shannon scan not found")
    if scan.status in ("completed", "failed", "cancelled"):
        return {"scan": scan_out(scan), "received": 0, "inserted": 0, "updated": 0}
    if not scan.runner_job_id:
        raise HTTPException(409, "Scan has no dispatched runner job")
    try:
        result = await ShannonRunnerAdapter().get_scan(scan.runner_job_id)
    except ShannonRunnerError:
        raise HTTPException(502, "Unable to retrieve Shannon runner status") from None
    status = result.get("status")
    if status not in ("queued", "running", "completed", "failed", "cancelled"):
        raise HTTPException(502, "Shannon runner returned an invalid scan status")
    inserted = updated = received = 0
    if status == "completed":
        if "findings" not in result:
            raise HTTPException(502, "Completed Shannon result is missing its findings array")
        records = result["findings"]
        if not isinstance(records, list) or len(records) > settings.shannon_max_findings:
            raise HTTPException(502, "Shannon runner returned an invalid findings collection")
        target = db.get(ShannonTarget, scan.target_id)
        if target is None:
            raise HTTPException(409, "Registered Shannon target no longer exists")
        received = len(records)
        inserted, updated = persist_validated_findings(db, records, target.target_url)
    scan.status = status
    if status in ("completed", "failed", "cancelled"):
        scan.finished_at = datetime.now(timezone.utc)
    if status == "failed":
        scan.error_code = str(result.get("error_code") or "runner_failed")[:80]
    if status == "completed":
        scan.findings_count = inserted + updated
    db.add(AuditLog(actor_user_id=actor.id, action="integration.shannon.scan.sync",
                    target=str(scan.id), detail=json.dumps({
                        "status": status, "received": received, "inserted": inserted, "updated": updated})))
    db.commit()
    return {"scan": scan_out(scan), "received": received, "inserted": inserted, "updated": updated}

def persist_validated_findings(db: Session, records: list[dict], expected_target_url: str) -> tuple[int, int]:
    levels = {"informational": FindingSeverity.informational, "info": FindingSeverity.informational,
              "low": FindingSeverity.low, "medium": FindingSeverity.medium,
              "high": FindingSeverity.high, "critical": FindingSeverity.critical}
    inserted = updated = 0
    now = datetime.now(timezone.utc)
    for record in records:
        if not isinstance(record, dict):
            raise HTTPException(502, "Shannon runner finding must be an object")
        if record.get("validation_status") != "exploited" or not isinstance(record.get("proof"), str) or not record["proof"].strip():
            raise HTTPException(502, "Runner finding lacks exploitation proof; refusing ingestion")
        fingerprint, title, affected_url = record.get("fingerprint"), record.get("title"), record.get("affected_url")
        if not all(isinstance(value, str) and value.strip() for value in (fingerprint, title, affected_url)):
            raise HTTPException(502, "Runner finding is missing required identity fields")
        if len(fingerprint) > 255 or len(title) > 500 or len(affected_url) > 1024:
            raise HTTPException(502, "Runner finding exceeds field limits")
        expected = urlsplit(expected_target_url)
        affected = urlsplit(affected_url)
        if (affected.scheme != "https" or affected.hostname != expected.hostname or
                affected.port not in (None, 443) or affected.username or affected.password or
                affected.query or affected.fragment):
            raise HTTPException(502, "Runner finding URL is outside the registered target scope")
        native_id = hashlib.sha256(fingerprint.encode()).hexdigest()
        evidence = {"validation_status": "exploited", "affected_url": affected_url,
                    "proof": record["proof"][:4000], "runner_fingerprint": fingerprint[:255],
                    "references": record.get("references", [])[:10] if isinstance(record.get("references"), list) else []}
        description = record.get("description")
        description = description[:4000] if isinstance(description, str) else None
        severity = levels.get(str(record.get("severity", "")).lower(), FindingSeverity.unknown)
        existing = db.scalar(select(Finding).where(
            Finding.source_engine == "shannon", Finding.source_native_id == native_id))
        if existing is None:
            db.add(Finding(source_engine="shannon", source_native_id=native_id, title=title,
                           description=description, severity=severity, first_seen_at=now,
                           last_seen_at=now, evidence=evidence))
            inserted += 1
        else:
            existing.title, existing.description = title, description
            existing.severity, existing.last_seen_at, existing.evidence = severity, now, evidence
            # Preserve analyst triage state and first_seen_at.
            updated += 1
    db.flush()
    return inserted, updated
