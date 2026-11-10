from __future__ import annotations

import hashlib
import os
import re
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.entities import AuditLog, Incident, IncidentEvidenceAttachment, User, UserRole
from app.security import require_roles

router = APIRouter(prefix="/incidents", tags=["incident evidence"])
OPERATORS = (UserRole.admin, UserRole.analyst)
_CHUNK_SIZE = 64 * 1024
_SAFE_NAME = re.compile(r"[^\w.() -]", re.UNICODE)


def _storage_root() -> Path:
    root = Path(settings.evidence_storage_path).expanduser().resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    return root


def _safe_filename(value: str | None) -> str:
    name = Path(value or "evidence").name
    name = _SAFE_NAME.sub("_", name).strip(" .")
    return (name or "evidence")[:160]


def _detect_media_type(path: Path) -> str:
    with path.open("rb") as stream:
        prefix = stream.read(16)
    if prefix.startswith(b"%PDF-"):
        return "application/pdf"
    if prefix.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if prefix.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    data = path.read_bytes()
    if b"\x00" not in data:
        try:
            data.decode("utf-8")
            return "text/plain"
        except UnicodeDecodeError:
            pass
    raise HTTPException(415, "Unsupported evidence type; upload PDF, PNG, JPEG or UTF-8 text only")


def _attachment_path(root: Path, storage_key: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{32}", storage_key):
        raise HTTPException(404, "Evidence attachment not found")
    path = (root / f"{storage_key}.blob").resolve()
    if path.parent != root:
        raise HTTPException(404, "Evidence attachment not found")
    return path


def _read_attachment(db: Session, incident_id: int, attachment_id: int) -> IncidentEvidenceAttachment:
    item = db.scalar(select(IncidentEvidenceAttachment).where(
        IncidentEvidenceAttachment.id == attachment_id,
        IncidentEvidenceAttachment.incident_id == incident_id,
    ))
    expiry = item.expires_at if item is not None else None
    if expiry is not None and expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if item is None or expiry <= datetime.now(timezone.utc):
        raise HTTPException(404, "Evidence attachment not found")
    return item


@router.get("/{incident_id}/attachments")
def list_incident_attachments(incident_id: int, db: Session = Depends(get_db),
                              actor: User = Depends(require_roles(*OPERATORS))):
    if db.get(Incident, incident_id) is None:
        raise HTTPException(404, "Incident not found")
    now = datetime.now(timezone.utc)
    items = db.scalars(select(IncidentEvidenceAttachment).where(
        IncidentEvidenceAttachment.incident_id == incident_id,
        IncidentEvidenceAttachment.expires_at > now,
    ).order_by(IncidentEvidenceAttachment.created_at.desc()).limit(100)).all()
    return {"incident_id": incident_id, "items": [{
        "id": item.id, "filename": item.original_filename, "media_type": item.media_type,
        "size_bytes": item.size_bytes, "sha256": item.sha256,
        "uploaded_by_user_id": item.uploaded_by_user_id,
        "created_at": item.created_at.isoformat(), "expires_at": item.expires_at.isoformat(),
    } for item in items], "limit": 100}


@router.post("/{incident_id}/attachments", status_code=201)
async def upload_incident_attachment(incident_id: int, file: UploadFile = File(...),
                                     db: Session = Depends(get_db),
                                     actor: User = Depends(require_roles(*OPERATORS))):
    if db.get(Incident, incident_id) is None:
        raise HTTPException(404, "Incident not found")
    active_count = db.scalar(select(IncidentEvidenceAttachment.id).where(
        IncidentEvidenceAttachment.incident_id == incident_id,
        IncidentEvidenceAttachment.expires_at > datetime.now(timezone.utc),
    ).limit(100))
    if active_count is not None:
        total_active = len(db.scalars(select(IncidentEvidenceAttachment.id).where(
            IncidentEvidenceAttachment.incident_id == incident_id,
            IncidentEvidenceAttachment.expires_at > datetime.now(timezone.utc),
        ).limit(100)).all())
        if total_active >= 100:
            raise HTTPException(409, "Incident evidence attachment limit (100) reached")
    root = _storage_root()
    temp_path: Path | None = None
    final_path: Path | None = None
    total = 0
    digest = hashlib.sha256()
    try:
        with tempfile.NamedTemporaryFile(prefix=".upload-", suffix=".tmp", dir=root, delete=False) as temp:
            temp_path = Path(temp.name)
            while chunk := await file.read(_CHUNK_SIZE):
                total += len(chunk)
                if total > settings.evidence_max_attachment_bytes:
                    raise HTTPException(413, "Evidence attachment exceeds the configured size limit")
                digest.update(chunk)
                temp.write(chunk)
        if total == 0:
            raise HTTPException(422, "Evidence attachment cannot be empty")
        media_type = _detect_media_type(temp_path)
        storage_key = uuid.uuid4().hex
        final_path = _attachment_path(root, storage_key)
        os.replace(temp_path, final_path)
        temp_path = None
        now = datetime.now(timezone.utc)
        item = IncidentEvidenceAttachment(
            incident_id=incident_id, uploaded_by_user_id=actor.id,
            storage_key=storage_key, original_filename=_safe_filename(file.filename),
            media_type=media_type, size_bytes=total, sha256=digest.hexdigest(),
            created_at=now, expires_at=now + timedelta(days=settings.evidence_retention_days),
        )
        db.add(item)
        db.flush()
        db.add(AuditLog(actor_user_id=actor.id, action="incident.evidence.upload",
                        target=f"incident:{incident_id}", detail=f"attachment_id:{item.id};bytes:{total}"))
        db.commit()
        db.refresh(item)
        return {
            "id": item.id, "incident_id": incident_id, "filename": item.original_filename,
            "media_type": item.media_type, "size_bytes": item.size_bytes,
            "sha256": item.sha256, "created_at": item.created_at.isoformat(),
            "expires_at": item.expires_at.isoformat(),
        }
    except HTTPException:
        db.rollback()
        if final_path and final_path.exists():
            final_path.unlink(missing_ok=True)
        raise
    except Exception:
        db.rollback()
        if final_path and final_path.exists():
            final_path.unlink(missing_ok=True)
        raise HTTPException(500, "Evidence attachment could not be stored")
    finally:
        if temp_path and temp_path.exists():
            temp_path.unlink(missing_ok=True)
        await file.close()


@router.get("/{incident_id}/attachments/{attachment_id}")
def download_incident_attachment(incident_id: int, attachment_id: int,
                                 db: Session = Depends(get_db),
                                 actor: User = Depends(require_roles(*OPERATORS))):
    item = _read_attachment(db, incident_id, attachment_id)
    path = _attachment_path(_storage_root(), item.storage_key)
    if not path.is_file():
        raise HTTPException(404, "Evidence attachment file is unavailable")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != item.sha256:
        raise HTTPException(409, "Evidence integrity check failed; notify an administrator")
    db.add(AuditLog(actor_user_id=actor.id, action="incident.evidence.download",
                    target=f"incident:{incident_id}", detail=f"attachment_id:{item.id}"))
    db.commit()
    return FileResponse(
        path, media_type="application/octet-stream", filename=item.original_filename,
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                 "X-Content-SHA256": item.sha256},
    )
