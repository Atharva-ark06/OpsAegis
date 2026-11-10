"""Prune expired incident evidence; dry-run unless --apply is supplied."""

from __future__ import annotations

import argparse
import re
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

from app.config import settings
from app.database import SessionLocal
from app.models.entities import AuditLog, IncidentEvidenceAttachment


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Delete expired files and metadata (default is dry-run)")
    parser.add_argument("--limit", type=int, default=500, help="Maximum records to process (1..5000)")
    args = parser.parse_args()
    if not 1 <= args.limit <= 5000:
        parser.error("--limit must be between 1 and 5000")

    root = Path(settings.evidence_storage_path).expanduser().resolve()
    now_query = select(IncidentEvidenceAttachment).where(
        IncidentEvidenceAttachment.expires_at <= datetime.now(timezone.utc)
    ).order_by(IncidentEvidenceAttachment.expires_at.asc()).limit(args.limit)

    session = SessionLocal()
    try:
        items = session.scalars(now_query).all()
        print(f"Expired evidence records found: {len(items)}")
        if not args.apply:
            print("Dry-run only. Re-run with --apply to permanently delete expired evidence.")
            return 0

        removed = 0
        skipped = 0
        for item in items:
            if not re.fullmatch(r"[0-9a-f]{32}", item.storage_key):
                skipped += 1
                continue
            path = (root / f"{item.storage_key}.blob").resolve()
            if path.parent != root:
                skipped += 1
                continue
            try:
                path.unlink(missing_ok=True)
            except OSError:
                skipped += 1
                continue
            session.delete(item)
            removed += 1
        session.add(AuditLog(
            actor_user_id=None,
            action="incident.evidence.retention_purge",
            target="evidence-retention",
            detail=f"records_removed:{removed};records_skipped:{skipped}",
        ))
        session.commit()
        print(f"Expired records removed: {removed}; skipped: {skipped}")
        return 0 if skipped == 0 else 1
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())
