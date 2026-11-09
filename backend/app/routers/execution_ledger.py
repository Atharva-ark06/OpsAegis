"""Read-only, privacy-minimized visibility into the playbook execution ledger.

This router cannot create, claim, mutate, retry, or dispatch an execution.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.entities import PlaybookExecution, User, UserRole
from app.playbook_execution import recovery_guidance
from app.security import require_roles

router = APIRouter(prefix="/playbooks/executions", tags=["playbook execution ledger"])
OPERATORS = (UserRole.admin, UserRole.analyst)
EXECUTION_STATES = {"pending", "claimed", "executing", "succeeded", "failed", "outcome_unknown"}


def _public_execution(item: PlaybookExecution) -> dict:
    """Expose operational status and safe next-step guidance only."""
    return {
        "id": item.id,
        "approval_id": item.approval_id,
        "action_id": item.action_id,
        "action_version": item.action_version,
        "status": item.status,
        "compensation_status": item.compensation_status,
        "recovery_guidance": recovery_guidance(item.status, item.compensation_status),
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "updated_at": item.updated_at.isoformat() if item.updated_at else None,
        "started_at": item.started_at.isoformat() if item.started_at else None,
        "completed_at": item.completed_at.isoformat() if item.completed_at else None,
    }


@router.get("")
def list_execution_ledger(
    status_filter: str | None = Query(default=None, alias="status"),
    approval_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=10000),
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(*OPERATORS)),
) -> dict:
    """Return bounded, read-only execution status records to authorized operators."""
    if status_filter is not None and status_filter not in EXECUTION_STATES:
        raise HTTPException(status_code=422, detail="Invalid execution status")

    statement = select(PlaybookExecution)
    if status_filter is not None:
        statement = statement.where(PlaybookExecution.status == status_filter)
    if approval_id is not None:
        statement = statement.where(PlaybookExecution.approval_id == approval_id)
    statement = statement.order_by(
        PlaybookExecution.created_at.desc(),
        PlaybookExecution.id.desc(),
    ).offset(offset).limit(limit + 1)

    rows = db.scalars(statement).all()
    has_more = len(rows) > limit
    items = rows[:limit]
    return {
        "items": [_public_execution(item) for item in items],
        "count": len(items),
        "limit": limit,
        "offset": offset,
        "has_more": has_more,
        "execution_enabled": False,
    }
