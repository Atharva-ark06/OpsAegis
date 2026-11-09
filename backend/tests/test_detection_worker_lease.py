from datetime import datetime, timezone
import threading

from app.models.entities import AuditLog, ScheduledDetectionRun
from app import worker


def make_run(db):
    run = ScheduledDetectionRun(
        schedule_slot="2026-11-09T12:00:00+00:00",
        status="queued",
        attempts=0,
        window_minutes=15,
        auth_threshold=3,
        next_attempt_at=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc),
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def test_process_run_does_not_start_after_lease_is_already_lost(monkeypatch):
    lease_lost = threading.Event()
    lease_lost.set()

    def unexpected_session():
        raise AssertionError("A stale worker must not open a run session")

    monkeypatch.setattr(worker, "SessionLocal", unexpected_session)
    worker.process_run(123, lease_lost)

 
def test_process_run_leaves_running_record_for_recovery_if_lease_lost_during_evaluation(
    db_session, test_session_factory, monkeypatch
):
    run = make_run(db_session)
    lease_lost = threading.Event()
    monkeypatch.setattr(worker, "SessionLocal", test_session_factory)

    def lose_lease_during_evaluation(*args, **kwargs):
        lease_lost.set()
        return {"created": 0, "refreshed": 0, "incidents_created": 0}

    monkeypatch.setattr(worker, "evaluate_detections", lose_lease_during_evaluation)
    worker.process_run(run.id, lease_lost)

    db_session.refresh(run)
    assert run.status == "running"
    assert run.attempts == 1
    assert run.finished_at is None
    assert db_session.query(AuditLog).filter_by(action="detection.schedule.complete").count() == 0
