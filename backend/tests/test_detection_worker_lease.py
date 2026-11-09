from datetime import datetime, timezone
import threading

from app import worker
from app.models.entities import AuditLog, ScheduledDetectionRun


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
    worker.process_run(123, lease_lost, "old-owner")


def test_process_run_leaves_record_running_if_lease_is_lost_during_evaluation(
    db_session, test_session_factory, monkeypatch
):
    run = make_run(db_session)
    lease_lost = threading.Event()
    monkeypatch.setattr(worker, "SessionLocal", test_session_factory)

    def lose_lease_during_evaluation(*args, **kwargs):
        lease_lost.set()
        return {"created": 0, "refreshed": 0, "incidents_created": 0}

    monkeypatch.setattr(worker, "evaluate_detections", lose_lease_during_evaluation)
    worker.process_run(run.id, lease_lost, "old-owner")

    db_session.refresh(run)
    assert run.status == "running"
    assert run.attempts == 1
    assert run.worker_token == "old-owner"
    assert run.finished_at is None
    assert db_session.query(AuditLog).filter_by(action="detection.schedule.complete").count() == 0


def test_old_worker_cannot_complete_after_new_owner_reclaims_run(
    db_session, test_session_factory, monkeypatch
):
    run = make_run(db_session)
    lease_lost = threading.Event()
    monkeypatch.setattr(worker, "SessionLocal", test_session_factory)

    def simulate_recovery_by_new_owner(window_minutes, auth_threshold, db, actor, evaluation_time):
        current = db.get(ScheduledDetectionRun, run.id)
        current.worker_token = "new-owner"
        db.commit()
        return {"created": 0, "refreshed": 0, "incidents_created": 0}

    monkeypatch.setattr(worker, "evaluate_detections", simulate_recovery_by_new_owner)
    worker.process_run(run.id, lease_lost, "old-owner")

    db_session.refresh(run)
    assert run.status == "running"
    assert run.worker_token == "new-owner"
    assert run.finished_at is None
    assert db_session.query(AuditLog).filter_by(action="detection.schedule.complete").count() == 0



def test_startup_recovery_clears_stale_worker_token(db_session):
    run = make_run(db_session)
    run.status = "running"
    run.worker_token = "previous-owner"
    db_session.commit()

    assert worker.recover_interrupted_runs(db_session) == 1

    db_session.refresh(run)
    assert run.status == "queued"
    assert run.worker_token is None
