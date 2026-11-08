from datetime import datetime, timedelta, timezone

from app.models.entities import (
    AuditLog, CorrelatedDetection, DetectionNotification, DetectionSchedule,
    DetectionStatus, FindingSeverity, ScheduledDetectionRun, User, UserRole,
)
from app.security import create_access_token, hash_password


def headers(db, role):
    user = User(email=f"pr12-{role.value}@example.test",
                password_hash=hash_password("Strong-Test-Password-2026!"),
                role=role, is_active=True)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user, {"Authorization": f"Bearer {create_access_token(user)}"}


def test_scheduler_is_admin_only_and_defaults_disabled(client, db_session):
    admin, admin_headers = headers(db_session, UserRole.admin)
    analyst, analyst_headers = headers(db_session, UserRole.analyst)
    viewer, viewer_headers = headers(db_session, UserRole.viewer)
    read = client.get("/api/v1/detections/scheduler", headers=viewer_headers)
    assert read.status_code == 200
    assert read.json()["enabled"] is False
    payload = {"enabled": True, "interval_seconds": 300, "window_minutes": 15, "auth_threshold": 3}
    assert client.put("/api/v1/detections/scheduler", json=payload, headers=analyst_headers).status_code == 403
    saved = client.put("/api/v1/detections/scheduler", json=payload, headers=admin_headers)
    assert saved.status_code == 200
    assert saved.json()["enabled"] is True
    assert saved.json()["interval_seconds"] == 300
    assert saved.json()["next_run_at"] is not None
    assert db_session.query(AuditLog).filter_by(action="detection.schedule.update").count() == 1


def test_scheduler_rejects_out_of_bounds_interval(client, db_session):
    _, admin_headers = headers(db_session, UserRole.admin)
    payload = {"enabled": True, "interval_seconds": 5, "window_minutes": 15, "auth_threshold": 3}
    assert client.put("/api/v1/detections/scheduler", json=payload, headers=admin_headers).status_code == 422


def test_detection_lifecycle_is_validated_and_audited(client, db_session):
    _, analyst_headers = headers(db_session, UserRole.analyst)
    item = CorrelatedDetection(
        rule_key="TEST-001", fingerprint="a" * 64, title="Test detection",
        description="Test only", severity=FindingSeverity.high,
        finding_ids=[], evidence={}, status="new",
    )
    db_session.add(item)
    db_session.commit()
    detection_id = item.id
    ack = client.patch(f"/api/v1/detections/{detection_id}/status",
                       json={"status": "acknowledged"}, headers=analyst_headers)
    assert ack.status_code == 200 and ack.json()["status"] == "acknowledged"
    investigating = client.patch(f"/api/v1/detections/{detection_id}/status",
                                 json={"status": "investigating"}, headers=analyst_headers)
    assert investigating.status_code == 200
    resolved = client.patch(f"/api/v1/detections/{detection_id}/status",
                            json={"status": "resolved"}, headers=analyst_headers)
    assert resolved.status_code == 200 and resolved.json()["resolved_at"] is not None
    invalid = client.patch(f"/api/v1/detections/{detection_id}/status",
                           json={"status": "new"}, headers=analyst_headers)
    assert invalid.status_code == 409
    assert db_session.query(AuditLog).filter_by(action="detection.status.update").count() == 3


def test_notifications_are_per_user_and_read_is_scoped(client, db_session):
    admin, admin_headers = headers(db_session, UserRole.admin)
    analyst, analyst_headers = headers(db_session, UserRole.analyst)
    _, viewer_headers = headers(db_session, UserRole.viewer)
    detection = CorrelatedDetection(
        rule_key="TEST-002", fingerprint="b" * 64, title="Critical test alert",
        description="Evidence-backed test", severity=FindingSeverity.critical,
        finding_ids=[10], evidence={}, status="new",
    )
    db_session.add(detection)
    db_session.commit()
    db_session.refresh(detection)
    db_session.add_all([
        DetectionNotification(user_id=admin.id, detection_id=detection.id,
                              severity=FindingSeverity.critical, title="Critical test alert", message="Test"),
        DetectionNotification(user_id=analyst.id, detection_id=detection.id,
                              severity=FindingSeverity.critical, title="Critical test alert", message="Test"),
    ])
    db_session.commit()
    admin_items = client.get("/api/v1/detections/notifications", headers=admin_headers).json()
    analyst_items = client.get("/api/v1/detections/notifications", headers=analyst_headers).json()
    assert len(admin_items) == len(analyst_items) == 1
    notification_id = admin_items[0]["id"]
    assert client.patch(f"/api/v1/detections/notifications/{notification_id}/read",
                        headers=analyst_headers).status_code == 404
    marked = client.patch(f"/api/v1/detections/notifications/{notification_id}/read",
                          headers=admin_headers)
    assert marked.status_code == 200 and marked.json()["read_at"] is not None
    assert client.get("/api/v1/detections/notifications", headers=viewer_headers).json() == []


def test_worker_scheduler_due_slot_and_retry_queue_helpers(test_session_factory):
    from app.worker import enqueue_pending, recover_interrupted_runs, schedule_due

    class FakeRedis:
        def __init__(self):
            self.markers = set()
            self.items = []
        def set(self, key, value, nx=False, ex=None):
            if nx and key in self.markers:
                return False
            self.markers.add(key)
            return True
        def lpush(self, key, value):
            self.items.insert(0, (key, value))

    factory = test_session_factory
    now = datetime.now(timezone.utc)
    client = FakeRedis()
    with factory() as db:
        config = DetectionSchedule(id=1, enabled=True, interval_seconds=300,
                                   window_minutes=15, auth_threshold=3,
                                   updated_at=now, next_run_at=now - timedelta(seconds=1))
        db.add(config)
        db.commit()
        assert schedule_due(db, client, now) == 1
        assert schedule_due(db, client, now) == 0
        run = db.query(ScheduledDetectionRun).one()
        assert run.status == "queued"
        assert enqueue_pending(db, client, now) == 1
        assert enqueue_pending(db, client, now) == 0
        assert client.items == [("opsaegis:detection:queue", str(run.id))]
        run.status = "running"
        db.commit()
        assert recover_interrupted_runs(db) == 1
        db.refresh(run)
        assert run.status == "queued"
        assert run.error_code == "WorkerRestartRecovery"
