from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.collection_worker import enqueue_pending, heartbeat_loop, process_run, recover_interrupted_runs, schedule_due
from app.models.entities import IntegrationCollectionRun, IntegrationSchedule


def test_due_schedule_creates_one_bounded_run_and_advances(db_session):
    now = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)
    schedule = IntegrationSchedule(
        source="wazuh-indexer-alerts", enabled=True, interval_seconds=300,
        lookback_minutes=15, next_run_at=now - timedelta(seconds=5), updated_at=now,
    )
    db_session.add(schedule)
    db_session.commit()

    assert schedule_due(db_session, now) == 1
    runs = db_session.scalars(select(IntegrationCollectionRun)).all()
    assert len(runs) == 1
    assert runs[0].source == "wazuh-indexer-alerts"
    assert runs[0].lookback_minutes == 15
    assert runs[0].status == "queued"
    next_run_at = schedule.next_run_at
    if next_run_at.tzinfo is None:
        next_run_at = next_run_at.replace(tzinfo=timezone.utc)
    assert next_run_at == now + timedelta(seconds=300)

    # A second scheduler tick cannot create another run for the same due slot.
    assert schedule_due(db_session, now) == 0
    assert db_session.query(IntegrationCollectionRun).count() == 1


def test_disabled_schedule_does_not_enqueue(db_session):
    now = datetime.now(timezone.utc)
    db_session.add(IntegrationSchedule(
        source="wazuh-manager-agents", enabled=False, interval_seconds=60,
        lookback_minutes=10, next_run_at=now - timedelta(minutes=1), updated_at=now,
    ))
    db_session.commit()
    assert schedule_due(db_session, now) == 0
    assert db_session.query(IntegrationCollectionRun).count() == 0


def test_interrupted_collection_run_recovers_with_bounded_retry(db_session):
    now = datetime.now(timezone.utc)
    schedule = IntegrationSchedule(source="wazuh-manager-agents", enabled=False,
        interval_seconds=60, lookback_minutes=10, updated_at=now)
    db_session.add(schedule)
    db_session.flush()
    run = IntegrationCollectionRun(
        schedule_id=schedule.id, schedule_slot="recovery:test", source=schedule.source,
        lookback_minutes=10, status="running", attempts=1, next_attempt_at=now,
        started_at=now, worker_token="stale-worker", created_at=now,
    )
    db_session.add(run)
    db_session.commit()

    assert recover_interrupted_runs(db_session) == 1
    db_session.refresh(run)
    assert run.status == "queued"
    assert run.error_code == "WorkerRestartRecovery"
    assert run.worker_token is None


def test_collection_schedule_api_enforces_allowlist_and_role(client, analyst_headers):
    response = client.get("/api/v1/collections/schedules", headers=analyst_headers)
    assert response.status_code == 200
    assert {item["source"] for item in response.json()} == {
        "wazuh-manager-agents", "wazuh-indexer-alerts"
    }
    denied = client.put("/api/v1/collections/schedules/wazuh-indexer-alerts",
        headers=analyst_headers,
        json={"enabled": True, "interval_seconds": 60, "lookback_minutes": 5})
    assert denied.status_code == 403
    unsupported = client.post("/api/v1/collections/arbitrary-url/run", headers=analyst_headers)
    assert unsupported.status_code == 404


def test_analyst_can_queue_manual_collection(client, analyst_headers):
    response = client.post("/api/v1/collections/wazuh-indexer-alerts/run", headers=analyst_headers)
    assert response.status_code == 202
    payload = response.json()
    assert payload["status"] == "queued"
    assert payload["source"] == "wazuh-indexer-alerts"
    assert payload["lookback_minutes"] == 15


def test_duplicate_manual_collection_is_rejected(client, analyst_headers):
    first = client.post("/api/v1/collections/wazuh-manager-agents/run", headers=analyst_headers)
    second = client.post("/api/v1/collections/wazuh-manager-agents/run", headers=analyst_headers)
    assert first.status_code == 202
    assert second.status_code == 409


def test_manual_collection_obeys_source_minimum_interval(client, analyst_headers, test_session_factory):
    first = client.post("/api/v1/collections/wazuh-indexer-alerts/run", headers=analyst_headers)
    assert first.status_code == 202
    with test_session_factory() as db:
        run = db.get(IntegrationCollectionRun, first.json()["id"])
        run.status = "succeeded"
        schedule = db.get(IntegrationSchedule, run.schedule_id)
        schedule.last_run_at = datetime.now(timezone.utc)
        db.commit()
    too_soon = client.post("/api/v1/collections/wazuh-indexer-alerts/run", headers=analyst_headers)
    assert too_soon.status_code == 429


def test_schedule_due_respects_minimum_interval_after_manual_run(db_session):
    now = datetime.now(timezone.utc)
    schedule = IntegrationSchedule(
        source="wazuh-manager-agents", enabled=True, interval_seconds=300,
        lookback_minutes=10, last_run_at=now - timedelta(seconds=30),
        next_run_at=now - timedelta(seconds=5), updated_at=now,
    )
    db_session.add(schedule)
    db_session.commit()
    assert schedule_due(db_session, now) == 0
    assert db_session.query(IntegrationCollectionRun).count() == 0
    db_session.refresh(schedule)
    assert schedule.next_run_at == schedule.last_run_at + timedelta(seconds=300)


def test_pending_run_queue_marker_prevents_duplicate_delivery(db_session):
    now = datetime.now(timezone.utc)
    schedule = IntegrationSchedule(source="wazuh-manager-agents", enabled=False,
        interval_seconds=300, lookback_minutes=10, updated_at=now)
    db_session.add(schedule)
    db_session.flush()
    db_session.add(IntegrationCollectionRun(
        schedule_id=schedule.id, schedule_slot="queue:dedupe", source=schedule.source,
        lookback_minutes=10, status="queued", attempts=0, next_attempt_at=now, created_at=now,
    ))
    db_session.commit()

    class FakeRedis:
        markers = set()
        queue = []
        def set(self, key, value, nx=False, ex=None):
            if nx and key in self.markers:
                return False
            self.markers.add(key)
            return True
        def lpush(self, key, value):
            self.queue.insert(0, value)

    client = FakeRedis()
    assert enqueue_pending(db_session, client, now) == 1
    assert enqueue_pending(db_session, client, now) == 0
    assert len(client.queue) == 1


def test_heartbeat_lease_loss_stops_worker_loop():
    class StopAfterOneWait:
        waits = 0
        def wait(self, _seconds):
            self.waits += 1
            return self.waits > 1

    class LostLeaseRedis:
        def eval(self, *_args):
            return 0

    lost = __import__("threading").Event()
    heartbeat_loop(LostLeaseRedis(), "worker-token", StopAfterOneWait(), lost)
    assert lost.is_set()


def test_redis_interruption_marks_worker_lease_lost():
    class StopAfterOneWait:
        waits = 0
        def wait(self, _seconds):
            self.waits += 1
            return self.waits > 1

    class BrokenRedis:
        def eval(self, *_args):
            raise ConnectionError("simulated redis outage")

    lost = __import__("threading").Event()
    heartbeat_loop(BrokenRedis(), "worker-token", StopAfterOneWait(), lost)
    assert lost.is_set()


def test_worker_does_not_start_run_after_lease_is_lost(db_session, monkeypatch):
    import threading
    now = datetime.now(timezone.utc)
    schedule = IntegrationSchedule(source="wazuh-manager-agents", enabled=False,
        interval_seconds=300, lookback_minutes=10, updated_at=now)
    db_session.add(schedule)
    db_session.flush()
    run = IntegrationCollectionRun(
        schedule_id=schedule.id, schedule_slot="lease:lost", source=schedule.source,
        lookback_minutes=10, status="queued", attempts=0, next_attempt_at=now, created_at=now,
    )
    db_session.add(run)
    db_session.commit()
    monkeypatch.setattr("app.collection_worker.SessionLocal", lambda: test_session_factory())
    lost = threading.Event()
    lost.set()
    process_run(run.id, lost, "stale-worker")
    db_session.refresh(run)
    assert run.status == "queued"
    assert run.attempts == 0


def test_worker_records_success_counts_exact_window_and_duration(db_session, test_session_factory, monkeypatch):
    import threading
    now = datetime.now(timezone.utc)
    schedule = IntegrationSchedule(source="wazuh-indexer-alerts", enabled=False,
        interval_seconds=300, lookback_minutes=15, updated_at=now)
    db_session.add(schedule)
    db_session.flush()
    run = IntegrationCollectionRun(
        schedule_id=schedule.id, schedule_slot="success:window", source=schedule.source,
        lookback_minutes=15, status="queued", attempts=0, next_attempt_at=now, created_at=now,
    )
    db_session.add(run)
    db_session.commit()

    async def fake_collect(current_run, _db):
        assert current_run.window_start_at is not None
        assert current_run.window_end_at is not None
        assert current_run.window_end_at - current_run.window_start_at == timedelta(minutes=15)
        return {"received": 12, "inserted": 4, "updated": 3, "truncated_possible": True}

    monkeypatch.setattr("app.collection_worker.SessionLocal", lambda: test_session_factory())
    monkeypatch.setattr("app.collection_worker._collect", fake_collect)
    process_run(run.id, threading.Event(), "valid-worker-token")
    db_session.refresh(run)
    assert run.status == "succeeded"
    assert run.attempts == 1
    assert run.received == 12
    assert run.created_count == 4
    assert run.updated_count == 3
    assert run.truncated_possible is True
    assert run.duration_ms is not None
    assert run.worker_token is None


def test_worker_uses_bounded_retry_and_sanitized_error_code(db_session, test_session_factory, monkeypatch):
    import threading
    now = datetime.now(timezone.utc)
    schedule = IntegrationSchedule(source="wazuh-manager-agents", enabled=False,
        interval_seconds=300, lookback_minutes=10, updated_at=now)
    db_session.add(schedule)
    db_session.flush()
    run = IntegrationCollectionRun(
        schedule_id=schedule.id, schedule_slot="retry:one", source=schedule.source,
        lookback_minutes=10, status="queued", attempts=0, next_attempt_at=now, created_at=now,
    )
    db_session.add(run)
    db_session.commit()

    async def fail_collection(_run, _db):
        raise RuntimeError("sensitive upstream response must not be persisted")

    monkeypatch.setattr("app.collection_worker.SessionLocal", lambda: test_session_factory())
    monkeypatch.setattr("app.collection_worker._collect", fail_collection)
    process_run(run.id, threading.Event(), "valid-worker-token")
    db_session.refresh(run)
    assert run.status == "retrying"
    assert run.attempts == 1
    assert run.error_code == "RuntimeError"
    assert run.finished_at is None
    next_attempt_at = run.next_attempt_at
    if next_attempt_at.tzinfo is None:
        next_attempt_at = next_attempt_at.replace(tzinfo=timezone.utc)
    assert next_attempt_at > now
    assert run.worker_token is None
