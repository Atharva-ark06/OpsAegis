from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.collection_worker import recover_interrupted_runs, schedule_due
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
