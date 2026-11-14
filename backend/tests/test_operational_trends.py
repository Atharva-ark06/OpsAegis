from datetime import datetime, timedelta, timezone

from app.models.entities import AuditLog, FindingSeverity, Incident, IntegrationCollectionRun, IntegrationSchedule, User, UserRole
from app.security import create_access_token, hash_password


def _admin_headers(db_session):
    admin = User(email="admin-trends@example.com", password_hash=hash_password("Test-Admin-Password-2026!"),
                 role=UserRole.admin, is_active=True)
    db_session.add(admin)
    db_session.commit()
    db_session.refresh(admin)
    return {"Authorization": f"Bearer {create_access_token(admin)}"}


def test_trends_return_daily_buckets_with_persisted_counts(client, analyst_headers, db_session):
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    schedule = IntegrationSchedule(source="wazuh-manager-agents", enabled=True, interval_seconds=300,
                                   lookback_minutes=15, updated_at=now)
    db_session.add(schedule)
    db_session.flush()
    db_session.add_all([
        IntegrationCollectionRun(schedule_id=schedule.id, schedule_slot="trend:success",
            source=schedule.source, lookback_minutes=15, status="succeeded", attempts=1,
            next_attempt_at=now, created_at=now - timedelta(days=1)),
        IntegrationCollectionRun(schedule_id=schedule.id, schedule_slot="trend:failed",
            source=schedule.source, lookback_minutes=15, status="failed", attempts=3,
            next_attempt_at=now, created_at=now - timedelta(days=1)),
    ])
    db_session.add(Incident(title="private", severity=FindingSeverity.high, status="open",
                            created_at=now - timedelta(days=1), updated_at=now))
    db_session.commit()
    response = client.get("/api/v1/reports/operations/trends",
        params={"since": (now - timedelta(days=3)).isoformat(), "until": now.isoformat()},
        headers=analyst_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["bucket"] == "day"
    assert len(body["points"]) == 4
    yesterday = next(point for point in body["points"] if point["collection_runs"] == 2)
    assert yesterday["collection_succeeded"] == 1
    assert yesterday["collection_failed"] == 1
    assert yesterday["incidents"] == 1


def test_weekly_trends_and_authentication(client, analyst_headers):
    response = client.get("/api/v1/reports/operations/trends", params={"bucket": "week"}, headers=analyst_headers)
    assert response.status_code == 200
    assert response.json()["bucket"] == "week"
    assert client.get("/api/v1/reports/operations/trends").status_code in (401, 403)


def test_thresholds_are_readable_but_analyst_cannot_change_them(client, analyst_headers):
    initial = client.get("/api/v1/reports/operations/thresholds", headers=analyst_headers)
    assert initial.status_code == 200
    assert initial.json()["collection_failure_rate_percent"] == 20
    assert "active_alerts" in initial.json()
    denied = client.put("/api/v1/reports/operations/thresholds",
        json={"collection_failure_rate_percent":25,"source_stale_after_minutes":45,
              "detection_to_incident_minutes":20,"incident_resolution_minutes":300},
        headers=analyst_headers)
    assert denied.status_code in (403, 401)


def test_thresholds_reject_out_of_range_values(client, db_session):
    headers = _admin_headers(db_session)
    response = client.put("/api/v1/reports/operations/thresholds",
        json={"collection_failure_rate_percent":0,"source_stale_after_minutes":45,
              "detection_to_incident_minutes":20,"incident_resolution_minutes":300},
        headers=headers)
    assert response.status_code == 422


def test_admin_can_update_thresholds_and_audit_change(client, db_session):
    headers = _admin_headers(db_session)
    response = client.put("/api/v1/reports/operations/thresholds",
        json={"collection_failure_rate_percent":25,"source_stale_after_minutes":45,
              "detection_to_incident_minutes":20,"incident_resolution_minutes":300},
        headers=headers)
    assert response.status_code == 200
    assert response.json()["collection_failure_rate_percent"] == 25
    assert "active_alerts" in response.json()
    assert db_session.query(AuditLog).filter_by(action="operations.thresholds.update").count() == 1

def test_overview_activity_aggregates_persisted_events_without_exposing_indicator_values(client, analyst_headers, db_session):
    now = datetime.now(timezone.utc)
    db_session.add_all([
        AuditLog(actor_user_id=None, action="threat_intel.enrich", target="ioc:41",
                 detail='{"indicator_type":"ip","indicator_value":"203.0.113.9"}', created_at=now),
        AuditLog(actor_user_id=None, action="threat_intel.enrich.cached", target="ioc:41",
                 detail='{"indicator_type":"ip","indicator_value":"203.0.113.9"}', created_at=now - timedelta(minutes=2)),
        AuditLog(actor_user_id=None, action="asset.create", target="asset:8",
                 detail="type:server", created_at=now - timedelta(minutes=4)),
        AuditLog(actor_user_id=None, action="demo.dataset.seed", target="demo:fixture",
                 detail="synthetic_only:true", created_at=now - timedelta(minutes=1)),
    ])
    db_session.commit()

    response = client.get("/api/v1/reports/operations/activity?days=30&limit=10", headers=analyst_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["section_counts"]["threat-intel"] == 2
    assert body["section_counts"]["assets"] == 1
    assert body["total_events"] == 3
    assert len(body["daily"]) >= 30
    assert body["daily"][-1]["total"] >= 3
    assert body["recent"][0]["summary"] == "Threat intelligence lookup completed"
    assert "203.0.113.9" not in response.text
    assert "indicator_value" not in response.text


def test_overview_activity_requires_authentication(client):
    response = client.get("/api/v1/reports/operations/activity")
    assert response.status_code in (401, 403)

