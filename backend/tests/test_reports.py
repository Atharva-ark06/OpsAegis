from datetime import datetime, timedelta, timezone

from app.models.entities import (
    AuditLog,
    CorrelatedDetection,
    FindingSeverity,
    Incident,
    IntegrationCollectionRun,
    IntegrationSchedule,
)


def _seed_report_data(db_session):
    end = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)
    start = end - timedelta(days=7)
    manager = IntegrationSchedule(
        source="wazuh-manager-agents",
        enabled=True,
        interval_seconds=300,
        lookback_minutes=15,
        updated_at=end,
    )
    indexer = IntegrationSchedule(
        source="wazuh-indexer-alerts",
        enabled=False,
        interval_seconds=600,
        lookback_minutes=15,
        updated_at=end,
    )
    db_session.add_all([manager, indexer])
    db_session.flush()
    db_session.add_all([
        IntegrationCollectionRun(
            schedule_id=manager.id,
            schedule_slot="report:manager:success",
            source=manager.source,
            lookback_minutes=15,
            status="succeeded",
            attempts=1,
            next_attempt_at=end - timedelta(minutes=5),
            started_at=end - timedelta(minutes=6),
            finished_at=end - timedelta(minutes=5),
            duration_ms=1000,
            received=12,
            created_count=4,
            updated_count=6,
            skipped_count=2,
            created_at=end - timedelta(minutes=6),
        ),
        IntegrationCollectionRun(
            schedule_id=indexer.id,
            schedule_slot="report:indexer:failed",
            source=indexer.source,
            lookback_minutes=15,
            status="failed",
            attempts=3,
            next_attempt_at=end - timedelta(minutes=4),
            started_at=end - timedelta(minutes=10),
            finished_at=end - timedelta(minutes=4),
            duration_ms=6000,
            error_code="ProviderUnavailable",
            created_at=end - timedelta(minutes=10),
        ),
    ])
    incident = Incident(
        title="Sensitive incident title must not appear in aggregate report",
        severity=FindingSeverity.high,
        status="resolved",
        created_at=end - timedelta(hours=2),
        updated_at=end - timedelta(hours=1, minutes=30),
    )
    db_session.add(incident)
    db_session.flush()
    detection = CorrelatedDetection(
        rule_key="AUTH-BRUTE-001",
        fingerprint="a" * 64,
        title="Private detection title",
        description="Private detection description",
        severity=FindingSeverity.high,
        finding_ids=[1, 2, 3],
        evidence={"private": "do not export"},
        incident_id=incident.id,
        status="new",
        created_at=end - timedelta(hours=2, minutes=5),
        last_seen_at=end - timedelta(hours=2, minutes=5),
    )
    db_session.add(detection)
    db_session.add(AuditLog(
        actor_user_id=None,
        action="incident.update",
        target=f"incident:{incident.id}",
        detail="status:investigating->resolved;resolution:updated",
        created_at=end - timedelta(hours=1, minutes=30),
    ))
    db_session.commit()
    return start, end


def test_operations_report_aggregates_collection_and_response_metrics(client, analyst_headers, db_session):
    start, end = _seed_report_data(db_session)
    response = client.get(
        "/api/v1/reports/operations",
        params={"since": start.isoformat(), "until": end.isoformat()},
        headers=analyst_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["window"]["timezone"] == "UTC"
    collection = {item["source"]: item for item in body["collection"]["sources"]}
    assert collection["wazuh-manager-agents"]["successful_runs"] == 1
    assert collection["wazuh-manager-agents"]["received"] == 12
    assert collection["wazuh-manager-agents"]["freshness"] == "fresh"
    assert collection["wazuh-indexer-alerts"]["failed_runs"] == 1
    assert collection["wazuh-indexer-alerts"]["failure_rate"] == 1.0
    assert body["collection"]["sources_with_successful_runs"] == 1
    assert body["response"]["detections_linked_to_incidents"] == 1
    assert body["response"]["mean_detection_to_incident_seconds"] == 300.0
    assert body["response"]["incidents_resolved"] == 1
    assert body["response"]["mean_incident_to_resolution_seconds"] == 1800.0
    serialized = response.text
    assert "Sensitive incident title" not in serialized
    assert "Private detection description" not in serialized
    assert "do not export" not in serialized


def test_operations_report_requires_authentication(client):
    response = client.get("/api/v1/reports/operations")
    assert response.status_code in (401, 403)


def test_operations_report_rejects_invalid_and_overlong_windows(client, analyst_headers):
    end = datetime.now(timezone.utc)
    reversed_window = client.get(
        "/api/v1/reports/operations",
        params={"since": end.isoformat(), "until": (end - timedelta(hours=1)).isoformat()},
        headers=analyst_headers,
    )
    assert reversed_window.status_code == 422
    overlong = client.get(
        "/api/v1/reports/operations",
        params={"since": (end - timedelta(days=91)).isoformat(), "until": end.isoformat()},
        headers=analyst_headers,
    )
    assert overlong.status_code == 422


def test_operations_report_csv_export_is_aggregate_only(client, analyst_headers, db_session):
    start, end = _seed_report_data(db_session)
    response = client.get(
        "/api/v1/reports/operations/export",
        params={"format": "csv", "since": start.isoformat(), "until": end.isoformat()},
        headers=analyst_headers,
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "wazuh-manager-agents" in response.text
    assert "failure_rate" in response.text
    assert "Sensitive incident title" not in response.text
    assert "Private detection title" not in response.text


def test_operations_report_json_export_and_format_validation(client, analyst_headers):
    json_response = client.get(
        "/api/v1/reports/operations/export",
        params={"format": "json"},
        headers=analyst_headers,
    )
    assert json_response.status_code == 200
    assert json_response.json()["collection"]["sources_configured"] == 2
    invalid = client.get(
        "/api/v1/reports/operations/export",
        params={"format": "xml"},
        headers=analyst_headers,
    )
    assert invalid.status_code == 422
