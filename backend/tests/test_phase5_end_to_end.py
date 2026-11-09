from datetime import datetime, timedelta, timezone

from app.integrations.contracts import NormalizedFinding
from app.models.entities import (
    AuditLog,
    CorrelatedDetection,
    DetectionNotification,
    Finding,
    Incident,
)
from app.routers import integrations as integrations_router


def test_wazuh_ingestion_to_detection_incident_and_notification_is_idempotent(
    client, db_session, analyst_headers, monkeypatch
):
    observed = datetime.now(timezone.utc)
    incoming = [
        NormalizedFinding(
            source_engine="wazuh",
            source_native_id=f"phase5-auth-{index}",
            title="Authentication failure",
            description="Controlled Phase 5 integration contract event",
            severity="high",
            observed_at=observed + timedelta(seconds=index),
            asset_reference="phase5-lab-agent",
            evidence={
                "groups": ["authentication"],
                "agent_id": "phase5-lab-004",
                "agent_name": "phase5-lab-agent",
                "agent_ip": "203.0.113.44",
            },
        )
        for index in range(3)
    ]

    class FakeWazuhIndexerAdapter:
        is_configured = True

        async def collect_findings(self, since):
            return incoming

    monkeypatch.setattr(
        integrations_router, "WazuhIndexerAdapter", FakeWazuhIndexerAdapter
    )

    ingestion = client.post(
        "/api/v1/integrations/wazuh/collect", headers=analyst_headers
    )
    assert ingestion.status_code == 200
    assert ingestion.json()["inserted"] == 3
    assert db_session.query(Finding).filter_by(source_engine="wazuh").count() == 3

    evaluated = client.post(
        "/api/v1/detections/evaluate?window_minutes=15&auth_threshold=3",
        headers=analyst_headers,
    )
    assert evaluated.status_code == 200
    assert evaluated.json()["created"] == 1
    assert evaluated.json()["incidents_created"] == 1

    detection = db_session.query(CorrelatedDetection).one()
    incident = db_session.query(Incident).one()
    assert detection.incident_id == incident.id
    assert len(detection.finding_ids) == 3

    notifications = client.get(
        "/api/v1/detections/notifications", headers=analyst_headers
    )
    assert notifications.status_code == 200
    assert len(notifications.json()) == 1
    notification = notifications.json()[0]
    assert notification["detection_id"] == detection.id
    assert notification["severity"] == "high"

    marked_read = client.patch(
        f"/api/v1/detections/notifications/{notification['id']}/read",
        headers=analyst_headers,
    )
    assert marked_read.status_code == 200
    assert marked_read.json()["read_at"] is not None

    repeated_evaluation = client.post(
        "/api/v1/detections/evaluate?window_minutes=15&auth_threshold=3",
        headers=analyst_headers,
    )
    assert repeated_evaluation.status_code == 200
    assert repeated_evaluation.json()["created"] == 0
    assert repeated_evaluation.json()["refreshed"] == 1
    assert db_session.query(Incident).count() == 1
    assert db_session.query(CorrelatedDetection).count() == 1
    assert db_session.query(DetectionNotification).count() == 1
    assert db_session.query(AuditLog).filter_by(action="detection.correlate").count() == 1
