from sqlalchemy import func, select

from app.models.entities import (
    Asset, CorrelatedDetection, Finding, Incident, ThreatIntelIOC,
    User, UserRole, Vulnerability,
)
from app.seed_demo_data import clear_demo, seed_demo


def test_demo_seed_creates_linked_records_and_is_idempotent(db_session):
    admin = User(
        email="demo-seed-admin@example.invalid",
        password_hash="not-a-login-credential",
        role=UserRole.admin,
        is_active=True,
    )
    db_session.add(admin)
    db_session.commit()

    result = seed_demo(db_session)
    db_session.commit()

    assert result == {
        "assets": 12,
        "findings": 18,
        "vulnerabilities": 5,
        "incidents": 5,
        "detections": 5,
        "iocs": 6,
    }
    assert db_session.scalar(select(func.count()).select_from(Asset)) == 12
    assert db_session.scalar(select(func.count()).select_from(Finding)) == 18
    assert db_session.scalar(select(func.count()).select_from(Vulnerability)) == 5
    assert db_session.scalar(select(func.count()).select_from(Incident)) == 5
    assert db_session.scalar(select(func.count()).select_from(CorrelatedDetection)) == 5
    assert db_session.scalar(select(func.count()).select_from(ThreatIntelIOC)) == 6

    second = seed_demo(db_session)
    assert second == {"already_seeded": 1}
    assert db_session.scalar(select(func.count()).select_from(Asset)) == 12

    # Every seeded finding points to a seeded asset; every detection references
    # seeded findings and an incident when one is specified.
    seeded_asset_ids = set(db_session.scalars(select(Asset.id)).all())
    for finding in db_session.scalars(select(Finding)).all():
        assert finding.asset_id in seeded_asset_ids
    finding_ids = set(db_session.scalars(select(Finding.id)).all())
    incident_ids = set(db_session.scalars(select(Incident.id)).all())
    for detection in db_session.scalars(select(CorrelatedDetection)).all():
        assert set(detection.finding_ids).issubset(finding_ids)
        assert detection.incident_id is None or detection.incident_id in incident_ids


def test_demo_reset_removes_only_seeded_records(db_session):
    admin = User(
        email="demo-reset-admin@example.invalid",
        password_hash="not-a-login-credential",
        role=UserRole.admin,
        is_active=True,
    )
    db_session.add(admin)
    db_session.commit()

    seed_demo(db_session)
    db_session.commit()
    clear_demo(db_session)
    db_session.commit()

    assert db_session.scalar(select(func.count()).select_from(Asset)) == 0
    assert db_session.scalar(select(func.count()).select_from(Finding)) == 0
    assert db_session.scalar(select(func.count()).select_from(Vulnerability)) == 0
    assert db_session.scalar(select(func.count()).select_from(Incident)) == 0
    assert db_session.scalar(select(func.count()).select_from(CorrelatedDetection)) == 0
    assert db_session.scalar(select(func.count()).select_from(ThreatIntelIOC)) == 0
    assert db_session.scalar(select(func.count()).select_from(User)) == 1
