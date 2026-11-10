from datetime import datetime, timedelta, timezone
import hashlib

from app.config import settings
from app.models.entities import IncidentEvidenceAttachment, User, UserRole
from app.security import create_access_token, hash_password


def _create_incident(client, headers):
    response = client.post("/api/v1/incidents", headers=headers, json={
        "title": "Evidence upload test",
        "severity": "medium",
        "description": "Disposable test incident.",
    })
    assert response.status_code == 201
    return response.json()["id"]


def _viewer_headers(db_session):
    viewer = User(
        email="viewer-evidence@example.com",
        password_hash=hash_password("Test-Viewer-Password-2026!"),
        role=UserRole.viewer,
        is_active=True,
    )
    db_session.add(viewer)
    db_session.commit()
    db_session.refresh(viewer)
    return {"Authorization": "Bearer " + create_access_token(viewer)}


def test_attachment_upload_list_download_and_digest(client, analyst_headers, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "evidence_storage_path", str(tmp_path))
    incident_id = _create_incident(client, analyst_headers)
    payload = b"%PDF-1.4\nDisposable evidence fixture\n"
    uploaded = client.post(
        f"/api/v1/incidents/{incident_id}/attachments",
        headers=analyst_headers,
        files={"file": ("test evidence.pdf", payload, "application/octet-stream")},
    )
    assert uploaded.status_code == 201
    item = uploaded.json()
    assert item["media_type"] == "application/pdf"
    assert item["sha256"] == hashlib.sha256(payload).hexdigest()
    assert item["size_bytes"] == len(payload)
    assert item["expires_at"]

    listed = client.get(f"/api/v1/incidents/{incident_id}/attachments", headers=analyst_headers)
    assert listed.status_code == 200
    assert listed.json()["items"][0]["id"] == item["id"]

    downloaded = client.get(
        f"/api/v1/incidents/{incident_id}/attachments/{item['id']}",
        headers=analyst_headers,
    )
    assert downloaded.status_code == 200
    assert downloaded.content == payload
    assert downloaded.headers["cache-control"] == "no-store"
    assert downloaded.headers["x-content-type-options"] == "nosniff"
    assert downloaded.headers["x-content-sha256"] == item["sha256"]


def test_attachment_rejects_unsupported_and_oversized_files(client, analyst_headers, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "evidence_storage_path", str(tmp_path))
    incident_id = _create_incident(client, analyst_headers)
    unsupported = client.post(
        f"/api/v1/incidents/{incident_id}/attachments",
        headers=analyst_headers,
        files={"file": ("payload.bin", b"\x00\x01\x02", "application/octet-stream")},
    )
    assert unsupported.status_code == 415

    monkeypatch.setattr(settings, "evidence_max_attachment_bytes", 4)
    oversized = client.post(
        f"/api/v1/incidents/{incident_id}/attachments",
        headers=analyst_headers,
        files={"file": ("large.txt", b"more than four bytes", "text/plain")},
    )
    assert oversized.status_code == 413
    assert list(tmp_path.iterdir()) == []


def test_viewer_cannot_access_incident_attachments(client, analyst_headers, db_session, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "evidence_storage_path", str(tmp_path))
    incident_id = _create_incident(client, analyst_headers)
    viewer = _viewer_headers(db_session)
    response = client.post(
        f"/api/v1/incidents/{incident_id}/attachments",
        headers=viewer,
        files={"file": ("test.txt", b"restricted", "text/plain")},
    )
    assert response.status_code == 403
    listed = client.get(f"/api/v1/incidents/{incident_id}/attachments", headers=viewer)
    assert listed.status_code == 403


def test_expired_attachment_is_not_downloadable(client, analyst_headers, db_session, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "evidence_storage_path", str(tmp_path))
    incident_id = _create_incident(client, analyst_headers)
    uploaded = client.post(
        f"/api/v1/incidents/{incident_id}/attachments",
        headers=analyst_headers,
        files={"file": ("test.txt", b"temporary evidence", "text/plain")},
    )
    assert uploaded.status_code == 201
    attachment_id = uploaded.json()["id"]
    item = db_session.get(IncidentEvidenceAttachment, attachment_id)
    item.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    db_session.commit()

    response = client.get(
        f"/api/v1/incidents/{incident_id}/attachments/{attachment_id}",
        headers=analyst_headers,
    )
    assert response.status_code == 404


def test_tampered_attachment_fails_integrity_check(client, analyst_headers, monkeypatch, tmp_path, db_session):
    monkeypatch.setattr(settings, "evidence_storage_path", str(tmp_path))
    incident_id = _create_incident(client, analyst_headers)
    payload = b"integrity fixture"
    uploaded = client.post(
        f"/api/v1/incidents/{incident_id}/attachments",
        headers=analyst_headers,
        files={"file": ("fixture.txt", payload, "text/plain")},
    )
    assert uploaded.status_code == 201
    attachment = db_session.get(IncidentEvidenceAttachment, uploaded.json()["id"])
    (tmp_path / f"{attachment.storage_key}.blob").write_bytes(b"tampered")
    response = client.get(
        f"/api/v1/incidents/{incident_id}/attachments/{attachment.id}",
        headers=analyst_headers,
    )
    assert response.status_code == 409


def test_viewer_cannot_download_operator_evidence(client, analyst_headers, db_session, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "evidence_storage_path", str(tmp_path))
    incident_id = _create_incident(client, analyst_headers)
    uploaded = client.post(
        f"/api/v1/incidents/{incident_id}/attachments",
        headers=analyst_headers,
        files={"file": ("private.txt", b"restricted", "text/plain")},
    )
    assert uploaded.status_code == 201
    viewer = _viewer_headers(db_session)
    response = client.get(
        f"/api/v1/incidents/{incident_id}/attachments/{uploaded.json()['id']}",
        headers=viewer,
    )
    assert response.status_code == 403


def test_attachment_respects_per_incident_storage_quota(client, analyst_headers, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "evidence_storage_path", str(tmp_path))
    monkeypatch.setattr(settings, "evidence_max_incident_bytes", 10)
    incident_id = _create_incident(client, analyst_headers)
    response = client.post(
        f"/api/v1/incidents/{incident_id}/attachments",
        headers=analyst_headers,
        files={"file": ("quota.txt", b"more than ten bytes", "text/plain")},
    )
    assert response.status_code == 413
    assert list(tmp_path.iterdir()) == []
