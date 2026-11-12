from app.models.entities import Asset, AuditLog


def test_analyst_can_register_asset_and_record_audit_event(client, analyst_headers, db_session):
    response = client.post(
        "/api/v1/assets",
        headers=analyst_headers,
        json={
            "name": "Staging API",
            "asset_type": "web_application",
            "environment": "staging",
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["name"] == "Staging API"
    assert payload["asset_type"] == "web_application"
    assert payload["environment"] == "staging"
    assert payload["source_engine"] is None

    stored = db_session.get(Asset, payload["id"])
    assert stored is not None
    event = db_session.query(AuditLog).filter_by(action="asset.create").one()
    assert event.target == f"asset:{stored.id}"
    assert event.actor_user_id is not None
    assert "environment:staging" in event.detail


def test_asset_registration_rejects_missing_required_fields(client, analyst_headers):
    response = client.post(
        "/api/v1/assets",
        headers=analyst_headers,
        json={"name": "Incomplete asset"},
    )
    assert response.status_code == 422
