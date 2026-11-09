from app.routers.incident_timeline import _redact


def _create_incident(client, headers):
    response = client.post("/api/v1/incidents", headers=headers, json={
        "title": "Suspicious authentication activity",
        "severity": "high",
        "description": "Repeated failed sign-ins from a test endpoint.",
    })
    assert response.status_code == 201
    return response.json()["id"]


def test_incident_timeline_records_analyst_notes(client, analyst_headers):
    incident_id = _create_incident(client, analyst_headers)
    note = client.post(f"/api/v1/incidents/{incident_id}/notes", headers=analyst_headers,
                       json={"note": "Validated the source agent and escalated for review."})
    assert note.status_code == 201
    assert note.json()["author_user_id"] is not None

    timeline = client.get(f"/api/v1/incidents/{incident_id}/timeline", headers=analyst_headers)
    assert timeline.status_code == 200
    events = timeline.json()["events"]
    assert any(event["type"] == "incident.created" for event in events)
    assert any(event["type"] == "incident.note" and
               event["provenance"] == "analyst_authored" for event in events)


def test_incident_note_rejects_blank_or_oversized_input(client, analyst_headers):
    incident_id = _create_incident(client, analyst_headers)
    blank = client.post(f"/api/v1/incidents/{incident_id}/notes", headers=analyst_headers,
                        json={"note": "   "})
    oversized = client.post(f"/api/v1/incidents/{incident_id}/notes", headers=analyst_headers,
                            json={"note": "x" * 5001})
    assert blank.status_code == 422
    assert oversized.status_code == 422


def test_evidence_export_is_no_store_and_redacts_secret_like_values(client, analyst_headers):
    incident_id = _create_incident(client, analyst_headers)
    response = client.get(f"/api/v1/incidents/{incident_id}/evidence-export", headers=analyst_headers)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-disposition"].endswith(f'opsaegis-incident-{incident_id}-evidence.json"')
    payload = response.json()
    assert payload["redaction"]["applied"] is True\n    assert any(event["type"] == "incident.evidence.export" for event in payload["timeline"]["events"])

    assert _redact({"api_key": "do-not-export", "message": "Bearer abc.def.ghi"}) == {
        "api_key": "[REDACTED]", "message": "Bearer [REDACTED]"
    }
