def test_asset_create_and_read(client, analyst_headers):
    response = client.post(
        "/api/v1/assets",
        json={"name": "lab-web-01", "asset_type": "server", "environment": "lab"},
        headers=analyst_headers,
    )
    assert response.status_code == 201
    asset_id = response.json()["id"]
    detail = client.get(f"/api/v1/assets/{asset_id}", headers=analyst_headers)
    assert detail.status_code == 200
    assert detail.json()["name"] == "lab-web-01"


def test_finding_create_and_missing_asset(client, analyst_headers):
    bad = client.post(
        "/api/v1/findings",
        json={"source_engine": "nuclei", "title": "test", "asset_id": 999},
        headers=analyst_headers,
    )
    assert bad.status_code == 404

    good = client.post(
        "/api/v1/findings",
        json={"source_engine": "nuclei", "title": "TLS issue", "severity": "medium"},
        headers=analyst_headers,
    )
    assert good.status_code == 201
    listed = client.get("/api/v1/findings", headers=analyst_headers)
    assert listed.status_code == 200
    assert len(listed.json()) == 1


def test_incident_create_and_list(client, analyst_headers):
    response = client.post(
        "/api/v1/incidents",
        json={"title": "Investigate login failures", "severity": "high"},
        headers=analyst_headers,
    )
    assert response.status_code == 201
    assert response.json()["status"] == "open"

    listed = client.get("/api/v1/incidents", headers=analyst_headers)
    assert listed.status_code == 200
    assert len(listed.json()) == 1


def test_pagination_bounds(client, analyst_headers):
    assert client.get("/api/v1/assets?limit=999", headers=analyst_headers).status_code == 422
    assert client.get("/api/v1/findings?skip=-1", headers=analyst_headers).status_code == 422
