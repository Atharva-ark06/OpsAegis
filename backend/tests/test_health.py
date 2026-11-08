def test_readiness_reports_database_and_redis_state(client):
    response = client.get("/api/v1/ready")
    assert response.status_code == 200
    assert response.json()["database"] == "ok"
    assert response.json()["redis"] in {"ok", "unavailable"}
