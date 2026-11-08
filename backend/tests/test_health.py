from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["name"] == "OpsAegis API"

def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_readiness_does_not_claim_unverified_dependencies():
    response = client.get("/api/v1/ready")
    assert response.status_code == 200
    assert response.json()["database"] == "not_checked"
