def test_api_responses_include_security_headers(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["permissions-policy"] == "camera=(), microphone=(), geolocation=()"
    assert response.headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"


def test_authentication_responses_are_not_cacheable(client):
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"


def test_unknown_host_is_rejected(client):
    response = client.get("/api/v1/health", headers={"Host": "attacker.invalid"})
    assert response.status_code == 400


def test_development_test_host_is_allowed(client):
    response = client.get("/api/v1/health", headers={"Host": "testserver"})
    assert response.status_code == 200
