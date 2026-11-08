def test_asset_create_and_read(client):
    response=client.post("/api/v1/assets",json={"name":"lab-web-01","asset_type":"server","environment":"lab"})
    assert response.status_code==201
    assert client.get(f"/api/v1/assets/{response.json()['id']}").json()["name"]=="lab-web-01"
def test_finding_create_and_missing_asset(client):
    bad=client.post("/api/v1/findings",json={"source_engine":"nuclei","title":"test","asset_id":999})
    assert bad.status_code==404
    good=client.post("/api/v1/findings",json={"source_engine":"nuclei","title":"TLS issue","severity":"medium"})
    assert good.status_code==201
    assert len(client.get("/api/v1/findings").json())==1
def test_incident_create_and_list(client):
    response=client.post("/api/v1/incidents",json={"title":"Investigate login failures","severity":"high"})
    assert response.status_code==201 and response.json()["status"]=="open"
    assert len(client.get("/api/v1/incidents").json())==1
def test_pagination_bounds(client):
    assert client.get("/api/v1/assets?limit=999").status_code==422
    assert client.get("/api/v1/findings?skip=-1").status_code==422
