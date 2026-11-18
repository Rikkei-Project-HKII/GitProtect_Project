from app.modules.dashboard import service
from test_pbi07 import services


def test_dashboard_routes_after_merge(services, monkeypatch):
    client, sessions, cache, routes = services
    monkeypatch.setattr(service, "_redis", cache)
    assert client.post("/api/v1/sync/native-alerts/1").status_code == 200
    response = client.get("/api/v1/dashboard/metrics")
    assert response.status_code == 200
    assert response.json()["total"] == 2
    assert client.get("/api/v1/dashboard/repo-breakdown").json()["items"][0]["repo_id"] == 1
    assert client.get("/api/v1/dashboard/trend").json()["points"][0]["total"] == 2
    assert client.get("/api/v1/dashboard/trend?granularity=invalid").status_code == 422
    paths = client.get("/openapi.json").json()["paths"]
    assert "/api/v1/audit/authors/{repo_id}" in paths
    assert "/api/v1/dashboard/export" in paths
