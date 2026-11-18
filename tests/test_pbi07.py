"""PBI-07 API/worker integration using SQLite, fakeredis Lua and GitHub fixtures."""
import base64

import fakeredis
import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.schema import CreateTable
from sqlalchemy.pool import StaticPool

from app.db.session import get_db
from app.main import app
from app.models import Base, Repository, SecurityAlert, AlertStatusHistory
from app.modules.engine import initial_scan as scan
from app.modules.engine.repository_api import RepositoryAPI


@pytest.fixture
def services(monkeypatch):
    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    with engine.begin() as conn:
        conn.connection.driver_connection.create_function("CHAR_LENGTH", 1, len)
        for table in Base.metadata.sorted_tables:
            ddl = str(CreateTable(table).compile(engine)).replace(" ON UPDATE CURRENT_TIMESTAMP", "")
            conn.exec_driver_sql(ddl)
    sessions = sessionmaker(bind=engine)
    with sessions.begin() as db:
        db.add(Repository(id=1, github_repo_id=7, repo_name="team/repo", default_branch="dev",
                          access_token_encrypted="fixture", repo_url="https://github.com/team/repo"))
    server = fakeredis.FakeServer()
    def cache():
        return fakeredis.FakeRedis(server=server, decode_responses=True)
    def database():
        with sessions() as db:
            yield db
    app.dependency_overrides[get_db] = database
    monkeypatch.setattr(scan, "redis_client", cache)
    monkeypatch.setattr(scan, "SessionLocal", sessions)
    routes = {
        "commits/dev": {"sha": "a"*40, "commit": {"tree": {"sha": "root"}}},
        "git/trees/root": {"tree": [{"path": "src", "type": "tree", "sha": "sub"}]},
        "git/trees/sub": {"tree": [{"path": "config.py", "type": "blob", "mode": "100644", "sha": "blob"}]},
        "git/blobs/blob": {"encoding": "base64", "content": base64.b64encode(
            b'password="aB9xK2pQ7zM4nP8qR5wX"').decode()},
        "secret-scanning/alerts": [{"number": 1, "state": "open", "secret_type": "test", "secret": "never-store"}],
        "dependabot/alerts": [{"number": 1, "state": "open", "dependency": {"manifest_path": "requirements.txt"},
                               "security_advisory": {"cve_id": "CVE-fixture"},
                               "security_vulnerability": {"severity": "high", "package": {"name": "example"},
                                                          "first_patched_version": {"identifier": "2.0"}}}],
    }
    def request(req):
        value = routes[req.url.path.removeprefix("/repos/team/repo/")]
        return httpx.Response(value if isinstance(value, int) else 200, json=value)
    def connect(repo):
        client = httpx.Client(base_url="https://api.github.com", transport=httpx.MockTransport(request))
        return RepositoryAPI(client, repo.repo_name)
    monkeypatch.setattr(RepositoryAPI, "connect", staticmethod(connect))
    try:
        yield TestClient(app), sessions, cache(), routes
    finally:
        app.dependency_overrides.pop(get_db)
        engine.dispose()


def test_initial_scan_and_redelivery(services):
    client, sessions, redis, routes = services
    trigger = "/api/v1/scan/trigger/1"
    first = client.post(trigger)
    assert first.status_code == 202
    jid = first.json()["job_id"]
    assert client.post(trigger).json()["job_id"] == jid
    assert scan.consume(redis)
    result = client.get("/api/v1/scan/jobs/" + jid).json()
    assert (result["scan_status"], result["progress_pct"], result["scanned_files"]) == ("completed", 100, 1)
    assert redis.ttl("scan:job:" + jid) > 0
    client.post(trigger)
    scan.consume(redis)
    with sessions() as db:
        alert = db.scalars(select(SecurityAlert)).one()
        assert alert.file_path == "src/config.py" and alert.commit_sha == "a"*40
        assert db.scalars(select(AlertStatusHistory)).one().actor_label == "system"
        assert db.get(Repository, 1).scan_status == "completed"
    assert client.get("/api/v1/scan/jobs/missing").status_code == 404


def test_failed_scan_is_retryable(services):
    client, sessions, redis, routes = services
    routes["git/blobs/blob"] = 403
    jid = client.post("/api/v1/scan/trigger/1").json()["job_id"]
    scan.consume(redis)
    assert scan.status(redis, jid)["scan_status"] == "failed"
    with sessions() as db:
        assert db.get(Repository, 1).scan_status == "failed"
    assert client.post("/api/v1/scan/trigger/1").json()["job_id"] != jid


def test_native_sync_collisions_dedup_and_rollback(services):
    client, sessions, redis, routes = services
    url = "/api/v1/sync/native-alerts/1"
    dependabot = routes["dependabot/alerts"]
    routes["dependabot/alerts"] = 403
    assert client.post(url).status_code == 502
    with sessions() as db:
        assert db.scalars(select(SecurityAlert)).all() == []
    routes["dependabot/alerts"] = dependabot
    assert client.post(url).json()["new_alerts_inserted"] == 2
    assert client.post(url).json()["duplicates_skipped"] == 2
    with sessions() as db:
        alert = db.scalar(select(SecurityAlert).where(SecurityAlert.package_name == "example"))
        assert (alert.fixed_version, alert.cve_id) == ("2.0", "CVE-fixture")
        assert all(x.actor_type == "system" for x in db.scalars(select(AlertStatusHistory)))


def test_native_pagination_handles_github_numeric_repository_link():
    seen = []
    def request(req):
        seen.append(req.url.path)
        if len(seen) == 1:
            return httpx.Response(200, json=[{"number": 1}], headers={
                "Link": '<https://api.github.com/repositories/7/dependabot/alerts?page=2>; rel="next"'})
        return httpx.Response(200, json=[{"number": 2}])
    with httpx.Client(base_url="https://api.github.com", transport=httpx.MockTransport(request)) as http:
        rows = list(RepositoryAPI(http, "team/repo").pages("dependabot/alerts"))
    assert [r["number"] for r in rows] == [1, 2]
    assert len(seen) == 2
