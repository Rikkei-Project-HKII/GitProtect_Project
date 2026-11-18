"""Run with pytest -q -s tests/test_sprint2_demo.py for live demo output."""
import hashlib
import hmac
import json
import secrets
import time

import fakeredis.aioredis
import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from app.core.security import crypto_service
from app.models import Repository, SecurityAlert
from app.modules.engine.worker import ScanQueueWorker, QUEUE
from app.modules.ingestion import webhook
from test_pbi07 import services


def test_signed_push_to_resolved_alert(services, monkeypatch):
    client, sessions, cache, routes = services
    secret = secrets.token_hex(24)
    with sessions.begin() as db:
        repo = db.get(Repository, 1)
        repo.access_token_encrypted = crypto_service.encrypt("synthetic-fixture")
        repo.webhook_secret_encrypted = crypto_service.encrypt(secret)

    # Both Redis clients talk to one disposable test server.
    server = fakeredis.FakeServer()
    cache = fakeredis.FakeRedis(server=server, decode_responses=True)
    monkeypatch.setattr(webhook, "Redis", lambda **kw: fakeredis.aioredis.FakeRedis(server=server))
    sha = "d" * 40
    async def github_diff(self, method, path, **kw):
        assert method == "GET" and path == "/repos/team/repo/commits/" + sha
        return '\n'.join(["diff --git a/config.py b/config.py", "--- a/config.py", "+++ b/config.py",
                          "@@ -4,2 +4,3 @@", " # demo", '-api_key="removed"',
                          '+api_key="aB9xK2pQ7zM4nP8qR5wX"',
                          '+cccd="001099012345"  # so can cuoc cong dan'])
    monkeypatch.setattr(webhook.GitHubClient, "request", github_diff)
    body = json.dumps({"repository": {"id": 7}, "ref": "refs/heads/dev",
                       "commits": [{"id": sha}]}).encode()
    headers = {"X-Hub-Signature-256": "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest(),
               "X-GitHub-Event": "push", "X-GitHub-Delivery": "demo-delivery"}
    start = time.monotonic()
    response = client.post("/api/v1/webhooks/github", content=body, headers=headers)
    assert response.json()["queued_commits_count"] == 1
    payload = cache.lindex(QUEUE, 0)
    worker = ScanQueueWorker(cache)
    with sessions() as db:
        assert worker.consume_once(db=db)["new_alerts"] == 2
    items = client.get("/api/v1/alerts", params={"repo_id": 1}).json()["items"]
    elapsed = time.monotonic() - start
    assert elapsed < 10
    assert {(a["line_number"], a["rule_name"]) for a in items} == {
        (5, "High Entropy Generic Secret Token"), (6, "Vietnamese Citizen ID Number (CCCD)")}
    assert all(a["commit_sha"] == sha and "****" in a["secret_masked"] for a in items)
    print(f"Push -> 2 masked alerts visible through API: {elapsed:.3f}s (local fixtures)")
    cache.rpush(QUEUE, payload)
    with sessions() as db:
        assert worker.consume_once(db=db)["new_alerts"] == 0

    sync = client.post("/api/v1/sync/native-alerts/1").json()
    assert sync["synced_dependabot_alerts"] == 1
    with sessions() as db:
        assert db.scalar(select(SecurityAlert).where(SecurityAlert.rule_name == "Dependabot")).cve_id == "CVE-fixture"
    url = "/api/v1/alerts/" + str(items[0]["id"])
    change = client.patch(url + "/status", json={"new_status": "resolved", "resolution_note": "Sprint demo fixture"})
    assert change.status_code == 200
    assert client.get(url).json()["status"] == "resolved"
    history = client.get(url + "/history").json()["items"]
    assert [(r["new_status"], r["actor_label"]) for r in history] == [
        ("open", "system"), ("resolved", "internal_operator")]
    print("Dependabot persisted; alert resolved with matching audit history.")
    with sessions.begin() as db:
        db.execute(text("CREATE TRIGGER demo_audit_failure BEFORE INSERT ON alert_status_history "
                        "BEGIN SELECT RAISE(ABORT, 'demo rollback'); END"))
    with pytest.raises(IntegrityError, match="demo rollback"):
        client.patch(url + "/status", json={"new_status": "in_review"})
    assert client.get(url).json()["status"] == "resolved"
    assert client.get(url + "/history").json()["items"] == history
    print("Audit write failure rolled back the status change.")

