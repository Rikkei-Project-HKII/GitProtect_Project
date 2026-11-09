import hashlib
import hmac
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest

from app.core.security import crypto_service
from app.db.session import get_db
from app.main import app


@pytest.mark.asyncio
async def test_push_signature_replay_and_queue_contents():
    secret = "webhook-fixture"
    sha = "1" * 40
    body = json.dumps({"repository": {"id": 2}, "commits": [{"id": sha}],
                       "ref": "refs/heads/main", "actor_type": "user"}).encode()
    signature = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    repo = SimpleNamespace(id=5, github_repo_id=2, repo_name="demo/test",
                           webhook_secret_encrypted=crypto_service.encrypt(secret),
                           access_token_encrypted=crypto_service.encrypt("token"))
    async def fake_db():
        return Mock(scalar=Mock(return_value=repo))

    app.dependency_overrides[get_db] = fake_db
    headers = {"X-GitHub-Event": "push", "X-GitHub-Delivery": "delivery-1",
               "X-Hub-Signature-256": signature}
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            with patch("app.modules.ingestion.webhook.Redis") as factory, patch(
                "app.modules.ingestion.webhook.GitHubClient.request", new_callable=AsyncMock,
                return_value="+secret"
            ) as github:
                url = "/api/v1/webhooks/github"
                assert (await client.post(url, content=body + b" ", headers=headers)).status_code == 401
                factory.assert_not_called()
                redis = factory.return_value.__aenter__.return_value
                redis.exists.side_effect = [False, True]
                redis.eval.return_value = 1
                response = await client.post(url, content=body, headers=headers)
                assert response.status_code == 200
                assert response.json()["queued_commits_count"] == 1
                job = json.loads(redis.eval.await_args.args[-1])
                assert (job["commit_sha"], job["diff"], job["actor_type"], job["actor_label"]) == (
                    sha, "+secret", "system", "system")
                replay = await client.post(url, content=body, headers=headers)
                assert replay.status_code == 200
                assert replay.json()["status"] == "duplicate_ignored"
                github.assert_awaited_once()
                redis.eval.assert_awaited_once()
    finally:
        app.dependency_overrides.pop(get_db)
