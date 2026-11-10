"""PBI-01 unit tests: run with pytest -q."""
import pytest
from fastapi import HTTPException
from app.modules.ingestion.service import parse_repo_url
from app.modules.ingestion.github_client import GitHubClient

def test_repo_url():
    assert parse_repo_url("https://github.com/example/demo") == ["example", "demo"]

@pytest.mark.parametrize("url", [
    "http://github.com/a/b", "https://evil.example/a/b",
    "https://github.com/a/b/extra", "https://github.com/a"
])
def test_bad_repo_url(url):
    with pytest.raises(HTTPException):
        parse_repo_url(url)

@pytest.mark.asyncio
async def test_github_repo_fetch(monkeypatch):
    async def fake_request(self, method, path, **kwargs):
        assert method == "GET"
        assert path == "/repos/demo/project"
        return {"id": 123, "full_name": "demo/project", "default_branch": "develop"}
    monkeypatch.setattr(GitHubClient, "request", fake_request)
    result = await GitHubClient("fake-token").repository("demo", "project")
    assert result["default_branch"] == "develop"

@pytest.mark.asyncio
async def test_webhook_delete_accepts_204(monkeypatch):
    import httpx
    async def fake_request(self, method, url, **kwargs):
        assert method == "DELETE"
        return httpx.Response(204, request=httpx.Request(method, url))
    monkeypatch.setattr(httpx.AsyncClient, "request", fake_request)
    assert await GitHubClient("fake-token").delete_webhook("demo", "project", 12) is None

@pytest.mark.asyncio
async def test_github_401_is_reported(monkeypatch):
    import httpx
    async def fake_request(self, method, url, **kwargs):
        return httpx.Response(401, request=httpx.Request(method, url))
    monkeypatch.setattr(httpx.AsyncClient, "request", fake_request)
    with pytest.raises(HTTPException) as error:
        await GitHubClient("fake-token").repository("demo", "project")
    assert error.value.status_code == 401

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
from sqlalchemy.exc import SQLAlchemyError
from app.core.security import crypto_service
from app.modules.ingestion.service import RepoConnectionService


@pytest.mark.asyncio
async def test_connect_encrypts_credentials_and_uses_canonical_name(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_CALLBACK_URL", "https://example.com/api/v1/webhooks/github")
    req = SimpleNamespace(repo_url="https://github.com/demo/test", github_pat="private-pat",
                          webhook_secret="private-secret")
    db = Mock()
    db.scalar.return_value = None
    metadata = dict(id=123, full_name="Demo/Test", default_branch="develop",
                    html_url="https://github.com/Demo/Test")
    with patch.object(GitHubClient, "repository", AsyncMock(return_value=metadata)), patch.object(
        GitHubClient, "create_webhook", AsyncMock(return_value={"id": 9})
    ) as create:
        record = await RepoConnectionService.connect_repository(req, db)
    assert record.default_branch == "develop"
    assert crypto_service.decrypt(record.access_token_encrypted) == req.github_pat
    assert crypto_service.decrypt(record.webhook_secret_encrypted) == req.webhook_secret
    assert create.await_args.args[:2] == ("Demo", "Test")
    db.commit.assert_called_once()


@pytest.mark.asyncio
async def test_connect_cleans_hook_after_commit_failure(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_CALLBACK_URL", "https://example.com/hook")
    req = SimpleNamespace(repo_url="https://github.com/demo/test", github_pat="private-pat",
                          webhook_secret="private-secret")
    db = Mock()
    db.scalar.return_value = None
    db.commit.side_effect = SQLAlchemyError("database unavailable")
    metadata = dict(id=123, full_name="demo/test", default_branch="main",
                    html_url="https://github.com/demo/test")
    with patch.object(GitHubClient, "repository", AsyncMock(return_value=metadata)), patch.object(
        GitHubClient, "create_webhook", AsyncMock(return_value={"id": 9})
    ), patch.object(GitHubClient, "delete_webhook", AsyncMock()) as delete:
        with pytest.raises(HTTPException) as error:
            await RepoConnectionService.connect_repository(req, db)
    assert error.value.status_code == 500
    db.rollback.assert_called_once()
    delete.assert_awaited_once_with("demo", "test", 9)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", [
    {"id": True}, {"default_branch": None}, {"full_name": "bad/name/extra"},
    {"html_url": "https://evil.example/demo/test"},
])
async def test_invalid_metadata_does_not_create_hook(change):
    metadata = dict(id=123, full_name="demo/test", default_branch="main",
                    html_url="https://github.com/demo/test")
    metadata.update(change)
    req = SimpleNamespace(repo_url="https://github.com/demo/test", github_pat="private-pat")
    with patch.object(GitHubClient, "repository", AsyncMock(return_value=metadata)), patch.object(
        GitHubClient, "create_webhook", AsyncMock()
    ) as create:
        with pytest.raises(HTTPException) as error:
            await RepoConnectionService.connect_repository(req, Mock())
    assert error.value.status_code == 502
    create.assert_not_called()
