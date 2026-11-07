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
