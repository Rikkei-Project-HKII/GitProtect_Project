"""GitHub REST API client for repository onboarding (PBI-01)."""
import httpx
from fastapi import HTTPException

API = "https://api.github.com"


class GitHubClient:
    def __init__(self, pat: str):
        self.headers = {
            "Authorization": f"Bearer {pat}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def request(self, method: str, path: str, **kwargs):
        try:
            async with httpx.AsyncClient(timeout=12.0, follow_redirects=False) as client:
                response = await client.request(method, API + path, headers=self.headers, **kwargs)
        except httpx.RequestError as exc:
            raise HTTPException(502, "GitHub API is temporarily unreachable") from exc
        if response.status_code == 401:
            raise HTTPException(401, "Invalid or expired GitHub PAT")
        if response.status_code == 403:
            raise HTTPException(403, "Insufficient GitHub permissions or rate limit")
        if response.status_code == 404:
            raise HTTPException(404, "Repository not found or inaccessible")
        if response.status_code == 422:
            raise HTTPException(422, "GitHub rejected the webhook configuration")
        if response.status_code == 409:
            raise HTTPException(409, "GitHub webhook conflict")
        if response.status_code >= 400 or 300 <= response.status_code < 400:
            raise HTTPException(502, f"Unexpected GitHub API HTTP {response.status_code}")
        if response.status_code == 204 or not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:
            raise HTTPException(502, "GitHub returned invalid JSON") from exc

    async def repository(self, owner: str, name: str):
        return await self.request("GET", f"/repos/{owner}/{name}")

    async def create_webhook(self, owner: str, name: str, callback: str, secret: str):
        return await self.request("POST", f"/repos/{owner}/{name}/hooks", json={
            "name": "web", "active": True, "events": ["push"],
            "config": {"url": callback, "content_type": "json", "secret": secret, "insecure_ssl": "0"},
        })

    async def delete_webhook(self, owner: str, name: str, hook_id: int):
        return await self.request("DELETE", f"/repos/{owner}/{name}/hooks/{hook_id}")
