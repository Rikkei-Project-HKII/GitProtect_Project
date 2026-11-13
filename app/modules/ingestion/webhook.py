"""Authenticate GitHub deliveries and enqueue one scan job per commit."""
import asyncio
import hashlib
import hmac
import json
import re

import httpx
from fastapi import HTTPException
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import select

from app.core.config import settings
from app.core.security import crypto_service
from app.models.repository import Repository
from app.modules.ingestion.github_client import GitHubClient


class DeliveryDedupService:
    # One Lua execution serializes competing deliveries. Release the marker
    # if the queue write fails so a GitHub redelivery can retry.
    script = """
        if not redis.call('SET', KEYS[1], '1', 'NX', 'EX', 86400) then return 0 end
        if #ARGV > 0 then
            local result = redis.pcall('RPUSH', KEYS[2], unpack(ARGV))
            if type(result) == 'table' and result.err then
                redis.call('DEL', KEYS[1])
                return redis.error_reply(result.err)
            end
        end
        return 1
    """

    @classmethod
    async def enqueue(cls, repo, delivery, commits, ref):
        key = f"gitprotect:delivery:{repo.github_repo_id}:{delivery}"
        try:
            async with Redis(host=settings.REDIS_HOST, port=settings.REDIS_PORT,
                             socket_connect_timeout=2, socket_timeout=2) as redis:
                if await redis.exists(key):
                    return False
                # Bound concurrency and reuse the HTTP connection pool. If any diff
                # fails, no marker or partial batch is written, allowing redelivery.
                semaphore = asyncio.Semaphore(8)
                async with httpx.AsyncClient(timeout=6, follow_redirects=False) as http:
                    client = GitHubClient(crypto_service.decrypt(repo.access_token_encrypted), http)

                    async def fetch_job(sha):
                        async with semaphore:
                            diff = await client.request(
                                "GET", f"/repos/{repo.repo_name}/commits/{sha}",
                                headers={"Accept": "application/vnd.github.diff"})
                        return json.dumps(dict(
                            repository_id=repo.id, commit_sha=sha, ref=ref,
                            delivery_id=delivery, diff=diff,
                            actor_type="system", actor_label="system"))

                    tasks = [asyncio.create_task(fetch_job(sha)) for sha in commits]
                    try:
                        jobs = await asyncio.wait_for(asyncio.gather(*tasks), timeout=7)
                    finally:
                        for task in tasks:
                            task.cancel()
                        await asyncio.gather(*tasks, return_exceptions=True)
                return bool(await redis.eval(cls.script, 2, key, "gitprotect:scan_queue", *jobs))
        except TimeoutError as exc:
            raise HTTPException(503, "Diff retrieval timed out; redeliver this webhook") from exc
        except RedisError as exc:
            raise HTTPException(503, "Scan queue unavailable") from exc


async def process_delivery(body, signature, delivery, event, db):
    if not re.fullmatch(r"sha256=[0-9a-f]{64}", signature):
        raise HTTPException(401, "Invalid webhook signature")
    try:
        payload = json.loads(body)
        github_id = payload["repository"]["id"]
        if type(github_id) is not int or github_id <= 0:
            raise ValueError()
    except (ValueError, KeyError, TypeError):
        raise HTTPException(400, "Invalid webhook payload")
    repo = db.scalar(select(Repository).where(Repository.github_repo_id == github_id))
    if not repo or not repo.webhook_secret_encrypted:
        raise HTTPException(401, "Invalid webhook signature")
    secret = crypto_service.decrypt(repo.webhook_secret_encrypted)
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(401, "Invalid webhook signature")
    if event == "ping":
        return dict(status="ping_ok", delivery_id=delivery)
    if event != "push":
        raise HTTPException(400, "Unsupported webhook event")
    try:
        if not isinstance(payload["commits"], list) or len(payload["commits"]) > 2048:
            raise ValueError()
        commits = list(dict.fromkeys(item["id"] for item in payload["commits"]))
        ref = payload["ref"]
        if not isinstance(ref, str) or not isinstance(payload["commits"], list) or not all(
            isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{40}", sha) for sha in commits
        ):
            raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise HTTPException(422, "Invalid push payload")
    queued = await DeliveryDedupService.enqueue(repo, delivery, commits, ref)
    return dict(status="queued" if queued else "duplicate_ignored", delivery_id=delivery,
                queued_commits_count=len(commits) if queued else 0)
