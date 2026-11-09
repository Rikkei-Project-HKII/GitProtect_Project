"""PBI-01 repository onboarding and listing."""
import logging
import os
import re
import secrets
from urllib.parse import urlsplit

from fastapi import HTTPException
from sqlalchemy import select, func
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.security import crypto_service
from app.models.repository import Repository
from app.modules.ingestion.github_client import GitHubClient

logger = logging.getLogger(__name__)
_REPO_PART = re.compile(r"^[A-Za-z0-9_.-]+$")


def parse_repo_url(url: str):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc != "github.com" or parsed.query or parsed.fragment:
        raise HTTPException(422, "Only canonical https://github.com repository URLs are allowed")
    segments = parsed.path.strip("/").split("/")
    if len(segments) != 2 or not all(_REPO_PART.fullmatch(s) for s in segments):
        raise HTTPException(422, "Expected https://github.com/owner/repo")
    return segments


class RepoConnectionService:
    @staticmethod
    async def connect_repository(req, db: Session):
        owner, name = parse_repo_url(req.repo_url)
        client = GitHubClient(req.github_pat)
        metadata = await client.repository(owner, name)
        if not isinstance(metadata, dict) or not all(k in metadata for k in ("id", "full_name", "default_branch", "html_url")):
            raise HTTPException(502, "Incomplete repository metadata from GitHub")
        github_id = metadata["id"]
        if db.scalar(select(Repository.id).where(Repository.github_repo_id == github_id)) is not None:
            raise HTTPException(409, "Repository already connected")

        callback = os.getenv("GITHUB_WEBHOOK_CALLBACK_URL", "").strip()
        if not callback.startswith("https://") or not urlsplit(callback).hostname:
            raise HTTPException(503, "GITHUB_WEBHOOK_CALLBACK_URL must be a public HTTPS URL")
        secret = req.webhook_secret or secrets.token_urlsafe(32)
        # Encrypt before creating any external resource to avoid orphan hooks on crypto errors.
        encrypted_pat = crypto_service.encrypt(req.github_pat)
        encrypted_secret = crypto_service.encrypt(secret)
        hook = await client.create_webhook(owner, name, callback, secret)
        if not isinstance(hook, dict) or not isinstance(hook.get("id"), int):
            raise HTTPException(502, "GitHub did not confirm webhook creation")

        record = Repository(
            github_repo_id=github_id,
            repo_name=metadata["full_name"],
            repo_url=metadata["html_url"],
            default_branch=metadata["default_branch"],
            access_token_encrypted=encrypted_pat,
            webhook_secret_encrypted=encrypted_secret,
            connection_status="active",
            scan_status="pending",
        )
        try:
            db.add(record)
            db.commit()
        except SQLAlchemyError as exc:
            db.rollback()
            try:
                await client.delete_webhook(owner, name, hook["id"])
            except Exception:
                logger.exception("Webhook cleanup failed after database error")
            if isinstance(exc, IntegrityError):
                raise HTTPException(409, "Repository already connected or database constraint failed") from exc
            raise HTTPException(500, "Could not persist repository connection") from exc
        db.refresh(record)
        # Initial scan integration with TV3 is pending; do not claim that a scan was queued.
        return record

    @staticmethod
    def list_repositories(db: Session, connection_status=None, scan_status=None,
                          search=None, page=1, page_size=20):
        query = select(Repository)
        if connection_status is not None:
            query = query.where(Repository.connection_status == connection_status.value)
        if scan_status is not None:
            query = query.where(Repository.scan_status == scan_status.value)
        if search:
            query = query.where(Repository.repo_name.ilike(f"%{search}%"))
        total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
        items = db.scalars(query.order_by(Repository.id.desc())
                           .offset((page - 1) * page_size).limit(page_size)).all()
        return {"items": items, "total": total, "page": page, "page_size": page_size}


# Existing PBI-02 implementation is preserved; it must be secured before public use.
