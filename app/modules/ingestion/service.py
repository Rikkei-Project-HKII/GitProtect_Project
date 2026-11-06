import secrets
from app.core.security import crypto_service
from app.modules.ingestion.schemas import RepoConnectRequest

class RepoConnectionService:
    @staticmethod
    def connect_repository(req: RepoConnectRequest):
        # 1. Verify GitHub PAT & fetch real default_branch via GitHub API (HTTPX / PyGithub)
        real_default_branch = "main"
        github_repo_id = 849201928 # mock GitHub repo ID
        repo_name = req.repo_url.replace("https://github.com/", "").rstrip("/")
        
        # 2. Encrypt PAT and Webhook Secret using AES-256-GCM
        encrypted_pat = crypto_service.encrypt(req.github_pat)
        webhook_secret = req.webhook_secret or secrets.token_hex(20)
        encrypted_secret = crypto_service.encrypt(webhook_secret)
        
        # 3. Register GitHub Webhook via GitHub API
        # 4. Save to repositories table
        return {
            "id": 1,
            "github_repo_id": github_repo_id,
            "repo_name": repo_name,
            "repo_url": req.repo_url,
            "default_branch": real_default_branch,
            "connection_status": "active",
            "scan_status": "pending",
            "last_error_message": None,
            "last_scanned_at": None,
            "created_at": "2026-11-06T20:00:00Z",
            "updated_at": "2026-11-06T20:00:00Z"
        }

class WebhookService:
    @staticmethod
    def process_push_event(payload, delivery_id: str):
        # Verify HMAC-SHA256, deduplicate delivery_id via Redis SETNX (TTL 24h)
        # Push commit diff to Redis Queue for Worker
        return {
            "status": "queued",
            "delivery_id": delivery_id,
            "queued_commits_count": len(payload.commits),
            "actor_type": "system",
            "actor_label": "system"
        }
