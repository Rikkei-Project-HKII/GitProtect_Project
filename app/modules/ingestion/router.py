from typing import Optional
from fastapi import APIRouter, Header, Query, status, Depends
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.core.enums import ConnectionStatusEnum, ScanStatusEnum
from app.modules.ingestion.schemas import (
    RepoConnectRequest, RepositoryResponse, RepositoryListResponse,
    GitHubWebhookPushPayload, WebhookAckResponse
)
from app.modules.ingestion.service import RepoConnectionService, WebhookService

router = APIRouter(prefix="", tags=["MOD-01: Ingestion & Webhook Gateway"])

@router.post("/webhooks/github", response_model=WebhookAckResponse)
async def receive_webhook(
    payload: GitHubWebhookPushPayload,
    x_hub_signature_256: str = Header(..., alias="X-Hub-Signature-256"),
    x_github_delivery: str = Header(..., alias="X-GitHub-Delivery"),
    x_github_event: str = Header("push", alias="X-GitHub-Event")
):
    # Existing PBI-02 placeholder; MUST be secured before public exposure.
    return WebhookService.process_push_event(payload, x_github_delivery)

@router.post("/repos/connect", response_model=RepositoryResponse,
             status_code=status.HTTP_201_CREATED)
async def connect_repo(req: RepoConnectRequest, db: Session = Depends(get_db)):
    return await RepoConnectionService.connect_repository(req, db)

@router.get("/repos", response_model=RepositoryListResponse)
async def list_repos(
    connection_status: Optional[ConnectionStatusEnum] = None,
    scan_status: Optional[ScanStatusEnum] = None,
    search: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=50),
    db: Session = Depends(get_db)
):
    return RepoConnectionService.list_repositories(
        db, connection_status, scan_status, search, page, page_size)
