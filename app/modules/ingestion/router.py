from typing import Optional
from fastapi import APIRouter, Header, Query, status
from app.core.enums import ConnectionStatusEnum, ScanStatusEnum
from app.modules.ingestion.schemas import (
    RepoConnectRequest, RepositoryResponse, RepositoryListResponse,
    GitHubWebhookPushPayload, WebhookAckResponse
)
from app.modules.ingestion.service import RepoConnectionService, WebhookService

router = APIRouter(prefix="", tags=["MOD-01: Ingestion & Webhook Gateway"])

@router.post("/webhooks/github", response_model=WebhookAckResponse, summary="Tiếp nhận sự kiện git push từ GitHub Webhook (FR-02)")
async def receive_webhook(
    payload: GitHubWebhookPushPayload,
    x_hub_signature_256: str = Header(..., alias="X-Hub-Signature-256"),
    x_github_delivery: str = Header(..., alias="X-GitHub-Delivery"),
    x_github_event: str = Header("push", alias="X-GitHub-Event")
):
    return WebhookService.process_push_event(payload, x_github_delivery)

@router.post("/repos/connect", response_model=RepositoryResponse, status_code=status.HTTP_201_CREATED, summary="Liên kết kho lưu trữ GitHub mới bằng PAT (FR-01)")
async def connect_repo(req: RepoConnectRequest):
    return RepoConnectionService.connect_repository(req)

@router.get("/repos", response_model=RepositoryListResponse, summary="Liệt kê danh sách các kho lưu trữ đã kết nối (FR-01, FR-05)")
async def list_repos(
    connection_status: Optional[ConnectionStatusEnum] = None,
    scan_status: Optional[ScanStatusEnum] = None,
    search: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=50)
):
    return {"items": [], "total": 0, "page": page, "page_size": page_size}
