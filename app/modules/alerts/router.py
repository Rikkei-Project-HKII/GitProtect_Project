from typing import Optional
from fastapi import APIRouter, Query
from app.core.enums import SeverityEnum, AlertStatusEnum, AlertSourceEnum
from app.modules.alerts.schemas import (
    AlertPaginatedListResponse, SecurityAlertDetailResponse,
    AlertStatusUpdateRequest, AlertStatusUpdateResponse,
    AlertHistoryListResponse
)
from app.modules.alerts.service import AlertLifecycleService

router = APIRouter(prefix="", tags=["MOD-03: Alert & Lifecycle Management"])

@router.get("/alerts", response_model=AlertPaginatedListResponse, summary="Truy vấn và lọc danh sách cảnh báo bảo mật đa tiêu chí (FR-04, FR-05)")
async def list_alerts(
    repo_id: Optional[int] = None,
    severity: Optional[SeverityEnum] = None,
    status: Optional[AlertStatusEnum] = None,
    source: Optional[AlertSourceEnum] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=50)
):
    return {"items": [], "total": 0, "page": page, "page_size": page_size}

@router.get("/alerts/{id}", response_model=SecurityAlertDetailResponse, summary="Xem chi tiết một cảnh báo bảo mật (Data Masking NFR-01)")
async def get_alert(id: int):
    return {
        "id": id,
        "repo_id": 1,
        "rule_id": 1,
        "fingerprint": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "source": "gitprotect_scanner",
        "rule_name": "GitHub Personal Access Token (PAT)",
        "severity": "critical",
        "file_path": "src/config.py",
        "secret_masked": "ghp_****1a2b",
        "status": "open",
        "detected_at": "2026-11-06T20:00:00Z"
    }

@router.patch("/alerts/{id}/status", response_model=AlertStatusUpdateResponse, summary="Cập nhật trạng thái cảnh báo & ghi lịch sử kiểm toán nguyên tử (AC-01..AC-05)")
async def update_status(id: int, req: AlertStatusUpdateRequest):
    return AlertLifecycleService.update_alert_status_atomic(id, req)

@router.get("/alerts/{id}/history", response_model=AlertHistoryListResponse, summary="Truy xuất toàn bộ lịch sử kiểm toán Append-only của cảnh báo (AC-05)")
async def get_history(id: int):
    return {"alert_id": id, "items": [], "total": 0}
