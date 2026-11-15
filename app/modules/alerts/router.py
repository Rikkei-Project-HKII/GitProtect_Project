from typing import Optional
from fastapi import APIRouter, Query, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.enums import SeverityEnum, AlertStatusEnum, AlertSourceEnum
from app.db.session import get_db
from app.models import SecurityAlert, AlertStatusHistory
from app.modules.alerts.schemas import (
    AlertPaginatedListResponse,
    SecurityAlertDetailResponse,
    AlertStatusUpdateRequest,
    AlertStatusUpdateResponse,
    AlertHistoryListResponse,
)
from app.modules.alerts.service import AlertLifecycleService

router = APIRouter(prefix="", tags=["MOD-03: Alert & Lifecycle Management"])


@router.get(
    "/alerts",
    response_model=AlertPaginatedListResponse,
    summary="Truy vấn và lọc danh sách cảnh báo bảo mật đa tiêu chí (FR-04, FR-05)",
)
async def list_alerts(
    repo_id: Optional[int] = None,
    severity: Optional[SeverityEnum] = None,
    status: Optional[AlertStatusEnum] = None,
    source: Optional[AlertSourceEnum] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=50),
    db: Session = Depends(get_db),
):
    query = db.query(SecurityAlert)
    if repo_id is not None:
        query = query.filter(SecurityAlert.repo_id == repo_id)
    if severity is not None:
        query = query.filter(SecurityAlert.severity == severity.value)
    if status is not None:
        query = query.filter(SecurityAlert.status == status.value)
    if source is not None:
        query = query.filter(SecurityAlert.source == source.value)

    p = 1 if hasattr(page, "default") else int(page)
    ps = 50 if hasattr(page_size, "default") else int(page_size)

    total = query.count()
    items = (
        query.order_by(SecurityAlert.detected_at.desc())
        .offset((p - 1) * ps)
        .limit(ps)
        .all()
    )
    return {"items": items, "total": total, "page": p, "page_size": ps}


@router.get(
    "/alerts/{id}",
    response_model=SecurityAlertDetailResponse,
    summary="Xem chi tiết một cảnh báo bảo mật (Data Masking NFR-01)",
)
async def get_alert(id: int, db: Session = Depends(get_db)):
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Không tìm thấy cảnh báo bảo mật với ID = {id}.",
        )
    return alert


@router.patch(
    "/alerts/{id}/status",
    response_model=AlertStatusUpdateResponse,
    summary="Cập nhật trạng thái cảnh báo & ghi lịch sử kiểm toán nguyên tử (AC-01..AC-05)",
)
async def update_status(
    id: int,
    req: AlertStatusUpdateRequest,
    db: Session = Depends(get_db),
):
    try:
        return AlertLifecycleService.update_alert_status_atomic(db=db, alert_id=id, req=req)
    except ValueError as e:
        error_msg = str(e)
        if "Không tìm thấy" in error_msg:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=error_msg)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_msg)


@router.get(
    "/alerts/{id}/history",
    response_model=AlertHistoryListResponse,
    summary="Truy xuất toàn bộ lịch sử kiểm toán Append-only của cảnh báo (AC-05)",
)
async def get_history(id: int, db: Session = Depends(get_db)):
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Không tìm thấy cảnh báo bảo mật với ID = {id}.",
        )
    items = (
        db.query(AlertStatusHistory)
        .filter(AlertStatusHistory.alert_id == id)
        .order_by(AlertStatusHistory.created_at.asc(), AlertStatusHistory.id.asc())
        .all()
    )
    return {"alert_id": id, "items": items, "total": len(items)}
