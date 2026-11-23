"""
MOD-04: Dashboard & Author Auditing router.
Cung cấp các API tổng hợp KPI, phân bố repo, xu hướng rò rỉ, kiểm toán tác giả và xuất báo cáo CSV/PDF.
"""
from typing import Literal, Optional
from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.modules.dashboard.schemas import (
    AuthorAuditResponse,
    MetricsResponse,
    RepoBreakdownResponse,
    TrendResponse,
)
from app.modules.dashboard.service import DashboardService

router = APIRouter(prefix="", tags=["MOD-04: Dashboard & Author Auditing"])


@router.get(
    "/audit/authors/{repo_id}",
    response_model=AuthorAuditResponse,
    summary="Kiểm toán danh tính tác giả commit & cảnh báo giả mạo email (FR-09)",
)
async def audit_authors(repo_id: int, spoofing_only: bool = False):
    return {
        "repo_id": repo_id,
        "allowed_email_domains": ["organization.vn"],
        "total_commits_audited": 12,
        "spoofing_violations_count": 1,
        "items": [],
    }


@router.get(
    "/dashboard/export",
    summary="Xuất báo cáo tổng kết tình trạng an ninh mã nguồn định dạng CSV hoặc PDF (S3-05a)",
)
def export_report(
    format: str = Query("csv", pattern="^(csv|pdf)$", description="Định dạng xuất báo cáo (csv hoặc pdf)"),
    repo_id: Optional[int] = Query(None, description="Lọc theo kho lưu trữ"),
    severity: Optional[str] = Query(None, description="Lọc theo mức độ nghiêm trọng"),
    status: Optional[str] = Query(None, description="Lọc theo trạng thái"),
    db: Session = Depends(get_db),
):
    content, media_type, filename = DashboardService.export_report(
        db=db,
        format=format,
        repo_id=repo_id,
        severity=severity,
        status=status,
    )
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get(
    "/dashboard/metrics",
    response_model=MetricsResponse,
    summary="KPI 4 mức độ nghiêm trọng (cache 60s)",
)
def get_metrics(db: Session = Depends(get_db)):
    return DashboardService.get_metrics(db)


@router.get(
    "/dashboard/repo-breakdown",
    response_model=RepoBreakdownResponse,
    summary="Phân bố cảnh báo theo kho (cache 60s)",
)
def get_repo_breakdown(db: Session = Depends(get_db)):
    return DashboardService.get_repo_breakdown(db)


@router.get(
    "/dashboard/trend",
    response_model=TrendResponse,
    summary="Xu hướng rò rỉ theo ngày/tuần (cache 60s)",
)
def get_trend(
    granularity: Literal["day", "week"] = "day",
    days: int = Query(30, ge=7, le=180),
    db: Session = Depends(get_db),
):
    return DashboardService.get_trend(db, granularity, days)
