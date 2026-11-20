from typing import Optional
from fastapi import APIRouter, Depends, Query, Response
from app.db.session import get_db
from app.modules.dashboard.author_audit import report
from app.modules.dashboard.schemas import (
    DashboardMetricsResponse, RepoBreakdownListResponse,
    DashboardTrendResponse, AuthorAuditResponse
)
from app.modules.dashboard.service import DashboardService

router = APIRouter(prefix="", tags=["MOD-04: Dashboard & Author Auditing"])

@router.get("/audit/authors/{repo_id}", response_model=AuthorAuditResponse, summary="Kiểm toán danh tính tác giả commit & cảnh báo giả mạo email (FR-09)")
def audit_authors(repo_id: int, spoofing_only: bool = False, page: int = Query(1, ge=1),
                  page_size: int = Query(50, ge=1, le=100), db=Depends(get_db)):
    return report(db, repo_id, spoofing_only, page, page_size)

@router.get("/dashboard/export", summary="Xuất báo cáo tổng hợp tình trạng an ninh mã nguồn định dạng CSV hoặc PDF")
async def export_report(format: str = Query("csv", pattern="^(csv|pdf)$")):
    if format == "csv":
        return Response(content="id,repo_name,rule_name,severity,secret_masked\n", media_type="text/csv")
    return Response(content=b"%PDF-1.4 Mock Export Content", media_type="application/pdf")

"""MOD-04 Dashboard router (S2-09a). Danh sách/chi tiết/lịch sử alert dùng lại API MOD-03."""
from typing import Literal
from sqlalchemy.orm import Session

from app.modules.dashboard.schemas import MetricsResponse, RepoBreakdownResponse, TrendResponse
from app.modules.dashboard.service import DashboardService




@router.get("/dashboard/metrics", response_model=MetricsResponse, summary="KPI 4 mức độ nghiêm trọng (cache 60s)")
def get_metrics(db: Session = Depends(get_db)):
    return DashboardService.get_metrics(db)


@router.get("/dashboard/repo-breakdown", response_model=RepoBreakdownResponse, summary="Phân bố cảnh báo theo kho (cache 60s)")
def get_repo_breakdown(db: Session = Depends(get_db)):
    return DashboardService.get_repo_breakdown(db)


@router.get("/dashboard/trend", response_model=TrendResponse, summary="Xu hướng rò rỉ theo ngày/tuần (cache 60s)")
def get_trend(granularity: Literal["day", "week"] = "day", days: int = Query(30, ge=7, le=180),
              db: Session = Depends(get_db)):
    return DashboardService.get_trend(db, granularity, days)
